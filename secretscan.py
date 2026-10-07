"""Scan every version of every file in a git repository for leaked secrets.

Most scanners look at the working tree. A key that was committed once and
deleted a week later is still in the history, and anyone who clones the repo
can read it. This walks every blob reachable from any ref, so a deleted
`.env` from two years ago is found the same as one committed today.

Matches are masked in the output: the report tells you what and where, never
the secret itself, so it is safe to paste into an issue or a CI log.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import asdict, dataclass

PATTERNS: dict[str, str] = {
    "aws_access_key": r"AKIA[0-9A-Z]{16}",
    "google_api_key": r"AIza[0-9A-Za-z_\-]{35}",
    "google_oauth_secret": r"GOCSPX-[0-9A-Za-z_\-]{20,}",
    "openai_key": r"sk-(?:proj-)?[A-Za-z0-9_\-]{32,}",
    "anthropic_key": r"sk-ant-[A-Za-z0-9_\-]{30,}",
    "github_token": r"gh[pousr]_[A-Za-z0-9]{36,}",
    "slack_token": r"xox[baprs]-[A-Za-z0-9\-]{10,}",
    "stripe_live_key": r"(?:sk|rk|pk)_live_[A-Za-z0-9]{16,}",
    "huggingface_token": r"hf_[A-Za-z]{30,}",
    "groq_key": r"gsk_[A-Za-z0-9]{40,}",
    "telegram_bot_token": r"\b\d{8,10}:AA[A-Za-z0-9_\-]{33}\b",
    "private_key_block": r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY",
    "jwt": r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
    "db_url_with_password": r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^:\s/'\"]+:[^@\s'\"]{4,}@",
}

# Files that should never be committed, whatever they contain.
SENSITIVE_PATH = re.compile(
    r"(?i)(^|/)(\.env(\.[a-z]+)?|id_rsa|id_ed25519|credentials\.json|"
    r"service[-_]?account.*\.json|client_secret.*\.json|.*\.pem|.*\.p12|.*\.pfx|.*\.keystore)$")
TEMPLATE_ENV = re.compile(r"(?i)\.env\.(example|sample|template|dist)$")

# A match that is obviously a placeholder is not a leak. Keeping this list
# short matters: every word here is a way for a real key to slip through.
PLACEHOLDER = re.compile(
    r"(?i)(x{6,}|your[_-]|example|placeholder|changeme|dummy|<|\*{4,}|"
    r"notareal|fake|password@|user:pass)")

MAX_BLOB_BYTES = 3_000_000


@dataclass
class Finding:
    kind: str
    path: str
    masked: str
    blob: str


def mask(secret: str) -> str:
    secret = secret.strip()
    return f"{secret[:6]}… ({len(secret)} chars)"


def git(repo: str, *args: str, data: str | None = None) -> str:
    return subprocess.run(["git", "-C", repo, *args], input=data, capture_output=True,
                          text=True, encoding="utf-8", errors="replace", check=True).stdout


def blobs(repo: str) -> dict[str, str]:
    """Every blob reachable from any ref, mapped to one path it lived at."""
    paths: dict[str, str] = {}
    for line in git(repo, "rev-list", "--all", "--objects").splitlines():
        oid, _, path = line.partition(" ")
        if path:
            paths.setdefault(oid, path)
    if not paths:
        return {}
    check = git(repo, "cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)",
                data="\n".join(paths))
    keep = {}
    for row in check.splitlines():
        oid, kind, size = row.split()
        if kind == "blob" and int(size) <= MAX_BLOB_BYTES:
            keep[oid] = paths[oid]
    return keep


def scan(repo: str, ignore: set[str] | None = None) -> list[Finding]:
    ignore = ignore or set()
    compiled = {k: re.compile(v) for k, v in PATTERNS.items() if k not in ignore}
    found: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    for oid, path in blobs(repo).items():
        if SENSITIVE_PATH.search(path) and not TEMPLATE_ENV.search(path):
            key = ("sensitive_file", path, "")
            if key not in seen:
                seen.add(key)
                found.append(Finding("sensitive_file", path, "(file should not be committed)", oid))
        raw = subprocess.run(["git", "-C", repo, "cat-file", "-p", oid], capture_output=True).stdout
        if b"\x00" in raw[:4000]:
            continue  # binary
        text = raw.decode("utf-8", "replace")
        for kind, rx in compiled.items():
            for m in rx.finditer(text):
                hit = m.group(0)
                if PLACEHOLDER.search(hit):
                    continue
                key = (kind, path, hit)
                if key in seen:
                    continue
                seen.add(key)
                found.append(Finding(kind, path, mask(hit), oid))
    return found


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("repos", nargs="+", help="paths to git repositories (bare or normal)")
    ap.add_argument("--json", action="store_true", help="print findings as JSON")
    ap.add_argument("--ignore", action="append", default=[], metavar="KIND",
                    help=f"skip a pattern; one of: {', '.join(PATTERNS)}")
    args = ap.parse_args(argv)

    total = 0
    report = {}
    for repo in args.repos:
        findings = scan(repo, set(args.ignore))
        total += len(findings)
        report[repo] = [asdict(f) for f in findings]
        if not args.json:
            print(f"{repo}: {len(findings)} finding(s)")
            for f in findings:
                print(f"  [{f.kind}] {f.path}  {f.masked}")
    if args.json:
        print(json.dumps(report, indent=2))
    # Non-zero exit lets CI fail the build on a leak.
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
