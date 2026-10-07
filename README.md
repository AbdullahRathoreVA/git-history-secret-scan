# git-history-secret-scan

Find API keys, tokens and `.env` files anywhere in a git repository's **history**,
not just in the files you have checked out today.

A key committed once and deleted in the next commit is still readable by anyone
who clones the repo. Before making a private repository public, run this.

```
$ python secretscan.py ../my-app
../my-app: 2 finding(s)
  [sensitive_file] .env  (file should not be committed)
  [openai_key] scripts/try_api.py  sk-pro… (164 chars)
```

Secrets are masked in the output, so the report is safe to paste into an issue
or keep in a CI log.

## What it checks

Every blob reachable from any branch or tag (`git rev-list --all --objects`), for:

- cloud and AI provider keys: AWS, Google, OpenAI, Anthropic, Hugging Face, Groq
- GitHub, Slack and Telegram bot tokens, Stripe live keys
- private key blocks, JWTs, database URLs with a password in them
- files that should never be committed: `.env`, `id_rsa`, `*.pem`, service account JSON

Obvious placeholders (`USER:PASSWORD@HOST`, `your-key-here`, `xxxxxx`) are skipped,
and `.env.example` style templates are allowed.

## Use it

Needs Python 3.10+ and git. No dependencies.

```bash
python secretscan.py path/to/repo                 # human-readable report
python secretscan.py repo-a repo-b --json         # machine-readable
python secretscan.py path/to/repo --ignore jwt    # skip a pattern
```

It exits with status 1 when anything is found, so it can gate a CI job.
Scanning a bare mirror (`git clone --mirror`) works too and is the fastest way to
check a repo you have not cloned yet.

## If it finds something

Removing the file in a new commit is not enough. Rotate the key at the provider
first, then decide whether to rewrite history (`git filter-repo`) or publish a
fresh repository without the old commits.

## Tests

```bash
pip install pytest
pytest -q
```

## License

MIT
