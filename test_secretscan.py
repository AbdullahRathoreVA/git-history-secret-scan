import subprocess

import secretscan


def make_repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    run = lambda *a: subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True)
    run("init", "-q")
    run("config", "user.email", "t@t.dev")
    run("config", "user.name", "t")
    return repo, run


def test_finds_a_key_that_was_deleted_later(tmp_path):
    repo, run = make_repo(tmp_path)
    (repo / "config.py").write_text('KEY = "AKIA' + "ABCDEFGHIJKLMNOP" + '"\n')
    run("add", ".")
    run("commit", "-qm", "add config")
    (repo / "config.py").write_text("KEY = None\n")
    run("commit", "-qam", "remove key")

    findings = secretscan.scan(str(repo))
    assert [f.kind for f in findings] == ["aws_access_key"]
    assert "ABCDEFGHIJKLMNOP" not in findings[0].masked


def test_flags_committed_env_file_but_not_the_example(tmp_path):
    repo, run = make_repo(tmp_path)
    (repo / ".env").write_text("DEBUG=1\n")
    (repo / ".env.example").write_text("API_KEY=\n")
    run("add", ".")
    run("commit", "-qm", "init")

    paths = [f.path for f in secretscan.scan(str(repo)) if f.kind == "sensitive_file"]
    assert paths == [".env"]


def test_placeholders_are_not_reported(tmp_path):
    repo, run = make_repo(tmp_path)
    # Built at runtime so GitHub's push protection doesn't mistake the fixture
    # for a real token.
    fake_hf = "hf_" + "ThisIsNotARealTokenJustForTestsXYZ"
    (repo / ".env.example").write_text(
        'DATABASE_URL="postgresql://USER:PASSWORD@HOST:5432/db"\n'
        f'HF_TOKEN="{fake_hf}"\n')
    run("add", ".")
    run("commit", "-qm", "example config")

    assert secretscan.scan(str(repo)) == []


def test_exit_code_is_nonzero_when_something_leaks(tmp_path):
    repo, run = make_repo(tmp_path)
    (repo / "k.txt").write_text("ghp_" + "a" * 36 + "\n")
    run("add", ".")
    run("commit", "-qm", "oops")

    assert secretscan.main([str(repo)]) == 1
