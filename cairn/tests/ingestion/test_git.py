import subprocess

import pytest

from cairn.server.domain.enums import GitCredentialKind
from cairn.server.ingestion import IngestionFailure, git_remote_host, validate_git_ref
from cairn.server.ingestion.git import GitFetcher


@pytest.mark.parametrize(
    ("remote", "host"),
    [
        ("https://git.example.com/team/app.git", "git.example.com"),
        ("ssh://git@git.example.com/team/app.git", "git.example.com"),
        ("git@git.example.com:team/app.git", "git.example.com"),
    ],
)
def test_git_remote_host_parses_supported_urls(remote: str, host: str) -> None:
    assert git_remote_host(remote) == host


@pytest.mark.parametrize("ref", ["-upload-pack=evil", "../main", "a..b", "a b", "x@{y"])
def test_git_ref_option_and_revision_injection_is_rejected(ref: str) -> None:
    with pytest.raises(IngestionFailure) as captured:
        validate_git_ref(ref)
    assert captured.value.error_code == "GIT_REF_INVALID"


def test_git_host_allowlist_is_checked_before_process_execution(
    tmp_path,
    monkeypatch,
) -> None:
    fetcher = GitFetcher(
        allowed_hosts=["git.example.com"],
        timeout_seconds=30,
        max_checkout_bytes=1024,
    )

    def unexpected_run(*args, **kwargs):
        raise AssertionError("git process must not start")

    monkeypatch.setattr("subprocess.run", unexpected_run)
    with pytest.raises(IngestionFailure) as captured:
        fetcher.fetch_into(
            "https://attacker.invalid/team/app.git",
            "main",
            tmp_path / "checkout",
        )

    assert captured.value.error_code == "GIT_HOST_NOT_ALLOWED"


def test_git_process_does_not_inherit_host_credentials(monkeypatch) -> None:
    monkeypatch.setenv("GIT_ASKPASS", "/tmp/host-askpass")
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("SSH_AUTH_SOCK", "/tmp/agent.sock")
    fetcher = GitFetcher(
        allowed_hosts=["git.example.com"],
        timeout_seconds=30,
        max_checkout_bytes=1024,
    )

    with fetcher._credential_environment(  # noqa: SLF001
        "https://git.example.com/team/app.git",
        None,
    ) as environment:
        assert "GIT_ASKPASS" not in environment
        assert "GIT_CONFIG_COUNT" not in environment
        assert "SSH_AUTH_SOCK" not in environment
        assert environment["GIT_CONFIG_NOSYSTEM"] == "1"


def test_ssh_remote_requires_explicit_credential(tmp_path) -> None:
    fetcher = GitFetcher(
        allowed_hosts=["git.example.com"],
        timeout_seconds=30,
        max_checkout_bytes=1024,
    )

    with pytest.raises(IngestionFailure) as captured:
        fetcher.fetch_into(
            "git@git.example.com:team/app.git",
            "main",
            tmp_path / "checkout",
        )

    assert captured.value.error_code == "GIT_CREDENTIAL_REQUIRED"


def test_https_token_is_never_put_in_git_command_arguments(
    tmp_path,
    monkeypatch,
) -> None:
    commands: list[list[str]] = []
    environments: list[dict[str, str]] = []
    destination = tmp_path / "checkout"

    def fake_run(command, **kwargs):
        commands.append(command)
        environments.append(kwargs["env"])
        if "init" in command:
            (destination / ".git").mkdir(parents=True)
            stdout = ""
        elif "rev-parse" in command:
            stdout = ("a" * 40) + "\n"
        elif "checkout" in command:
            (destination / "Demo.java").write_text("class Demo {}")
            stdout = ""
        else:
            stdout = ""
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    fetcher = GitFetcher(
        allowed_hosts=["git.example.com"],
        timeout_seconds=30,
        max_checkout_bytes=1024,
    )

    commit = fetcher.fetch_into(
        "https://git.example.com/team/app.git",
        "main",
        destination,
        (
            GitCredentialKind.HTTPS_TOKEN,
            {"username": "bot", "token": "never-in-argv"},
        ),
    )

    assert commit == "a" * 40
    assert all(
        "never-in-argv" not in argument
        for command in commands
        for argument in command
    )
    assert all(
        environment["CAIRN_GIT_ASKPASS_TOKEN"] == "never-in-argv"
        for environment in environments
    )
    assert not (destination / ".git").exists()
