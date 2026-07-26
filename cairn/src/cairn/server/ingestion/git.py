from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from typing import Iterator
from urllib.parse import urlparse

from cairn.server.domain.enums import GitCredentialKind
from cairn.server.ingestion.errors import IngestionFailure


_SCP_STYLE_URL = re.compile(r"^[^@\s]+@(?P<host>[^:\s]+):.+$")
_INVALID_REF_CHARACTERS = re.compile(r"[\x00-\x20~^:?*\\[]")


def git_remote_host(remote_url: str) -> str:
    scp_match = _SCP_STYLE_URL.fullmatch(remote_url)
    if scp_match is not None:
        return scp_match.group("host").lower().rstrip(".")
    parsed = urlparse(remote_url)
    if parsed.scheme not in {"https", "ssh"} or parsed.hostname is None:
        raise IngestionFailure(
            "GIT_REMOTE_INVALID",
            "Git remote must use HTTPS or SSH",
        )
    return parsed.hostname.lower().rstrip(".")


def validate_git_ref(value: str) -> str:
    if (
        not value
        or value.startswith("-")
        or value.startswith("/")
        or value == "@"
        or value.endswith(("/", ".", ".lock"))
        or ".." in value
        or "//" in value
        or "@{" in value
        or _INVALID_REF_CHARACTERS.search(value)
    ):
        raise IngestionFailure(
            "GIT_REF_INVALID",
            "Git ref is not valid",
        )
    return value


def _host_is_allowed(host: str, allowed_hosts: list[str]) -> bool:
    for allowed in allowed_hosts:
        normalized = allowed.lower().rstrip(".")
        if normalized.startswith("*."):
            suffix = normalized[1:]
            if host.endswith(suffix) and host != normalized[2:]:
                return True
        elif host == normalized:
            return True
    return False


class GitFetcher:
    def __init__(
        self,
        *,
        allowed_hosts: list[str],
        timeout_seconds: int,
        max_checkout_bytes: int,
    ) -> None:
        self.allowed_hosts = allowed_hosts
        self.timeout_seconds = timeout_seconds
        self.max_checkout_bytes = max_checkout_bytes

    def fetch_into(
        self,
        remote_url: str,
        ref: str,
        destination: Path,
        credential: tuple[GitCredentialKind, dict[str, str]] | None = None,
    ) -> str:
        host = git_remote_host(remote_url)
        if not _host_is_allowed(host, self.allowed_hosts):
            raise IngestionFailure(
                "GIT_HOST_NOT_ALLOWED",
                "Git remote host is not in the configured allowlist",
                http_status=403,
            )
        ref = validate_git_ref(ref)
        destination.parent.mkdir(parents=True, exist_ok=True)
        remote_scheme = urlparse(remote_url).scheme
        if remote_scheme in {"ssh", ""} and credential is None:
            raise IngestionFailure(
                "GIT_CREDENTIAL_REQUIRED",
                "SSH Git remotes require an explicitly stored credential",
            )

        try:
            with self._credential_environment(remote_url, credential) as environment:
                self._run(
                    [
                        "git",
                        "-c",
                        "core.hooksPath=/dev/null",
                        "-c",
                        "protocol.file.allow=never",
                        "init",
                        "--quiet",
                        "--",
                        str(destination),
                    ],
                    environment,
                )
                self._run(
                    [
                        "git",
                        "-C",
                        str(destination),
                        "-c",
                        "core.hooksPath=/dev/null",
                        "-c",
                        "protocol.file.allow=never",
                        "fetch",
                        "--depth=1",
                        "--no-tags",
                        "--",
                        remote_url,
                        ref,
                    ],
                    environment,
                )
                commit_sha = self._run(
                    [
                        "git",
                        "-C",
                        str(destination),
                        "rev-parse",
                        "--verify",
                        "FETCH_HEAD^{commit}",
                    ],
                    environment,
                ).strip()
                self._run(
                    [
                        "git",
                        "-C",
                        str(destination),
                        "-c",
                        "core.hooksPath=/dev/null",
                        "-c",
                        "filter.lfs.smudge=",
                        "-c",
                        "filter.lfs.required=false",
                        "checkout",
                        "--detach",
                        "--force",
                        commit_sha,
                    ],
                    environment,
                )
                if (
                    self._directory_size(destination)
                    > self.max_checkout_bytes * 2
                ):
                    raise IngestionFailure(
                        "GIT_REPOSITORY_TOO_LARGE",
                        "Git repository exceeds the configured ingestion size limit",
                        http_status=413,
                    )
        except FileNotFoundError as exc:
            raise IngestionFailure(
                "GIT_CLIENT_UNAVAILABLE",
                "Git client is not installed in the ingestion environment",
                http_status=503,
            ) from exc
        finally:
            git_metadata = destination / ".git"
            if git_metadata.exists():
                shutil.rmtree(git_metadata)

        if not re.fullmatch(r"[0-9a-fA-F]{40,64}", commit_sha):
            raise IngestionFailure(
                "GIT_COMMIT_INVALID",
                "Git did not return a valid commit identifier",
                http_status=500,
            )
        if self._directory_size(destination) > self.max_checkout_bytes:
            raise IngestionFailure(
                "GIT_CHECKOUT_TOO_LARGE",
                "Git checkout exceeds the configured expanded size limit",
                http_status=413,
            )
        return commit_sha.lower()

    def _run(self, command: list[str], environment: dict[str, str]) -> str:
        try:
            completed = subprocess.run(
                command,
                env=environment,
                check=True,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            raise IngestionFailure(
                "GIT_CLONE_TIMEOUT",
                "Git source retrieval timed out",
                http_status=504,
            ) from exc
        except subprocess.CalledProcessError as exc:
            raise IngestionFailure(
                "GIT_CLONE_FAILED",
                "Git source retrieval failed",
            ) from exc
        return completed.stdout

    @contextmanager
    def _credential_environment(
        self,
        remote_url: str,
        credential: tuple[GitCredentialKind, dict[str, str]] | None,
    ) -> Iterator[dict[str, str]]:
        environment = {
            key: value
            for key, value in os.environ.items()
            if not key.upper().startswith("GIT_") and key != "SSH_AUTH_SOCK"
        }
        environment.update(
            {
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_ALLOW_PROTOCOL": "https:ssh",
                "GIT_LFS_SKIP_SMUDGE": "1",
                "GIT_TERMINAL_PROMPT": "0",
            }
        )
        if credential is None:
            yield environment
            return

        kind, payload = credential
        with tempfile.TemporaryDirectory(prefix="cairn-git-credential-") as temporary:
            credential_root = Path(temporary)
            if kind is GitCredentialKind.HTTPS_TOKEN:
                if urlparse(remote_url).scheme != "https":
                    raise IngestionFailure(
                        "GIT_CREDENTIAL_TYPE_MISMATCH",
                        "HTTPS credentials require an HTTPS remote",
                    )
                if set(payload) != {"username", "token"}:
                    raise IngestionFailure(
                        "GIT_CREDENTIAL_INVALID",
                        "Stored HTTPS Git credential is invalid",
                        http_status=500,
                    )
                askpass = credential_root / "askpass.sh"
                askpass.write_text(
                    "#!/bin/sh\n"
                    'case "$1" in\n'
                    '  *Username*) printf "%s" "$CAIRN_GIT_ASKPASS_USERNAME" ;;\n'
                    '  *) printf "%s" "$CAIRN_GIT_ASKPASS_TOKEN" ;;\n'
                    "esac\n"
                )
                askpass.chmod(0o700)
                environment.update(
                    {
                        "GIT_ASKPASS": str(askpass),
                        "CAIRN_GIT_ASKPASS_USERNAME": payload["username"],
                        "CAIRN_GIT_ASKPASS_TOKEN": payload["token"],
                    }
                )
            elif kind is GitCredentialKind.SSH_KEY:
                if urlparse(remote_url).scheme not in {"ssh", ""}:
                    raise IngestionFailure(
                        "GIT_CREDENTIAL_TYPE_MISMATCH",
                        "SSH credentials require an SSH remote",
                    )
                if set(payload) != {"private_key", "known_hosts"}:
                    raise IngestionFailure(
                        "GIT_CREDENTIAL_INVALID",
                        "Stored SSH Git credential is invalid",
                        http_status=500,
                    )
                private_key = credential_root / "identity"
                known_hosts = credential_root / "known_hosts"
                private_key.write_text(payload["private_key"])
                known_hosts.write_text(payload["known_hosts"])
                private_key.chmod(0o600)
                known_hosts.chmod(0o600)
                environment["GIT_SSH_COMMAND"] = (
                    f"ssh -F {os.devnull} -i {private_key} "
                    "-o IdentitiesOnly=yes "
                    "-o StrictHostKeyChecking=yes "
                    "-o ProxyCommand=none "
                    "-o PermitLocalCommand=no "
                    f"-o UserKnownHostsFile={known_hosts}"
                )
            else:
                raise IngestionFailure(
                    "GIT_CREDENTIAL_INVALID",
                    "Stored Git credential kind is unsupported",
                    http_status=500,
                )
            yield environment

    @staticmethod
    def _directory_size(root: Path) -> int:
        total = 0
        for directory, _, filenames in os.walk(root, followlinks=False):
            for filename in filenames:
                path = Path(directory) / filename
                if not path.is_symlink():
                    total += path.stat().st_size
        return total
