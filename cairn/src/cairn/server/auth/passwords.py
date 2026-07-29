"""Argon2id password hashing (§9.8).

Uses the Argon2id primitive from ``cryptography``, which the project already
depends on for the SecretStore, rather than adding a second password library:
one KDF implementation to keep current, not two.

The stored form is PHC (``$argon2id$v=19$m=...,t=...,p=...$salt$hash``) so the
parameters travel with the hash. That is what makes ``needs_rehash`` possible:
a hash written under weaker parameters can be recognised and upgraded on the
next successful login instead of silently staying weak forever.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
import re
import secrets

from cryptography.exceptions import AlreadyFinalized, InvalidKey, UnsupportedAlgorithm
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id


ARGON2_VERSION = 19
SALT_BYTES = 16
HASH_BYTES = 32
MIN_MEMORY_KIB = 8
MAX_MEMORY_KIB = 4_194_304
MIN_ITERATIONS = 1
MAX_ITERATIONS = 64
MIN_LANES = 1
MAX_LANES = 64

_PHC_PATTERN = re.compile(
    r"^\$argon2id\$v=(?P<version>\d+)"
    r"\$m=(?P<memory>\d+),t=(?P<iterations>\d+),p=(?P<lanes>\d+)"
    r"\$(?P<salt>[A-Za-z0-9+/]+)\$(?P<digest>[A-Za-z0-9+/]+)$"
)


class PasswordHashError(ValueError):
    """A stored hash is not in the form this module writes."""


@dataclass(frozen=True, slots=True)
class Argon2Parameters:
    """Cost parameters.

    The defaults are the ones OWASP lists for Argon2id (64 MiB, t=3, p=4).
    Tests override them downward — a suite that logs in a few hundred times
    should not spend a minute deriving keys — which is safe precisely because
    the parameters are stored per hash.
    """

    memory_kib: int = 65536
    iterations: int = 3
    lanes: int = 4

    def __post_init__(self) -> None:
        if not MIN_MEMORY_KIB <= self.memory_kib <= MAX_MEMORY_KIB:
            raise ValueError(
                f"memory_kib must be between {MIN_MEMORY_KIB} and {MAX_MEMORY_KIB}"
            )
        if not MIN_ITERATIONS <= self.iterations <= MAX_ITERATIONS:
            raise ValueError(
                f"iterations must be between {MIN_ITERATIONS} and {MAX_ITERATIONS}"
            )
        if not MIN_LANES <= self.lanes <= MAX_LANES:
            raise ValueError(f"lanes must be between {MIN_LANES} and {MAX_LANES}")
        if self.memory_kib < 8 * self.lanes:
            raise ValueError("memory_kib must be at least 8 * lanes")


def _kdf(salt: bytes, parameters: Argon2Parameters) -> Argon2id:
    return Argon2id(
        salt=salt,
        length=HASH_BYTES,
        iterations=parameters.iterations,
        lanes=parameters.lanes,
        memory_cost=parameters.memory_kib,
    )


def _derive(password: str, salt: bytes, parameters: Argon2Parameters) -> bytes:
    return _kdf(salt, parameters).derive(password.encode("utf-8"))


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    try:
        return base64.b64decode(value + padding, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise PasswordHashError("stored password hash has invalid base64") from exc


def hash_password(
    password: str,
    parameters: Argon2Parameters | None = None,
) -> str:
    parameters = parameters or Argon2Parameters()
    salt = secrets.token_bytes(SALT_BYTES)
    digest = _derive(password, salt, parameters)
    return (
        f"$argon2id$v={ARGON2_VERSION}"
        f"$m={parameters.memory_kib},t={parameters.iterations},p={parameters.lanes}"
        f"${_b64(salt)}${_b64(digest)}"
    )


def _parse(encoded: str) -> tuple[Argon2Parameters, bytes, bytes]:
    match = _PHC_PATTERN.match(encoded)
    if match is None:
        raise PasswordHashError("stored password hash is malformed")
    try:
        if int(match["version"]) != ARGON2_VERSION:
            raise PasswordHashError("unsupported argon2 version")
        parameters = Argon2Parameters(
            memory_kib=int(match["memory"]),
            iterations=int(match["iterations"]),
            lanes=int(match["lanes"]),
        )
        salt = _unb64(match["salt"])
        digest = _unb64(match["digest"])
    except PasswordHashError:
        raise
    except (ValueError, OverflowError) as exc:
        raise PasswordHashError("stored password hash has invalid parameters") from exc
    if len(salt) != SALT_BYTES:
        raise PasswordHashError(f"stored password salt must be {SALT_BYTES} bytes")
    if len(digest) != HASH_BYTES:
        raise PasswordHashError(f"stored password digest must be {HASH_BYTES} bytes")
    return parameters, salt, digest


def verify_password(password: str, encoded: str) -> bool:
    """Constant-time check of a password against its stored hash.

    A malformed hash is a failed verification, not an exception that escapes to
    the caller: the login path must not distinguish "no such user" from "this
    row is corrupt" in its response.
    """

    try:
        parameters, salt, expected = _parse(encoded)
        kdf = _kdf(salt, parameters)
        kdf.verify(password.encode("utf-8"), expected)
    except (
        PasswordHashError,
        AlreadyFinalized,
        InvalidKey,
        UnsupportedAlgorithm,
        ValueError,
        OverflowError,
    ):
        return False
    return True


def needs_rehash(encoded: str, parameters: Argon2Parameters | None = None) -> bool:
    parameters = parameters or Argon2Parameters()
    try:
        stored, salt, _ = _parse(encoded)
        # Construction is cheap and catches hashes the active Argon2 backend
        # cannot safely evaluate before a login reaches ``verify``.
        _kdf(salt, stored)
    except (
        PasswordHashError,
        UnsupportedAlgorithm,
        ValueError,
        OverflowError,
    ):
        return True
    return (
        stored.memory_kib < parameters.memory_kib
        or stored.iterations < parameters.iterations
        or stored.lanes < parameters.lanes
    )
