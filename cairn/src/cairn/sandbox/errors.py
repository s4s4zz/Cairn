from cairn.server.errors import DomainError


class SandboxError(DomainError):
    def __init__(
        self,
        error_code: str,
        message: str,
        *,
        http_status: int = 422,
    ) -> None:
        super().__init__(error_code, message, http_status)


def sandbox_not_found(identifier: object) -> SandboxError:
    return SandboxError(
        "SANDBOX_NOT_FOUND",
        f"Sandbox {identifier} was not found",
        http_status=404,
    )


def invalid_sandbox_state(message: str) -> SandboxError:
    return SandboxError(
        "SANDBOX_INVALID_STATE",
        message,
        http_status=409,
    )
