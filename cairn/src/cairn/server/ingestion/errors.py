class IngestionFailure(Exception):
    def __init__(
        self,
        error_code: str,
        message: str,
        *,
        http_status: int = 422,
    ) -> None:
        super().__init__(message)
        self.error_code = error_code
        self.message = message
        self.http_status = http_status
