from __future__ import annotations

from contextlib import asynccontextmanager
import json
import logging
import time

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from cairn import __version__
from cairn.gateway.config import (
    GatewaySettings,
    get_gateway_settings,
    read_key_file,
)
from cairn.gateway.errors import GatewayError, grant_invalid, request_invalid
from cairn.gateway.policy import GatewayPolicy
from cairn.gateway.tokens import ModelGrant
from cairn.gateway.upstream import UpstreamClient
from cairn.model_provider import (
    ModelProviderConfigError,
    ModelProviderConfiguration,
    ModelProviderConfigStore,
    load_model_config_key,
)
from cairn.server.errors import register_error_handlers

LOG = logging.getLogger(__name__)


async def _read_bounded_body(request: Request, limit: int) -> bytes:
    """Read at most ``limit`` bytes, refusing as soon as the cap is passed.

    ``Request.body()`` concatenates the whole stream with no bound, and uvicorn
    imposes none either, so checking the length afterwards means the bytes have
    already been accepted. This service holds model-egress key material, and
    everything on the internal analysis network can reach it
    without presenting a valid grant, so the cheapest possible refusal has to
    come first.
    """

    declared = request.headers.get("content-length")
    if declared is not None and declared.isdigit() and int(declared) > limit:
        raise GatewayError(
            "LLM_REQUEST_TOO_LARGE",
            "Request body exceeds the configured limit",
            http_status=413,
        )
    chunks: list[bytes] = []
    received = 0
    async for chunk in request.stream():
        received += len(chunk)
        if received > limit:
            raise GatewayError(
                "LLM_REQUEST_TOO_LARGE",
                "Request body exceeds the configured limit",
                http_status=413,
            )
        chunks.append(chunk)
    return b"".join(chunks)


def _extract_grant_token(request: Request) -> str:
    """Accept the grant as ``x-api-key`` or ``Authorization: Bearer``.

    The Anthropic SDK constructed with ``api_key=<grant>`` sends ``x-api-key``;
    plain HTTP callers tend to send a bearer token. Both are the same
    capability, so both are accepted and nothing else is.
    """
    supplied = request.headers.get("x-api-key", "").strip()
    if supplied:
        return supplied
    authorization = request.headers.get("Authorization", "")
    scheme, separator, bearer = authorization.partition(" ")
    if separator == " " and scheme.lower() == "bearer" and bearer.strip():
        return bearer.strip()
    raise grant_invalid("Model grant was not supplied")


def _usage_tokens(payload: dict[str, object], field: str) -> int:
    usage = payload.get("usage")
    if not isinstance(usage, dict):
        return 0
    value = usage.get(field)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return 0
    return value


def _log_exchange(
    grant: ModelGrant,
    payload: dict[str, object],
    *,
    latency_ms: int,
    output_tokens: int,
) -> None:
    """Log the metering fields only.

    §5.1 forbids retaining full source prompts in ordinary logs, so the request
    body, the response content and the API key are all absent by construction.
    """
    stop_reason = payload.get("stop_reason")
    served_model = payload.get("model")
    # The refusal fallback can serve a different model than was requested, so
    # the response's own value is preferred when present and plausible.
    if not isinstance(served_model, str) or not served_model or len(served_model) > 255:
        served_model = grant.model
    LOG.info(
        "model exchange completed",
        extra={
            "model": served_model,
            "input_tokens": _usage_tokens(payload, "input_tokens"),
            "output_tokens": output_tokens,
            "latency_ms": latency_ms,
            "stop_reason": stop_reason if isinstance(stop_reason, str) else None,
            "worker": grant.worker,
            "audit_run_id": grant.audit_run_id,
        },
    )


def create_gateway_app(
    settings: GatewaySettings | None = None,
    *,
    upstream: UpstreamClient | None = None,
) -> FastAPI:
    settings = settings or get_gateway_settings()

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        grant_key = read_key_file(settings.grant_key_file)
        provider_store: ModelProviderConfigStore | None = None
        api_key = b""
        if settings.provider_config_file is not None:
            provider_store = ModelProviderConfigStore(
                settings.provider_config_file,
                load_model_config_key(settings.config_key_file),
            )
        else:
            assert settings.api_key_file is not None
            api_key = read_key_file(settings.api_key_file)
        owned_upstream = upstream is None
        active_upstream = upstream or UpstreamClient(settings)
        application.state.gateway_settings = settings
        application.state.api_key = api_key
        application.state.provider_store = provider_store
        application.state.gateway_policy = GatewayPolicy(settings, grant_key)
        application.state.upstream = active_upstream
        try:
            yield
        finally:
            if owned_upstream:
                active_upstream.close()

    application = FastAPI(
        title="Cairn LLM Gateway",
        description="Policy-enforcing egress proxy for the external model API",
        version=__version__,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    register_error_handlers(application)

    @application.get("/health/live", tags=["health"])
    def live() -> dict[str, str]:
        return {"status": "ok"}

    @application.get("/health/ready", tags=["health"])
    def ready() -> dict[str, str]:
        # Lifespan fails startup outright if either key file is unusable, so
        # this is a sanity assertion rather than a live dependency check. It
        # carries its own health code so the request-policy codes keep their
        # documented one-to-one mapping onto HTTP statuses.
        provider_store: ModelProviderConfigStore | None = getattr(
            application.state, "provider_store", None
        )
        configured = bool(getattr(application.state, "api_key", b""))
        if provider_store is not None:
            try:
                provider_store.read()
                configured = True
            except ModelProviderConfigError:
                configured = False
        if not configured or not getattr(application.state, "gateway_policy", None):
            raise GatewayError(
                "LLM_GATEWAY_NOT_READY",
                "Gateway is not holding a model API key",
                http_status=503,
            )
        return {"status": "ready"}

    @application.post("/v1/messages", tags=["messages"])
    async def create_message(request: Request) -> JSONResponse:
        policy: GatewayPolicy = application.state.gateway_policy
        active_upstream: UpstreamClient = application.state.upstream
        provider_store: ModelProviderConfigStore | None = application.state.provider_store

        # The raw bytes are measured before parsing so the size cap reflects
        # what was actually transferred, not the re-serialized form. Reading is
        # bounded as it streams: buffering first and checking afterwards would
        # let an unauthenticated peer on the analysis network exhaust the
        # memory of the one process holding the long-term model key.
        raw = await _read_bounded_body(request, settings.max_request_bytes)
        policy.check_circuit()
        token = _extract_grant_token(request)
        try:
            decoded = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise request_invalid("Request body is not valid JSON") from exc
        if not isinstance(decoded, dict):
            raise request_invalid("Request body must be a JSON object")

        provider_configuration: ModelProviderConfiguration | bytes
        if provider_store is None:
            provider_configuration = application.state.api_key
            allowed_models = settings.model_allowlist
        else:
            try:
                provider_configuration = provider_store.read()
            except ModelProviderConfigError as exc:
                raise GatewayError(
                    "LLM_GATEWAY_NOT_READY",
                    "Model provider is not configured",
                    http_status=503,
                ) from exc
            allowed_models = (provider_configuration.metadata.model,)

        grant = policy.authorize(
            token,
            decoded,
            len(raw),
            allowed_models=allowed_models,
        )
        # `authorize` reserved this much of the grant's output budget up front;
        # it is reconciled to actual usage below, or released on failure.
        reserved = decoded.get("max_tokens")
        reserved = reserved if isinstance(reserved, int) else 0
        started = time.monotonic()
        try:
            payload = await run_in_threadpool(
                active_upstream.forward,
                decoded,
                provider_configuration,
            )
        except GatewayError:
            # A transport or upstream-status failure trips the breaker. A
            # refusal never reaches here: it arrives as HTTP 200.
            policy.release(token, reserved)
            policy.record_failure()
            raise
        latency_ms = int((time.monotonic() - started) * 1000)
        output_tokens = _usage_tokens(payload, "output_tokens")
        policy.record_success(token, output_tokens, reserved=reserved)
        _log_exchange(
            grant,
            payload,
            latency_ms=latency_ms,
            output_tokens=output_tokens,
        )
        # Passed through verbatim, including ``stop_reason: "refusal"`` — a
        # safety decline is a successful exchange the caller must be able to see.
        return JSONResponse(status_code=200, content=payload)

    return application
