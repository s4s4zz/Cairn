from __future__ import annotations

import logging

import requests

from cairn.gateway.config import GatewaySettings
from cairn.gateway.errors import (
    upstream_timeout,
    upstream_unavailable,
)

LOG = logging.getLogger(__name__)

FALLBACK_BETA_HEADER = "server-side-fallback-2026-07-01"
MESSAGES_PATH = "/v1/messages"

# Credential and beta headers the egress leg controls exclusively. ``forward``
# builds its header set from scratch and never copies an inbound header, so a
# client-supplied value of any of these is dropped by construction.
STRIPPED_CLIENT_HEADERS = (
    "x-api-key",
    "authorization",
    "anthropic-beta",
)


class UpstreamClient:
    """Policy-free egress leg: substitutes the real key and forwards the body.

    The body is forwarded verbatim with ``requests`` rather than round-tripped
    through the Anthropic SDK, so fields the SDK does not yet know about survive
    the hop. Nothing here logs the request body, the response content, or the
    API key.
    """

    def __init__(
        self,
        settings: GatewaySettings,
        *,
        session: requests.Session | None = None,
    ) -> None:
        self.settings = settings
        self.url = f"{settings.upstream_base_url}{MESSAGES_PATH}"
        self.session = session or requests.Session()

    def forward(self, body: dict[str, object], api_key: bytes) -> dict[str, object]:
        payload = dict(body)
        # Built from scratch on every call: no inbound request header is ever
        # copied onto the egress leg, so a client-supplied x-api-key,
        # authorization or anthropic-beta simply has nowhere to go.
        headers = {
            "x-api-key": api_key.decode("ascii"),
            "anthropic-version": self.settings.anthropic_version,
            "content-type": "application/json",
            "accept": "application/json",
        }
        if self.settings.refusal_fallback and "fallbacks" not in payload:
            # Route cyber-category refusals to the fallback model rather than
            # failing a legitimate audit outright.
            payload["fallbacks"] = "default"
            headers["anthropic-beta"] = FALLBACK_BETA_HEADER
        try:
            response = self.session.post(
                self.url,
                json=payload,
                headers=headers,
                timeout=self.settings.request_timeout_seconds,
                # `requests` strips Authorization across hosts but not a custom
                # x-api-key header, so following a 307/308 would re-POST the
                # prompt and the long-term key to the redirect target.
                allow_redirects=False,
            )
        except requests.Timeout as exc:
            raise upstream_timeout() from exc
        except requests.RequestException as exc:
            raise upstream_unavailable() from exc
        if not 200 <= response.status_code < 300:
            LOG.warning(
                "upstream model API rejected the request",
                extra={"upstream_status": response.status_code},
            )
            if response.status_code in {408, 504}:
                raise upstream_timeout()
            raise upstream_unavailable()
        try:
            decoded = response.json()
        except ValueError as exc:
            raise upstream_unavailable() from exc
        if not isinstance(decoded, dict):
            raise upstream_unavailable()
        return decoded

    def close(self) -> None:
        self.session.close()
