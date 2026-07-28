"""Output contract for the Dynamic Verifier (§7.7, §13.6).

One rule shapes every type here: **only a probe that ran and found nothing may
report ``rejected``.** §7.7 states it directly — a missing environment, a failed
build and a timeout produce ``inconclusive`` — and the consequence is that
``ProbeVerdict`` has to make "I tried and it did not reproduce" and "I could not
try" different values rather than different shades of the same one.

The evidence carried alongside each verdict is what §7.7 asks to be saved:
the request, the response, the timing and the exit status. It is bounded here
rather than at the reader, because the application's response is
repository-influenced data arriving from a process the platform started.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field, model_validator

from cairn.analysis.contracts import StrictModel, ToolStatus

DYNAMIC_CONTRACT = "cairn-dynamic-result-v1"
DYNAMIC_TOOL_NAME = "dynamic-verifier"

REASON_BUILD_ARTIFACT_MISSING = "DYNAMIC_BUILD_ARTIFACT_MISSING"
REASON_PLAN_INVALID = "DYNAMIC_PLAN_INVALID"
REASON_SERVICE_UNAVAILABLE = "DYNAMIC_SERVICE_UNAVAILABLE"
REASON_APP_START_FAILED = "DYNAMIC_APP_START_FAILED"
REASON_APP_NOT_READY = "DYNAMIC_APP_NOT_READY"
REASON_INTERNAL_FAILURE = "DYNAMIC_INTERNAL_FAILURE"

# Per-probe reasons. Each of these is a reason the probe could not settle the
# question, never a reason to believe the weakness is absent.
REASON_ROUTE_UNKNOWN = "PROBE_ROUTE_UNKNOWN"
REASON_CATEGORY_UNSUPPORTED = "PROBE_CATEGORY_UNSUPPORTED"
REASON_REQUEST_FAILED = "PROBE_REQUEST_FAILED"
REASON_TIMEOUT = "PROBE_TIMEOUT"

MAX_BODY_EXCERPT = 2048
MAX_PROBES = 256


class HttpExchange(StrictModel):
    """One request and its response, bounded for storage."""

    method: str = Field(min_length=1, max_length=16)
    url: str = Field(min_length=1, max_length=4096)
    request_body: str | None = Field(default=None, max_length=MAX_BODY_EXCERPT)
    status_code: int | None = Field(default=None, ge=0, le=999)
    response_excerpt: str | None = Field(default=None, max_length=MAX_BODY_EXCERPT)
    response_bytes: int = Field(default=0, ge=0)
    elapsed_ms: int = Field(default=0, ge=0)
    error: str | None = Field(default=None, max_length=512)


class ProbeOutcome(StrictModel):
    """What one deterministic probe established about one Finding."""

    finding_id: str = Field(min_length=1, max_length=64)
    category: str = Field(min_length=1, max_length=255)
    verdict: Literal["confirmed", "rejected", "inconclusive"]
    reason_code: str | None = Field(default=None, max_length=128)
    detail: str = Field(min_length=1, max_length=4096)
    baseline: HttpExchange | None = None
    payload: HttpExchange | None = None
    # The nonce this probe planted, and whether the echo service saw it. An
    # out-of-band hit confirms SSRF, command execution and XXE without having to
    # interpret the application's own response.
    nonce: str | None = Field(default=None, max_length=64)
    echo_observed: bool = False

    @model_validator(mode="after")
    def validate_verdict(self) -> "ProbeOutcome":
        if self.verdict == "inconclusive" and not self.reason_code:
            raise ValueError("an inconclusive probe must carry a reason code")
        if self.verdict != "inconclusive" and self.reason_code:
            raise ValueError("a settled probe cannot carry a reason code")
        if self.verdict == "confirmed" and self.payload is None:
            # A confirmation with no request behind it is not evidence.
            raise ValueError("a confirmed probe must carry the request that showed it")
        return self


class DynamicResult(StrictModel):
    """Per-run manifest, mirroring the semantic and verify manifests."""

    contract: Literal["cairn-dynamic-result-v1"]
    status: ToolStatus
    tool_name: str = Field(min_length=1, max_length=128)
    reason_code: str | None = Field(default=None, max_length=128)
    app_started: bool = False
    app_exit_code: int | None = None
    app_log_path: str | None = Field(default=None, max_length=1024)
    services_ready: list[str] = Field(default_factory=list, max_length=8)
    outcomes: list[ProbeOutcome] = Field(default_factory=list, max_length=MAX_PROBES)
    warnings: list[dict[str, object]] = Field(default_factory=list, max_length=64)

    @model_validator(mode="after")
    def validate_status_payload(self) -> "DynamicResult":
        if self.status is ToolStatus.COMPLETED and self.reason_code is not None:
            raise ValueError("completed result cannot contain reason_code")
        if self.status is not ToolStatus.COMPLETED:
            if not self.reason_code:
                raise ValueError("non-completed result requires reason_code")
            # An environment that never came up cannot have settled anything.
            if any(outcome.verdict != "inconclusive" for outcome in self.outcomes):
                raise ValueError(
                    "a non-completed run cannot report a settled probe verdict"
                )
        return self
