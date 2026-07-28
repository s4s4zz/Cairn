"""In-container entry point for the Dynamic Verifier (§7.7, §9.7).

Runs inside the `validation` Sandbox template on `validation-net-<run-id>`,
with the Snapshot mounted read-only and the build output unpacked into scratch.
Same `/work/source` `/work/scratch` `/work/output` contract as the other
runners, and the same "always emit a manifest" discipline: a crash has to reach
the Orchestrator as a terminal status, not as a missing file.

Everything that can go wrong resolves to `inconclusive`. §7.7 permits no other
answer from an environment that did not come up, and the manifest contract
enforces it — a non-completed `DynamicResult` cannot carry a settled verdict.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys

from cairn.analysis.contracts import ToolStatus
from cairn.dynamic.app import (
    EnvironmentError_,
    start_application,
    stop_application,
    wait_for_services,
)
from cairn.dynamic.contracts import (
    DYNAMIC_CONTRACT,
    DYNAMIC_TOOL_NAME,
    REASON_CATEGORY_UNSUPPORTED,
    REASON_INTERNAL_FAILURE,
    REASON_PLAN_INVALID,
    DynamicResult,
    ProbeOutcome,
)
from cairn.dynamic.poc import PocExecutor, REASON_PLAN_INVALID as POC_PLAN_INVALID
from cairn.dynamic.probes import ProbeRunner, ProbeTarget
from cairn.poc.contracts import PocPlan
from pydantic import ValidationError

PLAN_FILENAME = "cairn-dynamic-plan.json"
RESULT_FILENAME = "dynamic-result.json"

__all__ = ["PLAN_FILENAME", "RESULT_FILENAME", "load_plan", "main", "run"]


def _write_json(path: Path, payload: dict[str, object]) -> None:
    temporary = path.with_suffix(f"{path.suffix}.tmp")
    temporary.write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def _failed(
    reason_code: str,
    targets: list[ProbeTarget],
    poc_plans: list["PocPlan"],
    detail: str,
) -> DynamicResult:
    """A terminal result whose every probe and PoC is inconclusive.

    Both the probe targets and the authored PoCs appear, each with the reason
    the environment could not settle it: the Orchestrator records one
    verification per Finding either way, so "the environment never came up" is
    visible per finding rather than only as a run-level note.
    """

    outcomes = [
        ProbeOutcome(
            finding_id=target.finding_id,
            category=target.category,
            verdict="inconclusive",
            reason_code=reason_code,
            detail=detail,
        )
        for target in targets
    ]
    outcomes.extend(
        ProbeOutcome(
            finding_id=plan.finding_id,
            category=plan.category,
            verdict="inconclusive",
            reason_code=reason_code,
            detail=detail,
        )
        for plan in poc_plans
    )
    return DynamicResult(
        contract=DYNAMIC_CONTRACT,
        status=ToolStatus.FAILED,
        tool_name=DYNAMIC_TOOL_NAME,
        reason_code=reason_code,
        outcomes=outcomes,
    )


def load_plan(scratch: Path) -> dict[str, object]:
    """Read the probe plan the Sandbox Manager wrote into scratch."""

    path = scratch / PLAN_FILENAME
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError("dynamic plan file is unreadable") from exc
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("dynamic plan file is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("dynamic plan file is not an object")
    if not str(payload.get("app_jar") or "").strip():
        raise ValueError("dynamic plan names no runnable artifact")
    return payload


def parse_targets(payload: dict[str, object]) -> list[ProbeTarget]:
    targets: list[ProbeTarget] = []
    raw = payload.get("targets")
    if not isinstance(raw, list):
        return targets
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        finding_id = str(entry.get("finding_id") or "").strip()
        category = str(entry.get("category") or "").strip()
        if not finding_id or not category:
            continue
        prefixes = entry.get("route_prefixes")
        targets.append(
            ProbeTarget(
                finding_id=finding_id,
                category=category,
                http_method=str(entry.get("http_method") or "GET"),
                route=str(entry["route"]) if entry.get("route") else None,
                route_prefixes=tuple(
                    str(prefix) for prefix in prefixes if str(prefix).strip()
                )
                if isinstance(prefixes, list)
                else (),
                parameter=str(entry["parameter"]) if entry.get("parameter") else None,
            )
        )
    return targets


def parse_poc_plans(payload: dict[str, object]) -> list[PocPlan]:
    """Parse the authored PoCs, dropping any that no longer validate.

    Each already passed the contract when it was authored and again at the wire
    boundary; this is a third gate, in the container that will run it, so a
    plan the executor could misread never reaches the application.
    """

    plans: list[PocPlan] = []
    raw = payload.get("poc_plans")
    if not isinstance(raw, list):
        return plans
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        try:
            plans.append(PocPlan.model_validate(entry))
        except ValidationError:
            continue
    return plans


def run(source: Path, scratch: Path, output: Path) -> DynamicResult:
    del source
    try:
        plan = load_plan(scratch)
    except (ValueError, OSError) as exc:
        return _failed(REASON_PLAN_INVALID, [], [], str(exc)[:512])
    targets = parse_targets(plan)
    poc_plans = parse_poc_plans(plan)

    service_hosts = plan.get("service_hosts")
    service_hosts = service_hosts if isinstance(service_hosts, dict) else {}
    build_directory = str(plan.get("build_directory") or "build")
    jar_path = scratch / build_directory / str(plan["app_jar"])
    try:
        app_port = int(plan.get("app_port") or 8080)
    except (TypeError, ValueError):
        app_port = 8080

    try:
        ready = wait_for_services(
            {
                name: endpoint
                for name, endpoint in service_hosts.items()
                # The echo service is the platform's own probe target, not a
                # dependency the application waits for.
                if name != "echo"
            }
        )
        application = start_application(
            jar_path,
            port=app_port,
            service_hosts=service_hosts,
            output_root=output,
            scratch_root=scratch,
        )
    except EnvironmentError_ as exc:
        return _failed(exc.reason_code, targets, poc_plans, exc.detail)
    except Exception as exc:  # noqa: BLE001 - a manifest must still be emitted
        return _failed(REASON_INTERNAL_FAILURE, targets, poc_plans, str(exc)[:512])

    runner = ProbeRunner(
        application.base_url,
        echo_endpoint=str(service_hosts.get("echo") or "") or None,
    )
    outcomes: list[ProbeOutcome] = []
    echo_endpoint = str(service_hosts.get("echo") or "") or None
    try:
        for target in targets:
            try:
                outcomes.append(runner.run(target))
            except Exception as exc:  # noqa: BLE001
                # One probe's failure costs that probe, not the run.
                outcomes.append(
                    ProbeOutcome(
                        finding_id=target.finding_id,
                        category=target.category,
                        verdict="inconclusive",
                        reason_code=REASON_CATEGORY_UNSUPPORTED,
                        detail=f"The probe raised before it could conclude: {exc}"[:4096],
                    )
                )
        # Model-authored PoCs run against the same live application. The
        # executor decides what each result means; the model wrote only the
        # request.
        executor = PocExecutor(application.base_url, echo_endpoint=echo_endpoint)
        for poc_plan in poc_plans:
            try:
                outcomes.append(executor.run(poc_plan))
            except Exception as exc:  # noqa: BLE001
                outcomes.append(
                    ProbeOutcome(
                        finding_id=poc_plan.finding_id,
                        category=poc_plan.category,
                        verdict="inconclusive",
                        reason_code=POC_PLAN_INVALID,
                        detail=f"The PoC raised before it could conclude: {exc}"[:4096],
                    )
                )
    finally:
        exit_code = stop_application(application.process)

    return DynamicResult(
        contract=DYNAMIC_CONTRACT,
        status=ToolStatus.COMPLETED,
        tool_name=DYNAMIC_TOOL_NAME,
        reason_code=None,
        app_started=True,
        app_exit_code=exit_code,
        app_log_path=str(application.log_path.relative_to(output)),
        services_ready=ready,
        outcomes=outcomes,
    )


def main(argv: list[str] | None = None) -> int:
    del argv
    source = Path("/work/source")
    scratch = Path("/work/scratch")
    output = Path("/work/output")
    if not source.is_dir() or not scratch.is_dir() or not output.is_dir():
        return 70
    try:
        result = run(source, scratch, output)
    except Exception as exc:  # noqa: BLE001 - never leave an empty output dir
        result = _failed(REASON_INTERNAL_FAILURE, [], [], str(exc)[:512])
    _write_json(output / RESULT_FILENAME, result.model_dump(mode="json"))
    return 0


if __name__ == "__main__":  # pragma: no cover - container entry point
    sys.exit(main())
