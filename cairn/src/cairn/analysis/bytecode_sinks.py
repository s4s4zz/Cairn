from __future__ import annotations

from dataclasses import dataclass

from cairn.analysis.contracts import (
    BytecodeCallRecord,
    CandidateFinding,
    CodeLocationV2,
    ProgramIndexV2,
)
from cairn.analysis.fingerprints import candidate_identity


TOOL_NAME = "bytecode-sinks"


@dataclass(frozen=True, slots=True)
class _SinkRule:
    rule_id: str
    owners: frozenset[str]
    method_prefixes: tuple[str, ...]
    cwe_id: str
    category: str
    severity: str
    sink_family: str


_RULES = (
    _SinkRule(
        "jvm-bytecode-sql-execution",
        frozenset(
            {
                "java.sql.Statement",
                "java.sql.PreparedStatement",
                "java.sql.CallableStatement",
            }
        ),
        ("execute", "addBatch"),
        "CWE-89",
        "sql-injection",
        "high",
        "JDBC SQL execution",
    ),
    _SinkRule(
        "jvm-bytecode-command-execution",
        frozenset({"java.lang.Runtime", "java.lang.ProcessBuilder"}),
        ("exec", "start"),
        "CWE-78",
        "command-injection",
        "critical",
        "process execution",
    ),
    _SinkRule(
        "jvm-bytecode-object-deserialization",
        frozenset({"java.io.ObjectInputStream"}),
        ("readObject", "readUnshared"),
        "CWE-502",
        "unsafe-deserialization",
        "high",
        "Java object deserialization",
    ),
    _SinkRule(
        "jvm-bytecode-outbound-http",
        frozenset(
            {
                "java.net.URL",
                "java.net.http.HttpClient",
            }
        ),
        ("openConnection", "openStream", "send", "sendAsync"),
        "CWE-918",
        "ssrf",
        "high",
        "outbound HTTP request",
    ),
    _SinkRule(
        "jvm-bytecode-file-write",
        frozenset({"java.nio.file.Files"}),
        ("write", "newOutputStream", "copy", "move"),
        "CWE-73",
        "external-control-of-file-name",
        "medium",
        "filesystem mutation",
    ),
)


def bytecode_sink_candidates(
    index: ProgramIndexV2,
    *,
    snapshot_sha256: str,
) -> list[CandidateFinding]:
    candidates: list[CandidateFinding] = []
    for call in index.calls:
        rule = _matching_rule(call)
        if rule is None:
            continue
        location = CodeLocationV2(
            origin_kind="bytecode",
            container_path=call.container_path,
            entry_path=call.entry_path,
            class_name=call.class_name,
            method_name=call.method_name,
            method_descriptor=call.method_descriptor,
            bytecode_offset=call.bytecode_offset,
            symbol=(
                f"{call.class_name}.{call.method_name}"
                f"{call.method_descriptor}"
            ),
            role="sink",
        )
        target = (
            f"{call.target_owner}.{call.target_name}"
            f"{call.target_descriptor}"
        )
        location_payload = location.model_dump(mode="json")
        fingerprint, root_cause_key = candidate_identity(
            snapshot_sha256=snapshot_sha256,
            rule_id=rule.rule_id,
            cwe_ids=[rule.cwe_id],
            category=rule.category,
            primary_location=location_payload,
            sink=target,
            tool_name=TOOL_NAME,
        )
        candidates.append(
            CandidateFinding(
                rule_id=rule.rule_id,
                cwe_ids=[rule.cwe_id],
                category=rule.category,
                severity=rule.severity,
                confidence="low",
                message=(
                    f"Bytecode contains a call to {target}, a "
                    f"{rule.sink_family} API. Reachability and attacker "
                    "control have not been established."
                ),
                locations=[location],
                sink=target,
                fingerprint=fingerprint,
                root_cause_key=root_cause_key,
                discovered_by=[TOOL_NAME],
                source_rules=[rule.rule_id],
                attack_preconditions=(
                    "Not established from the symbolic bytecode call alone."
                ),
                impact=(
                    "Potential impact depends on whether untrusted data reaches "
                    "this API and on the runtime arguments."
                ),
                recommended_verification=(
                    "Trace callers and arguments from an externally reachable "
                    "entrypoint before treating this candidate as exploitable."
                ),
            )
        )
    return sorted(candidates, key=lambda candidate: candidate.fingerprint)


def _matching_rule(call: BytecodeCallRecord) -> _SinkRule | None:
    if call.target_owner is None or call.target_name is None:
        return None
    for rule in _RULES:
        if call.target_owner in rule.owners and call.target_name.startswith(
            rule.method_prefixes
        ):
            return rule
    return None
