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
        "JDBC SQL 执行",
    ),
    _SinkRule(
        "jvm-bytecode-command-execution",
        frozenset({"java.lang.Runtime", "java.lang.ProcessBuilder"}),
        ("exec", "start"),
        "CWE-78",
        "command-injection",
        "critical",
        "进程执行",
    ),
    _SinkRule(
        "jvm-bytecode-object-deserialization",
        frozenset({"java.io.ObjectInputStream"}),
        ("readObject", "readUnshared"),
        "CWE-502",
        "unsafe-deserialization",
        "high",
        "Java 对象反序列化",
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
        "外发 HTTP 请求",
    ),
    _SinkRule(
        "jvm-bytecode-file-write",
        frozenset({"java.nio.file.Files"}),
        ("write", "newOutputStream", "copy", "move"),
        "CWE-73",
        "external-control-of-file-name",
        "medium",
        "文件系统写入",
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
                    f"字节码中存在对 {target} 的调用，属于「{rule.sink_family}」类 "
                    "API。该调用的可达性与攻击者可控性尚未确认。"
                ),
                locations=[location],
                sink=target,
                fingerprint=fingerprint,
                root_cause_key=root_cause_key,
                discovered_by=[TOOL_NAME],
                source_rules=[rule.rule_id],
                attack_preconditions=(
                    "仅凭这一处符号化的字节码调用无法确认攻击前提。"
                ),
                impact=(
                    "潜在影响取决于是否有不可信数据抵达该 API，以及运行时的实际参数。"
                ),
                recommended_verification=(
                    "在把该候选视为可利用之前，先从外部可达的入口回溯调用方与参数。"
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
