# Java Deterministic Analysis Implementation

**Status:** Implemented

**Date:** 2026-07-26

**Goal:** Deliver subproject four from the approved Java audit platform
design: controlled Java project inventory and build execution, deterministic
scanner adapters, normalized candidate findings, formal Artifact ownership,
and explicit per-tool Coverage.

## Delivery boundary

This increment starts an Audit Orchestrator process and carries a run from
`created` through source resolution, `preprocessing`, and `static_scanning`.
After deterministic analysis it parks the run in `semantic_auditing`, which is
owned by the next subproject. It does not create semantic-agent tasks, perform
dynamic verification, promote candidates into final Findings, or generate a
report.

The Orchestrator is a separate control-plane process. It can access
PostgreSQL, the Artifact Store, source-ingestion configuration, and the
authenticated Sandbox Manager API. It never receives a Docker socket.

## Controlled execution profiles

The Sandbox Manager retains the three server-owned templates: `analysis`,
`build`, and `validation`. This increment adds a closed execution-profile enum
to the create request:

```text
default
inventory
build
codeql
semgrep
findsecbugs
dependency-check
trivy
gitleaks
config-rules
```

Each profile is registered against exactly one template and expands to a fixed
image command. A caller still cannot provide an image, executable, argument,
environment variable, mount, network, capability, device, or port. Invalid
template/profile pairs fail before a container is created.

`default` preserves the template-contract probe used by Sandbox Manager
operations and tests. `inventory` and source-only scanners run without a
network. `build`, CodeQL, and FindSecBugs use the build template; any build
network is still the single administrator-configured fixed network.

## Result contract

Every deterministic profile writes `/work/output/manifest.json` using
`cairn-deterministic-result-v1`. The common envelope contains:

- the exact operation and tool name/version;
- `completed`, `failed`, `unavailable`, or `skipped`;
- stable error and warning codes without host paths or command stderr;
- raw-result paths relative to the output root;
- operation-specific inventory, build, or normalized candidate data.

An absent binary or rules/database bundle is `unavailable`, never success.
Non-zero tool exits are `failed`. The workload still exits successfully after
writing a valid failure manifest so the Orchestrator can persist the raw
Artifact and Coverage reason. A malformed or missing manifest fails the
AuditTask and is retried under its fixed attempt budget.

## Java inventory

The inventory profile uses standard-library parsers and conservative lexical
indexing; it does not execute repository code or build scripts. It emits:

- Maven POM, Gradle settings/build file, wrapper, mixed-build, and nested
  multi-module detection;
- module coordinates and inter-module dependency edges;
- JDK candidates from Maven compiler properties/plugins, Gradle toolchains and
  compatibility settings, `.java-version`, and `jvm.config`;
- a deterministic build plan honoring Maven Wrapper, system Maven, Gradle
  Wrapper, then system Gradle for matching module roots only;
- Java package, type, method, and annotation symbols;
- HTTP, Servlet, filter/interceptor, RPC, message-consumer, and scheduled
  entrypoints;
- authorization annotations and security configuration references;
- request/input sources and database, HTTP, filesystem, process,
  deserialization, expression, XML, and template sinks;
- configuration, container, Kubernetes, Terraform, test, generated, vendored,
  and unsupported paths;
- initial module, Java file, entrypoint, and sensitive-sink Coverage totals.

Parsers cap file sizes and decode source with replacement. Paths are normalized
POSIX paths and output ordering is stable.

## Build behavior

The build profile consumes the same immutable Snapshot and independently
recomputes the build plan. It invokes only fixed argument vectors:

```text
./mvnw --batch-mode --no-transfer-progress ... package
mvn    --batch-mode --no-transfer-progress ... package
./gradlew --no-daemon --console=plain ... classes
gradle    --no-daemon --console=plain ... classes
```

Wrapper execution is preferred only when the matching wrapper exists.
Maven and Gradle are not tried indiscriminately against the other build
system. Process output is capped, written to fixed files, and represented by a
structured build manifest.

A failed build sets Coverage to `failed` or `partial`, records a warning, and
causes bytecode-dependent scanner tasks to be `skipped`. Semgrep, gitleaks,
Trivy filesystem analysis, dependency manifest analysis, configuration rules,
and the inventory remain eligible.

## Scanner adapters and normalization

The image entrypoint contains fixed adapters for CodeQL, Semgrep,
FindSecBugs/SpotBugs, OWASP Dependency-Check, Trivy, gitleaks, and Cairn
configuration rules. External adapters use exact non-shell commands and local,
image-owned rules or vulnerability databases. Runtime downloading of rule
packs or scanner databases is forbidden.

Normalizers accept bounded raw files and convert SARIF, Semgrep JSON,
SpotBugs XML, Dependency-Check JSON, Trivy JSON, and gitleaks JSON into one
candidate contract:

```text
rule_id, cwe_ids, category, severity, confidence
message, locations, sink, fingerprint, discovered_by
```

Locations are rejected unless their normalized relative paths exist in the
Snapshot and line numbers are positive and ordered. Fingerprints are computed
by Cairn from the Snapshot hash, canonical CWE/category, primary path, symbol
or sink, and stable line context; tool-provided fingerprints are evidence only.
Candidates with the same root-cause key are merged while preserving every
tool, rule, location, and raw Artifact reference.

The built-in configuration scanner covers dangerous Spring settings,
Dockerfile privilege/user mistakes, Kubernetes privileged/host namespace
settings, and broad Terraform network exposure. It is deterministic and
versioned with the platform.

Dependency-Check commonly reports a JAR path under its external Maven or
Gradle cache rather than a source path. The normalizer first validates a
reported Snapshot path, then deterministically falls back to the nearest
module descriptor, root `pom.xml`, or Gradle lock file. The fallback still
produces only a location that exists inside the immutable Snapshot.

## Default toolchain image and offline assets

The default template image now bundles JDK 17, checksum-verified Maven 3.9.11
and Gradle 8.14.3 distributions, Semgrep 1.130.0, and a platform-owned Java
security ruleset. `sandbox-images/toolchain.json` records the fixed versions,
checksums, local rules path, and the administrator-provisioned asset contract.

CodeQL, FindSecBugs/SpotBugs, OWASP Dependency-Check, Trivy, and gitleaks are
not silently downloaded or partially installed. An administrator supplies
fixed versions and the declared rules/database bundles in a derived image.
When either the binary or required asset is absent, the adapter writes an
explicit `unavailable` result. This lets the default image execute inventory,
build, configuration rules, and Semgrep immediately without overstating the
coverage of externally distributed tools.

## Orchestrator and persistence

`cairn orchestrate` runs a bounded polling loop. PostgreSQL row locks with
`SKIP LOCKED` claim one eligible run at a time. Task creation is idempotent on
`(audit_run_id, type, scope_key)`, and each task records a stable execution
profile in `scope`.

For every successful Sandbox collection the Orchestrator:

1. verifies the content-addressed descriptor against the Artifact Store;
2. creates an `Artifact` row bound to the `AuditRun` and producing
   `AuditTask`;
3. appends its UUID to `AuditTask.output_artifact_ids`;
4. opens the TAR with safe bounded readers and validates `manifest.json`;
5. persists inventory facts or normalized candidate facts;
6. commits Artifact metadata, facts, Coverage, and terminal task status in one
   database transaction.

Retries reuse an already registered `(task, SHA-256, kind)` Artifact rather
than creating duplicate ownership rows. Artifact-store or database failures
must not mark a task successful.

Malformed, missing, unsafe, or operation-mismatched result manifests consume
the same fixed task attempt budget. Every distinct attempt output is formally
registered before retry; byte-identical outputs reuse the existing task-owned
Artifact. A known sandbox that was created but whose start request fails is
destroyed before the task is queued again.

Inventory facts use `architecture`, `entrypoint`, `source`, and `sink`.
Deterministic candidates remain `candidate_finding` AuditFacts in this
subproject. The Finding Pipeline in the machine-review subproject is
responsible for creating or merging formal `Finding` rows.

## Coverage contract

`AuditCoverage.static_tools_completed` has one entry for every scanner enabled
by the immutable policy version. Each value contains:

```text
status: completed | failed | unavailable | skipped
version: string | null
task_id: UUID
artifact_ids: UUID[]
reason_code: string | null
candidate_count: integer
```

Build and scanner failures append stable, de-duplicated warnings and increment
the run warning count. Disabled tools are absent rather than reported as
completed. The run may enter `semantic_auditing` after every enabled tool is
terminal and every failure is represented in Coverage.

## Implementation sequence

1. Add strict deterministic result contracts and bounded TAR loading.
2. Implement Maven/Gradle/JDK/module detection and Java indexes.
3. Implement build planning and the fixed build runner.
4. Implement scanner invocations, raw-format normalizers, fingerprints, and
   root-cause merging.
5. Add controlled Sandbox execution profiles without widening request control.
6. Add the authenticated Sandbox client and Artifact registrar.
7. Add Orchestrator task generation, retry, Coverage, and run-stage handling.
8. Add the standalone Orchestrator CLI and Compose service.
9. Add Maven, Gradle, mixed-module, scanner-format, failed-build, and
   orchestration fixtures.
10. Verify migrations, the complete unit suite, image contracts, and opt-in
    Docker execution.

## Acceptance

- Maven and Gradle fixture projects produce stable module, JDK, symbol,
  entrypoint, permission, source, sink, and build-plan indexes.
- The Orchestrator records output bytes as formal task-owned Artifacts before
  marking tasks successful.
- Build failure skips only bytecode-dependent work and source-level scanners
  still run.
- Every enabled tool has a versioned terminal Coverage entry and a raw
  Artifact when it emitted output.
- Normalized results contain rules, CWEs, validated locations, and raw
  Artifact references.
- Results from multiple tools with the same root-cause key merge
  deterministically.
- No request can choose commands, arguments, environment, images, mounts,
  capabilities, devices, ports, or networks.
- The Audit API and Orchestrator have no Docker socket; timeout, cancellation,
  and Sandbox cleanup behavior remains intact.

## Verification

Final verification on 2026-07-26, after the legacy dispatcher deletion:

- `220 passed, 5 skipped` for the complete suite against a disposable
  PostgreSQL 16, including analysis, orchestration, ingestion, persistence,
  Sandbox Manager, API, CLI, and Compose contracts; the five skipped cases are
  the opt-in Docker template matrix;
- focused tests cover Maven, Gradle, independent mixed builds, Java indexes,
  every raw scanner format, dependency-cache location fallback, failed builds,
  cross-tool merge, task-owned Artifact idempotency, malformed-output retries,
  attempt-budget exhaustion, HTTP client errors, and start-failure cleanup;
- live PostgreSQL upgrade, downgrade, and re-upgrade passed; the applied schema
  carries the new columns and all three unique constraints, matching the
  offline Alembic DDL assertions;
- the toolchain image built and its bundled versions match `toolchain.json`
  exactly: JDK 17.0.19, Maven 3.9.11, Gradle 8.14.3, and Semgrep 1.130.0. Both
  Gradle and Semgrep require the runner-supplied `HOME`/`GRADLE_USER_HOME`
  under scratch; they fail without it because the image user has no writable
  home by design;
- Semgrep executed the bundled `/opt/cairn/rules/semgrep` ruleset inside the
  image under `--network none` with a read-only source mount, reporting zero
  errors and matching both seeded findings
  (`cairn.java.jdbc.concatenated-query`, `cairn.java.runtime.exec`) at their
  expected lines. This confirms the offline-rules contract;
- all five opt-in Docker cases passed against a disposable daemon and left no
  labeled container or network behind;
- `docker compose config --quiet` and `git diff --check` passed.

The earlier `236 passed` figure predates the legacy dispatcher deletion, which
removed 82 tests belonging to that package.

One environment-dependent check remains outstanding: the profile matrix has not
run against a genuinely rootless daemon, because this host lacks `newuidmap`.
The available daemon was rootful, so the matrix ran only under the explicit
test-only override; with `require_rootless=True` the Manager correctly refuses
it. The rootless path itself is therefore still unverified end to end and is not
reported as passed.
