# Java Audit Semantic Execution

**Status:** Implemented

**Date:** 2026-07-27

**Goal:** Deliver increment 5b of subproject five: run the AI semantic review
stage end to end. Derive review tasks from index evidence, mint a short-lived
model grant per task, execute the reviewer inside a Sandbox on the internal
analysis network, merge its candidates with scanner evidence, record an
AuditIntent for verification, and advance the run out of `semantic_auditing`.

## Delivery boundary

5b does **not** create `Finding` rows, run dynamic verification, or implement
machine review. Candidates remain `candidate_finding` AuditFacts and
`AuditIntent` rows stay `pending` until the dynamic-verification subproject
claims them. `CandidateConfidence` still has no `confirmed` member, so the AI
cannot promote its own conclusion.

**The live model hop is not verified here.** No model API key exists in this
environment, and none was requested. Everything up to and including the LLM
Gateway's egress call is exercised against a stub upstream; the final hop to
`api.anthropic.com` is unconfirmed. `cairn semantic-smoke` exists so an
operator can close that gap in one command.

## What changed at the seam

Before this increment `_run_static_scans` ended by transitioning to
`AuditRunStatus.SEMANTIC_AUDITING` and stopping. It now calls
`_semantic_audit`, and a run proceeds to `dynamic_verifying`.

## Evidence-driven task split

Each task is one model conversation, so the split is the cost control. The
planner (`cairn/src/cairn/orchestrator/semantic_tasks.py`) reads the index the
deterministic stage already produced — 8 entrypoint kinds and 8 sink kinds from
`cairn/src/cairn/analysis/indexer.py` — and emits a (module, attack surface,
category) task only where the evidence justifies one:

- **Sink-driven.** A module gets a `sql-injection` review when it holds both an
  entrypoint and a `database-query` sink. A module with no `xml-parser` sink
  gets no XXE review. Fixed mapping for all eight sink kinds.
- **Surface-driven.** Authorization applies to any reachable surface whether or
  not it reaches a tainted sink, and Spring Security misconfiguration follows a
  `security-configuration` permission record.

On a three-module fixture this produces 7 tasks where a cartesian product over
14 categories would produce 210. Both vocabularies are closed, so an unknown
kind contributes nothing rather than falling into a default category — a new
indexer kind shows up as missing coverage, not as a miscategorised review.

Ordering is deterministic and deduplicated on `ReviewScope.scope_key`, which is
bounded to `AuditTask.scope_key`'s `String(128)`, so the existing
`uq_audit_tasks_run_scope_key` constraint makes re-planning idempotent — a
second pass cannot pay for the same conversation twice. `AuditPolicy.
semantic_budget` caps the total; a truncated plan records a coverage warning,
because a silent cap reads as "fully covered" when it is not.

## The closed semantic channel

The reviewer needs a credential and an assignment, and subproject three's core
property is that a create request cannot choose an image, a command, an
environment variable, a mount, a capability, a device, a port or a network.
Both arrive as **one typed block** (`SemanticSandboxSpec`) rather than by
reopening any of those:

- Required when the template is `semantic`, refused for every other template,
  so no build or scanner container can be handed a model credential.
- The grant is **write-only**. `SandboxRecord` never carries it back — the
  record is persisted, served by the internal API and logged by the
  Orchestrator, none of which should hold a live credential.
- The scope is written by the Manager to `<scratch>/cairn-semantic-scope.json`
  in canonical JSON. It is the only file the Manager ever writes into a
  workspace and its shape is fixed, so this is not a general file channel.
- The container environment stays a closed set of names
  (`_CREDENTIAL_KEYS`): the caller supplies values through a typed block, never
  keys, and a name outside the set is a backend failure.

Network policy is `FIXED` via `CAIRN_SANDBOX_SEMANTIC_NETWORK`. The Manager
drives its own rootless daemon, so the Compose network `cairn-analysis-net` is
**not** visible to it — the operator must create an equivalent restricted
network on that daemon that routes to `cairn-llm-gateway:8002`, exactly as for
the build dependency proxy. Left unset the template has no route, and its tasks
fail with a coverage warning rather than silently reviewing nothing.

## The semantic image

`sandbox-images/Dockerfile.semantic` is deliberately **not** a layer on the
analysis image. That image carries a JDK, Maven, Gradle and Semgrep; §9.7 gives
the reviewer a read-only index and bounded snippets, not a toolchain. Verified
in the built image: `java`, `javac`, `mvn`, `gradle`, `git`, `curl`, `wget`,
`uv`, `uvx`, `pip` and `semgrep` are all absent; `anthropic` 0.120.0 is present;
it runs as uid 65532.

The in-container entry point (`cairn/src/cairn/semantic/runner.py`) reads the
scope, takes the grant from the environment and **removes it**, so nothing the
reviewer runs afterwards can read the credential back out of `os.environ` or
`/proc/self/environ`. Candidates are derived in-container, exactly as the
scanners derive theirs: identity depends on the Snapshot tree hash and every
location is re-resolved against the source, and the source exists only inside
the sandbox.

## Severity conflicts (§7.6)

5a recorded disagreements in `severity_conflict` but kept adopting the highest
severity. That is now reversed: when tools disagree the merged candidate keeps
the **lowest** undisputed severity and carries the claims, so a single tool's
"critical" cannot outvote three tools' "low" and reach a reviewer as settled
fact. Verification raises it on evidence instead.

This exposed a latent coupling worth recording. `merge_candidates` picks its
`primary` member — the source of `message` and `category` — by ordering on
severity. Once the merged candidate's stored severity became the conservative
value rather than any tool's claim, a merged candidate re-sorted against a raw
member and `message` flipped between passes. The ordering now keys off the
strongest *claim* a candidate stands for, and `merge_candidates` and
`_merge_prose` share one `_merge_order_key` instead of two copies of the same
sort. Order-independence, idempotence and stability under re-merge all still
hold, which matters because the engine re-merges an already-merged payload on
every subsequent tool.

## Verification

Full suite against a disposable PostgreSQL 16: **620 passed, 5 skipped**
(baseline entering this increment: 521 passed, 5 skipped; the five skips are
the opt-in Docker template matrix). `docker compose config --quiet` and
`git diff --check` pass. The new migration `20260727_0004` upgrades, downgrades
and re-upgrades, and `audit_policies.semantic_budget` lands NOT NULL.

Notable coverage:

- **`test_semantic_tasks.py`** — the split declines what the index does not
  justify: no XXE task without an `xml-parser` sink, nothing for a module with
  no entrypoints, no leakage across module boundaries, and an unknown kind
  contributes nothing. Truncation is a deterministic prefix and is reported.
- **`test_semantic_template.py`** — the semantic block is required for its
  template and refused for the other three; the grant reaches the backend and
  appears in neither `SandboxRecord` nor any log record; the injected
  environment is exactly the closed set and `CAIRN_SANDBOX_ID` cannot be
  overwritten by a credential; traversal in an entrypoint hint is refused.
- **`test_runner.py`** — the grant does not survive in `os.environ`; a
  malformed scope fails closed with a well-formed manifest rather than an empty
  output directory.
- **`test_semantic_stage.py`** — a semantic candidate merges with a scanner
  candidate on a shared `root_cause_key` and the call chain survives; one
  AuditIntent per scope with its source links; a refusal becomes a coverage
  warning and the run still advances; an empty plan advances; a missing grant
  key fails closed *and visibly*; the stage is idempotent on a second pass.
- **`test_gateway_integration.py`** — the full chain with only the model
  replaced: an Orchestrator-minted grant is accepted by the real
  `create_gateway_app`, the stub upstream receives the real API key and never
  the grant, the Gateway clamps the reviewer's output ceiling to the grant, a
  foreign-signed grant is refused before egress, and a request declaring
  server-side `web_fetch` is refused with `LLM_TOOL_NOT_ALLOWED`.

The image was built and run for real: with no grant supplied it emits
`SEMANTIC_GRANT_MISSING` in a valid `cairn-semantic-result-v1` and exits 0,
under `--network none --read-only --user 65532:65532`.

**Not verified, and not claimed:** a real request to `api.anthropic.com`. The
rootless-daemon path also remains unverified end to end — this host lacks
`newuidmap`, unchanged since subproject 3.

## Operator steps before first real use

1. Build `cairn-sandbox-semantic:local` from `sandbox-images/Dockerfile.semantic`.
2. Create a restricted network on the sandbox daemon that routes to the
   Gateway, and set `CAIRN_SANDBOX_SEMANTIC_NETWORK`.
3. Mount the long-term model key at the Gateway and the grant signing key at
   both the Gateway and the Orchestrator. The Orchestrator must **not** receive
   the model key.
4. Run `cairn semantic-smoke --source <tree> --grant-key-file <key>` once and
   confirm it reports `status completed`. Check `cache_read` in its usage line
   on a second run to confirm the prompt prefix is caching.
