# Java Audit Finding Pipeline and Independent Machine Review

**Status:** Implemented

**Date:** 2026-07-27

**Goal:** Deliver increment 6a of subproject six: promote candidate facts into
formal Findings, subject critical and high ones to an independent blind review,
apply §7.8's confirmation rule, and carry a run from `dynamic_verifying`
through `machine_review` to `human_review`.

## What was missing

The platform had never created a `Finding`. The `findings`,
`finding_locations`, `evidence` and `verifications` tables and the read-only
API have existed since subproject one, and `FindingService.create_candidate`
was written and tested — with no caller. Every result stopped at a
`candidate_finding` AuditFact.

That blocked everything downstream, because `Verification` and `Evidence` are
both keyed on `finding_id`: with no Findings there was nowhere for a
verification result to land. §6.14's Finding Pipeline — "a `candidate_finding`
becomes a Finding only after passing the data contract, location validation and
deduplication" — did not exist.

## Delivery boundary

6a does **not** build the dynamic verification environment: no multi-container
sandbox groups, no temporary PostgreSQL/MySQL/Redis/HTTP-echo dependencies, no
application start probe, no PoC execution, no runtime evidence collection and
no teardown-reachability check. Those are 6b.

`runtime_verification` is therefore only ever `unverified` or `not_applicable`
in 6a; `verified` requires runtime evidence that does not exist yet. The run
parks at `human_review`, which subproject seven owns along with the workbench,
the §7.10 completion gate and reporting.

**The live model hop is not verified here.** No model API key exists in this
environment and none was requested. Everything up to and including the LLM
Gateway's egress call runs for real against a stub upstream; the final hop to
`api.anthropic.com` is unconfirmed. The **rootless-daemon path also remains
unverified** — this host lacks `newuidmap`, unchanged since subproject three.

## The Finding Pipeline

`cairn/src/cairn/pipeline/` runs in the Orchestrator process. That is the right
home: the Orchestrator already clones repositories and builds Snapshots
(`_resolve_snapshot`), so reading a Snapshot Artifact back adds no access it did
not have, and another sandbox round-trip per finding would buy nothing.

- `snippets.py` streams the Snapshot TAR under the same bounds
  `orchestrator/artifacts.py` applies to sandbox output — entry count, path
  safety, per-file and per-snippet limits. A Snapshot is repository-controlled
  data and stays untrusted even though the platform produced the archive.
- `catalogue.py` holds two code constants: CWE → remediation, CWE → OWASP 2021.
  A remediation paragraph reaching a security reviewer should be a statement the
  platform stands behind, reproducible across runs and reviewable in a diff —
  not text a model generated once that nobody can re-derive. Where no specific
  guidance exists the generic text says so plainly rather than inventing some.
- `promote.py` is the gate, and it is strict in one direction: a candidate that
  cannot be substantiated is rejected **whole**, never promoted with the
  unsubstantiated parts quietly dropped.

Two rules carry the weight.

**Every location is re-resolved against the Snapshot.** Line numbers computed
inside a sandbox are checked against the Snapshot the report will cite, and the
extracted snippet is stored with `snapshot_sha`. A location the Snapshot cannot
support fails its candidate rather than producing a Finding pointing at a line
nobody can show.

**A candidate with no CWE cannot become a Finding.** `Finding.cwe_id` is
mandatory and validated as `CWE-<n>`. Inventing one to satisfy the column would
put a weakness class into a report that no tool claimed, so the candidate is
rejected and the rejection recorded as a coverage warning.

Locations lead with the call chain in entrypoint-to-sink order, then any
location the chain does not already cover, so the list reads as the path an
attacker takes rather than as an unordered set.

## Blindness enforced by the channel, not by discipline

§7.8 says the independent worker receives the candidate's category, code
locations and necessary context, and rebuilds the call chain itself — it does
not read the reporting worker's reasoning.

That is implemented as a property of the wire contract.
`VerifyCandidateSpec` (`cairn/src/cairn/sandbox/contracts.py`) declares exactly
six fields — `root_cause_key`, `module`, `category`, `cwe_ids`, `sink`,
`locations` — and `StrictModel` forbids extras. There is no field for
`message`, `controllability`, `call_chain`, `attack_preconditions`, `impact` or
`existing_defenses`, so a request carrying any of them is a validation error.
The blindness cannot be lost by a future author filling in one more field that
looked helpful, and `_verify_candidate` could not leak the original's analysis
even by accident.

`SemanticSandboxSpec` now carries exactly one assignment — a `scope` for the
Semantic Reviewer or a `candidate` for the Independent Reviewer — and
`SandboxCreateRequest` requires the one matching the operation. Subproject
three's property is unchanged: a create request still cannot choose an image,
command, environment variable, mount, capability, device, port or network.

## A verdict has to be falsifiable

`cairn/src/cairn/verify/` mirrors `cairn/semantic/`, reusing the model client,
the Tool Broker and the conversation driver. Two downgrades keep the verdict
checkable, both enforced against untrusted output:

- a `confirmed` verdict with fewer than two traced steps becomes
  `inconclusive` — a confirmation nobody can retrace is not evidence, and the
  reviewer never receives a chain to inherit;
- a `rejected` verdict naming no defeating control becomes `inconclusive` —
  "I do not think this is exploitable" is not a result anyone can check. The
  blank check handles invisible characters, so a "control" of U+200B does not
  pass.

**Nothing that goes wrong produces a rejection.** A refusal, a transport
failure, an exhausted turn budget, an unparseable answer, a chain citing lines
the source does not have, a sandbox that never started: every one becomes
`inconclusive`. §7.7 states this rule for dynamic verification and it holds
identically here — a reviewer that could not do its job must not be able to
delete a candidate.

## The §7.8 decision rule

`cairn/src/cairn/pipeline/decide.py` is a pure function over (severity, blind
verdict, dynamic verdict, corroboration count, CWE), separated from persistence
so the whole table is testable as a table.

What counts as one "independent static conclusion" was settled as: one blind
review, **or** one additional deterministic tool that reached the same
`root_cause_key` on its own. The merge already records the latter — a
candidate's `discovered_by` lists every tool that independently produced it —
so `len(discovered_by) - 1` is the corroboration count with no new bookkeeping.

| severity | blind verdict | outcome |
| --- | --- | --- |
| critical/high | confirmed, ≥2 conclusions | `machine_confirmed`, `confidence=confirmed`, runtime `unverified` |
| critical/high | confirmed, runtime confirmed | `machine_confirmed`, `confidence=confirmed`, runtime `verified` |
| critical/high | confirmed, 1 conclusion | `machine_confirmed`, confidence unchanged, `VERIFICATION_SINGLE_CONCLUSION` |
| critical/high | rejected, no corroboration | `rejected` |
| critical/high | rejected, with corroboration | conflict → human, `VERIFICATION_CONFLICT` |
| critical/high | inconclusive | `machine_confirmed`, confidence unchanged, → human |
| medium and below | not required | `machine_confirmed`, no human queue (§7.9) |

Two conventions are documented in the module because the names mislead
otherwise. `MACHINE_CONFIRMED` means *the machine stage finished*, not *the
machine decided it is real* — it is the only state the finding state machine
offers on the way to human review, and the actual verdicts live in the
`Verification` rows and in `confidence`. And a **conflict is never resolved
here**: when the blind reviewer rejects something two independent tools found,
or runtime contradicts static, the finding reaches a human with both verdicts
attached. That is the same rule §7.6 sets for severity disagreement.

Weaknesses no request can exercise — hardcoded credentials, exposed
credentials, unmaintained components — are marked `not_applicable` rather than
`unverified`, because `unverified` implies a runtime check is still owed.

## Independence, in three layers

1. **The wire contract**, above.
2. **Worker identity.** The verify task runs as
   `<orchestrator_worker_name>:independent-verifier` and records
   `Verification.verifier = independent-reviewer`.
   `FindingService.record_verification` refuses to record an
   `independent_agent` verification whose verifier appears in the candidate's
   `discovered_by`. The check lives in the service so no future call site can
   arrange the same worker on both sides (§6.10).
3. **Task identity.** The verify `AuditTask` is never the task that produced the
   candidate fact, asserted directly.

**The §13.6 gate.** `FindingService.enter_human_queue` refuses to move a
critical or high Finding into the human queue without an `independent_agent`
verification on record. The gate is the presence of the row rather than a flag
someone has to remember to set: a review that ran but could not conclude records
an `inconclusive` verification and passes; a review that never ran records
nothing and is refused.

## Orchestrator stages

`process_run` gained `semantic_auditing`, `dynamic_verifying` and
`machine_review` branches, and `_ELIGIBLE_STATUSES` gained all three.

This closes a resumability gap 5b introduced: `_semantic_audit` was called
inline at the end of `_static_scan`, and `SEMANTIC_AUDITING` was not an eligible
status — so a worker that died mid-stage left a run `process_next` would never
look at again. All three stages are now branches, and a run parked in any of
them is picked up.

`_dynamic_verify` promotes candidates, then records an `inconclusive`
`dynamic_poc` verification on each Finding naming why no runtime evidence
exists. That is not a placeholder: §7.7 states that a missing environment, a
failed build and a timeout all produce `inconclusive` and never `rejected`, so
recording the absence honestly *is* the specified behaviour. 6b changes which of
those verdicts become real; `_dynamic_verdict` reads the recorded verdict back
rather than assuming it, so the decision rule needs no change then.

`_machine_review` reviews critical and high findings in severity order (a
truncated budget must spend itself on the most serious findings, reproducibly),
applies the rule, and concludes the `AuditIntent` rows 5b opened.

The Semantic and Independent Reviewers now share `_drive_model_sandbox`: both
run one conversation in one container producing one output Artifact, and the
failure handling — queue-or-fail, destroy on every exit path, honour a
cancellation mid-wait — has to be identical or one of them leaks a container.

## Shared conversation driver

`cairn/semantic/conversation.py` was extracted from `SemanticReviewer` when the
Independent Reviewer needed the same loop. The mechanics are worth sharing
precisely because none are obvious and all were paid for once: `pause_turn` must
be appended verbatim and re-sent, a `max_tokens` truncation may still carry
complete `tool_use` blocks each needing a matching `tool_result`, refused calls
still return an `is_error` result, and the §9.6 channel layout is asserted
before every request. Reason codes are parameterised so a verify result never
reports a `SEMANTIC_*` code.

`SemanticReviewer`'s 149 tests passed unchanged through the extraction.

## Verification

**756 passed, 5 skipped** against a disposable PostgreSQL 16 (subproject 5b left
it at 620/5; the 5 skips are the opt-in Docker matrix). `docker compose config
--quiet` and `git diff --check` pass.

Beyond the suite:

- **The reviewer image rebuilt** and verified: `cairn.verify` imports, the
  container runs `run-semantic independent-verify` as uid 65532, reads its
  assignment from scratch, fails closed without a grant, emits a contract-valid
  manifest and exits 0. No JDK, Maven, Gradle, git, curl, wget, uv or pip on
  PATH.
- **The migration** applies on PostgreSQL; `verification_budget` lands NOT NULL
  alongside `semantic_budget`.
- **Mutation-checked.** Three §13.6 properties were verified to fail when the
  code enforcing them is disabled: removing the human-queue gate, disabling the
  independence check, and letting a failed review record a rejection each break
  exactly the test that names them.

A new regression test pins an invariant nothing enforced before:
`ingestion/tree.py`'s `content_sha256` and `analysis/tree_hash.py`'s
`source_tree_sha256` are two independent implementations of one hash, agreeing
by convention. The Finding Pipeline binds every `FindingLocation.snapshot_sha`
to the ingestion-side value while the candidate that produced the location was
identified by the sandbox-side one, so a drift would leave findings citing a
Snapshot they do not describe — silently, with no test failing.

## Defects fixed alongside

- `FindingService.record_verification` added the `Verification` to the session
  without appending it to `finding.verifications`. `enter_human_queue` reads
  that collection in the same transaction that records the review, so an
  already-loaded collection would not show the new row — turning the §13.6 gate
  into a refusal of findings that *were* reviewed.
- Both in-container runners crashed rather than emitting a manifest when the
  `anthropic` SDK was absent, because only `ValueError` was caught around client
  construction. An image built without the `semantic` extra would have left an
  empty output directory instead of a reported `MODEL_UNAVAILABLE`. Fixed in the
  semantic runner too, where the gap predated this increment.

## Operator steps before first real use

- Set `verification_budget` on the active `AuditPolicy` if the defaults (24
  findings, 16 turns, 16k output tokens per review) do not suit. Independent
  review is one model conversation per critical or high Finding.
- The reviewer image must be rebuilt: it now carries `cairn/verify`.
- Nothing else changes. The Independent Reviewer runs on the existing `semantic`
  template with the same permissions, image and network as the Semantic
  Reviewer, so the `CAIRN_SANDBOX_SEMANTIC_NETWORK` the operator already had to
  create for 5b covers it.
