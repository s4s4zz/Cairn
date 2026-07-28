# Java Audit Model-Authored PoCs

**Status:** Implemented

**Date:** 2026-07-28

**Goal:** Deliver increment 6c of subproject six: for findings whose category
the built-in probes do not cover, let a model write the request that would
demonstrate them at runtime, while keeping the decision of what counts as
evidence entirely with the platform.

## What was missing

6b's deterministic probes cover five categories: SQL injection, path traversal,
SSRF, XXE and command execution. Everything else — deserialization, template
injection, expression injection, authorization — returned `inconclusive` with
"no deterministic probe". Those are among the categories the semantic reviewer
is best at finding, so a large class of real findings reached the human queue
with no runtime signal at all.

## The problem 6c actually solves

Not "let a model write a PoC" — that part is easy. The problem is that a model
which both writes the payload and defines success can manufacture a
confirmation from nothing: "send `GET /`, confirmed if the response contains
`html`". §13.5 says the AI may not confirm a Finding, so the contract has to
make a forged confirmation **unrepresentable**, not merely discouraged.

Letting the model submit a baseline and an attack request is not enough either:
it could make them differ somewhere other than the payload. Baseline `GET
/nope` returning 404 against attack `GET /` returning 200 discriminates
perfectly and proves nothing.

## Three properties, each enforced in code

**The model submits one request template and one injection point, not two
requests.** `PocInjection` carries a `benign` value and a `payload` value; the
platform (`cairn.dynamic.poc.PocExecutor`) substitutes each into the same
template and sends both. The two requests provably differ at exactly one place,
by construction. `cairn/tests/dynamic/test_poc.py` asserts the two bodies are
identical but for the injected field.

**A criterion is evidence only when it discriminates.** It must match the
attack response and *not* the control response. A criterion that matches both —
the "contains html" case — is reported as `POC_CRITERION_NOT_DISCRIMINATING`,
an inconclusive, not a confirmation. This is the property that kills forgery,
and it is tested directly.

**The callback nonce belongs to the platform.** The model writes
`{{CAIRN_CALLBACK}}` into its payload; the platform substitutes a generated
`http://<echo>/<nonce>` and checks the echo service itself. The model never
sees the nonce and `PocPlan` has no field to assert one was observed. An
out-of-band confirmation — the strongest signal, reusing 6b's echo tripwire —
cannot be faked because the model has no access to what it would need to fake.

The criterion vocabulary is closed: `contains_text`, `status_code_is`,
`status_code_differs`, `elapsed_exceeds_ms`, `echo_nonce_observed`. No regex and
no expression — a regex is expressive enough to route around the discrimination
rule, quite apart from being a denial-of-service surface.

## Author and executor in different sandboxes

The author (`cairn/src/cairn/poc/`) runs on the semantic template under a new
`author-poc` operation: read-only source, the Tool Broker, the Gateway, and no
target network — the application does not exist yet. It produces a `PocPlan`.

The executor runs in the validation sandbox: the target network and the echo
service, and no Gateway (only the semantic template may carry a `semantic`
block, enforced since 6a).

The container that can talk to the model cannot reach the application; the one
that can reach the application cannot talk to the model. No single context both
writes a PoC and judges whether it worked — and that is a channel property, not
a workflow convention.

The plan is validated three times: by `PocPlan` when authored, by
`PocPlanSpec` at the wire boundary, and by `PocPlan` again inside the container
that will run it. The platform-side gate applies on both sides of every
boundary the plan crosses.

## Category coverage and an honest boundary

Supported: deserialization, template injection, expression injection (payload
into a body field or parameter, with `{{CAIRN_CALLBACK}}` or a timing
criterion). Authorization is supported only in its unauthenticated-access
shape — the control value carries an obviously invalid credential that should
be rejected, the payload omits it.

**Owner-scoped authorization (IDOR) is not covered and stays `inconclusive`
with the reason stated.** It needs two authenticated identities to show one
principal reaching another's object, and the platform has no credentials for
the target application. The prompt tells the author to say so in its rationale
rather than invent an authentication story, and an honest inconclusive is worth
more than a confirmation the discrimination rule would discard anyway.

## Orchestrator wiring

`engine.py`'s `_dynamic_verify` authors PoCs before the environment stands up,
for critical and high findings whose category is not in
`PROBEABLE_CATEGORIES`, reusing `_drive_model_sandbox` and `_mint_grant` with a
`:poc-author` worker identity. Validated plans ride the same
`DynamicSandboxSpec` into the one validation environment and run alongside the
deterministic probes.

`AuditPolicy.dynamic_budget` gained `max_authored_pocs` (default 12). It lives
inside the existing `dynamic_budget` JSON, so — unlike the plan's guess — there
is **no new migration**; a policy written before 6c simply uses the default.
Truncation records a coverage warning.

`decide.py` is unchanged: a PoC outcome is a `ProbeOutcome`, and its verdict
flows into the §7.8 decision exactly as a deterministic probe's does. A
confirmed PoC gives a critical/high finding `runtime_verification=verified` and
`confidence=confirmed`; `cairn/tests/orchestrator/test_poc_stage.py` checks that
equivalence end to end.

## Verification

**916 passed, 15 skipped** against a disposable PostgreSQL 16 (6b left it at
848/11). `docker compose config --quiet`, `git diff --check` and `uv lock
--check` pass.

New tests: `poc/test_contracts.py` (every forgery and escape attempt refused),
`poc/test_author.py`, `poc/test_runner.py`, `dynamic/test_poc.py` (the
substitution differs at one place, the nonce is the platform's, the criterion
truth table, no failure mode rejects), `orchestrator/test_poc_stage.py`.

The opt-in real-Docker layer (`CAIRN_TEST_LOCAL_DOCKER=1`) gained a test that
plants a nonce and confirms it out of band through the running echo container —
the mechanism a PoC's `echo_nonce_observed` criterion rides.

## A 6b defect this increment surfaced

Rebuilding the validation image to ship `cairn.poc` revealed that the image had
**never carried Pydantic**, so `cairn.dynamic.runner` — which validates every
manifest — could not import. 6b did not catch it because its integration tests
run the container with a `sleep` command and never invoke `run-validation`; the
real entry point would have failed on first use in production.

Fixed by installing Pydantic v2 at build time and removing pip afterwards, so
the image still ships no package manager. Two new opt-in image tests guard it:
one imports the dynamic runner inside the built image, one asserts no `javac`,
`mvn`, `gradle`, `git`, `curl`, `wget` or `pip` (module included) is present.
These are the regression guards the `sleep`-command tests structurally could not
provide.

## Delivery boundary

6c does not implement owner-scoped authorization PoCs, the human review
workbench, the §7.10 completion gate or reporting (subproject seven). The model
still cannot confirm a finding: it writes the request, and the platform decides
what counts as evidence.

**Unverified, and reported as such:** the live model hop (no API key here); the
rootless-daemon path (this host lacks `newuidmap`, unchanged since subproject
three). The local-Docker layer runs against an ordinary daemon and proves the
orchestration and network isolation, not user-namespace mapping.

## Operator steps before first real use

- Rebuild both `cairn-sandbox-semantic` (now ships `cairn.poc`) and
  `cairn-sandbox-validation` (now ships `cairn.poc` and Pydantic).
- Set `max_authored_pocs` on the active `AuditPolicy`'s `dynamic_budget` if the
  default of 12 does not suit. Each authored PoC is one model conversation.
