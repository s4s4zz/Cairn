# Java Audit Workbench, Human Review, and Reporting

**Status:** Implemented

**Date:** 2026-07-29

**Goal:** Deliver subproject seven: protect the single-tenant control plane with
local identity and explicit roles, make the human-review stage executable,
enforce the §7.10 completion gate, produce durable reports, and expose the
complete workflow through a Vue workbench served by the API image.

## Delivery boundary

This increment closes the main seven-subproject workflow. A run no longer parks
at `human_review`: a reviewer can make a final disposition, an auditor can
request a real reverification task, the platform checks Coverage and review
completeness, and an auditor can generate versioned HTML, JSON, and SARIF
reports. The resulting run ends as `completed` or `completed_with_warnings`.

It does not turn the current deployment into a public multi-tenant service.
OIDC, trusted-proxy configuration, rate limiting, certificate termination,
backup/restore, S3/MinIO, Kubernetes, and the other production-hardening items
remain outside this increment. The deployment is still single tenant.

Closed-platform CP0 proceeded in parallel and is deliberately separate from
this completion claim. Its synthetic fixtures, contracts, schemas, and
deterministic benchmark are implemented; authorized Yonyou/Weaver commercial
samples and human-adjudicated private gold labels are not present. Nothing in
subproject seven establishes support for either vendor.

Its published JSON Schemas are structural preflight contracts. Cross-field
invariants that portable JSON Schema cannot express are declared in
`x-cairn-runtime-invariants` and enforced by the version-matched Pydantic/CLI
loader. CP0 archive reproduction is pinned to JDK 21 with Java 17 classfile
output; the committed synthetic hash was verified using `javac 21.0.11`.

## Delivered paths

The backend work is concentrated in these ownership boundaries:

- `cairn/migrations/versions/20260728_0007_workbench_identity.py` and
  `cairn/src/cairn/server/persistence/models/identity.py`: local users,
  server-side sessions, and operator audit entries with no edit/delete API.
  The migration brings the domain schema to 21 tables.
- `cairn/src/cairn/server/auth/`: Argon2id password handling, opaque sessions,
  cookie handling,
  CSRF validation, explicit role dependencies, and the audit-log writer.
- `cairn/src/cairn/server/routers/auth.py`, `users.py`, and `audit_logs.py`:
  login/logout,
  self-service password changes, administrator account management, and
  filterable audit-log reads.
- `cairn/src/cairn/server/services/findings.py` and
  `server/routers/findings.py`: final human dispositions and executable
  reverify requests.
- `cairn/src/cairn/server/services/audit_runs.py` and
  `server/routers/audit_runs.py`: persistent
  task/Coverage reads, retry, completion checks, report creation, and resumable
  SSE run events.
- `cairn/src/cairn/server/services/reports.py` and
  `server/routers/artifacts.py`: versioned report metadata and HTML/JSON/SARIF
  downloads.
- `cairn/src/cairn/server/routers/snapshots.py`: persistent Repository Snapshot
  lists and
  bounded source reads for the workbench.
- `cairn/src/cairn/pipeline/decide.py` and the orchestration stages: severe
  machine rejections enter human review without discarding their computed
  runtime state, and reverify tasks are durably claimed before worker execution
  so competing orchestrators cannot run the same request twice.

The browser application lives under `cairn/web`. It uses Vue 3, TypeScript,
Pinia, Vue Router, Monaco, ECharts, and `@lucide/vue`, and supplies login, dashboard,
Repository/Snapshot import, run launch and detail, task timeline, SSE progress,
Coverage, Finding/source inspection, review/reverify, reports, policies, users,
and audit logs. Tasks, reports, and Snapshot history are read from persistent
backend APIs rather than browser storage.

Static delivery is owned by `cairn/src/cairn/server/app.py`, `Dockerfile`,
`.dockerignore`, and `docker-compose.yaml`. The image builds `cairn/web` in a
Node 22 stage and
copies `dist` into the Python image. FastAPI serves real assets and extensionless
SPA routes when `index.html` exists, while `/api`, `/health`, `/docs`, `/redoc`,
and `/openapi.json` remain reserved and never fall through to the SPA.

## Security model

Passwords are stored as parameterized Argon2id PHC strings. The account CLI
prompts on the terminal instead of accepting a password option, and CLI account
changes are audited as the `system` principal. Passwords, password hashes,
session values, CSRF values, and Git credentials do not enter audit details.
Stored PHC values are parsed with exact salt and digest lengths plus bounded
cost parameters; malformed or backend-rejected values fail authentication
closed instead of escaping as server errors.

Authentication uses a random opaque `cairn_session` cookie backed by a
server-side session row. The session cookie is HttpOnly; its companion
`cairn_csrf` cookie is readable so the same-origin client can echo the value in
`X-CSRF-Token`. Every unsafe request validates that header against the session
row. Both cookies are `SameSite=Strict` and `Secure` by default. The repository's
localhost-only HTTP Compose profile explicitly opts out with
`CAIRN_SESSION_COOKIE_SECURE=false`; an HTTPS deployment must retain the secure
default.

The roles are `admin`, `auditor`, `reviewer`, and `viewer`. Authorization is an
explicit allow-set on each endpoint, not an ordering comparison. A newly added
role therefore receives no accidental permissions. Role changes, account
deactivation, administrative password resets, and self-service password changes
revoke affected sessions.

Business mutations and their audit entries commit in one database transaction.
Denied role checks and failed logins are committed before their domain errors
leave the request, so the events are retained. The audit-log API is read-only.
Sensitive Artifact authorization happens before resolving the content-addressed
file path or bytes, preventing a `viewer` from reaching runtime logs, PoC
traffic, scanner output, or source material.

SSE does not retain the request's database session for the life of the stream.
Each poll opens a short-lived session, observes committed worker updates, and
rechecks that the login session is still valid. Streams support `Last-Event-ID`,
send heartbeat comments and a retry interval, and stop on revocation,
disconnect, or a terminal AuditRun state.

## Human review and completion gate

A reviewer can record `confirmed`, `rejected`, or `accepted_risk`. An auditor
can instead request `reverify`; this creates a real `AuditTask` using the
requested verification method. Its result is attached to the Finding and
returns the run to the human queue. A `reverify` request is not a final human
disposition.

The machine stage cannot silently terminate a critical/high Finding by
rejecting it. Any Finding that is currently, or was originally, critical/high
must reach human review and have a final non-reverify disposition. This retains
human accountability when a reviewer changes severity as part of the decision.

Report generation is the completion boundary and refuses a run unless all of
the following are true:

1. At least one Inventory task succeeded; a missing or failed Inventory cannot
   be treated as usable audit coverage.
2. Numerical Coverage gaps have matching reason classes. An unrelated generic
   warning, such as a build warning, cannot excuse a missing entrypoint or an
   unsupported component.
3. Every current or historical critical/high Finding has its final human
   disposition, and no required reverify remains unresolved.

When the gate passes, report generation locks the run against concurrent review
changes, first records a successful `coverage_check` task to prove the check
ran, creates a versioned `Report`, and stores HTML, JSON, and SARIF Artifacts.
HTML includes attack preconditions, confidence and runtime state, call-chain
locations and snippets, evidence, machine verification, human review,
static-tool status, Coverage warnings, skipped paths, and unsupported
components. Report metadata is queryable independently of browser state.

## Batch-review invariant

The design mentions batching Findings with the same rule, root cause, and
evidence. Within one AuditRun, the promotion pipeline already merges candidates
with the same `root_cause_key` and retains their corroborating tools and
locations on one Finding. The exact batch key therefore normally denotes one
review object, not several.

No cross-run batch action was added. Different runs can refer to different
Snapshots, tool versions, dynamic evidence, or controls, so carrying one human
decision across them would weaken the evidence boundary. If promotion semantics
later allow multiple same-root Findings in a run, batch review needs a new
transactional contract and tests rather than a UI-only shortcut.

## Deployment

The image build is self-contained: `docker compose up -d --build` compiles the
workbench and starts it with the API. After the migration has completed, the
first administrator is bootstrapped interactively:

```bash
docker compose exec cairn-server uv run cairn create-user \
  --username admin --role admin
```

For a manual source run, build and point FastAPI at the output before starting
the API:

```bash
cd cairn/web
npm ci
npm run build
cd ../..
export CAIRN_STATIC_ROOT=$PWD/cairn/web/dist
```

Plain HTTP is only supported as an explicit localhost development choice with
`CAIRN_SESSION_COOKIE_SECURE=false`. Production must terminate HTTPS before the
application and keep Secure Cookie enabled.

## Verification evidence

The close-out regression evidence recorded for this increment is:

- full non-Docker backend suite: **1133 passed, 15 deselected**;
- focused backend API, authorization, review, Coverage, report, persistence,
  and orchestration selection at the preceding checkpoint: **169 passed**;
- static delivery and Compose contract selection: **23 passed**;
- legacy public-scope/OpenAPI selection: **14 passed**;
- PostgreSQL 16 migration upgrade/downgrade/upgrade selection: **2 passed**;
- Vue/Vitest: **8 files, 18 tests passed**;
- Vue TypeScript check and Vite production build: passed;
- `npm audit --omit=dev`: **0 vulnerabilities**;
- CP0 contracts, fixture builder, baseline, metrics, and CLI: **23 CP0 tests
  passed**, and **32 passed** in the combined CLI + CP0 selection;
- Python `compileall`, `docker compose config --quiet`, and `git diff --check`:
  passed;
- the production `cairn-server` image, including its Node workbench stage,
  built successfully; an ephemeral container confirmed
  `/cairn/src/cairn/server/static/index.html` is present in the final image;
- the final image ran with PostgreSQL 16 and migration `20260728_0007`; `/`, an
  SPA deep link, the referenced JavaScript asset, `/health/ready`, API 404,
  unauthenticated session, invalid login, and missing-asset responses all
  returned the expected status, JSON/HTML boundary, and media type.

The Vite build reports a roughly 2.3 MB Monaco chunk and a roughly 498 KB
dashboard/ECharts chunk. They are deployment performance warnings, not test
failures; later splitting should be measured against actual loading behavior.
The full development-dependency audit still reports six high-severity entries
under `@vue/test-utils -> js-beautify`; they are absent from the runtime image
and `npm audit --omit=dev` is clean. Clearing them currently requires either an
older test-utils release or incompatible transitive overrides, so they remain a
development-tooling risk rather than being hidden with `--force`.

## Residual risks and unverified paths

The local Artifact Store is content addressed. If report bytes are written and
the subsequent database transaction rolls back, those bytes can remain without
a Report/Artifact reference. Immediate deletion in the failing request is not
safe because another committed row may reference the same deduplicated content.
Production maintenance therefore needs offline, reference-based garbage
collection with a grace period.

The current `/health/ready` response supplies direct readiness facts only for
the API and database. The dashboard therefore renders workers, scanners, the
LLM Gateway, and the Sandbox Manager as `unknown`. Compose deliberately
prevents the Audit API from reaching the Sandbox Manager, so `unknown` must not
be rendered or documented as `down`; aggregated auxiliary health needs a
separately designed observation path.

The following paths were not verified during this increment and are not claimed
as completed test evidence:

- a real browser/Playwright screenshot and viewport pass; browser tooling was
  unavailable, although component tests, type checking, and the production
  build passed;
- the complete authentication/review/report API workflow suite against
  PostgreSQL 16; the migration itself was verified against an isolated
  PostgreSQL database;
- the production rootless Docker daemon/user-namespace path;
- the final live-model hop with an operator-provided API key.

Those omissions do not change the unit/API contract results above, but they are
required deployment qualification before a production rollout.
