# Java Audit Dynamic Verification

**Status:** Implemented

**Date:** 2026-07-28

**Goal:** Deliver increment 6b of subproject six: stand a one-shot verification
environment up from a read-only Snapshot, exercise Findings with deterministic
probes, save the runtime evidence §7.7 requires, and confirm the environment is
gone afterwards.

## What was missing

6a recorded an unconditional `inconclusive` in `dynamic_verifying` because no
environment existed. That was the specified behaviour for a missing environment
— but it meant §7.8's full confirmation path (`original finding + independent
worker confirmation + dynamic verification`) was unreachable, and
`runtime_verification` could never be `verified`.

Three things blocked it, and none was obvious from the plan:

- **The build produced nothing runnable.** Maven already ran `package
  -DskipTests`, but Gradle stopped at `classes`, and neither retained the
  archive. There was no artifact to start.
- **The index did not know what the application needs.** `application.yml` was
  classified as `spring-config` and never read, so nothing could decide which
  dependency services to start.
- **The validation image was a placeholder.** `cairn-sandbox-validation:local`
  was a settings key with no Dockerfile; `run-validation` was a symlink in the
  analysis image.

## Delivery boundary

6b does not implement model-generated PoCs (6c), the human review workbench, the
§7.10 completion gate or reporting (subproject seven).

Categories with no deterministic probe — authorization, deserialization,
template injection, expression injection — remain `inconclusive` with the reason
stated, rather than being dressed up as verified.

**The rootless-daemon path remains unverified.** This host lacks `newuidmap`,
unchanged since subproject three. The new integration layer runs against an
ordinary daemon and is explicit that it proves nothing about user-namespace
mapping.

## Multi-container sandbox groups

The backend was already a multi-resource model — `cairn.sandbox.managed`,
`.id` and `.resource` labels already distinguished `container`, `network` and
`helper`, and `destroy` and orphan reclamation already worked by label. Adding
a `service` resource was an extension of that, not a new architecture.

Services are created and started before the task container, on the same
`internal: true` per-sandbox network, under the same §9.3 baseline: non-root,
read-only root filesystem, `cap_drop: ALL`, no-new-privileges, bounded CPU,
memory and PIDs. A partial failure rolls the whole group back — a half-built
environment would let a probe run against a dependency that never started and
report the result as if it meant something. `destroy` removes services first,
because the network cannot be removed while a container is still attached.

The service catalogue (`cairn/src/cairn/sandbox/services.py`) is closed the same
way the template registry is: a caller names a `ServiceKind` and the platform
supplies the image, command, port, user, environment and tmpfs. Images are
settings so an air-gapped deployment can point at its own mirror; the *set*
stays closed either way.

**The target application runs as a child process of the runner, not in its own
container.** It needs no image the platform would otherwise build, its stdout
and stderr are captured directly as §7.7's required log evidence, and
destroying the sandbox already destroys it without a second lifecycle to
coordinate.

## Deterministic probes

The platform writes these, not a model, and each is a baseline request and a
payload request against the same route with a difference stated in advance.

| category | mechanism | confirmed when |
| --- | --- | --- |
| sql-injection | response | a SQL driver error appears, or the tautology widens the response |
| path-traversal | response | `/etc/passwd` content comes back |
| ssrf | out-of-band | a planted nonce reaches the echo service |
| xxe | out-of-band | an external entity fetches the nonce |
| command-execution | timing | `; sleep 5` costs the payload request 5 s the baseline did not |

The out-of-band nonce is what makes SSRF and XXE certain: the **application**
performs the fetch, so a nonce arriving at the echo service is proof the payload
executed, with no response-body heuristic involved.

Command execution cannot use it, and finding that out was worth the detour. The
injected command runs inside the validation container, which deliberately ships
no HTTP client — the same hardening that stops a prompt-injected "just fetch and
run this" also leaves a real command injection with nothing to call out with. A
`sleep` needs neither a client nor output reflection, and is the standard blind
technique for exactly that situation.

**Only a probe that ran and found nothing returns `rejected`.** An unknown
route, an unsupported category, a route the application does not serve, a
transport failure and an absent echo service all return `inconclusive` with a
reason. §7.7 requires it, and the asymmetry is deliberate: a missed
vulnerability that stays in the human queue is recoverable; one deleted by a
probe that never really ran is not. `ProbeOutcome` enforces the shape —
a confirmation must carry the request that produced it, an inconclusive must
carry a reason code — and `DynamicResult` refuses to hold a settled verdict at
all when the run did not complete.

The index records method-level mapping values but does not resolve class-level
`@RequestMapping` prefixes, so a route may be a suffix. The probe tries the bare
route first, then each recorded prefix, and reports `inconclusive` when none is
served rather than guessing further.

## Build plan detection

`cairn/src/cairn/analysis/buildplan.py` reads the application's own Spring
configuration for `spring.datasource.url`, Redis host and `server.port`, and
reports which `ServiceKind`s to start.

It deliberately does **not** parse a repository's `docker-compose.yml`. That
would be convenient and it would hand the repository the decision of which
containers the platform runs. It also only reads where Spring itself looks: a
stray `application.yml` under test fixtures or a vendored sample is not the
deployed configuration, and reading one would start a database the application
never asked for.

## Verification

**848 passed, 11 skipped** against a disposable PostgreSQL 16 (6a left it at
756/5). `docker compose config --quiet` and `git diff --check` pass.

The layer that matters most is new: an **opt-in integration test against a real
Docker daemon** (`CAIRN_TEST_LOCAL_DOCKER=1`, `cairn/tests/sandbox/
test_dynamic_integration.py`). It builds the validation image, starts a real
group, and asserts:

1. three containers on one network whose `Internal` flag is actually set;
2. the task reaches PostgreSQL by container name;
3. the task reaches **neither** the cloud metadata address nor the public
   internet;
4. the out-of-band echo tripwire records a planted nonce end to end;
5. after `destroy`, no labelled container or network remains.

It states plainly in its own docstring that it is **not** the rootless
configuration production requires — `require_rootless` is off, so it proves the
orchestration and the network isolation, not user-namespace mapping.
`test_docker_integration.py` remains the rootless matrix.

The validation image was rebuilt and checked: `java` present (a JRE runs a
packaged artifact), `javac`, `mvn`, `gradle`, `git`, `curl`, `wget`, `pip` and
`apt` all absent — a JDK would let a compromised probe rebuild the application
it is supposed to be testing.

## Defects found by the real-Docker layer

`_validate_template_image` refuses any image declaring a `VOLUME`, because
Docker would create an anonymous volume outside the Manager's lifecycle and real
data would outlive the sandbox. Every official database image declares one for
its data directory, so that rule banned every supported dependency — and no fake
Docker client would ever have shown it.

The fix is not to drop the check but to state what it is actually protecting: a
service image's declared volumes must each be **covered by a tmpfs mount in its
spec**. The mount takes precedence, the data lives in memory, and it disappears
with the container; an uncovered volume is still refused. The catalogue's tmpfs
coverage is now pinned against the volumes the current images declare, so an
image bump that adds one fails in the suite rather than in a deployment.

A second, quieter one: `cairn/dynamic/app.py` originally imported the throwaway
service credentials from `cairn.sandbox.services`. The validation image ships
only `cairn.analysis` and `cairn.dynamic`, so that import would have failed in
the container and nowhere else. The constants are re-declared locally with a
test pinning them against the catalogue — the same drift hazard as the two tree
hash implementations, caught at introduction this time.

## Operator steps before first real use

- **Pre-pull the dependency images on the Sandbox Manager's daemon**:
  `postgres:16-alpine`, `mysql:8`, `redis:7-alpine`. They are not in
  `docker-compose.yaml` — the Manager creates them per sandbox and destroys them
  with it. Without them, dynamic verification degrades to `inconclusive` rather
  than failing.
- Build `cairn-sandbox-validation` from `sandbox-images/Dockerfile.validation`.
  It was previously a settings key with no image behind it.
- Set `dynamic_budget` on the active `AuditPolicy` if the defaults (32 findings,
  900 s environment, 30 s per probe) do not suit. One environment serves a whole
  run, so this bounds probes rather than environments.
- `AuditPolicy.dynamic_verification = disabled` still skips the stage entirely
  and records why.
