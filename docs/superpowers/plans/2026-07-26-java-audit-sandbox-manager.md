# Java Audit Sandbox Manager Implementation

**Status:** Implemented

**Date:** 2026-07-26

**Goal:** Deliver subproject three from the approved Java audit platform
design: an independently deployed Sandbox Manager, a rootless Docker backend,
server-owned execution templates, enforced resource budgets, timeout and
cancellation cleanup, and durable output Artifacts.

## Delivery boundary

This increment supplies the isolation and lifecycle substrate. It does not yet
run Maven, Gradle, scanners, target services, or Agents. Those commands and
images are introduced by the deterministic-analysis and dynamic-verification
subprojects.

The Audit API never receives a Docker socket. Only the independently deployed
Sandbox Manager connects to a dedicated rootless Docker daemon. The internal
Sandbox API is not published on a host port and requires a bearer token loaded
from a mounted secret file.

The MVP Manager is a single-replica service paired one-to-one with its daemon
and state volume. Horizontal coordination belongs to the Kubernetes backend;
running multiple Managers against the same local daemon is unsupported.

## Internal protocol

```text
POST   /internal/v1/sandboxes
GET    /internal/v1/sandboxes/{sandbox_id}
POST   /internal/v1/sandboxes/{sandbox_id}/start
POST   /internal/v1/sandboxes/{sandbox_id}/wait
POST   /internal/v1/sandboxes/{sandbox_id}/cancel
POST   /internal/v1/sandboxes/{sandbox_id}/artifacts
DELETE /internal/v1/sandboxes/{sandbox_id}
GET    /internal/v1/sandbox-artifacts/{sha256}
```

The artifact download route serves a collected output TAR by content address
from the Manager-owned store. It is read-only, requires the same bearer token,
and carries the digest as its `ETag` so the Orchestrator can verify bytes it
did not itself collect.

Creation accepts only:

- a server-defined template identifier;
- a content-addressed Snapshot Artifact descriptor;
- an optional AuditTask identifier;
- resource limits no larger than that template's ceiling.

The request schema rejects image names, commands, environment variables,
Capabilities, host paths, mounts, devices, ports, privileged flags, PID/IPC
modes, and network selection.

## Templates

The fixed template registry contains `analysis`, `build`, and `validation`.
Each template owns its image, command, non-root uid/gid, network policy,
resource defaults, and resource ceilings.

A template's network policy is one of three server-fixed values:

- `none` — no network namespace at all (`network_mode: none`). This is the
  `analysis` template's policy and the safe default.
- `fixed` — a pre-created, non-control Docker network named in Sandbox Manager
  configuration. The `build` template uses this when an administrator supplies
  `CAIRN_SANDBOX_BUILD_NETWORK`, so Maven and Gradle can reach an approved
  internal mirror; it falls back to `none` when unset.
- `isolated` — the Manager creates a per-sandbox `internal: true` bridge
  network labeled with the sandbox id, attaches only that workload, and removes
  it during teardown and restart reconciliation. `internal: true` means no
  route to the host or the internet; it exists so a validation workload can
  reach sidecars in its own namespace without ever sharing a network with
  another sandbox. The `validation` template uses this policy.

A request can never select, override, or name a network under any policy.

## Container baseline

Every workload is created with:

- a non-root user;
- read-only root filesystem;
- all Linux capabilities dropped;
- `no-new-privileges`;
- no privileged mode, host PID/IPC/network, devices, ports, or Docker socket;
- fixed CPU, memory, PID, tmpfs, output-disk, and execution-time limits;
- `/work/source` read-only;
- `/work/scratch` and `/work/output` as the only writable work directories;
- `/tmp` as a size-limited, `noexec`, `nosuid`, `nodev` tmpfs.

Snapshot archives are hash-checked and safely extracted by the Manager. Only
ordinary files and directories are accepted. Output collection independently
rejects symbolic links and special files before producing a deterministic TAR.
Invalid or over-budget output is discarded with a stable failure code; a
transient Artifact-store failure retains the stopped output directory for
retry.

## Lifecycle and recovery

```text
created -> running -> succeeded | failed
created | running -> cancelled | timed_out | resource_exceeded
terminal outcome -> resources_destroyed=true
```

Lifecycle records are atomically persisted outside the containers. Cancellation
and timeout attempt a graceful stop and always attempt force-removal. Once no
workload can mutate output, the Manager archives eligible evidence and removes
the controlled work directory. Output bytes enter the content-addressed
Artifact store before that directory is removed.

On Manager startup, all previously active records fail closed: their output is
collected when possible and every labeled Docker resource is removed. Labeled
resources without a matching record are treated as orphans and removed.

## Failure contracts

The complete set of stable codes is:

Request rejection:

- `SANDBOX_UNAUTHORIZED`
- `SANDBOX_TEMPLATE_UNKNOWN`
- `SANDBOX_OPERATION_INVALID`
- `SANDBOX_LIMIT_EXCEEDED`
- `SANDBOX_SNAPSHOT_INVALID`
- `SANDBOX_NOT_FOUND`
- `SANDBOX_INVALID_STATE`
- `SANDBOX_CAPACITY_EXHAUSTED`

Readiness and environment:

- `SANDBOX_BACKEND_UNAVAILABLE`
- `SANDBOX_ROOTLESS_REQUIRED`
- `SANDBOX_RESOURCE_CONTROLS_UNAVAILABLE`
- `SANDBOX_TEMPLATE_UNSAFE`
- `SANDBOX_WORKSPACE_UNAVAILABLE`
- `SANDBOX_STATE_CORRUPT`

Execution outcome:

- `SANDBOX_START_TIMEOUT`
- `SANDBOX_PROCESS_FAILED`
- `SANDBOX_TIMEOUT`
- `SANDBOX_CANCELLED`
- `SANDBOX_DESTROYED`
- `SANDBOX_CONTAINER_LOST`
- `SANDBOX_MANAGER_RESTARTED`

Resource enforcement:

- `SANDBOX_MEMORY_LIMIT_EXCEEDED`
- `SANDBOX_DISK_LIMIT_EXCEEDED`
- `SANDBOX_FILE_SIZE_LIMIT_EXCEEDED`
- `SANDBOX_OUTPUT_LIMIT_EXCEEDED`

Output collection:

- `SANDBOX_COLLECTION_PREPARATION_FAILED`
- `SANDBOX_OUTPUT_INVALID`
- `SANDBOX_ARTIFACT_WRITE_FAILED`
- `SANDBOX_ARTIFACT_NOT_FOUND`

Backend exceptions and Docker daemon responses are not returned verbatim
because they can contain host paths, registry credentials, or daemon details.

## Implemented deployment

`cairn sandbox-serve` runs a FastAPI service separate from the Audit API.
`Dockerfile.sandbox-manager` builds a dedicated image without the API image's
Git and SSH clients. Compose places it on an internal-only network with no
published port. The Audit API has no Docker mount; the Manager alone receives
the configured dedicated rootless socket.

Rootless Docker is an external prerequisite rather than a privileged DinD
service. Manager startup pings the daemon and rejects it unless its security
options report rootless mode. The socket path, work root, and token file are
explicit administrator-controlled mounts.

`sandbox-images/Dockerfile` supplies an inert non-root template probe under all
three local image tags. It validates the filesystem contract and writes a fixed
result only. Maven, Gradle, scanner, application, or Agent execution remains
out of scope until the next subprojects.

The same platform-owned image also supplies a separate collection helper. It
runs only after the workload is stopped, mounts scratch/output but never source
or a Docker socket, has no network, and receives only namespaced
`DAC_OVERRIDE`/`FOWNER`. This lets the Manager recover files deliberately
created with mode `000` under rootless uid mappings before independently
validating and archiving them. It is infrastructure, not a workload template.

No audit-domain database migration is required. Manager lifecycle state is
stored atomically in its own persistent volume. Output descriptors stay in that
state and output bytes share the content-addressed Artifact store; the future
Orchestrator binds them to `AuditTask` and formal `Artifact` metadata.

## Resource enforcement

- CPU, memory, PID, swap, and tmpfs limits are passed to Docker/cgroups.
- `RLIMIT_FSIZE` rejects a single oversized workload file.
- A Manager reaper accounts for combined scratch/output allocation and
  terminates tasks over their directory budget.
- The execution deadline is persisted and checked by both requests and the
  background reaper. A template-owned `/usr/bin/timeout` wrapper adds
  defense-in-depth for accidental Manager interruption; restart reconciliation
  remains the authoritative orphan-cleanup mechanism.
- Production deployments place the work root on a quota-backed dedicated
  filesystem to eliminate disk bursts inside the reaper interval.

## Verification

Tests cover:

- strict request schemas and template-owned settings;
- rootless-daemon readiness;
- exact Docker security arguments;
- Snapshot extraction and hostile output trees;
- create, start, wait, timeout, cancel, collect, destroy, and restart recovery;
- orphan cleanup and idempotent destruction;
- internal API authentication;
- Compose network, socket, privilege, port, and volume contracts;
- a real local Docker smoke test when an explicitly configured test daemon is
  available.

Final verification on 2026-07-26, after the legacy dispatcher deletion:

- `220 passed, 5 skipped` for the complete suite against a disposable
  PostgreSQL 16 with real upgrade, downgrade, and re-upgrade; the five skipped
  cases are the opt-in Docker template matrix;
- all five opt-in Docker cases passed separately against a disposable daemon:
  `analysis`, `build`, `validation`, timeout/cancel cleanup, and a mode-`000`
  hostile-output case; these inspect the effective Docker security
  configuration and post-run orphan state, and left no labeled container or
  network behind;
- the available local daemon was intentionally rootful, which exercised both
  rootless defenses: `SandboxSettings` rejects the conventional host socket
  before connecting, and the backend rejects a daemon whose `SecurityOptions`
  omit `rootless` with `SANDBOX_ROOTLESS_REQUIRED`. With
  `require_rootless=True` all five cases fail closed; they run only under the
  explicit test-only override. A genuine rootless daemon remains unverified on
  this host, which lacks `newuidmap`;
- the Audit API, dedicated Sandbox Manager, and template images all built
  successfully; the Manager image contains neither Git nor SSH clients;
- Compose rendering and whitespace checks passed.

The earlier `264 passed` figure predates the legacy dispatcher deletion, which
removed 82 tests belonging to that package.
