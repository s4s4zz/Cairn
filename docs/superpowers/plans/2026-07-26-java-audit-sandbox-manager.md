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
```

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

The safe default for every template is no network. An administrator may bind a
template to a pre-created, non-control Docker network through Sandbox Manager
configuration. A request can never select or override that network.

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

Stable errors include:

- `SANDBOX_UNAUTHORIZED`
- `SANDBOX_TEMPLATE_UNKNOWN`
- `SANDBOX_LIMIT_EXCEEDED`
- `SANDBOX_CAPACITY_EXHAUSTED`
- `SANDBOX_COLLECTION_PREPARATION_FAILED`
- `SANDBOX_SNAPSHOT_INVALID`
- `SANDBOX_INVALID_STATE`
- `SANDBOX_BACKEND_UNAVAILABLE`
- `SANDBOX_ROOTLESS_REQUIRED`
- `SANDBOX_RESOURCE_CONTROLS_UNAVAILABLE`
- `SANDBOX_TEMPLATE_UNSAFE`
- `SANDBOX_WORKSPACE_UNAVAILABLE`
- `SANDBOX_OUTPUT_INVALID`
- `SANDBOX_OUTPUT_LIMIT_EXCEEDED`

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

Final verification on 2026-07-26:

- `264 passed, 5 skipped` for the complete suite with real PostgreSQL upgrade,
  downgrade, and re-upgrade; the five skipped cases are the opt-in Docker
  template matrix;
- all five opt-in Docker cases passed separately: `analysis`, `build`,
  `validation`, timeout/cancel cleanup, and a mode-`000` hostile-output case;
  these inspect the effective Docker security configuration and post-run
  orphan state;
- the available local daemon was intentionally rootful: default Manager
  readiness rejected it, while the disposable smoke test used the explicit
  test-only override; a temporary rootless-daemon launch was also attempted
  but stopped before daemon creation because this host lacks `newuidmap`;
- the Audit API, dedicated Sandbox Manager, and template images all built
  successfully; the Manager image contains neither Git nor SSH clients;
- Compose rendering and whitespace checks passed.
