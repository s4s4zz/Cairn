# Java Audit Source and Artifact Management Implementation

**Status:** Implemented

**Date:** 2026-07-26

**Goal:** Deliver subproject two from the approved Java audit platform design:
Git, ZIP, and browser-directory archive ingestion; stable source-tree hashes;
immutable Snapshot Artifacts; encrypted Git credentials; and a local
content-addressed Artifact backend.

## Delivery boundary

This increment performs source acquisition and normalization only. It never
executes Maven, Gradle, repository hooks, project tests, or source-controlled
programs. Build isolation remains part of the Sandbox Manager subproject.

The HTTP API remains bound to localhost until authentication and authorization
are implemented. Artifact role checks and operation-audit records remain part
of the workbench/authentication subproject.

## Implemented contracts

### Uploads and snapshots

```text
POST /api/v1/uploads?source_type=zip|local_upload
POST /api/v1/repositories/{repository_id}/snapshots
GET  /api/v1/snapshots/{snapshot_id}
GET  /api/v1/artifacts/{artifact_id}
```

`POST /uploads` accepts a ZIP byte stream. A browser directory uploader creates
that transport archive client-side and uses `source_type=local_upload`; both
upload forms enter the same validation and normalization pipeline.

Snapshot creation accepts either:

```json
{"type": "upload", "upload_id": "..."}
```

or:

```json
{"type": "git_ref", "ref": "main"}
```

Git repositories require their hostname to match
`CAIRN_GIT_ALLOWED_HOSTS`. The default is an empty deny-all list.

### Git credentials

```text
POST   /api/v1/git-credentials
DELETE /api/v1/git-credentials/{reference}
```

Credential plaintext is encrypted with AES-256-GCM before it enters
PostgreSQL. The 32-byte master key is read from `CAIRN_SECRET_KEY_FILE`;
credentials cannot be created or used when the key is unavailable.

There is intentionally no credential read endpoint. Git HTTPS secrets are
passed through a short-lived AskPass environment, SSH keys and known-host
entries through mode-0600 temporary files. Credential material and `.git`
metadata are removed before source-tree normalization.

## Canonical source tree

The tree digest is versioned as `cairn-source-tree-v1` and is computed from
ordinary files sorted by UTF-8 relative path. Each digest record contains:

- the normalized relative path;
- the ordinary-file type marker;
- the executable-bit marker;
- the file content SHA-256.

ZIP timestamps, member order, uid/gid, and writable permission bits do not
affect `content_sha256`. Snapshot TAR files are deterministic: sorted members,
zero timestamps and ownership, and read-only `0444`/`0555` modes.

Each ingestion creates its own immutable Snapshot so distinct Git Commits are
never conflated, even when their trees are byte-identical. Identical trees keep
the same `content_sha256`; Artifact bytes stored under
`sha256/<prefix>/<digest>` are shared by independent metadata rows.

## Rejection rules

The ingestion pipeline rejects:

- absolute, parent-relative, Windows-drive, backslash, control-character,
  overlong, and over-deep archive paths;
- duplicate normalized paths;
- symbolic links and non-regular special files;
- encrypted ZIP members;
- excessive upload size, file count, expanded bytes, single-file bytes, or
  compression ratio;
- source trees without a `.java` file (`NO_JAVA_SOURCE`);
- Git refs with option/revision injection characters;
- Git hosts outside the configured allowlist.

Default limits are configurable through `CAIRN_UPLOAD_MAX_BYTES` and the
`CAIRN_SNAPSHOT_MAX_*` settings documented in the README.

Compose uses a dedicated `cairn-ingestion-data` work volume because the
expanded-source limit is intentionally larger than the server's small `/tmp`
tmpfs. Per-request directories are removed after success or failure.

## Persistence changes

Migration `20260726_0002` adds:

- `source_uploads`;
- `encrypted_secrets`;
- nullable `artifacts.audit_run_id` for pre-run uploads and snapshots;
- reusable content-addressed `storage_key` values;
- the `source_upload` Artifact kind.

The existing database and ORM guards that reject updates to ready Snapshots
remain in force.

## Verification

Coverage includes:

- canonical hash and deterministic TAR behavior;
- ZIP Slip, live/archive symlink, special-file, compression-bomb, and size
  rejection;
- Artifact hash and size verification, deduplication, and tamper detection;
- Git host/ref validation and credential isolation;
- encrypted credential persistence with no public read route;
- upload, ZIP Snapshot, directory-archive Snapshot, Git Snapshot, Artifact
  download, and AuditRun upload-reference API flows;
- PostgreSQL upgrade, downgrade, and re-upgrade.

The next independently deployable increment is the Sandbox Manager described
in subproject three of the approved platform design.
