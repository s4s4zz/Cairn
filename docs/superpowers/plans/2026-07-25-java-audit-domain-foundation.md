# Java Audit Domain Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace Cairn's public generic Project/Fact/Intent protocol with a PostgreSQL-backed Java code-audit domain foundation and versioned `/api/v1` API, while retaining legacy dispatcher internals only as temporarily unreachable code.

**Architecture:** FastAPI remains the control-plane HTTP server. SQLAlchemy 2.0 and Alembic replace the global raw-SQLite connection; audit entities live in focused persistence modules, domain enums and state machines remain independent of persistence, and routers call transaction-scoped services. This first delivery exposes repository metadata, audit policy, audit-run lifecycle, read-only finding endpoints, health checks, and no generic task creation surface.

**Tech Stack:** Python 3.12, FastAPI, Pydantic 2, pydantic-settings, SQLAlchemy 2, Alembic, psycopg 3, PostgreSQL 16, pytest, Docker Compose.

---

## Scope and delivery boundary

This plan implements design subproject 1 only. Source ingestion, Artifact byte storage, Sandbox Manager, deterministic Java scanners, semantic agents, dynamic verification, production authentication UI, and reports receive separate plans.

At the end of this plan:

- `/projects`, `/settings`, `/projects/*/intents`, `/projects/*/hints`, and generic export endpoints return 404.
- The `cairn dispatch` generic CLI command is unavailable.
- The public server uses PostgreSQL and Alembic.
- All approved audit-domain tables exist.
- Repository metadata and audit policies can be managed through `/api/v1`.
- Audit runs can be created, listed, read, cancelled, and transitioned through an internal service.
- Findings can only be created through an internal service; the public API is read-only for findings.
- The legacy dispatcher package remains importable for later extraction of reusable scheduling/runtime code, but nothing in the public app or CLI invokes it.
- Until the authentication work in subproject 7, Docker Compose binds the API to `127.0.0.1` and the API records the fixed internal actor `system`; the service must not be exposed to an untrusted network.

## File map

### Create

- `cairn/src/cairn/server/config.py` — environment-backed server settings.
- `cairn/src/cairn/server/errors.py` — stable API/domain errors and handlers.
- `cairn/src/cairn/server/domain/enums.py` — domain enum definitions.
- `cairn/src/cairn/server/domain/state_machines.py` — pure AuditRun/Finding transition rules.
- `cairn/src/cairn/server/domain/__init__.py` — domain exports.
- `cairn/src/cairn/server/persistence/base.py` — declarative base and ID/time helpers.
- `cairn/src/cairn/server/persistence/session.py` — engine/session construction and FastAPI dependency.
- `cairn/src/cairn/server/persistence/models/core.py` — Repository, Snapshot, Policy, Run, Task.
- `cairn/src/cairn/server/persistence/models/findings.py` — Finding, Location, Evidence, Verification, Review.
- `cairn/src/cairn/server/persistence/models/artifacts.py` — Artifact, Coverage, Report.
- `cairn/src/cairn/server/persistence/models/graph.py` — internal AuditFact and AuditIntent.
- `cairn/src/cairn/server/persistence/models/__init__.py` — complete metadata imports.
- `cairn/src/cairn/server/persistence/__init__.py` — persistence exports.
- `cairn/src/cairn/server/schemas/common.py` — pagination and error schemas.
- `cairn/src/cairn/server/schemas/repositories.py` — Repository schemas.
- `cairn/src/cairn/server/schemas/policies.py` — AuditPolicy schemas.
- `cairn/src/cairn/server/schemas/audit_runs.py` — AuditRun schemas.
- `cairn/src/cairn/server/schemas/findings.py` — read-only Finding schemas.
- `cairn/src/cairn/server/schemas/__init__.py` — schema exports.
- `cairn/src/cairn/server/services/repositories.py` — Repository transactions.
- `cairn/src/cairn/server/services/policies.py` — versioned policy transactions.
- `cairn/src/cairn/server/services/audit_runs.py` — run creation and transitions.
- `cairn/src/cairn/server/services/findings.py` — internal candidate creation and read queries.
- `cairn/src/cairn/server/services/__init__.py` — service exports.
- `cairn/src/cairn/server/routers/health.py` — liveness/readiness.
- `cairn/src/cairn/server/routers/repositories.py` — `/api/v1/repositories`.
- `cairn/src/cairn/server/routers/policies.py` — `/api/v1/audit-policies`.
- `cairn/src/cairn/server/routers/audit_runs.py` — `/api/v1/audit-runs`.
- `cairn/src/cairn/server/routers/findings.py` — read-only `/api/v1/findings`.
- `cairn/alembic.ini` — Alembic configuration.
- `cairn/migrations/env.py` — migration environment.
- `cairn/migrations/script.py.mako` — Alembic template.
- `cairn/migrations/versions/20260725_0001_audit_domain.py` — initial domain schema.
- `cairn/tests/domain/test_state_machines.py` — pure lifecycle tests.
- `cairn/tests/api/conftest.py` — isolated SQLAlchemy/API fixtures.
- `cairn/tests/api/test_repositories.py` — repository contract tests.
- `cairn/tests/api/test_policies.py` — policy versioning tests.
- `cairn/tests/api/test_audit_runs.py` — run lifecycle tests.
- `cairn/tests/api/test_findings.py` — finding visibility and public-write rejection tests.
- `cairn/tests/api/test_legacy_routes_removed.py` — generic API removal tests.
- `cairn/tests/persistence/test_postgres_migrations.py` — real PostgreSQL migration smoke test.

### Modify

- `cairn/pyproject.toml` — database/config dependencies and pytest marker.
- `cairn/uv.lock` — locked dependency graph.
- `cairn/src/cairn/server/app.py` — app factory and new routers only.
- `cairn/src/cairn/server/routers/__init__.py` — audit router exports only.
- `cairn/src/cairn/cli.py` — PostgreSQL-aware serve command; remove generic dispatch command.
- `docker-compose.yaml` — PostgreSQL + server only, localhost binding.
- `Dockerfile` — run migrations before serving through Compose command.
- `README.md` — temporary domain-foundation startup/API instructions.

### Delete

- `cairn/src/cairn/server/db.py`
- `cairn/src/cairn/server/services.py`
- `cairn/src/cairn/server/routers/export.py`
- `cairn/src/cairn/server/routers/hints.py`
- `cairn/src/cairn/server/routers/intents.py`
- `cairn/src/cairn/server/routers/projects.py`
- `cairn/src/cairn/server/routers/settings.py`
- `cairn/tests/test_server_api.py`
- `cairn/tests/test_db_migrations.py`
- `cairn/tests/test_mock_end_to_end.py`

The legacy dispatcher and its focused unit tests are not deleted in this subproject. Removing or extracting them before the new Audit Orchestrator exists would discard reusable behavior and unnecessarily broaden the change.

---

### Task 1: Add database and configuration dependencies

**Files:**
- Modify: `cairn/pyproject.toml`
- Modify: `cairn/uv.lock`
- Create: `cairn/src/cairn/server/config.py`
- Test: `cairn/tests/test_server_config.py`

- [ ] **Step 1: Write failing configuration tests**

```python
from pydantic import ValidationError
import pytest

from cairn.server.config import ServerSettings


def test_database_url_is_required() -> None:
    with pytest.raises(ValidationError):
        ServerSettings(database_url="")


def test_settings_accept_postgresql_url() -> None:
    settings = ServerSettings(database_url="postgresql+psycopg://cairn:secret@db/cairn")
    assert settings.database_url.startswith("postgresql+psycopg://")
    assert settings.api_prefix == "/api/v1"
```

- [ ] **Step 2: Run the tests and verify the missing module failure**

Run:

```bash
uv run --project cairn --group dev pytest cairn/tests/test_server_config.py -v
```

Expected: collection fails with `ModuleNotFoundError: cairn.server.config`.

- [ ] **Step 3: Add dependencies**

Add to project dependencies:

```toml
"alembic>=1.16,<2",
"pydantic-settings>=2.10,<3",
"psycopg[binary]>=3.2,<4",
"sqlalchemy>=2.0.40,<3",
```

Add the PostgreSQL marker:

```toml
[tool.pytest.ini_options]
testpaths = ["tests"]
markers = [
    "postgres: requires TEST_DATABASE_URL pointing to PostgreSQL",
]
```

Run:

```bash
uv lock --project cairn
```

- [ ] **Step 4: Implement settings**

```python
from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class ServerSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="CAIRN_", extra="ignore")

    database_url: str = Field(min_length=1)
    api_prefix: str = "/api/v1"
    sql_echo: bool = False

    @field_validator("database_url")
    @classmethod
    def validate_database_url(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("database_url must not be empty")
        return value


@lru_cache
def get_settings() -> ServerSettings:
    return ServerSettings()
```

- [ ] **Step 5: Run tests**

Run:

```bash
uv run --project cairn --group dev pytest cairn/tests/test_server_config.py -v
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add cairn/pyproject.toml cairn/uv.lock cairn/src/cairn/server/config.py cairn/tests/test_server_config.py
git commit -m "build: add audit database configuration"
```

---

### Task 2: Implement domain enums and lifecycle rules

**Files:**
- Create: `cairn/src/cairn/server/domain/enums.py`
- Create: `cairn/src/cairn/server/domain/state_machines.py`
- Create: `cairn/src/cairn/server/domain/__init__.py`
- Create: `cairn/tests/domain/test_state_machines.py`

- [ ] **Step 1: Write failing transition tests**

```python
import pytest

from cairn.server.domain.enums import AuditRunStatus, FindingStatus
from cairn.server.domain.state_machines import InvalidTransition, transition_audit_run, transition_finding


def test_audit_run_follows_fixed_pipeline() -> None:
    assert transition_audit_run(AuditRunStatus.CREATED, AuditRunStatus.INGESTING) is AuditRunStatus.INGESTING
    assert transition_audit_run(AuditRunStatus.INGESTING, AuditRunStatus.PREPROCESSING) is AuditRunStatus.PREPROCESSING


def test_audit_run_cannot_skip_to_completed() -> None:
    with pytest.raises(InvalidTransition):
        transition_audit_run(AuditRunStatus.CREATED, AuditRunStatus.COMPLETED)


def test_high_finding_requires_human_review_state() -> None:
    assert transition_finding(FindingStatus.MACHINE_CONFIRMED, FindingStatus.AWAITING_HUMAN_REVIEW) is FindingStatus.AWAITING_HUMAN_REVIEW


def test_machine_confirmed_finding_cannot_be_directly_accepted_as_risk() -> None:
    with pytest.raises(InvalidTransition):
        transition_finding(FindingStatus.MACHINE_CONFIRMED, FindingStatus.ACCEPTED_RISK)


def test_reverify_returns_finding_to_validating() -> None:
    assert transition_finding(FindingStatus.AWAITING_HUMAN_REVIEW, FindingStatus.VALIDATING) is FindingStatus.VALIDATING


def test_dynamic_stage_is_explicit_even_when_execution_is_disabled() -> None:
    with pytest.raises(InvalidTransition):
        transition_audit_run(AuditRunStatus.SEMANTIC_AUDITING, AuditRunStatus.MACHINE_REVIEW)
    assert transition_audit_run(AuditRunStatus.SEMANTIC_AUDITING, AuditRunStatus.DYNAMIC_VERIFYING) is AuditRunStatus.DYNAMIC_VERIFYING
    assert transition_audit_run(AuditRunStatus.DYNAMIC_VERIFYING, AuditRunStatus.MACHINE_REVIEW) is AuditRunStatus.MACHINE_REVIEW
```

- [ ] **Step 2: Verify tests fail due to missing domain package**

Run:

```bash
uv run --project cairn --group dev pytest cairn/tests/domain/test_state_machines.py -v
```

Expected: import failure.

- [ ] **Step 3: Define string enums**

Define `StrEnum` classes for every persisted enum from the approved design:

```python
from enum import StrEnum


class SourceType(StrEnum):
    GIT = "git"
    ZIP = "zip"
    LOCAL_UPLOAD = "local_upload"


class SnapshotStatus(StrEnum):
    CREATING = "creating"
    READY = "ready"
    REJECTED = "rejected"
    FAILED = "failed"


class AuditRunStatus(StrEnum):
    CREATED = "created"
    INGESTING = "ingesting"
    PREPROCESSING = "preprocessing"
    STATIC_SCANNING = "static_scanning"
    SEMANTIC_AUDITING = "semantic_auditing"
    DYNAMIC_VERIFYING = "dynamic_verifying"
    MACHINE_REVIEW = "machine_review"
    HUMAN_REVIEW = "human_review"
    REPORTING = "reporting"
    COMPLETED = "completed"
    COMPLETED_WITH_WARNINGS = "completed_with_warnings"
    CANCELLING = "cancelling"
    CANCELLED = "cancelled"
    FAILED = "failed"
```

Also define `BuildSystem`, `DynamicVerificationMode`, `AuditStage`, `AuditTaskType`, `AuditTaskStatus`, `FindingSeverity`, `FindingConfidence`, `FindingStatus`, `RuntimeVerificationStatus`, `LocationRole`, `ArtifactKind`, `ArtifactAccessLevel`, `EvidenceType`, `VerificationMethod`, `VerificationVerdict`, `BuildStatus`, `ReviewVerdict`, `AuditFactKind`, and `AuditIntentStatus` with exactly the values from the design document.

- [ ] **Step 4: Implement pure transition functions**

```python
from dataclasses import dataclass

from cairn.server.domain.enums import AuditRunStatus, FindingStatus


@dataclass(slots=True)
class InvalidTransition(ValueError):
    entity: str
    current: str
    target: str

    def __str__(self) -> str:
        return f"invalid {self.entity} transition: {self.current} -> {self.target}"


AUDIT_RUN_TRANSITIONS = {
    AuditRunStatus.CREATED: {AuditRunStatus.INGESTING, AuditRunStatus.CANCELLING, AuditRunStatus.FAILED},
    AuditRunStatus.INGESTING: {AuditRunStatus.PREPROCESSING, AuditRunStatus.CANCELLING, AuditRunStatus.FAILED},
    AuditRunStatus.PREPROCESSING: {AuditRunStatus.STATIC_SCANNING, AuditRunStatus.CANCELLING, AuditRunStatus.FAILED},
    AuditRunStatus.STATIC_SCANNING: {AuditRunStatus.SEMANTIC_AUDITING, AuditRunStatus.CANCELLING, AuditRunStatus.FAILED},
    AuditRunStatus.SEMANTIC_AUDITING: {AuditRunStatus.DYNAMIC_VERIFYING, AuditRunStatus.CANCELLING, AuditRunStatus.FAILED},
    AuditRunStatus.DYNAMIC_VERIFYING: {AuditRunStatus.MACHINE_REVIEW, AuditRunStatus.CANCELLING, AuditRunStatus.FAILED},
    AuditRunStatus.MACHINE_REVIEW: {AuditRunStatus.HUMAN_REVIEW, AuditRunStatus.CANCELLING, AuditRunStatus.FAILED},
    AuditRunStatus.HUMAN_REVIEW: {AuditRunStatus.REPORTING, AuditRunStatus.CANCELLING, AuditRunStatus.FAILED},
    AuditRunStatus.REPORTING: {
        AuditRunStatus.COMPLETED,
        AuditRunStatus.COMPLETED_WITH_WARNINGS,
        AuditRunStatus.CANCELLING,
        AuditRunStatus.FAILED,
    },
    AuditRunStatus.CANCELLING: {AuditRunStatus.CANCELLED, AuditRunStatus.FAILED},
    AuditRunStatus.COMPLETED: set(),
    AuditRunStatus.COMPLETED_WITH_WARNINGS: set(),
    AuditRunStatus.CANCELLED: set(),
    AuditRunStatus.FAILED: set(),
}


FINDING_TRANSITIONS = {
    FindingStatus.CANDIDATE: {FindingStatus.VALIDATING, FindingStatus.REJECTED},
    FindingStatus.VALIDATING: {FindingStatus.MACHINE_CONFIRMED, FindingStatus.REJECTED},
    FindingStatus.MACHINE_CONFIRMED: {FindingStatus.AWAITING_HUMAN_REVIEW},
    FindingStatus.AWAITING_HUMAN_REVIEW: {
        FindingStatus.CONFIRMED,
        FindingStatus.REJECTED,
        FindingStatus.ACCEPTED_RISK,
        FindingStatus.VALIDATING,
    },
    FindingStatus.CONFIRMED: {FindingStatus.ACCEPTED_RISK},
    FindingStatus.REJECTED: set(),
    FindingStatus.ACCEPTED_RISK: set(),
}
```

Implement a shared `_transition` helper and the two public functions; both raise `InvalidTransition` when `target` is not allowed.

The run state machine always passes through `dynamic_verifying`. A later orchestrator must create a
`dynamic_verify` task with `status=skipped` when policy disables dynamic execution, then advance the
run to `machine_review`; it must never bypass the stage with a direct
`semantic_auditing -> machine_review` transition. `accepted_risk` is exclusively a human-review
verdict, so `machine_confirmed` cannot transition to it directly.

- [ ] **Step 5: Run domain tests**

Run:

```bash
uv run --project cairn --group dev pytest cairn/tests/domain/test_state_machines.py -v
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add cairn/src/cairn/server/domain cairn/tests/domain
git commit -m "feat: define audit lifecycle state machines"
```

---

### Task 3: Add SQLAlchemy session infrastructure and all domain tables

**Files:**
- Create: `cairn/src/cairn/server/persistence/base.py`
- Create: `cairn/src/cairn/server/persistence/session.py`
- Create: `cairn/src/cairn/server/persistence/models/*.py`
- Create: `cairn/src/cairn/server/persistence/__init__.py`
- Test: `cairn/tests/persistence/test_models.py`

- [ ] **Step 1: Write failing metadata tests**

```python
from cairn.server.persistence.base import Base
from cairn.server.persistence import models  # noqa: F401


def test_metadata_contains_complete_audit_domain() -> None:
    assert set(Base.metadata.tables) == {
        "repositories",
        "source_snapshots",
        "audit_policies",
        "audit_runs",
        "audit_tasks",
        "artifacts",
        "findings",
        "finding_locations",
        "evidence",
        "verifications",
        "audit_coverage",
        "human_reviews",
        "reports",
        "audit_facts",
        "audit_intents",
        "audit_intent_sources",
    }
```

- [ ] **Step 2: Verify the persistence imports fail**

Run:

```bash
uv run --project cairn --group dev pytest cairn/tests/persistence/test_models.py -v
```

Expected: import failure.

- [ ] **Step 3: Implement base and session factory**

Use SQLAlchemy's typed declarative API:

```python
from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import DateTime, Uuid
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class UUIDPrimaryKeyMixin:
    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
```

`session.py` must expose `configure_engine(database_url, sql_echo=False)`, `dispose_engine()`, `session_scope()`, and FastAPI `get_db_session()`. Calling `configure_engine` twice must dispose the previous engine so isolated tests do not share state.

- [ ] **Step 4: Implement ORM models exactly matching section 6 of the design**

Rules:

- Use `Uuid(as_uuid=True)` for IDs.
- Persist enums as bounded `String` columns with explicit `CheckConstraint`; do not create PostgreSQL enum types.
- Use `JSON` for arrays and structured payloads so fast SQLite application tests remain possible.
- Use `DateTime(timezone=True)` for timestamps.
- Add indexes for repository name, snapshot hash, run status, task status/lease, finding fingerprint, finding severity/status, and Artifact SHA-256.
- Add a unique constraint on `(audit_run_id, fingerprint)`.
- Use `ondelete="CASCADE"` for run-owned data and `ondelete="RESTRICT"` for immutable Snapshot references from AuditRun.
- `AuditRun.snapshot_id` is nullable only during `created/ingesting`.
- Do not add a tenant column to any table.

Each model module must contain only the entities assigned in the file map. `models/__init__.py` imports every model so Alembic always sees complete metadata.

- [ ] **Step 5: Add relationship and default-value tests**

Use an in-memory SQLite engine only for fast mapping tests. Assert UUID generation, timezone-aware creation timestamps, cascade ownership metadata, and unique finding fingerprint constraints. PostgreSQL behavior is verified separately in Task 4.

- [ ] **Step 6: Run persistence unit tests**

Run:

```bash
uv run --project cairn --group dev pytest cairn/tests/persistence/test_models.py -v
```

Expected: all tests pass.

- [ ] **Step 7: Commit**

```bash
git add cairn/src/cairn/server/persistence cairn/tests/persistence/test_models.py
git commit -m "feat: add audit domain persistence models"
```

---

### Task 4: Add Alembic and verify the schema on PostgreSQL

**Files:**
- Create: `cairn/alembic.ini`
- Create: `cairn/migrations/env.py`
- Create: `cairn/migrations/script.py.mako`
- Create: `cairn/migrations/versions/20260725_0001_audit_domain.py`
- Create: `cairn/tests/persistence/test_postgres_migrations.py`

- [ ] **Step 1: Write the PostgreSQL migration smoke test**

```python
import os

from alembic import command
from alembic.config import Config
import pytest
from sqlalchemy import create_engine, inspect, text


@pytest.mark.postgres
def test_initial_migration_upgrades_and_downgrades() -> None:
    url = os.environ["TEST_DATABASE_URL"]
    config = Config("cairn/alembic.ini")
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")

    engine = create_engine(url)
    assert "audit_runs" in inspect(engine).get_table_names()
    with engine.connect() as conn:
        assert conn.execute(text("select count(*) from alembic_version")).scalar_one() == 1

    command.downgrade(config, "base")
    assert "audit_runs" not in inspect(engine).get_table_names()
```

- [ ] **Step 2: Start a disposable PostgreSQL test service and verify failure**

Run:

```bash
docker run --rm -d --name cairn-plan-postgres \
  -e POSTGRES_USER=cairn -e POSTGRES_PASSWORD=cairn -e POSTGRES_DB=cairn_test \
  -p 55432:5432 postgres:16-alpine
TEST_DATABASE_URL=postgresql+psycopg://cairn:cairn@127.0.0.1:55432/cairn_test \
  uv run --project cairn --group dev pytest cairn/tests/persistence/test_postgres_migrations.py -v -m postgres
```

Expected: failure because Alembic configuration does not exist.

- [ ] **Step 3: Implement Alembic configuration and explicit initial migration**

`env.py` imports `Base` and `cairn.server.persistence.models`, reads `CAIRN_DATABASE_URL` when `sqlalchemy.url` is not set, enables `compare_type=True`, and runs online/offline migrations.

The initial migration must explicitly create all 16 tables, foreign keys, check constraints, unique constraints, and indexes represented by ORM metadata. Do not call `Base.metadata.create_all()` from the migration.

- [ ] **Step 4: Verify upgrade, downgrade, and re-upgrade**

Run the test above, then:

```bash
TEST_DATABASE_URL=postgresql+psycopg://cairn:cairn@127.0.0.1:55432/cairn_test \
  uv run --project cairn alembic -c cairn/alembic.ini upgrade head
docker stop cairn-plan-postgres
```

Expected: migration test passes and the final upgrade exits 0.

- [ ] **Step 5: Commit**

```bash
git add cairn/alembic.ini cairn/migrations cairn/tests/persistence/test_postgres_migrations.py
git commit -m "feat: add initial PostgreSQL audit schema"
```

---

### Task 5: Add strict API schemas and stable errors

**Files:**
- Create: `cairn/src/cairn/server/errors.py`
- Create: `cairn/src/cairn/server/schemas/*.py`
- Test: `cairn/tests/api/test_schemas.py`

- [ ] **Step 1: Write failing strict-schema tests**

```python
from pydantic import ValidationError
import pytest

from cairn.server.domain.enums import SourceType
from cairn.server.schemas.repositories import RepositoryCreate


def test_repository_create_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        RepositoryCreate.model_validate({"name": "demo", "source_type": "git", "origin": "legacy"})


def test_git_repository_requires_remote_url() -> None:
    with pytest.raises(ValidationError):
        RepositoryCreate(name="demo", source_type=SourceType.GIT)
```

- [ ] **Step 2: Verify schema imports fail**

Run:

```bash
uv run --project cairn --group dev pytest cairn/tests/api/test_schemas.py -v
```

- [ ] **Step 3: Implement common strict model and error model**

```python
from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", from_attributes=True)


class ErrorResponse(StrictModel):
    error_code: str
    message: str
    request_id: str


class PageMeta(StrictModel):
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)
    total: int = Field(ge=0)
```

All request schemas inherit `StrictModel`; response schemas use `from_attributes=True`. Define concrete request/response objects for Repository, AuditPolicy, AuditRun, FindingLocation, Evidence summary, Verification summary, and Finding detail. No public schema accepts `status`, `created_by`, `worker_name`, `confidence=confirmed`, or raw evidence IDs during create operations.

- [ ] **Step 4: Implement stable domain/API errors**

`DomainError` contains `error_code`, `message`, and `http_status`. Register handlers that attach or reuse `X-Request-ID` and emit `ErrorResponse`. Provide concrete `NotFoundError`, `ConflictError`, and `InvalidStateError` constructors.

- [ ] **Step 5: Run schema tests**

Run:

```bash
uv run --project cairn --group dev pytest cairn/tests/api/test_schemas.py -v
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add cairn/src/cairn/server/errors.py cairn/src/cairn/server/schemas cairn/tests/api/test_schemas.py
git commit -m "feat: add strict audit API contracts"
```

---

### Task 6: Implement Repository and AuditPolicy services and routes

**Files:**
- Create: `cairn/src/cairn/server/services/repositories.py`
- Create: `cairn/src/cairn/server/services/policies.py`
- Create: `cairn/src/cairn/server/routers/repositories.py`
- Create: `cairn/src/cairn/server/routers/policies.py`
- Create: `cairn/tests/api/conftest.py`
- Create: `cairn/tests/api/test_repositories.py`
- Create: `cairn/tests/api/test_policies.py`

- [ ] **Step 1: Create isolated API fixtures**

Build a SQLite `StaticPool` engine for fast route tests, create all metadata at fixture setup, override `get_db_session`, and instantiate the application with `create_app(settings)`. This is not a production database substitute; Task 4 remains the PostgreSQL contract.

- [ ] **Step 2: Write failing repository API tests**

Cover:

```python
def test_create_and_list_git_repository(client): ...
def test_duplicate_repository_name_returns_409(client): ...
def test_git_repository_requires_https_or_ssh_url(client): ...
def test_zip_repository_rejects_remote_url(client): ...
def test_delete_repository_with_runs_returns_409(client): ...
```

Expected API paths are `/api/v1/repositories` and `/api/v1/repositories/{id}`.

- [ ] **Step 3: Implement repository service and router**

The service owns normalization, duplicate checks, database writes, and delete constraints. The router only validates HTTP inputs, calls the service, and returns schemas. All created records use actor `system` in this subproject.

- [ ] **Step 4: Write failing policy tests**

Cover version creation, immutable old versions, only one active version per policy name, default comprehensive scanners, `dynamic_verification=required`, and rejection of unknown scanners.

- [ ] **Step 5: Implement policy service and router**

Expose:

```text
POST /api/v1/audit-policies
GET  /api/v1/audit-policies
GET  /api/v1/audit-policies/{id}
```

Editing creates a new version rather than mutating an existing row. Seed the first comprehensive policy from an explicit migration insert or a deterministic CLI bootstrap function; never seed it lazily on GET.

- [ ] **Step 6: Run API tests**

Run:

```bash
uv run --project cairn --group dev pytest \
  cairn/tests/api/test_repositories.py cairn/tests/api/test_policies.py -v
```

Expected: all tests pass.

- [ ] **Step 7: Commit**

```bash
git add cairn/src/cairn/server/services cairn/src/cairn/server/routers/repositories.py \
  cairn/src/cairn/server/routers/policies.py cairn/tests/api
git commit -m "feat: add repository and audit policy APIs"
```

---

### Task 7: Implement AuditRun lifecycle service and API

**Files:**
- Create: `cairn/src/cairn/server/services/audit_runs.py`
- Create: `cairn/src/cairn/server/routers/audit_runs.py`
- Create: `cairn/tests/api/test_audit_runs.py`

- [ ] **Step 1: Write failing lifecycle API tests**

Cover:

- create from an existing ready Snapshot;
- create from a Git ref source request with null `snapshot_id`;
- reject a Snapshot owned by another Repository;
- list/filter by Repository and status;
- cancel a running run using `running → cancelling`;
- make cancel idempotent while already cancelling/cancelled;
- reject direct public status updates;
- require a ready Snapshot before internal `ingesting → preprocessing` transition.

- [ ] **Step 2: Implement transactional service methods**

Required interface:

```python
class AuditRunService:
    def create(self, request: AuditRunCreate, actor: str) -> AuditRun: ...
    def get(self, run_id: UUID) -> AuditRun: ...
    def list(self, filters: AuditRunFilters) -> tuple[list[AuditRun], int]: ...
    def request_cancel(self, run_id: UUID, actor: str) -> AuditRun: ...
    def transition(self, run_id: UUID, target: AuditRunStatus, *, snapshot_id: UUID | None = None) -> AuditRun: ...
```

`transition` locks the row with `SELECT ... FOR UPDATE` on PostgreSQL, calls the pure state machine, validates Snapshot prerequisites, writes timestamps, and commits atomically.

- [ ] **Step 3: Implement public routes**

Expose only:

```text
POST /api/v1/audit-runs
GET  /api/v1/audit-runs
GET  /api/v1/audit-runs/{id}
POST /api/v1/audit-runs/{id}/cancel
```

Do not expose the internal transition method as HTTP.

- [ ] **Step 4: Run tests**

Run:

```bash
uv run --project cairn --group dev pytest cairn/tests/api/test_audit_runs.py -v
```

Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add cairn/src/cairn/server/services/audit_runs.py \
  cairn/src/cairn/server/routers/audit_runs.py cairn/tests/api/test_audit_runs.py
git commit -m "feat: add audit run lifecycle API"
```

---

### Task 8: Add internal Finding creation and public read-only APIs

**Files:**
- Create: `cairn/src/cairn/server/services/findings.py`
- Create: `cairn/src/cairn/server/routers/findings.py`
- Create: `cairn/tests/api/test_findings.py`

- [ ] **Step 1: Write failing service/API tests**

Cover:

- internal service creates a Candidate with at least one Location;
- missing Location, CWE, attack preconditions, impact, or remediation is rejected;
- `(audit_run_id, fingerprint)` duplicate merges no data yet and returns 409 in this subproject;
- list filters by run, CWE, severity, and status;
- detail returns Locations, Evidence, and Verifications;
- `POST /api/v1/findings` returns 405/404 because public finding creation is forbidden;
- public schemas cannot set confirmed status.

- [ ] **Step 2: Implement internal service**

Required interface:

```python
class FindingService:
    def create_candidate(self, command: CandidateFindingCommand) -> Finding: ...
    def get(self, finding_id: UUID) -> Finding: ...
    def list(self, filters: FindingFilters) -> tuple[list[Finding], int]: ...
```

Candidate creation computes no fingerprint itself in this subproject; the command must contain a validated 64-character lowercase SHA-256 fingerprint from the future normalization pipeline. It always persists `status=candidate` and never accepts arbitrary status/confidence.

- [ ] **Step 3: Implement GET-only router**

Expose:

```text
GET /api/v1/findings
GET /api/v1/findings/{id}
```

- [ ] **Step 4: Run tests**

Run:

```bash
uv run --project cairn --group dev pytest cairn/tests/api/test_findings.py -v
```

Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add cairn/src/cairn/server/services/findings.py \
  cairn/src/cairn/server/routers/findings.py cairn/tests/api/test_findings.py
git commit -m "feat: add read-only finding API"
```

---

### Task 9: Rewire the application and remove public generic behavior

**Files:**
- Modify: `cairn/src/cairn/server/app.py`
- Modify: `cairn/src/cairn/server/routers/__init__.py`
- Create: `cairn/src/cairn/server/routers/health.py`
- Modify: `cairn/src/cairn/cli.py`
- Delete: legacy server DB/services/routers listed in the file map
- Delete: `cairn/tests/test_server_api.py`
- Delete: `cairn/tests/test_db_migrations.py`
- Delete: `cairn/tests/test_mock_end_to_end.py`
- Create: `cairn/tests/api/test_legacy_routes_removed.py`
- Test: `cairn/tests/test_cli.py`

- [ ] **Step 1: Write failing removal tests**

Assert every legacy route returns 404 and OpenAPI contains none of `Project`, `Fact`, `Intent`, `Hint`, `origin`, `goal`, or `bootstrap_enabled`. Assert `cairn --help` lists `serve` but not `dispatch`.

- [ ] **Step 2: Implement app factory**

```python
from contextlib import asynccontextmanager

from fastapi import FastAPI

from cairn import __version__
from cairn.server.config import ServerSettings, get_settings
from cairn.server.errors import install_error_handlers
from cairn.server.persistence.session import configure_engine, dispose_engine
from cairn.server.routers import audit_runs, findings, health, policies, repositories


def create_app(settings: ServerSettings | None = None) -> FastAPI:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        configure_engine(settings.database_url, sql_echo=settings.sql_echo)
        yield
        dispose_engine()

    app = FastAPI(
        title="Cairn Java Audit",
        description="Single-tenant Java source code audit platform",
        version=__version__,
        lifespan=lifespan,
    )
    install_error_handlers(app)
    app.include_router(health.router)
    for router in (repositories.router, policies.router, audit_runs.router, findings.router):
        app.include_router(router, prefix=settings.api_prefix)
    return app


app = create_app()
```

Root `/` returns a small JSON service descriptor and links to `/docs`; it does not serve the old graph UI.

- [ ] **Step 3: Replace CLI surface**

Remove Dispatcher imports and the `dispatch` command. `serve` reads `CAIRN_DATABASE_URL`, accepts host/port/log options, and no longer accepts `--db-path`.

- [ ] **Step 4: Delete legacy public server modules and old endpoint tests**

Delete only the files in this task. Do not delete dispatcher runtime modules or their focused tests.

- [ ] **Step 5: Run removal and CLI tests**

Run:

```bash
uv run --project cairn --group dev pytest \
  cairn/tests/api/test_legacy_routes_removed.py cairn/tests/test_cli.py -v
```

Expected: all tests pass.

- [ ] **Step 6: Run all non-PostgreSQL tests and classify legacy failures**

Run:

```bash
uv run --project cairn --group dev pytest cairn/tests -m "not postgres" -q
```

Any failure caused solely by an unreachable legacy dispatcher test must be handled explicitly: either adapt its fixture away from the public app or remove the test only when it exercises removed generic protocol behavior. Do not weaken runtime, process, archive, healthcheck, cancellation, parser, or adapter tests.

- [ ] **Step 7: Commit**

```bash
git add -A cairn/src/cairn/server cairn/src/cairn/cli.py cairn/tests
git commit -m "refactor: expose Java audit API only"
```

---

### Task 10: Add PostgreSQL Docker Compose runtime

**Files:**
- Modify: `docker-compose.yaml`
- Modify: `Dockerfile`
- Modify: `.gitignore`
- Test: `cairn/tests/test_compose_contract.py`

- [ ] **Step 1: Write a failing Compose contract test**

Parse `docker-compose.yaml` with `yaml.safe_load` and assert:

- services are exactly `cairn-postgres` and `cairn-server`;
- server has no Docker Socket mount;
- server publishes `127.0.0.1:8000:8000`;
- PostgreSQL has a healthcheck and persistent volume;
- server depends on healthy PostgreSQL;
- healthcheck calls `/health/ready`;
- no service uses host networking or privileged mode.

- [ ] **Step 2: Replace Compose configuration**

Use PostgreSQL 16 Alpine with a named data volume. Set `CAIRN_DATABASE_URL` through environment interpolation, bind the API to localhost, and run:

```text
uv run alembic -c alembic.ini upgrade head
uv run cairn serve --host 0.0.0.0 --no-access-log
```

Do not include the legacy dispatcher service.

- [ ] **Step 3: Validate Compose and test the contract**

Run:

```bash
docker compose config --quiet
uv run --project cairn --group dev pytest cairn/tests/test_compose_contract.py -v
```

Expected: both commands pass.

- [ ] **Step 4: Start the stack and verify readiness**

Run:

```bash
docker compose up -d --build
docker compose ps
curl --fail http://127.0.0.1:8000/health/ready
curl --fail http://127.0.0.1:8000/api/v1/repositories
docker compose down
```

Expected: PostgreSQL and server become healthy; readiness and repository list return 200.

- [ ] **Step 5: Commit**

```bash
git add docker-compose.yaml Dockerfile .gitignore cairn/tests/test_compose_contract.py
git commit -m "build: run audit API with PostgreSQL"
```

---

### Task 11: Update documentation and run the complete foundation verification

**Files:**
- Modify: `README.md`
- Modify: `docs/superpowers/specs/2026-07-25-java-code-audit-platform-design.md` only if implementation reveals a contradiction; otherwise leave unchanged.

- [ ] **Step 1: Replace the public README scope**

The README must state that the branch is a Java code-audit platform foundation, list PostgreSQL/Docker prerequisites, explain manual API startup, identify implemented versus later design subprojects, and remove instructions for generic projects, local execution, penetration testing, and CTF.

- [ ] **Step 2: Run formatting and placeholder checks**

Run:

```bash
git diff --check
rg -n "TBD|TODO|FIXME|XXX" cairn/src cairn/tests README.md
```

Expected: `git diff --check` passes; no implementation placeholders appear in changed production or test files.

- [ ] **Step 3: Run the full automated suite**

Run:

```bash
uv run --project cairn --group dev pytest cairn/tests -m "not postgres" -q
```

Then start PostgreSQL and run:

```bash
TEST_DATABASE_URL=postgresql+psycopg://cairn:cairn@127.0.0.1:55432/cairn_test \
  uv run --project cairn --group dev pytest cairn/tests -m postgres -v
```

Expected: both suites pass with zero failures.

- [ ] **Step 4: Verify product-surface removal**

Run the server and verify:

```bash
curl -i http://127.0.0.1:8000/projects
curl -i -X POST http://127.0.0.1:8000/projects \
  -H 'Content-Type: application/json' \
  -d '{"title":"legacy","origin":"x","goal":"y"}'
curl http://127.0.0.1:8000/openapi.json
```

Expected: both legacy calls return 404 and OpenAPI has no generic project/fact/intent schemas.

- [ ] **Step 5: Review against the approved design**

Confirm:

- no multi-tenant field exists;
- public APIs are Java-audit-specific;
- Finding creation is internal only;
- Snapshot is immutable once ready;
- model output cannot mutate run/finding states;
- generic dispatcher is unreachable from app and CLI;
- PostgreSQL is the formal runtime database;
- API is bound to localhost until authentication exists.

- [ ] **Step 6: Commit**

```bash
git add README.md
git commit -m "docs: document Java audit domain foundation"
```

---

## Execution order after this plan

After this foundation is merged, write and execute separate plans in this order:

1. Source ingestion and Artifact storage.
2. Sandbox Manager and rootless execution backend.
3. Java deterministic analysis and indexing.
4. AI semantic auditing and Finding normalization.
5. Dynamic verification and independent machine review.
6. Vue audit workbench, local authentication, human review, and reports.
7. Production hardening, recovery, MinIO/S3, OIDC, and Kubernetes backend.
