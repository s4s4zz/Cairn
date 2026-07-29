from datetime import datetime
from uuid import UUID

from pydantic import Field

from cairn.server.schemas.common import Page, StrictModel


class ReportResponse(StrictModel):
    id: UUID
    audit_run_id: UUID
    version: int
    summary_json: dict[str, object]
    html_artifact_id: UUID
    json_artifact_id: UUID
    sarif_artifact_id: UUID
    generated_at: datetime


class ReportFilters(StrictModel):
    audit_run_id: UUID | None = None
    limit: int = Field(default=50, ge=1, le=100)
    offset: int = Field(default=0, ge=0)


ReportPage = Page[ReportResponse]
