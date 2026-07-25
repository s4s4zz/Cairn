from __future__ import annotations

from typing import Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        from_attributes=True,
        str_strip_whitespace=True,
    )


class ErrorResponse(StrictModel):
    error_code: str
    message: str
    request_id: str


class PageMeta(StrictModel):
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)
    total: int = Field(ge=0)


ItemT = TypeVar("ItemT")


class Page(StrictModel, Generic[ItemT]):
    items: list[ItemT]
    meta: PageMeta
