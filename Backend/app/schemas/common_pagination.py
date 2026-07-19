from __future__ import annotations

from pydantic import BaseModel, Field


class PaginationMeta(BaseModel):
    limit: int = Field(..., ge=1)
    offset: int = Field(..., ge=0)
    total: int | None = None

