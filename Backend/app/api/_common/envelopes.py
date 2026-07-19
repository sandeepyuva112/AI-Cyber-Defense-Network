from __future__ import annotations

from typing import Any, Generic, Optional, TypeVar

from pydantic import BaseModel

T = TypeVar("T")


class ErrorEnvelope(BaseModel):
    error: dict[str, Any]


class SuccessEnvelope(BaseModel, Generic[T]):
    success: bool = True
    data: T
    meta: Optional[dict[str, Any]] = None


class EnvelopeFactory:
    @staticmethod
    def ok(data: Any, *, meta: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        return {"success": True, "data": data, "meta": meta}

    @staticmethod
    def err(status_code: int, detail: Any) -> dict[str, Any]:
        return {"success": False, "error": {"status_code": status_code, "detail": detail}}

