from __future__ import annotations

from typing import Any


def export_json(report_obj: Any) -> dict[str, Any]:
    # Pydantic models: use model_dump
    if hasattr(report_obj, "model_dump"):
        return report_obj.model_dump(mode="json")
    # Fallback: try to coerce
    if isinstance(report_obj, dict):
        return report_obj
    return {"report": str(report_obj)}

