from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SortSpec:
    field: str
    direction: str = "asc"  # asc|desc

