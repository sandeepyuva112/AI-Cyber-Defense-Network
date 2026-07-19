from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FilterSpec:
    """Simple filter spec placeholder.

    Future extension: parse query params into SQLAlchemy expressions.
    """

    field: str
    op: str
    value: str

