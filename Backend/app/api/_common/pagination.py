from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Pagination:
    limit: int = 50
    offset: int = 0


def clamp_limit(limit: int, *, min_limit: int = 1, max_limit: int = 200) -> int:
    if limit < min_limit:
        return min_limit
    if limit > max_limit:
        return max_limit
    return limit

