from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Optional

from app.schemas.log_event import LogEvent


class BaseLogParser(ABC):
    """Base interface for all log parsers."""

    @abstractmethod
    def parse(self, text: str, metadata: Optional[dict[str, Any]] = None) -> list[LogEvent]:
        """Parse input log text into one or more normalized LogEvent objects."""
        raise NotImplementedError

