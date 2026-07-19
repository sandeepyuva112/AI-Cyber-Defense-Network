"""Log parsing engine.

Parsers normalize heterogeneous log inputs into a single schema:
`app.schemas.log_event.LogEvent`.
"""

from app.parsers.factory import get_parser
from app.schemas.log_event import LogEvent

__all__ = ["get_parser", "LogEvent"]

