"""SQLAlchemy ORM models.

Alembic autogenerate relies on importing this package so that all model modules
are registered in Base.metadata.

Keep this file as the single aggregation point for models.
"""

from app.db.base import Base  # noqa: F401

from app.db.models.user import User  # noqa: F401
from app.db.models.log import Log  # noqa: F401
from app.db.models.alert import Alert  # noqa: F401
from app.db.models.incident import Incident  # noqa: F401
from app.db.models.threat import Threat  # noqa: F401
from app.db.models.ai_analysis import AIAnalysis  # noqa: F401
from app.db.models.report import Report  # noqa: F401
from app.db.models.mitre_attack_mapping import MITREAttackMapping  # noqa: F401
from app.db.models.ioc import IOC  # noqa: F401
from app.db.models.audit_log import AuditLog  # noqa: F401

