from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class Threat(Base):
    __tablename__ = "threats"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    log_id: Mapped[int] = mapped_column(Integer, ForeignKey("logs.id"), index=True)
    incident_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("incidents.id"), nullable=True, index=True
    )

    threat_category: Mapped[str] = mapped_column(String(64), index=True)

    # Confidence distribution.
    confidence_value: Mapped[float | None] = mapped_column(Float, nullable=True, index=True)
    severity_level: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)

    log: Mapped[object] = relationship("Log")

    incident: Mapped[object | None] = relationship("Incident")


