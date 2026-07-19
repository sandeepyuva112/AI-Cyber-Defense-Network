from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    log_id: Mapped[int] = mapped_column(Integer, ForeignKey("logs.id"), index=True)
    incident_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("incidents.id"), nullable=True, index=True
    )

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)

    severity_level: Mapped[str] = mapped_column(String(32), index=True)
    severity_score: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)

    threat_category: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)

    confidence_value: Mapped[float | None] = mapped_column(Float, nullable=True, index=True)

    # One alert can be mapped to multiple MITRE techniques.

    log: Mapped[object] = relationship("Log", back_populates="alerts")

    incident: Mapped[object | None] = relationship("Incident", back_populates="alerts")

    mitre_mappings: Mapped[list[object]] = relationship(
        "MITREAttackMapping", back_populates="alert", cascade="all, delete-orphan"
    )


