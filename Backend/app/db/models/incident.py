from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.db.models.report import Report


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    log_id: Mapped[int] = mapped_column(Integer, ForeignKey("logs.id"), index=True)

    incident_id: Mapped[str] = mapped_column(String(64), index=True, unique=False)
    log_type: Mapped[str] = mapped_column(String(100), index=True)

    classification_type: Mapped[str] = mapped_column(String(64), index=True)
    classification_description: Mapped[str | None] = mapped_column(Text, nullable=True)

    severity_level: Mapped[str] = mapped_column(String(32), index=True)
    severity_score: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)

    confidence_value: Mapped[float | None] = mapped_column(Integer, nullable=True)  # stored later as float via migration if needed
    confidence_rationale: Mapped[str | None] = mapped_column(Text, nullable=True)

    plain_english_attack_explanation: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)

    log: Mapped[object] = relationship("Log", back_populates="incidents")

    alerts: Mapped[list[object]] = relationship("Alert", back_populates="incident")

    reports: Mapped[list["Report"]] = relationship(
        "Report", back_populates="incident", cascade="all, delete-orphan"
    )
    ai_analyses: Mapped[list[object]] = relationship("AIAnalysis", back_populates="incident")
    mitre_mappings: Mapped[list[object]] = relationship(
        "MITREAttackMapping", back_populates="incident", cascade="all, delete-orphan"
    )


