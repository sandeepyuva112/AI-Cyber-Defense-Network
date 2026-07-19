from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class MITREAttackMapping(Base):
    __tablename__ = "mitre_attack_mappings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # References alert OR incident (nullable side).
    alert_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("alerts.id"), nullable=True, index=True)
    incident_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("incidents.id"), nullable=True, index=True
    )

    technique_id: Mapped[str] = mapped_column(String(32), index=True)
    technique_name: Mapped[str | None] = mapped_column(String(255), nullable=True)

    tactics_json: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)

    alert: Mapped[object | None] = relationship("Alert", back_populates="mitre_mappings")
    incident: Mapped[object | None] = relationship("Incident", back_populates="mitre_mappings")


