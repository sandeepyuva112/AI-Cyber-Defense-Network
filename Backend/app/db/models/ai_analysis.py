from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class AIAnalysis(Base):
    __tablename__ = "ai_analyses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    log_id: Mapped[int] = mapped_column(Integer, ForeignKey("logs.id"), index=True)
    incident_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("incidents.id"), nullable=True, index=True
    )

    model_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)

    confidence_value: Mapped[float | None] = mapped_column(Float, nullable=True, index=True)
    severity_level: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    severity_score: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)

    classification_type: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)

    raw_json: Mapped[str | None] = mapped_column(Text, nullable=True)

    log: Mapped[object] = relationship("Log", back_populates="ai_analyses")
    incident: Mapped[object | None] = relationship("Incident", back_populates="ai_analyses")


