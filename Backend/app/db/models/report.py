from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    incident_id: Mapped[int] = mapped_column(Integer, ForeignKey("incidents.id"), index=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)

    report_type: Mapped[str] = mapped_column(String(64), index=True, default="dashboard")
    content_json: Mapped[str | None] = mapped_column(Text, nullable=True)

    incident: Mapped[object] = relationship("Incident", back_populates="reports")


