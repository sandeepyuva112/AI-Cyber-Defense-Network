from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class Log(Base):
    __tablename__ = "logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    log_type: Mapped[str] = mapped_column(String(100), index=True)

    source_filename: Mapped[str | None] = mapped_column(String(500), nullable=True)
    uploaded_by_user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id"), nullable=True, index=True
    )

    total_events_estimated: Mapped[int | None] = mapped_column(Integer, nullable=True)
    total_alerts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Store the full raw text if you need forensic reprocessing.
    raw_text: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)

    uploaded_by: Mapped[object | None] = relationship("User", back_populates="logs")
    events: Mapped[list[object]] = relationship(
        "LogEvent", back_populates="log", cascade="all, delete-orphan"
    )
    alerts: Mapped[list[object]] = relationship(
        "Alert", back_populates="log", cascade="all, delete-orphan"
    )
    incidents: Mapped[list[object]] = relationship(
        "Incident", back_populates="log", cascade="all, delete-orphan"
    )
    ai_analyses: Mapped[list[object]] = relationship(
        "AIAnalysis", back_populates="log", cascade="all, delete-orphan"
    )



class LogEvent(Base):
    __tablename__ = "log_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    log_id: Mapped[int] = mapped_column(Integer, ForeignKey("logs.id"), index=True)

    timestamp: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)

    source: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)

    ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    username: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    process: Mapped[str | None] = mapped_column(String(255), nullable=True)

    severity: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True, default="unknown")

    message: Mapped[str | None] = mapped_column(Text, nullable=True)

    threat_score: Mapped[float | None] = mapped_column(Float, nullable=True, index=True)

    # Best-effort iocs stored as JSON string for SQLite portability.
    ioc_json: Mapped[str | None] = mapped_column(Text, nullable=True)

    raw_json: Mapped[str | None] = mapped_column(Text, nullable=True)

    log: Mapped[object] = relationship("Log", back_populates="events")


