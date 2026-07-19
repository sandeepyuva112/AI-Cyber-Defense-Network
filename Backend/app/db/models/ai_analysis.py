from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class AIAnalysis(Base):
    """Represents a single AI analysis/response lifecycle for a given log.

    Notes:
    - Table name and core relationships are preserved for compatibility.
    - New columns are additive and nullable to keep existing records valid.
    """

    __tablename__ = "ai_analyses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # One Log -> many AIAnalysis records.
    log_id: Mapped[int] = mapped_column(Integer, ForeignKey("logs.id"), index=True)

    # AIAnalysis may or may not be tied to an incident.
    incident_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("incidents.id"), nullable=True, index=True
    )

    # --- AI provider / model metadata (provider-agnostic) ---
    ai_provider: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    model_name: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    prompt_version: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    analysis_type: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)

    # --- Input summary & structured findings ---
    input_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    structured_findings_json: Mapped[str | None] = mapped_column(Text, nullable=True)

    # --- Executive summary / classification ---
    executive_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    threat_classification: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)

    severity: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    severity_score: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)

    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True, index=True)
    confidence_score: Mapped[float | None] = mapped_column(Float, nullable=True, index=True)

    # Backwards-compatible fields (existing columns). Keep semantics mapped.
    classification_type: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    confidence_value: Mapped[float | None] = mapped_column(Float, nullable=True, index=True)

    mitre_attack_mapping_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    recommended_response_actions: Mapped[str | None] = mapped_column(Text, nullable=True)

    reasoning_explanation: Mapped[str | None] = mapped_column(Text, nullable=True)

    # --- Status/error lifecycle ---
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True, default="completed")
    error_details: Mapped[str | None] = mapped_column(Text, nullable=True)

    # --- Processing time ---
    processing_time_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # --- Token usage ---
    token_prompt: Mapped[int | None] = mapped_column(Integer, nullable=True)
    token_completion: Mapped[int | None] = mapped_column(Integer, nullable=True)
    token_total: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # --- Correlation/request ---
    correlation_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    request_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)

    # Existing raw_json preserved for compatibility.
    raw_json: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Timestamps: created + updated.
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )

    # Relationships
    log: Mapped[object] = relationship("Log", back_populates="ai_analyses")
    incident: Mapped[object | None] = relationship("Incident", back_populates="ai_analyses")



