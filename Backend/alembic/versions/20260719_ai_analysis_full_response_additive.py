"""Add full AI response lifecycle fields to ai_analyses (additive, nullable). 

Revision ID: 20260719_ai_analysis_full_response_additive
Revises: 03902652e31f
Create Date: 2026-07-19

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "20260719_ai_analysis_full_response_additive"
down_revision: Union[str, Sequence[str], None] = "03902652e31f"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Additive schema changes only; keep backward compatibility.
    op.add_column(
        "ai_analyses",
        sa.Column("ai_provider", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "ai_analyses",
        sa.Column("prompt_version", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "ai_analyses",
        sa.Column("analysis_type", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "ai_analyses",
        sa.Column("input_summary", sa.Text(), nullable=True),
    )
    op.add_column(
        "ai_analyses",
        sa.Column("structured_findings_json", sa.Text(), nullable=True),
    )
    op.add_column(
        "ai_analyses",
        sa.Column("executive_summary", sa.Text(), nullable=True),
    )
    op.add_column(
        "ai_analyses",
        sa.Column("threat_classification", sa.String(length=64), nullable=True),
    )

    # risk/confidence upgrades
    op.add_column(
        "ai_analyses",
        sa.Column("risk_score", sa.Float(), nullable=True),
    )
    op.add_column(
        "ai_analyses",
        sa.Column("confidence_score", sa.Float(), nullable=True),
    )

    # Actions/Reasoning
    op.add_column(
        "ai_analyses",
        sa.Column("mitre_attack_mapping_json", sa.Text(), nullable=True),
    )
    op.add_column(
        "ai_analyses",
        sa.Column("recommended_response_actions", sa.Text(), nullable=True),
    )
    op.add_column(
        "ai_analyses",
        sa.Column("reasoning_explanation", sa.Text(), nullable=True),
    )

    # Status/Error lifecycle
    op.add_column(
        "ai_analyses",
        sa.Column(
            "status",
            sa.String(length=32),
            nullable=False,
            server_default="completed",
        ),
    )
    op.add_column(
        "ai_analyses",
        sa.Column("error_details", sa.Text(), nullable=True),
    )

    # Processing time
    op.add_column(
        "ai_analyses",
        sa.Column("processing_time_ms", sa.Integer(), nullable=True),
    )

    # Token usage
    op.add_column(
        "ai_analyses",
        sa.Column("token_prompt", sa.Integer(), nullable=True),
    )
    op.add_column(
        "ai_analyses",
        sa.Column("token_completion", sa.Integer(), nullable=True),
    )
    op.add_column(
        "ai_analyses",
        sa.Column("token_total", sa.Integer(), nullable=True),
    )

    # Correlation/request
    op.add_column(
        "ai_analyses",
        sa.Column("correlation_id", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "ai_analyses",
        sa.Column("request_id", sa.String(length=128), nullable=True),
    )

    # created_at/updated_at are already present in the models but may not exist in initial migration.
    # Add updated_at first; created_at remains as-is.
    op.add_column(
        "ai_analyses",
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
    )


    # Remove server defaults to keep schema clean (optional).
    op.alter_column("ai_analyses", "status", server_default=None)


def downgrade() -> None:
    # Drop columns added in upgrade (best-effort).
    with op.batch_alter_table("ai_analyses") as batch_op:
        batch_op.drop_column("request_id")
        batch_op.drop_column("correlation_id")
        batch_op.drop_column("token_total")
        batch_op.drop_column("token_completion")
        batch_op.drop_column("token_prompt")
        batch_op.drop_column("processing_time_ms")
        batch_op.drop_column("error_details")
        batch_op.drop_column("status")
        batch_op.drop_column("reasoning_explanation")
        batch_op.drop_column("recommended_response_actions")
        batch_op.drop_column("mitre_attack_mapping_json")
        batch_op.drop_column("confidence_score")
        batch_op.drop_column("risk_score")
        batch_op.drop_column("threat_classification")
        batch_op.drop_column("executive_summary")
        batch_op.drop_column("structured_findings_json")
        batch_op.drop_column("input_summary")
        batch_op.drop_column("analysis_type")
        batch_op.drop_column("prompt_version")
        batch_op.drop_column("ai_provider")
        batch_op.drop_column("updated_at")

