import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, Enum, Text, ForeignKey, Float, func
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from typing import TYPE_CHECKING

from app.db.base import Base
from app.models.enums import DecisionStatus, RiskLevel

if TYPE_CHECKING:
    from app.models.project import Project
    from app.models.requirement_document import RequirementDocument
    from app.models.architecture_baseline import ArchitectureBaseline
    from app.models.delivery_outcome import DeliveryOutcome

class Decision(Base):
    __tablename__ = "decisions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    requirement_document_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("requirement_documents.id", ondelete="SET NULL"), nullable=True
    )
    architecture_baseline_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("architecture_baselines.id", ondelete="SET NULL"), nullable=True
    )
    
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    
    status: Mapped[DecisionStatus] = mapped_column(
        Enum(DecisionStatus), default=DecisionStatus.DRAFT, nullable=False
    )
    risk_level: Mapped[RiskLevel] = mapped_column(
        Enum(RiskLevel), default=RiskLevel.MEDIUM, nullable=False
    )
    
    # Store full analysis results as JSONB
    requirements_spec: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    architecture_design: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    impact_analysis: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    estimation: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    rule_results: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    executive_summary: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    
    # Estimation fields
    estimated_hours: Mapped[float | None] = mapped_column(Float, nullable=True)
    estimated_cost: Mapped[str | None] = mapped_column(String(100), nullable=True)
    timeline_weeks: Mapped[float | None] = mapped_column(Float, nullable=True)
    
    approved_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    # Relationships
    project: Mapped["Project"] = relationship("Project", back_populates="decisions")
    requirement_document: Mapped["RequirementDocument"] = relationship(
        "RequirementDocument", back_populates="decisions"
    )
    architecture_baseline: Mapped["ArchitectureBaseline"] = relationship(
        "ArchitectureBaseline", back_populates="decisions"
    )
    delivery_outcome: Mapped["DeliveryOutcome"] = relationship(
        "DeliveryOutcome", back_populates="decision", uselist=False
    )
