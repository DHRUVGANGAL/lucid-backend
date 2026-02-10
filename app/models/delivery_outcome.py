import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, Enum, Text, ForeignKey, Float, func
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from typing import TYPE_CHECKING

from app.db.base import Base
from app.models.enums import DeliveryStatus

if TYPE_CHECKING:
    from app.models.decision import Decision

class DeliveryOutcome(Base):
    __tablename__ = "delivery_outcomes"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    decision_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("decisions.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    
    status: Mapped[DeliveryStatus] = mapped_column(
        Enum(DeliveryStatus), default=DeliveryStatus.NOT_STARTED, nullable=False
    )
    
    # Actual vs Estimated
    actual_hours: Mapped[float | None] = mapped_column(Float, nullable=True)
    actual_cost: Mapped[str | None] = mapped_column(String(100), nullable=True)
    
    # Outcome metrics
    variance_percentage: Mapped[float | None] = mapped_column(Float, nullable=True)
    quality_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    
    # Store any post-delivery feedback or lessons learned
    feedback: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    # Relationships
    decision: Mapped["Decision"] = relationship("Decision", back_populates="delivery_outcome")
