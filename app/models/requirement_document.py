import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, Enum, Text, ForeignKey, Float, func
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from typing import List, TYPE_CHECKING

from app.db.base import Base
from app.models.enums import DocumentStatus, ContextType

if TYPE_CHECKING:
    from app.models.project import Project
    from app.models.normalized_requirement import NormalizedRequirement
    from app.models.decision import Decision

class RequirementDocument(Base):
    __tablename__ = "requirement_documents"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    content_type: Mapped[str] = mapped_column(String(100), nullable=False)
    raw_text: Mapped[str] = mapped_column(Text, nullable=False)
    
    context_type: Mapped[ContextType] = mapped_column(
        Enum(ContextType), default=ContextType.UNKNOWN, nullable=False
    )
    confidence_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    
    status: Mapped[DocumentStatus] = mapped_column(
        Enum(DocumentStatus), default=DocumentStatus.PENDING, nullable=False
    )
    
    # Store normalized data as JSONB
    normalized_data: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    # Relationships
    project: Mapped["Project"] = relationship("Project", back_populates="requirement_documents")
    normalized_requirements: Mapped[List["NormalizedRequirement"]] = relationship(
        "NormalizedRequirement", back_populates="document", cascade="all, delete-orphan"
    )
    decisions: Mapped[List["Decision"]] = relationship(
        "Decision", back_populates="requirement_document"
    )
