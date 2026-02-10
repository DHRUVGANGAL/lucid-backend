import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, Text, ForeignKey, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from typing import TYPE_CHECKING

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.requirement_document import RequirementDocument

class NormalizedRequirement(Base):
    __tablename__ = "normalized_requirements"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    document_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("requirement_documents.id", ondelete="CASCADE"), nullable=False
    )
    
    requirement_id: Mapped[str] = mapped_column(String(50), nullable=False)  # e.g., FR-001
    requirement_type: Mapped[str] = mapped_column(String(50), nullable=False)  # functional, non_functional
    description: Mapped[str] = mapped_column(Text, nullable=False)
    priority: Mapped[str | None] = mapped_column(String(20), nullable=True)  # High, Medium, Low
    category: Mapped[str | None] = mapped_column(String(100), nullable=True)  # e.g., Performance, Security
    
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    # Relationships
    document: Mapped["RequirementDocument"] = relationship(
        "RequirementDocument", back_populates="normalized_requirements"
    )
