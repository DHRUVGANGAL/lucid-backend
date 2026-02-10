import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, Enum, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from typing import List, TYPE_CHECKING

from app.db.base import Base
from app.models.enums import ProjectStatus

if TYPE_CHECKING:
    from app.models.requirement_document import RequirementDocument
    from app.models.architecture_baseline import ArchitectureBaseline
    from app.models.decision import Decision

class Project(Base):
    __tablename__ = "projects"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[ProjectStatus] = mapped_column(
        Enum(ProjectStatus), default=ProjectStatus.ACTIVE, nullable=False
    )
    
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    # Relationships
    requirement_documents: Mapped[List["RequirementDocument"]] = relationship(
        "RequirementDocument", back_populates="project", cascade="all, delete-orphan"
    )
    architecture_baselines: Mapped[List["ArchitectureBaseline"]] = relationship(
        "ArchitectureBaseline", back_populates="project", cascade="all, delete-orphan"
    )
    decisions: Mapped[List["Decision"]] = relationship(
        "Decision", back_populates="project", cascade="all, delete-orphan"
    )
