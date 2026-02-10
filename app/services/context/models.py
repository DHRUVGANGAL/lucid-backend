from typing import List, Optional
from uuid import UUID
from pydantic import BaseModel, Field
from datetime import datetime

from app.models.enums import ProjectStatus, ContextType, DecisionStatus, RiskLevel


class RequirementSummary(BaseModel):
    """Summarized requirement data for context."""
    id: str
    requirement_type: str
    description: str
    priority: Optional[str] = None
    category: Optional[str] = None


class DocumentSummary(BaseModel):
    """Summarized document data for context."""
    id: UUID
    filename: str
    context_type: ContextType
    confidence_score: float
    status: str
    created_at: datetime
    requirements: List[RequirementSummary] = Field(default_factory=list)


class ArchitectureSummary(BaseModel):
    """Summarized architecture baseline for context."""
    id: UUID
    version: int
    name: str
    description: Optional[str] = None
    component_count: int = 0
    data_model_count: int = 0
    api_count: int = 0
    is_active: bool = True


class DecisionSummary(BaseModel):
    """Summarized locked decision for context."""
    id: UUID
    title: str
    status: DecisionStatus
    risk_level: RiskLevel
    estimated_hours: Optional[float] = None
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None


class ProjectContext(BaseModel):
    """
    Aggregated project context for use by orchestrator and agents.
    This is the single source of truth for project state.
    """
    # Project metadata
    project_id: UUID
    project_name: str
    project_description: Optional[str] = None
    project_status: ProjectStatus
    
    # Aggregated data
    documents: List[DocumentSummary] = Field(default_factory=list)
    active_architecture: Optional[ArchitectureSummary] = None
    locked_decisions: List[DecisionSummary] = Field(default_factory=list)
    
    # Computed stats
    total_requirements: int = 0
    total_decisions: int = 0
    approved_decisions: int = 0
    
    # Timestamps
    context_generated_at: datetime = Field(default_factory=datetime.utcnow)
    
    class Config:
        from_attributes = True
