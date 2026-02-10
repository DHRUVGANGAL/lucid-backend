from typing import List, Optional
from uuid import UUID
from pydantic import BaseModel, Field
from datetime import datetime

from app.models.enums import RiskLevel


class MemoryEntry(BaseModel):
    """A single memory entry representing a decision's semantic summary."""
    decision_id: UUID
    project_id: UUID
    
    # Semantic content
    summary: str
    key_insights: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    
    # Metadata
    risk_level: RiskLevel
    estimated_hours: Optional[float] = None
    actual_hours: Optional[float] = None
    
    # Embedding placeholder (would be real vector in production)
    embedding: Optional[List[float]] = None
    
    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow)
    
    class Config:
        from_attributes = True


class BiasSignal(BaseModel):
    """Bias signal detected from historical patterns."""
    signal_type: str  # e.g., "underestimation", "overconfidence", "scope_creep"
    confidence: float  # 0.0 to 1.0
    description: str
    supporting_decisions: List[UUID] = Field(default_factory=list)


class RecallResult(BaseModel):
    """Result of a similarity search / recall operation."""
    entries: List[MemoryEntry]
    bias_signals: List[BiasSignal] = Field(default_factory=list)
    patterns: List[str] = Field(default_factory=list)
    total_matches: int = 0
