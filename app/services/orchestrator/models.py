from pydantic import BaseModel
from typing import Optional, Dict, Any
from app.services.rules.models import RuleResult
from app.agents.models import (
    RequirementsSpec, 
    ArchitectureDesign, 
    ImpactAnalysis, 
    EstimationReport, 
    ExecutiveSummary
)

class Decision(BaseModel):
    project_id: Optional[str] = None
    decision_id: Optional[str] = None
    context_type: str
    confidence_score: float
    normalized_data: Dict[str, Any]
    rule_results: Dict[str, Any]
    requirements: RequirementsSpec
    architecture: ArchitectureDesign
    impact: ImpactAnalysis
    estimation: EstimationReport
    explanation: ExecutiveSummary
    risk_level: Optional[str] = None
