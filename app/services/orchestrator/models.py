from pydantic import BaseModel
from typing import Optional, Dict, Any, List

class Decision(BaseModel):
    project_id: Optional[str] = None
    decision_id: Optional[str] = None
    context_type: str
    confidence_score: float
    normalized_data: Dict[str, Any] = {}
    rule_results: Dict[str, Any] = {}
    requirements: Optional[Any] = None
    architecture: Optional[Any] = None
    impact: Optional[Any] = None
    estimation: Optional[Any] = None
    explanation: Optional[Any] = None
    risk_level: Optional[str] = None

