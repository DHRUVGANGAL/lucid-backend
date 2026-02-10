from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any
from app.services.normalization.models import NormalizedDocument
from app.services.rules.models import RuleResult

# --- Requirement Agent Models ---
class FunctionalRequirement(BaseModel):
    id: str
    description: str
    priority: str

class NonFunctionalRequirement(BaseModel):
    category: str
    description: str

class RequirementsSpec(BaseModel):
    functional_requirements: List[FunctionalRequirement]
    non_functional_requirements: List[NonFunctionalRequirement]
    user_stories: List[str]

# --- Architecture Agent Models ---
class Component(BaseModel):
    name: str
    type: str  # e.g., Service, Database, Queue
    responsibilities: List[str]

class DataModel(BaseModel):
    name: str
    fields: List[str]

class APIEndpoint(BaseModel):
    method: str
    path: str
    description: str

class ArchitectureDesign(BaseModel):
    components: List[Component]
    data_models: List[DataModel]
    api_definitions: List[APIEndpoint]
    diagram_mermaid: Optional[str] = None

# --- Impact Agent Models ---
class FileChange(BaseModel):
    path: str
    change_type: str  # MODIFY, CREATE, DELETE
    reason: str

class ImpactAnalysis(BaseModel):
    affected_components: List[str]
    file_changes: List[FileChange]
    database_migrations: List[str]
    risk_assessment: str

# --- Estimation Agent Models ---
class TaskEstimate(BaseModel):
    task_name: str
    hours: float
    complexity: str

class EstimationReport(BaseModel):
    total_hours: float
    breakdown: List[TaskEstimate]
    cost_estimate: Optional[str]
    timeline_weeks: float
    assumptions_used: List[str]

# --- Explanation Agent Models ---
class ExecutiveSummary(BaseModel):
    overview: str
    key_risks: List[str]
    recommendation: str
    technical_summary: str
