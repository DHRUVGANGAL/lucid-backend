from pydantic import BaseModel, Field
from typing import List

class NormalizedDocument(BaseModel):
    business_intent: str = Field(..., description="High-level business goal of the document")
    explicit_requirements: List[str] = Field(default_factory=list, description="List of explicitly stated requirements")
    assumptions: List[str] = Field(default_factory=list, description="List of assumptions made in the document")
    constraints: List[str] = Field(default_factory=list, description="List of technical or business constraints")
    ambiguities: List[str] = Field(default_factory=list, description="List of ambiguous statements requiring clarification")
