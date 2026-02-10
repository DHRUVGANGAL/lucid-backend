from dataclasses import dataclass, field
from typing import List, Any, Optional
from enum import Enum
from app.services.normalization.models import NormalizedDocument
from app.services.context.enums import ContextType

class Operator(str, Enum):
    EQUALS = "equals"
    CONTAINS = "contains"
    GREATER_THAN = "greater_than"
    LESS_THAN = "less_than"

class EffectType(str, Enum):
    RISK_LEVEL = "risk_level"
    EFFORT_MULTIPLIER = "effort_multiplier"
    FLAG = "flag"

@dataclass
class Condition:
    field: str  # dot notation, e.g., "context_type" or "normalized_doc.business_intent"
    operator: Operator
    value: Any

@dataclass
class Effect:
    type: EffectType
    value: Any
    description: str

@dataclass
class Rule:
    id: str
    description: str
    condition: Condition
    effects: List[Effect]

@dataclass
class AnalysisContext:
    context_type: ContextType
    normalized_doc: NormalizedDocument
    
@dataclass
class RuleResult:
    triggered_rules: List[str] = field(default_factory=list)
    risk_level: str = "LOW"
    effort_multiplier: float = 1.0
    flags: List[str] = field(default_factory=list)
