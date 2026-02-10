from typing import Any, List
from app.services.rules.models import (
    Rule, AnalysisContext, RuleResult, Operator, EffectType
)

class RuleEngine:
    def __init__(self, rules: List[Rule]):
        self.rules = rules

    def evaluate(self, context: AnalysisContext) -> RuleResult:
        result = RuleResult()
        
        for rule in self.rules:
            if self._check_condition(rule.condition, context):
                result.triggered_rules.append(rule.id)
                self._apply_effects(rule.effects, result)
                
        return result

    def _check_condition(self, condition, context: AnalysisContext) -> bool:
        # Resolve field value
        field_parts = condition.field.split(".")
        value = context
        
        try:
            for part in field_parts:
                if hasattr(value, part):
                    value = getattr(value, part)
                elif isinstance(value, dict):
                    value = value.get(part)
                else:
                    return False
        except Exception:
            return False

        # Check operator
        if condition.operator == Operator.EQUALS:
            return value == condition.value
        elif condition.operator == Operator.CONTAINS:
            if isinstance(value, (list, str)):
                return condition.value in value
            return False
        elif condition.operator == Operator.GREATER_THAN:
            return value > condition.value
        elif condition.operator == Operator.LESS_THAN:
            return value < condition.value
            
        return False

    def _apply_effects(self, effects, result: RuleResult):
        for effect in effects:
            if effect.type == EffectType.RISK_LEVEL:
                # Simple logic: assume HIGH overrides LOW
                if effect.value == "HIGH":
                    result.risk_level = "HIGH"
                elif effect.value == "MEDIUM" and result.risk_level == "LOW":
                    result.risk_level = "MEDIUM"
                    
            elif effect.type == EffectType.EFFORT_MULTIPLIER:
                result.effort_multiplier *= float(effect.value)
                
            elif effect.type == EffectType.FLAG:
                if effect.value not in result.flags:
                    result.flags.append(effect.value)
