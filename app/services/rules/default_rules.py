from app.services.rules.models import Rule, Condition, Effect, Operator, EffectType
from app.services.context.enums import ContextType

DEFAULT_RULES = [
    Rule(
        id="risk_high_legacy",
        description="Legacy code changes imply high risk",
        condition=Condition(
            field="normalized_doc.business_intent",
            operator=Operator.CONTAINS,
            value="legacy"
        ),
        effects=[
            Effect(EffectType.RISK_LEVEL, "HIGH", "Legacy code modification detected"),
            Effect(EffectType.EFFORT_MULTIPLIER, 1.5, "Legacy code overhead")
        ]
    ),
    Rule(
        id="risk_medium_change_request",
        description="Change requests are generally medium risk",
        condition=Condition(
            field="context_type",
            operator=Operator.EQUALS,
            value=ContextType.CHANGE_REQUEST
        ),
        effects=[
            Effect(EffectType.RISK_LEVEL, "MEDIUM", "Change request context"),
        ]
    ),
    Rule(
        id="flag_ambiguity",
        description="Flag if ambiguity is detected in assumptions",
        condition=Condition(
            field="normalized_doc.assumptions",
            operator=Operator.CONTAINS,
            value="TBD"
        ),
        effects=[
            Effect(EffectType.FLAG, "AMBIGUOUS_REQUIREMENTS", "TBD found in assumptions")
        ]
    )
]
