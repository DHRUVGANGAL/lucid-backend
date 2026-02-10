from dataclasses import asdict
from pydantic import BaseModel
from app.agents.base import BaseAgent
from app.agents.models import ImpactAnalysis, EstimationReport
from app.services.rules.models import RuleResult
from app.core.llm.client import LLMClient
from app.core.llm.prompts import ESTIMATION_AGENT_SYSTEM, ESTIMATION_AGENT_USER

class EstimationInput(BaseModel):
    impact: ImpactAnalysis
    rules: RuleResult

class EstimationAgent(BaseAgent[EstimationInput, EstimationReport]):
    async def process(self, input_data: EstimationInput) -> EstimationReport:
        client = LLMClient.get_instance()
        
        rules_dict = asdict(input_data.rules)
        
        prompt = ESTIMATION_AGENT_USER.format(
            affected_components=", ".join(input_data.impact.affected_components),
            file_changes="\n".join(
                f"- {fc.path} ({fc.change_type}): {fc.reason}"
                for fc in input_data.impact.file_changes
            ),
            database_migrations="\n".join(f"- {m}" for m in input_data.impact.database_migrations),
            risk_assessment=input_data.impact.risk_assessment,
            risk_level=rules_dict["risk_level"],
            effort_multiplier=rules_dict["effort_multiplier"],
            flags=", ".join(rules_dict["flags"]) if rules_dict["flags"] else "None"
        )
        
        return await client.generate_structured(
            prompt=prompt,
            response_model=EstimationReport,
            system_prompt=ESTIMATION_AGENT_SYSTEM
        )
