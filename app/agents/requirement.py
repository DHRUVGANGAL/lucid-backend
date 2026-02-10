from app.agents.base import BaseAgent
from app.agents.models import RequirementsSpec
from app.services.normalization.models import NormalizedDocument
from app.core.llm.client import LLMClient
from app.core.llm.prompts import REQUIREMENT_AGENT_SYSTEM, REQUIREMENT_AGENT_USER

class RequirementAgent(BaseAgent[NormalizedDocument, RequirementsSpec]):
    async def process(self, input_data: NormalizedDocument) -> RequirementsSpec:
        client = LLMClient.get_instance()
        
        prompt = REQUIREMENT_AGENT_USER.format(
            business_intent=input_data.business_intent,
            explicit_requirements="\n".join(f"- {r}" for r in input_data.explicit_requirements),
            assumptions="\n".join(f"- {a}" for a in input_data.assumptions),
            constraints="\n".join(f"- {c}" for c in input_data.constraints),
            ambiguities="\n".join(f"- {a}" for a in input_data.ambiguities)
        )
        
        return await client.generate_structured(
            prompt=prompt,
            response_model=RequirementsSpec,
            system_prompt=REQUIREMENT_AGENT_SYSTEM
        )
