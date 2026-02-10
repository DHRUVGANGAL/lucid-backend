from app.agents.base import BaseAgent
from app.agents.models import ArchitectureDesign, ImpactAnalysis
from app.core.llm.client import LLMClient
from app.core.llm.prompts import IMPACT_AGENT_SYSTEM, IMPACT_AGENT_USER

class ImpactDiffAgent(BaseAgent[ArchitectureDesign, ImpactAnalysis]):
    async def process(self, input_data: ArchitectureDesign) -> ImpactAnalysis:
        client = LLMClient.get_instance()
        
        prompt = IMPACT_AGENT_USER.format(
            components="\n".join(
                f"- {c.name} ({c.type}): {', '.join(c.responsibilities)}"
                for c in input_data.components
            ),
            data_models="\n".join(
                f"- {m.name}: {', '.join(m.fields)}"
                for m in input_data.data_models
            ),
            api_definitions="\n".join(
                f"- {e.method} {e.path}: {e.description}"
                for e in input_data.api_definitions
            )
        )
        
        return await client.generate_structured(
            prompt=prompt,
            response_model=ImpactAnalysis,
            system_prompt=IMPACT_AGENT_SYSTEM
        )
