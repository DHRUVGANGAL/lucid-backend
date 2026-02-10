from app.agents.base import BaseAgent
from app.agents.models import RequirementsSpec, ArchitectureDesign
from app.core.llm.client import LLMClient
from app.core.llm.prompts import ARCHITECTURE_AGENT_SYSTEM, ARCHITECTURE_AGENT_USER

class ArchitectureAgent(BaseAgent[RequirementsSpec, ArchitectureDesign]):
    async def process(self, input_data: RequirementsSpec) -> ArchitectureDesign:
        client = LLMClient.get_instance()
        
        prompt = ARCHITECTURE_AGENT_USER.format(
            functional_requirements="\n".join(
                f"- [{r.id}] {r.description} (Priority: {r.priority})" 
                for r in input_data.functional_requirements
            ),
            non_functional_requirements="\n".join(
                f"- [{r.category}] {r.description}" 
                for r in input_data.non_functional_requirements
            ),
            user_stories="\n".join(f"- {s}" for s in input_data.user_stories)
        )
        
        return await client.generate_structured(
            prompt=prompt,
            response_model=ArchitectureDesign,
            system_prompt=ARCHITECTURE_AGENT_SYSTEM
        )
