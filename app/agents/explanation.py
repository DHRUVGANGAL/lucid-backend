from pydantic import BaseModel
from app.agents.base import BaseAgent
from app.agents.models import ExecutiveSummary, RequirementsSpec, ArchitectureDesign, ImpactAnalysis, EstimationReport
from app.core.llm.client import LLMClient
from app.core.llm.prompts import EXPLANATION_AGENT_SYSTEM, EXPLANATION_AGENT_USER

class ExplanationInput(BaseModel):
    requirements: RequirementsSpec
    architecture: ArchitectureDesign
    impact: ImpactAnalysis
    estimation: EstimationReport

class ExplanationAgent(BaseAgent[ExplanationInput, ExecutiveSummary]):
    async def process(self, input_data: ExplanationInput) -> ExecutiveSummary:
        client = LLMClient.get_instance()
        
        prompt = EXPLANATION_AGENT_USER.format(
            requirements_summary=f"{len(input_data.requirements.functional_requirements)} functional requirements, "
                                  f"{len(input_data.requirements.non_functional_requirements)} non-functional requirements",
            architecture_overview=f"{len(input_data.architecture.components)} components, "
                                   f"{len(input_data.architecture.data_models)} data models, "
                                   f"{len(input_data.architecture.api_definitions)} API endpoints",
            impact_summary=f"{len(input_data.impact.affected_components)} affected components, "
                           f"{len(input_data.impact.file_changes)} file changes, "
                           f"Risk: {input_data.impact.risk_assessment}",
            total_hours=input_data.estimation.total_hours,
            timeline_weeks=input_data.estimation.timeline_weeks,
            cost_estimate=input_data.estimation.cost_estimate or "Not estimated"
        )
        
        return await client.generate_structured(
            prompt=prompt,
            response_model=ExecutiveSummary,
            system_prompt=EXPLANATION_AGENT_SYSTEM
        )
