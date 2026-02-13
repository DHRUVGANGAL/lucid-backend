from typing import Dict, Any
from archestra.agents.base_agent import BaseAgent
from archestra.client import ArchestraClient
import json

class ImpactAgent(BaseAgent):
    """
    Analyzes technical and business impact of the proposed architecture.
    """
    
    @property
    def agent_name(self) -> str:
        return "impact_agent"

    @property
    def description(self) -> str:
        return "Identifies impacted modules, risk factors, and breaking changes."
    
    @property
    def input_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "architecture": {"type": "object"},
                "context": {"type": "object"}
            },
            "required": ["architecture", "context"]
        }

    @property
    def output_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "impacted_modules": {"type": "array", "items": {"type": "string"}},
                "risk_factors": {"type": "array", "items": {"type": "string"}},
                "breaking_changes": {"type": "boolean"}
            },
            "required": ["impacted_modules", "risk_factors", "breaking_changes"]
        }

    async def run(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        client = ArchestraClient()
        
        system_prompt = """
        You are a Technical Lead and Risk Analyst. Assess the impact of this architecture.
        
        Rules:
        1. Use the Context to check if this is a change request or new project.
        2. Identify SPECIFIC impacted areas (modules, data, API).
        3. Be explicit about risks (e.g. data migration, latency).
        4. Determine if there are BREAKING changes.
        5. NO speculation - stick to the provided info.
        6. Return ONLY valid JSON.
        """
        
        arch_summary = json.dumps(payload['architecture'], indent=2)
        ctx_summary = json.dumps(payload['context'], indent=2)
        
        user_prompt = f"""
        Proposed Architecture:
        {arch_summary}
        
        Context:
        {ctx_summary}
        """
        
        return await client.call_llm(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            json_schema=self.output_schema,
            temperature=0.1
        )
