from typing import Dict, Any, List
from archestra.agents.base_agent import BaseAgent
from archestra.client import ArchestraClient
import json

class EstimationAgent(BaseAgent):
    """
    Estimates development effort and confidence.
    """
    
    @property
    def agent_name(self) -> str:
        return "estimation_agent"

    @property
    def description(self) -> str:
        return "Estimates development effort in days with confidence levels."
    
    @property
    def input_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "requirements": {"type": "object"},
                "architecture": {"type": "object"},
                "impact": {"type": "object"}
            },
            "required": ["requirements", "architecture", "impact"]
        }

    @property
    def output_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "effort_days": {"type": "number"},
                "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
                "assumptions": {"type": "array", "items": {"type": "string"}}
            },
            "required": ["effort_days", "confidence", "assumptions"]
        }

    async def run(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        client = ArchestraClient()
        
        system_prompt = """
        You are a Technical Project Manager. Estimate the effort for this project.
        
        Rules:
        1. Base estimate on requirements complexity, architecture components, and impact.
        2. Be CONSERVATIVE. Multiply your initial gut feeling by 1.5x.
        3. Explain the main sources of uncertainty in 'assumptions'.
        4. Return ONLY valid JSON.
        """
        
        # Serialize inputs
        req_summary = json.dumps(payload['requirements'], indent=2)
        arch_summary = json.dumps(payload['architecture'], indent=2)
        imp_summary = json.dumps(payload['impact'], indent=2)
        
        user_prompt = f"""
        Requirements:
        {req_summary}
        
        Architecture:
        {arch_summary}
        
        Impact Analysis:
        {imp_summary}
        """
        
        return await client.call_llm(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            json_schema=self.output_schema,
            temperature=0.1
        )
