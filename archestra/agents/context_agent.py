from typing import Dict, Any
from archestra.agents.base_agent import BaseAgent
from archestra.client import ArchestraClient
import json

class ContextAgent(BaseAgent):
    """
    Detects project context, intent, and risk level.
    """
    
    @property
    def agent_name(self) -> str:
        return "context_agent"

    @property
    def description(self) -> str:
        return "Analyzes requirements to determine project context, domain, and risk."
    
    @property
    def input_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "requirements": {"type": "array"}
            },
            "required": ["requirements"]
        }

    @property
    def output_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "context_type": {"type": "string", "enum": ["new_project", "change_request"]},
                "risk_level": {"type": "string", "enum": ["low", "medium", "high"]},
                "domain": {"type": "string", "enum": ["fintech", "healthcare", "ecommerce", "general"]}
            },
            "required": ["context_type", "risk_level", "domain"]
        }

    async def run(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detect context and risk level.
        
        Args:
            payload: Must contain 'requirements' (list).
                     Optional: 'similar_decisions' (list of strings/dicts).
        """
        requirements = payload.get("requirements", [])
        similar_decisions = payload.get("similar_decisions", [])
        
        system_prompt = """
        1. Determine if this describes a NEW system or a CHANGE to an existing one.
        2. Assess risk conservatively. If financial or health data is involved, risk is HIGH.
        3. Identify the business domain.
        4. Return ONLY valid JSON.
        """
        
        req_summary = json.dumps(payload['requirements'], indent=2)
        
        user_prompt = f"""
        Requirements:
        {req_summary}
        """
        
        client = ArchestraClient()
        return await client.call_llm(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            json_schema=self.output_schema,
            temperature=0.0
        )
