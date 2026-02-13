from typing import Dict, Any, List
from archestra.agents.base_agent import BaseAgent
from archestra.client import ArchestraClient
import json

class ExplanationAgent(BaseAgent):
    """
    Generates a human-readable executive summary.
    """
    
    @property
    def agent_name(self) -> str:
        return "explanation_agent"

    @property
    def description(self) -> str:
        return "Synthesizes technical details into a clear executive summary."
    
    @property
    def input_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "requirements": {"type": "object"},
                "architecture": {"type": "object"},
                "impact": {"type": "object"},
                "estimation": {"type": "object"}
            },
            "required": ["requirements", "architecture", "impact", "estimation"]
        }

    @property
    def output_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "summary": {"type": "string"},
                "key_decisions": {"type": "array", "items": {"type": "string"}},
                "risks": {"type": "array", "items": {"type": "string"}}
            },
            "required": ["summary", "key_decisions", "risks"]
        }

    async def run(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        client = ArchestraClient()
        
        system_prompt = """
        You are a CTO writing an executive summary for stakeholders.
        
        Rules:
        1. Write in CLEAR English. NO jargon unless necessary.
        2. NO EMOJIS.
        3. 'summary' should be a concise paragraph explaining WHAT is being built and WHY.
        4. Highlight 'key_decisions' made in the architecture.
        5. Summarize 'risks' from the impact and estimation.
        6. Return ONLY valid JSON.
        """
        
        # Serialize inputs
        req_summary = json.dumps(payload['requirements'], indent=2)
        arch_summary = json.dumps(payload['architecture'], indent=2)
        imp_summary = json.dumps(payload['impact'], indent=2)
        est_summary = json.dumps(payload['estimation'], indent=2)
        
        user_prompt = f"""
        Requirements context:
        {req_summary}
        
        Architecture context:
        {arch_summary}
        
        Impact context:
        {imp_summary}
        
        Estimation context:
        {est_summary}
        """
        
        return await client.call_llm(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            json_schema=self.output_schema,
            temperature=0.3
        )
