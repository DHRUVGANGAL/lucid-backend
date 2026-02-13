from typing import Dict, Any
from archestra.agents.base_agent import BaseAgent
from archestra.client import ArchestraClient
import json

class ArchitectureAgent(BaseAgent):
    """
    Generates high-level architecture recommendations based on requirements and context.
    """
    
    @property
    def agent_name(self) -> str:
        return "architecture_agent"

    @property
    def description(self) -> str:
        return "Proposes high-level system architecture, components, and data stores."
    
    @property
    def input_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "requirements": {"type": "object"},
                "context": {"type": "object"}
            },
            "required": ["requirements", "context"]
        }

    @property
    def output_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "architecture": {
                    "type": "object",
                    "properties": {
                        "components": {"type": "array", "items": {"type": "string"}},
                        "services": {"type": "array", "items": {"type": "string"}},
                        "datastores": {"type": "array", "items": {"type": "string"}},
                        "external_dependencies": {"type": "array", "items": {"type": "string"}}
                    },
                    "required": ["components", "services", "datastores", "external_dependencies"]
                },
                "assumptions": {"type": "array", "items": {"type": "string"}}
            },
            "required": ["architecture", "assumptions"]
        }

    async def run(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        client = ArchestraClient()
        
        system_prompt = """
        You are a Senior System Architect. Design a high-level architecture for the system.
        
        Rules:
        1. Focus on COMPONENTS, SERVICES, and DATASTORES.
        2. NO CODE.
        3. NO specific vendor lock-in (e.g. say "Relational Database" instead of "AWS RDS").
        4. List explicit assumptions embedded in your design.
        5. Build for scalability and maintainability.
        6. Return ONLY valid JSON.
        """
        
        req_summary = json.dumps(payload['requirements'], indent=2)
        ctx_summary = json.dumps(payload['context'], indent=2)
        
        user_prompt = f"""
        Requirements:
        {req_summary}
        
        Context:
        {ctx_summary}
        """
        
        return await client.call_llm(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            json_schema=self.output_schema,
            temperature=0.2
        )
