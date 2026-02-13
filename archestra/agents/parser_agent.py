from typing import Dict, Any, List
from archestra.agents.base_agent import BaseAgent
from archestra.client import ArchestraClient

class ParserAgent(BaseAgent):
    """
    Extracts structured requirements from raw document text.
    """
    
    @property
    def agent_name(self) -> str:
        return "parser_agent"

    @property
    def description(self) -> str:
        return "Extracts structured functional and non-functional requirements from text documents."
    
    @property
    def input_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "document_text": {"type": "string"},
                "document_type": {"type": "string", "enum": ["BRD", "PRD", "ChangeRequest"]}
            },
            "required": ["document_text"]
        }

    @property
    def output_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "requirements": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "string"},
                            "description": {"type": "string"},
                            "type": {"type": "string", "enum": ["functional", "non-functional"]},
                            "priority": {"type": "string", "enum": ["high", "medium", "low"]}
                        },
                        "required": ["id", "description", "type", "priority"]
                    }
                }
            },
            "required": ["requirements"]
        }

    async def run(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        client = ArchestraClient()
        
        system_prompt = """
        You are an expert Business Analyst. Your task is to extract structured requirements from the provided document text.
        
        Rules:
        1. Extract INDIVIDUAL, ATOMIC requirements.
        2. Assign a unique ID (REQ-1, REQ-2, etc.) to each.
        3. Classify as 'functional' or 'non-functional'.
        4. Assign priority based on the text (default to medium if unsure).
        5. Do NOT hallucinate architecture or implementation details.
        6. Return ONLY valid JSON matching the schema.
        """
        
        user_prompt = f"""
        Document Type: {payload.get('document_type', 'unknown')}
        
        Document Text:
        {payload['document_text']}
        """
        
        return await client.call_llm(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            json_schema=self.output_schema,
            temperature=0.0
        )
