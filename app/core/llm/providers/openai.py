# import json
# from typing import Type, TypeVar, List
# from pydantic import BaseModel
# from openai import AsyncOpenAI

# from app.core.config import settings
# from app.core.llm.provider import BaseLLMProvider, Message

# T = TypeVar("T", bound=BaseModel)

# class OpenAIProvider(BaseLLMProvider):
#     def __init__(self):
#         self.client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY)
#         self.model = settings.OPENAI_MODEL

#     async def generate(self, messages: List[Message], temperature: float = 0.7) -> str:
#         response = await self.client.chat.completions.create(
#             model=self.model,
#             messages=[{"role": m.role, "content": m.content} for m in messages],
#             temperature=temperature,
#         )
#         return response.choices[0].message.content or ""

#     async def generate_structured(
#         self, 
#         messages: List[Message], 
#         response_model: Type[T],
#         temperature: float = 0.2
#     ) -> T:
#         # Build JSON schema from Pydantic model
#         schema = response_model.model_json_schema()
        
#         # Add schema instruction to the system message
#         schema_instruction = f"""
# You MUST respond with valid JSON that exactly matches this schema:
# {json.dumps(schema, indent=2)}

# Do not include any text before or after the JSON. Only output the raw JSON object.
# """
        
#         # Prepend schema instruction
#         enhanced_messages = [
#             Message(role="system", content=schema_instruction)
#         ] + messages
        
#         response = await self.client.chat.completions.create(
#             model=self.model,
#             messages=[{"role": m.role, "content": m.content} for m in enhanced_messages],
#             temperature=temperature,
#             response_format={"type": "json_object"}
#         )
        
#         content = response.choices[0].message.content or "{}"
        
#         # Parse and validate with Pydantic
#         return response_model.model_validate_json(content)
