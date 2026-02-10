import json
from typing import Type, TypeVar, List
from pydantic import BaseModel
import google.generativeai as genai

from app.core.config import settings
from app.core.llm.provider import BaseLLMProvider, Message

T = TypeVar("T", bound=BaseModel)

class GeminiProvider(BaseLLMProvider):
    def __init__(self):
        genai.configure(api_key=settings.GEMINI_API_KEY)
        self.model = genai.GenerativeModel(settings.GEMINI_MODEL)

    async def generate(self, messages: List[Message], temperature: float = 0.7) -> str:
        # Convert messages to Gemini format
        # Gemini uses 'user' and 'model' roles
        gemini_messages = []
        system_prompt = ""
        
        for m in messages:
            if m.role == "system":
                system_prompt = m.content
            elif m.role == "user":
                gemini_messages.append({"role": "user", "parts": [m.content]})
            elif m.role == "assistant":
                gemini_messages.append({"role": "model", "parts": [m.content]})
        
        # If there's a system prompt, prepend it to the first user message
        if system_prompt and gemini_messages:
            first_content = gemini_messages[0]["parts"][0]
            gemini_messages[0]["parts"][0] = f"{system_prompt}\n\n{first_content}"
        
        generation_config = genai.types.GenerationConfig(temperature=temperature)
        
        response = await self.model.generate_content_async(
            gemini_messages,
            generation_config=generation_config
        )
        return response.text or ""

    async def generate_structured(
        self, 
        messages: List[Message], 
        response_model: Type[T],
        temperature: float = 0.2
    ) -> T:
        # Build JSON schema from Pydantic model
        schema = response_model.model_json_schema()
        
        # Add schema instruction to the system message
        schema_instruction = f"""
You MUST respond with valid JSON that exactly matches this schema:
{json.dumps(schema, indent=2)}

Do not include any text before or after the JSON. Only output the raw JSON object.
"""
        
        # Prepend schema instruction
        enhanced_messages = [
            Message(role="system", content=schema_instruction)
        ] + messages
        
        # Convert messages to Gemini format
        gemini_messages = []
        system_prompt = ""
        
        for m in enhanced_messages:
            if m.role == "system":
                system_prompt = m.content if not system_prompt else system_prompt + "\n" + m.content
            elif m.role == "user":
                gemini_messages.append({"role": "user", "parts": [m.content]})
            elif m.role == "assistant":
                gemini_messages.append({"role": "model", "parts": [m.content]})
        
        # Prepend system prompt to first user message
        if system_prompt and gemini_messages:
            first_content = gemini_messages[0]["parts"][0]
            gemini_messages[0]["parts"][0] = f"{system_prompt}\n\n{first_content}"
        
        generation_config = genai.types.GenerationConfig(
            temperature=temperature,
            response_mime_type="application/json"
        )
        
        response = await self.model.generate_content_async(
            gemini_messages,
            generation_config=generation_config
        )
        
        content = response.text or "{}"
        
        # Parse and validate with Pydantic
        return response_model.model_validate_json(content)
