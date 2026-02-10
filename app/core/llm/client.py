from typing import Type, TypeVar, Optional, List
from pydantic import BaseModel
from app.core.config import settings
from app.core.llm.provider import BaseLLMProvider, Message

T = TypeVar("T", bound=BaseModel)

class LLMClient:
    _instance: Optional["LLMClient"] = None
    provider: BaseLLMProvider

    def __init__(self):
        self.provider = self._get_provider()

    @classmethod
    def get_instance(cls) -> "LLMClient":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _get_provider(self) -> BaseLLMProvider:
        if settings.LLM_PROVIDER == "gemini":
            from app.core.llm.providers.gemini import GeminiProvider
            return GeminiProvider()
        elif settings.LLM_PROVIDER == "openai":
            # from app.core.llm.providers.openai import OpenAIProvider
            # return OpenAIProvider()
            raise NotImplementedError("OpenAI provider is currently commented out")
        elif settings.LLM_PROVIDER == "azure":
            # Future: from app.core.llm.providers.azure import AzureOpenAIProvider
            raise NotImplementedError("Azure provider not yet implemented")
        else:
            raise ValueError(f"Unknown LLM provider: {settings.LLM_PROVIDER}")

    async def generate(
        self, 
        prompt: str, 
        system_prompt: Optional[str] = None,
        temperature: float = 0.7
    ) -> str:
        messages = []
        if system_prompt:
            messages.append(Message(role="system", content=system_prompt))
        messages.append(Message(role="user", content=prompt))
        
        return await self.provider.generate(messages, temperature)

    async def generate_structured(
        self, 
        prompt: str, 
        response_model: Type[T],
        system_prompt: Optional[str] = None,
        temperature: float = 0.2
    ) -> T:
        messages = []
        if system_prompt:
            messages.append(Message(role="system", content=system_prompt))
        messages.append(Message(role="user", content=prompt))
        
        return await self.provider.generate_structured(messages, response_model, temperature)
