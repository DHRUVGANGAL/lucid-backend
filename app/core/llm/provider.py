from abc import ABC, abstractmethod
from typing import Type, TypeVar, List, Dict, Any, Optional
from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)

class Message(BaseModel):
    role: str  # "system", "user", "assistant"
    content: str

class BaseLLMProvider(ABC):
    @abstractmethod
    async def generate(self, messages: List[Message], temperature: float = 0.7) -> str:
        """
        Generate a text completion for the given messages.
        """
        pass

    @abstractmethod
    async def generate_structured(
        self, 
        messages: List[Message], 
        response_model: Type[T],
        temperature: float = 0.2
    ) -> T:
        """
        Generate a structured response valid against the given Pydantic model.
        Uses JSON mode and validates the response.
        """
        pass
