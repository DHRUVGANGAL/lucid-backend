from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from pydantic import BaseModel

class BaseAgent(ABC):
    """
    Abstract base class for all Archestra agents.
    Defines the contract for agent execution.
    """
    
    def __init__(self):
        pass

    @property
    @abstractmethod
    def agent_name(self) -> str:
        """Unique name of the agent."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Description of what the agent does."""
        pass
    
    @property
    @abstractmethod
    def input_schema(self) -> Dict[str, Any]:
        """JSON schema for the input payload."""
        pass

    @property
    @abstractmethod
    def output_schema(self) -> Dict[str, Any]:
        """JSON schema for the output payload."""
        pass

    @abstractmethod
    async def run(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the agent logic.
        
        Args:
            payload: The input dictionary matching input_schema.
            
        Returns:
            The output dictionary matching output_schema.
        """
        pass
