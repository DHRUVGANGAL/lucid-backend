from abc import ABC, abstractmethod
from typing import Generic, TypeVar

InputType = TypeVar("InputType")
OutputType = TypeVar("OutputType")

class BaseAgent(ABC, Generic[InputType, OutputType]):
    @abstractmethod
    def process(self, input_data: InputType) -> OutputType:
        """
        Process the input data and return the structured output.
        """
        pass
