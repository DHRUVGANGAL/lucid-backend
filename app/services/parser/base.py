from abc import ABC, abstractmethod
from fastapi import UploadFile

class BaseParser(ABC):
    @abstractmethod
    async def parse(self, file: UploadFile) -> str:
        """
        Parse the upload file and extract text.
        """
        pass
