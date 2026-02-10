from fastapi import UploadFile
from app.services.parser.base import BaseParser

class TextParser(BaseParser):
    async def parse(self, file: UploadFile) -> str:
        content = await file.read()
        await file.seek(0)  # Reset cursor
        return content.decode("utf-8")
