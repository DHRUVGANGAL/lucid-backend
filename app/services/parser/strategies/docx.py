from fastapi import UploadFile
import docx
import io
from app.services.parser.base import BaseParser

class DocxParser(BaseParser):
    async def parse(self, file: UploadFile) -> str:
        content = await file.read()
        await file.seek(0)
        
        doc = docx.Document(io.BytesIO(content))
        full_text = []
        for para in doc.paragraphs:
            full_text.append(para.text)
            
        return "\n".join(full_text)
