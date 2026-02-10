from fastapi import UploadFile
import pypdf
import io
from app.services.parser.base import BaseParser

class PdfParser(BaseParser):
    async def parse(self, file: UploadFile) -> str:
        content = await file.read()
        await file.seek(0)
        
        pdf_reader = pypdf.PdfReader(io.BytesIO(content))
        full_text = []
        for page in pdf_reader.pages:
            full_text.append(page.extract_text())
            
        return "\n".join(full_text)
