from typing import Dict, Type
from app.services.parser.base import BaseParser
from app.services.parser.strategies.txt import TextParser
from app.services.parser.strategies.docx import DocxParser
from app.services.parser.strategies.pdf import PdfParser

class ParserFactory:
    _parsers: Dict[str, Type[BaseParser]] = {
        "text/plain": TextParser,
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document": DocxParser,
        "application/pdf": PdfParser,
    }

    @classmethod
    def get_parser(cls, content_type: str) -> BaseParser:
        parser_class = cls._parsers.get(content_type)
        if not parser_class:
            raise ValueError(f"No parser found for content type: {content_type}")
        return parser_class()
