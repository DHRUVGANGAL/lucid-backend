"""
Normalization Service - Extracts structured data from documents using LLM.
"""
from typing import Optional
import structlog

from app.services.normalization.models import NormalizedDocument
from app.services.normalization.prompts import (
    NORMALIZATION_SYSTEM_PROMPT,
    build_normalization_prompt,
)
from app.core.llm.client import LLMClient

logger = structlog.get_logger(__name__)


class NormalizationError(Exception):
    """Raised when document normalization fails."""
    pass


class NormalizationService:
    """
    Service for normalizing documents into structured data.
    
    Uses LLM to extract business intent, requirements, assumptions,
    constraints, and ambiguities from raw document text.
    """
    
    DEFAULT_TEMPERATURE = 0.1
    
    def __init__(
        self, 
        llm_client: Optional[LLMClient] = None,
        temperature: float = DEFAULT_TEMPERATURE,
    ):
        """
        Initialize the normalization service.
        
        Args:
            llm_client: Optional LLM client instance (uses singleton if not provided)
            temperature: LLM temperature for generation (lower = more deterministic)
        """
        self._llm_client = llm_client or LLMClient.get_instance()
        self._temperature = temperature
        self._logger = logger.bind(service="normalization")
    
    async def normalize(self, text: str) -> NormalizedDocument:
        """
        Normalize document text into structured data.
        
        Args:
            text: Raw document text to analyze
            
        Returns:
            NormalizedDocument with extracted structured data
            
        Raises:
            NormalizationError: If normalization fails and no fallback is available
        """
        if not text or not text.strip():
            self._logger.warning("Empty text provided for normalization")
            return self._create_empty_document()
        
        try:
            return await self._analyze_with_llm(text)
        except Exception as e:
            self._logger.error("LLM normalization failed", error=str(e))
            return self._create_fallback_document(text, error=e)
    
    async def _analyze_with_llm(self, text: str) -> NormalizedDocument:
        """
        Perform LLM-based document analysis.
        
        Args:
            text: Document text to analyze
            
        Returns:
            NormalizedDocument with LLM-extracted data
        """
        prompt = build_normalization_prompt(text)
        
        self._logger.info(
            "Starting LLM normalization",
            text_length=len(text),
            temperature=self._temperature,
        )
        
        result = await self._llm_client.generate_structured(
            prompt=prompt,
            response_model=NormalizedDocument,
            system_prompt=NORMALIZATION_SYSTEM_PROMPT,
            temperature=self._temperature,
        )
        
        self._logger.info(
            "Normalization complete",
            requirements_count=len(result.explicit_requirements),
            assumptions_count=len(result.assumptions),
            constraints_count=len(result.constraints),
            ambiguities_count=len(result.ambiguities),
        )
        
        return result
    
    def _create_empty_document(self) -> NormalizedDocument:
        """Create an empty normalized document for empty input."""
        return NormalizedDocument(
            business_intent="No content provided for analysis",
            explicit_requirements=[],
            assumptions=[],
            constraints=[],
            ambiguities=["Empty document - no analysis possible"],
        )
    
    def _create_fallback_document(
        self, 
        text: str, 
        error: Exception,
    ) -> NormalizedDocument:
        """
        Create a fallback document when LLM analysis fails.
        
        Args:
            text: Original document text
            error: The exception that caused the failure
            
        Returns:
            NormalizedDocument with error information
        """
        preview = text[:200] + "..." if len(text) > 200 else text
        
        return NormalizedDocument(
            business_intent=f"Document analysis failed: {str(error)}. Preview: {preview}",
            explicit_requirements=[],
            assumptions=[],
            constraints=[],
            ambiguities=["LLM analysis failed - manual review required"],
        )
