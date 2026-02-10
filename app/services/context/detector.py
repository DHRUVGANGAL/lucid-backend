from typing import Tuple
from pydantic import BaseModel, Field
from app.services.context.enums import ContextType
from app.core.llm.client import LLMClient
import structlog

logger = structlog.get_logger(__name__)

class ContextDetectionResult(BaseModel):
    context_type: str = Field(..., description="One of: initial_requirement, change_request, unknown")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score between 0 and 1")
    reasoning: str = Field(..., description="Brief explanation for the classification")

CONTEXT_DETECTION_SYSTEM = """You are an expert document classifier for software engineering contexts.
Your task is to classify whether a document represents:
1. **initial_requirement**: A new project, greenfield development, new feature specification, or original requirements document
2. **change_request**: A bug fix, enhancement, modification, refactoring, or update to existing functionality
3. **unknown**: Cannot be determined with reasonable confidence

Guidelines:
- Look for explicit signals (e.g., "bug fix", "new project", "existing system", "proposed feature")
- Consider implicit context (tone, references to existing code/systems)
- Be decisive - only use "unknown" when truly ambiguous
- Confidence should reflect your certainty: 0.9+ for clear cases, 0.7-0.9 for likely cases, <0.7 for uncertain"""

CONTEXT_DETECTION_USER = """Classify the following document text:

---
{text}
---

Determine if this is an initial_requirement, change_request, or unknown."""

class ContextDetector:
    INITIAL_KEYWORDS = {
        "overview", "introduction", "background", "scope", 
        "greenfield", "new project", "proposed system", "objective"
    }
    
    CHANGE_KEYWORDS = {
        "bug", "fix", "update", "change", "refactor", 
        "modify", "existing", "legacy", "enhancement", "patch"
    }

    async def detect(self, text: str) -> Tuple[ContextType, float]:
        """
        Detects the context type of the given text.
        Returns a tuple of (ContextType, confidence_score).
        """
        # First, try heuristic check
        context_type, confidence = self._heuristic_check(text)
        
        # If confidence is low, use LLM for better classification
        if confidence < 0.7:
            logger.info("Low confidence from heuristic check, using LLM for classification")
            context_type, confidence = await self._llm_check(text)
        
        return context_type, confidence

    def _heuristic_check(self, text: str) -> Tuple[ContextType, float]:
        text_lower = text.lower()
        
        initial_score = sum(1 for keyword in self.INITIAL_KEYWORDS if keyword in text_lower)
        change_score = sum(1 for keyword in self.CHANGE_KEYWORDS if keyword in text_lower)
        
        if initial_score == 0 and change_score == 0:
            return ContextType.UNKNOWN, 0.0
            
        total_matches = initial_score + change_score
        
        if initial_score > change_score:
            confidence = initial_score / total_matches if total_matches > 0 else 0.0
            return ContextType.INITIAL_REQUIREMENT, min(confidence + 0.5, 0.95)
        elif change_score > initial_score:
            confidence = change_score / total_matches if total_matches > 0 else 0.0
            return ContextType.CHANGE_REQUEST, min(confidence + 0.5, 0.95)
        else:
            return ContextType.UNKNOWN, 0.5

    async def _llm_check(self, text: str) -> Tuple[ContextType, float]:
        """
        LLM-based context detection with structured output.
        """
        client = LLMClient.get_instance()
        
        # Truncate text if too long to fit in context
        truncated_text = text[:4000] if len(text) > 4000 else text
        
        prompt = CONTEXT_DETECTION_USER.format(text=truncated_text)
        
        result = await client.generate_structured(
            prompt=prompt,
            response_model=ContextDetectionResult,
            system_prompt=CONTEXT_DETECTION_SYSTEM
        )
        
        # Map string result to enum
        type_mapping = {
            "initial_requirement": ContextType.INITIAL_REQUIREMENT,
            "change_request": ContextType.CHANGE_REQUEST,
            "unknown": ContextType.UNKNOWN
        }
        
        context_type = type_mapping.get(result.context_type.lower(), ContextType.UNKNOWN)
        
        return context_type, result.confidence
