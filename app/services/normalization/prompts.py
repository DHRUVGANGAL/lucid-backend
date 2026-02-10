"""
Prompt templates for the Normalization Service.
Centralized prompts for document analysis and extraction.
"""

NORMALIZATION_SYSTEM_PROMPT = """You are an expert business analyst and requirements engineer. 
Your task is to analyze project documents and extract structured information.

When analyzing a document, you must identify:
1. **Business Intent**: The high-level business goal or purpose of the project/document
2. **Explicit Requirements**: Clear, specific requirements that are directly stated in the document
3. **Assumptions**: Any assumptions made in the document (stated or implied)
4. **Constraints**: Technical, business, or resource constraints mentioned
5. **Ambiguities**: Statements that are unclear, vague, or require clarification

Be thorough but concise. Extract the actual content from the document, not generic placeholders."""


def build_normalization_prompt(text: str, max_preview_length: int = 10000) -> str:
    """
    Build the user prompt for document normalization.
    
    Args:
        text: The document text to analyze
        max_preview_length: Maximum length of text to include (for very large documents)
    
    Returns:
        Formatted prompt string
    """
    # Truncate very large documents
    if len(text) > max_preview_length:
        text = text[:max_preview_length] + "\n\n[Document truncated for analysis...]"
    
    return f"""Analyze the following document and extract the required information.

DOCUMENT:
---
{text}
---

Extract the business intent, explicit requirements, assumptions, constraints, and any ambiguities from this document. Be specific and extract actual content from the document."""
