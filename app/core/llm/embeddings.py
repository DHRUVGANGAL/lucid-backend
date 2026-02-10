from typing import List
import structlog
import google.generativeai as genai
from app.core.config import settings

logger = structlog.get_logger(__name__)

# # OpenAI Implementation (commented out)
# from openai import AsyncOpenAI
# 
# class EmbeddingClient:
#     """
#     Client for generating embeddings using OpenAI.
#     Uses text-embedding-3-small model with 1536 dimensions.
#     """
#     
#     MODEL = "text-embedding-3-small"
#     DIMENSIONS = 1536
#     
#     _instance: "EmbeddingClient" = None
#     _client: AsyncOpenAI = None
#     
#     @classmethod
#     def get_instance(cls) -> "EmbeddingClient":
#         if cls._instance is None:
#             cls._instance = cls()
#         return cls._instance
#     
#     def __init__(self):
#         self._client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY)
#     
#     async def embed(self, text: str) -> List[float]:
#         response = await self._client.embeddings.create(
#             model=self.MODEL,
#             input=text,
#             dimensions=self.DIMENSIONS,
#         )
#         return response.data[0].embedding
#     
#     async def embed_batch(self, texts: List[str]) -> List[List[float]]:
#         response = await self._client.embeddings.create(
#             model=self.MODEL,
#             input=texts,
#             dimensions=self.DIMENSIONS,
#         )
#         return [item.embedding for item in response.data]


class EmbeddingClient:
    """
    Client for generating embeddings using Google Gemini.
    Uses text-embedding-004 model with 768 dimensions.
    """
    
    MODEL = "gemini-embedding-001"
    DIMENSIONS = 3072  # gemini-embedding-001 produces 3072 dimensions
    
    _instance: "EmbeddingClient" = None
    
    @classmethod
    def get_instance(cls) -> "EmbeddingClient":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance
    
    def __init__(self):
        genai.configure(api_key=settings.GEMINI_API_KEY)
    
    async def embed(self, text: str) -> List[float]:
        """
        Generate embedding for a single text string.
        
        Args:
            text: Input text to embed
            
        Returns:
            List of floats representing the embedding vector (768 dimensions)
        """
        # Note: genai.embed_content is synchronous, wrapping for async interface
        logger.info("Generating embedding", text_preview=text[:100] if len(text) > 100 else text)
        result = genai.embed_content(
            model=self.MODEL,
            content=text,
            task_type="retrieval_document"
        )
        logger.info("Generated embedding", dimensions=len(result['embedding']))
        return result['embedding']
    
    async def embed_batch(self, texts: List[str]) -> List[List[float]]:
        """
        Generate embeddings for multiple texts.
        
        Args:
            texts: List of input texts
            
        Returns:
            List of embedding vectors
        """
        embeddings = []
        for text in texts:
            logger.info("Generating batch embedding", text_preview=text[:50] if len(text) > 50 else text)
            result = genai.embed_content(
                model=self.MODEL,
                content=text,
                task_type="retrieval_document"
            )
            embeddings.append(result['embedding'])
        logger.info("Generated batch embeddings", count=len(embeddings))
        return embeddings
