from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List, Optional

class Settings(BaseSettings):
    PROJECT_NAME: str = "Lucid"
    API_V1_STR: str = "/api/v1"
    BACKEND_CORS_ORIGINS: List[str] = ["https://frontend-lucid-sigma.vercel.app", "http://localhost:5173"]
    DEBUG: bool = False
    
    # LLM Configuration
    LLM_PROVIDER: str = "gemini"
    # OPENAI_API_KEY: str = ""
    # OPENAI_MODEL: str = "gpt-4o"
    GEMINI_API_KEY: str = ""
    GEMINI_MODEL: str = "gemini-3-flash-preview"
    
    # Database Configuration
    DATABASE_URL: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/lucid"
    DATABASE_ECHO: bool = False
    
    # Qdrant Configuration (Cloud)
    # QDRANT_HOST: str = "localhost"
    # QDRANT_PORT: int = 6333
    QDRANT_URL: str = "http://localhost:6333"
    QDRANT_API_KEY: Optional[str] = None
    QDRANT_COLLECTION: str = "supermemory"
    
    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=True,
        env_file_encoding="utf-8"
    )

settings = Settings()
