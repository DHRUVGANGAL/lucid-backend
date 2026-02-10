"""
Database initialization script.
Creates all tables defined in the ORM models.
"""
import asyncio
from app.db.session import engine
from app.db.base import Base

# Import all models to register them with Base
from app.models import (
    Project,
    RequirementDocument,
    NormalizedRequirement,
    ArchitectureBaseline,
    Decision,
    DeliveryOutcome,
)


async def init_db():
    """Create all tables."""
    async with engine.begin() as conn:
        # Create all tables
        await conn.run_sync(Base.metadata.create_all)
    print("✓ Database tables created successfully!")


async def drop_db():
    """Drop all tables (use with caution)."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    print("✓ Database tables dropped!")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "drop":
        asyncio.run(drop_db())
    else:
        asyncio.run(init_db())
