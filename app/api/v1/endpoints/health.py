from fastapi import APIRouter
from app.core.config import settings

router = APIRouter()

@router.get("/health")
def health_check():
    return {
        "status": "ok",
        "project_name": settings.PROJECT_NAME,
        "debug": settings.DEBUG
    }
