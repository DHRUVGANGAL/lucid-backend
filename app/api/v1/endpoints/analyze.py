from fastapi import APIRouter, Depends, Form, UploadFile, status, HTTPException
from typing import Optional
from uuid import UUID
from sqlalchemy.ext.asyncio import AsyncSession

from app.api import deps
from app.db import get_db
from app.services.orchestrator.service import DecisionOrchestrator

router = APIRouter()

@router.post("/analyze-file", status_code=status.HTTP_200_OK)
async def analyze_file(
    file: UploadFile = Depends(deps.validate_upload_file),
    project_id: Optional[str] = Form(None),
    project_name: Optional[str] = Form(None),
    db: AsyncSession = Depends(get_db),
):
    """
    Analyze an uploaded file and create a decision.
    
    Orchestrates the full analysis pipeline:
    1. Parsing & DB storage
    2. Context Detection
    3. Normalization & requirements extraction
    4. Architecture generation
    5. Rule Engine evaluation
    6. Agent Execution (Impact, Estimation, Explanation)
    7. Decision persistence
    8. Supermemory storage
    
    - **file**: Document to analyze (PDF, DOCX, TXT)
    - **project_id**: Optional existing project ID
    - **project_name**: Optional name for new project (used if project_id not provided)
    """
    try:
        # Parse UUID if provided
        parsed_project_id = UUID(project_id) if project_id else None
        
        orchestrator = DecisionOrchestrator(db)
        decision = await orchestrator.run(
            file=file,
            project_id=parsed_project_id,
            project_name=project_name,
        )
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid project_id format: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error analyzing file: {str(e)}"
        )
        
    return decision.model_dump()
