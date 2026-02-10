from fastapi import APIRouter, Depends, HTTPException, status
from typing import Optional
from uuid import UUID
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db
from app.services.decision import (
    DecisionService,
    DecisionLockError,
    DecisionNotFoundError,
    DecisionStateError,
)


router = APIRouter()


class ApprovalRequest(BaseModel):
    approved_by: str
    notes: Optional[str] = None


class RejectionRequest(BaseModel):
    rejected_by: str
    reason: Optional[str] = None


class DecisionUpdateRequest(BaseModel):
    title: Optional[str] = None
    summary: Optional[str] = None
    estimated_hours: Optional[float] = None
    estimated_cost: Optional[float] = None
    timeline_weeks: Optional[int] = None


class DecisionStatusResponse(BaseModel):
    decision_id: str
    status: str
    is_locked: bool
    message: str


@router.get("/{decision_id}", status_code=status.HTTP_200_OK)
async def get_decision(
    decision_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get a decision by ID."""
    try:
        service = DecisionService(db)
        decision = await service.get_decision(decision_id)
        return {
            "id": str(decision.id),
            "project_id": str(decision.project_id),
            "title": decision.title,
            "status": decision.status.value,
            "is_locked": decision.status.value in {"approved", "implemented"},
            "risk_level": decision.risk_level.value if decision.risk_level else None,
            "estimated_hours": decision.estimated_hours,
            "created_at": decision.created_at.isoformat() if decision.created_at else None,
            "approved_at": decision.approved_at.isoformat() if decision.approved_at else None,
        }
    except DecisionNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post("/{decision_id}/submit", response_model=DecisionStatusResponse)
async def submit_for_review(
    decision_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """
    Submit a draft decision for review.
    
    Transition: DRAFT -> PENDING_REVIEW
    """
    try:
        service = DecisionService(db)
        await service.submit_for_review(decision_id)
        is_locked = await service.is_locked(decision_id)
        
        return DecisionStatusResponse(
            decision_id=str(decision_id),
            status="pending_review",
            is_locked=is_locked,
            message="Decision submitted for review"
        )
    except DecisionNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except DecisionStateError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/{decision_id}/approve", response_model=DecisionStatusResponse)
async def approve_decision(
    decision_id: UUID,
    request: ApprovalRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Approve a decision.
    
    Transition: DRAFT/PENDING_REVIEW -> APPROVED
    
    Once approved, the decision becomes LOCKED and cannot be modified.
    """
    try:
        service = DecisionService(db)
        await service.approve(
            decision_id=decision_id,
            approved_by=request.approved_by,
            notes=request.notes,
        )
        
        return DecisionStatusResponse(
            decision_id=str(decision_id),
            status="approved",
            is_locked=True,
            message=f"Decision approved by {request.approved_by}"
        )
    except DecisionNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except DecisionStateError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/{decision_id}/lock", response_model=DecisionStatusResponse)
async def lock_decision(
    decision_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """
    Lock a decision by marking it as IMPLEMENTED.
    
    Transition: APPROVED -> IMPLEMENTED
    
    Implemented decisions are fully immutable and serve as
    the source of truth for future change requests.
    """
    try:
        service = DecisionService(db)
        await service.lock(decision_id)
        
        return DecisionStatusResponse(
            decision_id=str(decision_id),
            status="implemented",
            is_locked=True,
            message="Decision locked and marked as implemented"
        )
    except DecisionNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except DecisionStateError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/{decision_id}/reject", response_model=DecisionStatusResponse)
async def reject_decision(
    decision_id: UUID,
    request: RejectionRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Reject a decision.
    
    Transition: DRAFT/PENDING_REVIEW -> REJECTED
    
    Cannot reject locked decisions.
    """
    try:
        service = DecisionService(db)
        await service.reject(
            decision_id=decision_id,
            rejected_by=request.rejected_by,
            reason=request.reason,
        )
        
        return DecisionStatusResponse(
            decision_id=str(decision_id),
            status="rejected",
            is_locked=False,
            message=f"Decision rejected by {request.rejected_by}"
        )
    except DecisionNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except DecisionLockError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except DecisionStateError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.patch("/{decision_id}", response_model=DecisionStatusResponse)
async def update_decision(
    decision_id: UUID,
    request: DecisionUpdateRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Update a decision.
    
    Only allowed for DRAFT decisions. Locked decisions cannot be modified.
    """
    try:
        service = DecisionService(db)
        
        updates = request.model_dump(exclude_unset=True)
        await service.update_decision(decision_id, **updates)
        
        decision = await service.get_decision(decision_id)
        
        return DecisionStatusResponse(
            decision_id=str(decision_id),
            status=decision.status.value,
            is_locked=await service.is_locked(decision_id),
            message="Decision updated successfully"
        )
    except DecisionNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except DecisionLockError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except DecisionStateError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/{decision_id}/status", response_model=DecisionStatusResponse)
async def get_decision_status(
    decision_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get the current status and lock state of a decision."""
    try:
        service = DecisionService(db)
        decision = await service.get_decision(decision_id)
        is_locked = await service.is_locked(decision_id)
        
        return DecisionStatusResponse(
            decision_id=str(decision_id),
            status=decision.status.value,
            is_locked=is_locked,
            message=f"Decision is {'locked' if is_locked else 'unlocked'}"
        )
    except DecisionNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
