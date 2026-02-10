from typing import Optional
from uuid import UUID
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.repositories import DecisionRepository
from app.models.enums import DecisionStatus
from app.services.memory.supermemory import SupermemoryService


class DecisionLockError(Exception):
    """Raised when attempting to modify a locked decision."""
    pass


class DecisionNotFoundError(Exception):
    """Raised when decision is not found."""
    pass


class DecisionStateError(Exception):
    """Raised when decision is in invalid state for operation."""
    pass


class DecisionService:
    """
    Service for managing decision lifecycle and state transitions.
    
    State Machine:
    DRAFT -> PENDING_REVIEW -> APPROVED -> IMPLEMENTED (LOCKED)
                            -> REJECTED
    
    Rules:
    - DRAFT: Can be modified freely
    - PENDING_REVIEW: Can be approved or rejected
    - APPROVED: Cannot be modified, can be locked (implemented)
    - IMPLEMENTED: Fully locked, immutable
    - REJECTED: Terminal state
    """
    
    LOCKED_STATES = {DecisionStatus.APPROVED, DecisionStatus.IMPLEMENTED}
    TERMINAL_STATES = {DecisionStatus.IMPLEMENTED, DecisionStatus.REJECTED}
    
    def __init__(self, session: AsyncSession):
        self.session = session
        self._repo = DecisionRepository(session)
    
    async def get_decision(self, decision_id: UUID) -> dict:
        """Get decision by ID."""
        decision = await self._repo.get_by_id(decision_id)
        if not decision:
            raise DecisionNotFoundError(f"Decision {decision_id} not found")
        return decision
    
    async def is_locked(self, decision_id: UUID) -> bool:
        """Check if decision is locked (approved or implemented)."""
        decision = await self._repo.get_by_id(decision_id)
        if not decision:
            raise DecisionNotFoundError(f"Decision {decision_id} not found")
        return decision.status in self.LOCKED_STATES
    
    async def submit_for_review(self, decision_id: UUID) -> bool:
        """
        Submit a draft decision for review.
        
        Transition: DRAFT -> PENDING_REVIEW
        """
        decision = await self._repo.get_by_id(decision_id)
        if not decision:
            raise DecisionNotFoundError(f"Decision {decision_id} not found")
        
        if decision.status != DecisionStatus.DRAFT:
            raise DecisionStateError(
                f"Cannot submit for review: decision is {decision.status.value}, expected DRAFT"
            )
        
        await self._repo.update(
            decision_id=decision_id,
            status=DecisionStatus.PENDING_REVIEW
        )
        return True
    
    async def approve(
        self,
        decision_id: UUID,
        approved_by: str,
        notes: Optional[str] = None,
    ) -> bool:
        """
        Approve a decision.
        
        Transition: PENDING_REVIEW -> APPROVED
        
        Once approved, the decision becomes LOCKED and cannot be modified.
        """
        decision = await self._repo.get_by_id(decision_id)
        if not decision:
            raise DecisionNotFoundError(f"Decision {decision_id} not found")
        
        if decision.status not in {DecisionStatus.DRAFT, DecisionStatus.PENDING_REVIEW}:
            raise DecisionStateError(
                f"Cannot approve: decision is {decision.status.value}, expected DRAFT or PENDING_REVIEW"
            )
        
        await self._repo.update(
            decision_id=decision_id,
            status=DecisionStatus.APPROVED,
            approved_by=approved_by,
            approved_at=datetime.utcnow(),
        )
        
        # Update Supermemory with approval status
        try:
            memory = await SupermemoryService.get_instance()
            await memory.update(
                decision_id=decision_id,
                key_insights=[f"Approved by {approved_by}"],
            )
        except Exception:
            pass
        
        return True
    
    async def lock(self, decision_id: UUID) -> bool:
        """
        Lock a decision by marking it as IMPLEMENTED.
        
        Transition: APPROVED -> IMPLEMENTED
        
        Implemented decisions are fully immutable and serve as
        the source of truth for future change requests.
        """
        decision = await self._repo.get_by_id(decision_id)
        if not decision:
            raise DecisionNotFoundError(f"Decision {decision_id} not found")
        
        if decision.status != DecisionStatus.APPROVED:
            raise DecisionStateError(
                f"Cannot lock: decision is {decision.status.value}, expected APPROVED"
            )
        
        await self._repo.update(
            decision_id=decision_id,
            status=DecisionStatus.IMPLEMENTED,
        )
        
        # Create delivery outcome tracking
        await self._repo.create_outcome(decision_id=decision_id)
        
        return True
    
    async def reject(
        self,
        decision_id: UUID,
        rejected_by: str,
        reason: Optional[str] = None,
    ) -> bool:
        """
        Reject a decision.
        
        Transition: DRAFT/PENDING_REVIEW -> REJECTED
        """
        decision = await self._repo.get_by_id(decision_id)
        if not decision:
            raise DecisionNotFoundError(f"Decision {decision_id} not found")
        
        if decision.status in self.TERMINAL_STATES:
            raise DecisionStateError(
                f"Cannot reject: decision is in terminal state {decision.status.value}"
            )
        
        if decision.status in self.LOCKED_STATES:
            raise DecisionLockError(
                f"Cannot reject: decision is locked ({decision.status.value})"
            )
        
        await self._repo.update(
            decision_id=decision_id,
            status=DecisionStatus.REJECTED,
        )
        return True
    
    async def update_decision(
        self,
        decision_id: UUID,
        **updates
    ) -> bool:
        """
        Update a decision. Only allowed for DRAFT decisions.
        
        Locked decisions cannot be modified.
        """
        decision = await self._repo.get_by_id(decision_id)
        if not decision:
            raise DecisionNotFoundError(f"Decision {decision_id} not found")
        
        if decision.status in self.LOCKED_STATES:
            raise DecisionLockError(
                f"Cannot modify locked decision ({decision.status.value})"
            )
        
        if decision.status in self.TERMINAL_STATES:
            raise DecisionStateError(
                f"Cannot modify decision in terminal state ({decision.status.value})"
            )
        
        # Filter allowed fields
        allowed_fields = {
            'title', 'summary', 'requirements_spec', 'architecture_design',
            'impact_analysis', 'estimation', 'executive_summary',
            'estimated_hours', 'estimated_cost', 'timeline_weeks', 'risk_level'
        }
        filtered_updates = {k: v for k, v in updates.items() if k in allowed_fields}
        
        if filtered_updates:
            await self._repo.update(decision_id=decision_id, **filtered_updates)
        
        return True
    
    async def get_locked_decisions(self, project_id: UUID) -> list:
        """
        Get all locked decisions for a project.
        These are the source of truth for change requests.
        """
        decisions = await self._repo.get_by_project(project_id)
        return [d for d in decisions if d.status in self.LOCKED_STATES]
