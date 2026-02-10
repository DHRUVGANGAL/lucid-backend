from typing import Optional, List
from uuid import UUID
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.db.repositories import (
    ProjectRepository,
    RequirementRepository,
    ArchitectureRepository,
    DecisionRepository,
)
from app.models.enums import (
    ContextType,
    DocumentStatus,
    DecisionStatus,
    DeliveryStatus,
    RiskLevel,
)

logger = get_logger(__name__)


class MCPWriteService:
    """
    MCP-style write service for persisting project data.
    
    All writes go through repositories for consistency.
    No direct ORM usage - explicit, auditable operations only.
    """
    
    def __init__(self, session: AsyncSession):
        self.session = session
        self._project_repo = ProjectRepository(session)
        self._requirement_repo = RequirementRepository(session)
        self._architecture_repo = ArchitectureRepository(session)
        self._decision_repo = DecisionRepository(session)
    
    # =====================
    # Project Operations
    # =====================
    
    async def create_project(
        self,
        name: str,
        description: Optional[str] = None
    ) -> UUID:
        """Create a new project and return its ID."""
        project = await self._project_repo.create(name=name, description=description)
        return project.id
    
    # =====================
    # Document Operations
    # =====================
    
    async def persist_requirement_document(
        self,
        project_id: UUID,
        filename: str,
        content_type: str,
        raw_text: str,
        context_type: ContextType = ContextType.UNKNOWN,
        confidence_score: float = 0.0,
        normalized_data: Optional[dict] = None,
    ) -> UUID:
        """
        Persist a new requirement document.
        Returns the document ID.
        """
        doc = await self._requirement_repo.create_document(
            project_id=project_id,
            filename=filename,
            content_type=content_type,
            raw_text=raw_text,
        )
        
        # Update with analysis results
        await self._requirement_repo.update_document(
            document_id=doc.id,
            context_type=context_type,
            confidence_score=confidence_score,
            normalized_data=normalized_data,
            status=DocumentStatus.ANALYZED,
        )
        
        return doc.id
    
    async def persist_normalized_requirements(
        self,
        document_id: UUID,
        requirements: List[dict],
    ) -> List[UUID]:
        """
        Persist normalized requirements for a document.
        
        Each requirement dict should have:
        - requirement_id: str (e.g., "FR-001")
        - requirement_type: str ("functional" or "non_functional")
        - description: str
        - priority: Optional[str]
        - category: Optional[str]
        """
        ids = []
        for req in requirements:
            normalized_req = await self._requirement_repo.create_normalized_requirement(
                document_id=document_id,
                requirement_id=req["requirement_id"],
                requirement_type=req["requirement_type"],
                description=req["description"],
                priority=req.get("priority"),
                category=req.get("category"),
            )
            ids.append(normalized_req.id)
        return ids
    
    # =====================
    # Architecture Operations
    # =====================
    
    async def persist_architecture_baseline(
        self,
        project_id: UUID,
        name: str,
        components: Optional[list] = None,
        data_models: Optional[list] = None,
        api_definitions: Optional[list] = None,
        description: Optional[str] = None,
        set_active: bool = True,
    ) -> UUID:
        """
        Persist a new architecture baseline.
        Automatically versions based on existing baselines.
        """
        # Get existing baselines to determine version
        existing = await self._architecture_repo.get_all_by_project(project_id)
        next_version = 1 if not existing else existing[0].version + 1
        
        # Deactivate old baselines if setting new one as active
        if set_active:
            await self._architecture_repo.deactivate_all(project_id)
        
        baseline = await self._architecture_repo.create(
            project_id=project_id,
            name=name,
            version=next_version,
            description=description,
            components=components,
            data_models=data_models,
            api_definitions=api_definitions,
        )
        
        return baseline.id
    
    # =====================
    # Decision Operations
    # =====================
    
    async def persist_decision(
        self,
        project_id: UUID,
        title: str,
        requirement_document_id: Optional[UUID] = None,
        architecture_baseline_id: Optional[UUID] = None,
        risk_level: RiskLevel = RiskLevel.MEDIUM,
        requirements_spec: Optional[dict] = None,
        architecture_design: Optional[dict] = None,
        impact_analysis: Optional[dict] = None,
        estimation: Optional[dict] = None,
        rule_results: Optional[dict] = None,
        executive_summary: Optional[dict] = None,
        estimated_hours: Optional[float] = None,
        estimated_cost: Optional[str] = None,
        timeline_weeks: Optional[float] = None,
    ) -> UUID:
        """
        Persist a new decision in DRAFT status.
        """
        logger.info(
            "decision_create_started",
            project_id=str(project_id),
            title=title,
            risk_level=risk_level.value,
        )
        
        decision = await self._decision_repo.create(
            project_id=project_id,
            title=title,
            requirement_document_id=requirement_document_id,
            architecture_baseline_id=architecture_baseline_id,
        )
        
        # Update with analysis data
        await self._decision_repo.update(
            decision_id=decision.id,
            risk_level=risk_level,
            requirements_spec=requirements_spec,
            architecture_design=architecture_design,
            impact_analysis=impact_analysis,
            estimation=estimation,
            rule_results=rule_results,
            executive_summary=executive_summary,
            estimated_hours=estimated_hours,
            estimated_cost=estimated_cost,
            timeline_weeks=timeline_weeks,
            status=DecisionStatus.DRAFT,
        )
        
        logger.info(
            "decision_created",
            decision_id=str(decision.id),
            project_id=str(project_id),
            status="draft",
        )
        
        return decision.id
    
    async def approve_decision(
        self,
        decision_id: UUID,
        approved_by: str,
    ) -> bool:
        """
        Move decision from DRAFT/PENDING_REVIEW to APPROVED.
        """
        logger.info(
            "decision_approval_started",
            decision_id=str(decision_id),
            approved_by=approved_by,
        )
        
        decision = await self._decision_repo.update(
            decision_id=decision_id,
            status=DecisionStatus.APPROVED,
            approved_by=approved_by,
            approved_at=datetime.utcnow(),
        )
        
        logger.info(
            "decision_approved",
            decision_id=str(decision_id),
            approved_by=approved_by,
            status="approved",
        )
        
        return decision is not None
    
    async def lock_decision(
        self,
        decision_id: UUID,
    ) -> bool:
        """
        Move decision from APPROVED to IMPLEMENTED (locked).
        """
        logger.info("decision_lock_started", decision_id=str(decision_id))
        
        decision = await self._decision_repo.update(
            decision_id=decision_id,
            status=DecisionStatus.IMPLEMENTED,
        )
        
        logger.info(
            "decision_locked",
            decision_id=str(decision_id),
            status="implemented",
        )
        
        return decision is not None
    
    async def reject_decision(
        self,
        decision_id: UUID,
    ) -> bool:
        """
        Reject a decision.
        """
        logger.info("decision_rejection_started", decision_id=str(decision_id))
        
        decision = await self._decision_repo.update(
            decision_id=decision_id,
            status=DecisionStatus.REJECTED,
        )
        
        logger.info(
            "decision_rejected",
            decision_id=str(decision_id),
            status="rejected",
        )
        
        return decision is not None
    
    # =====================
    # Delivery Outcome Operations
    # =====================
    
    async def persist_delivery_outcome(
        self,
        decision_id: UUID,
        status: DeliveryStatus = DeliveryStatus.NOT_STARTED,
        actual_hours: Optional[float] = None,
        actual_cost: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> UUID:
        """
        Create or update delivery outcome for a decision.
        """
        outcome = await self._decision_repo.create_outcome(decision_id=decision_id)
        
        await self._decision_repo.update_outcome(
            decision_id=decision_id,
            status=status,
            actual_hours=actual_hours,
            actual_cost=actual_cost,
            notes=notes,
        )
        
        return outcome.id
    
    async def complete_delivery(
        self,
        decision_id: UUID,
        actual_hours: float,
        actual_cost: Optional[str] = None,
        quality_score: Optional[float] = None,
        feedback: Optional[dict] = None,
    ) -> bool:
        """
        Mark delivery as completed with actual metrics.
        Calculates variance from estimation.
        """
        # Get decision to calculate variance
        decision = await self._decision_repo.get_by_id(decision_id)
        if not decision:
            return False
        
        variance = None
        if decision.estimated_hours and decision.estimated_hours > 0:
            variance = ((actual_hours - decision.estimated_hours) / decision.estimated_hours) * 100
        
        await self._decision_repo.update_outcome(
            decision_id=decision_id,
            status=DeliveryStatus.COMPLETED,
            actual_hours=actual_hours,
            actual_cost=actual_cost,
            quality_score=quality_score,
            variance_percentage=variance,
            feedback=feedback,
            completed_at=datetime.utcnow(),
        )
        
        return True
