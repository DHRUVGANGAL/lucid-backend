from typing import Optional
from uuid import UUID
from datetime import datetime
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models import (
    Project,
    RequirementDocument,
    NormalizedRequirement,
    ArchitectureBaseline,
    Decision,
    DecisionStatus,
)
from app.services.context.models import (
    ProjectContext,
    DocumentSummary,
    RequirementSummary,
    ArchitectureSummary,
    DecisionSummary,
)


class MCPContextService:
    """
    MCP-style context service for fetching aggregated project context.
    
    Read-only service that provides a unified view of project state
    for use by the orchestrator and agents.
    """
    
    def __init__(self, session: AsyncSession):
        self.session = session
    
    async def get_project_context(self, project_id: UUID) -> Optional[ProjectContext]:
        """
        Fetch complete project context including:
        - Project metadata
        - All requirement documents with normalized requirements
        - Active architecture baseline
        - Locked (approved/implemented) decisions
        """
        # Fetch project with eager loading
        result = await self.session.execute(
            select(Project)
            .options(
                selectinload(Project.requirement_documents)
                .selectinload(RequirementDocument.normalized_requirements),
                selectinload(Project.architecture_baselines),
                selectinload(Project.decisions),
            )
            .where(Project.id == project_id)
        )
        project = result.scalar_one_or_none()
        
        if not project:
            return None
        
        # Build document summaries
        documents = []
        total_requirements = 0
        
        for doc in project.requirement_documents:
            req_summaries = [
                RequirementSummary(
                    id=req.requirement_id,
                    requirement_type=req.requirement_type,
                    description=req.description,
                    priority=req.priority,
                    category=req.category,
                )
                for req in doc.normalized_requirements
            ]
            total_requirements += len(req_summaries)
            
            documents.append(DocumentSummary(
                id=doc.id,
                filename=doc.filename,
                context_type=doc.context_type,
                confidence_score=doc.confidence_score,
                status=doc.status.value,
                created_at=doc.created_at,
                requirements=req_summaries,
            ))
        
        # Find active architecture baseline
        active_baseline = None
        for baseline in project.architecture_baselines:
            if baseline.is_active:
                active_baseline = ArchitectureSummary(
                    id=baseline.id,
                    version=baseline.version,
                    name=baseline.name,
                    description=baseline.description,
                    component_count=len(baseline.components or []),
                    data_model_count=len(baseline.data_models or []),
                    api_count=len(baseline.api_definitions or []),
                    is_active=baseline.is_active,
                )
                break
        
        # Get locked decisions (approved or implemented only)
        locked_statuses = {DecisionStatus.APPROVED, DecisionStatus.IMPLEMENTED}
        locked_decisions = [
            DecisionSummary(
                id=dec.id,
                title=dec.title,
                status=dec.status,
                risk_level=dec.risk_level,
                estimated_hours=dec.estimated_hours,
                approved_by=dec.approved_by,
                approved_at=dec.approved_at,
            )
            for dec in project.decisions
            if dec.status in locked_statuses
        ]
        
        approved_count = sum(1 for d in project.decisions if d.status == DecisionStatus.APPROVED)
        
        return ProjectContext(
            project_id=project.id,
            project_name=project.name,
            project_description=project.description,
            project_status=project.status,
            documents=documents,
            active_architecture=active_baseline,
            locked_decisions=locked_decisions,
            total_requirements=total_requirements,
            total_decisions=len(project.decisions),
            approved_decisions=approved_count,
            context_generated_at=datetime.utcnow(),
        )
    
    async def get_requirements_context(self, project_id: UUID) -> list[RequirementSummary]:
        """
        Fetch only the requirements for a project.
        Lighter weight than full context for requirement-focused operations.
        """
        result = await self.session.execute(
            select(NormalizedRequirement)
            .join(RequirementDocument)
            .where(RequirementDocument.project_id == project_id)
        )
        requirements = result.scalars().all()
        
        return [
            RequirementSummary(
                id=req.requirement_id,
                requirement_type=req.requirement_type,
                description=req.description,
                priority=req.priority,
                category=req.category,
            )
            for req in requirements
        ]
    
    async def get_architecture_context(self, project_id: UUID) -> Optional[ArchitectureSummary]:
        """
        Fetch only the active architecture baseline for a project.
        """
        result = await self.session.execute(
            select(ArchitectureBaseline)
            .where(
                ArchitectureBaseline.project_id == project_id,
                ArchitectureBaseline.is_active == True
            )
            .order_by(ArchitectureBaseline.version.desc())
            .limit(1)
        )
        baseline = result.scalars().first()
        
        if not baseline:
            return None
        
        return ArchitectureSummary(
            id=baseline.id,
            version=baseline.version,
            name=baseline.name,
            description=baseline.description,
            component_count=len(baseline.components or []),
            data_model_count=len(baseline.data_models or []),
            api_count=len(baseline.api_definitions or []),
            is_active=baseline.is_active,
        )
