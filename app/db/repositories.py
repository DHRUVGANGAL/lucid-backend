from typing import List, Optional
from uuid import UUID
from sqlalchemy import select, update, delete
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models import (
    Project,
    RequirementDocument,
    NormalizedRequirement,
    ArchitectureBaseline,
    Decision,
    DeliveryOutcome,
)


class BaseRepository:
    """Base repository with common CRUD operations."""
    
    def __init__(self, session: AsyncSession):
        self.session = session


class ProjectRepository(BaseRepository):
    """Repository for Project aggregate root."""
    
    async def create(self, name: str, description: Optional[str] = None) -> Project:
        project = Project(name=name, description=description)
        self.session.add(project)
        await self.session.flush()
        return project
    
    async def get_by_id(self, project_id: UUID) -> Optional[Project]:
        result = await self.session.execute(
            select(Project).where(Project.id == project_id)
        )
        return result.scalar_one_or_none()
    
    async def get_by_id_with_relations(self, project_id: UUID) -> Optional[Project]:
        result = await self.session.execute(
            select(Project)
            .options(
                selectinload(Project.requirement_documents),
                selectinload(Project.decisions),
            )
            .where(Project.id == project_id)
        )
        return result.scalar_one_or_none()
    
    async def get_all(self, skip: int = 0, limit: int = 100) -> List[Project]:
        result = await self.session.execute(
            select(Project).offset(skip).limit(limit)
        )
        return list(result.scalars().all())
    
    async def update(self, project_id: UUID, **kwargs) -> Optional[Project]:
        await self.session.execute(
            update(Project).where(Project.id == project_id).values(**kwargs)
        )
        return await self.get_by_id(project_id)
    
    async def delete(self, project_id: UUID) -> bool:
        result = await self.session.execute(
            delete(Project).where(Project.id == project_id)
        )
        return result.rowcount > 0


class RequirementRepository(BaseRepository):
    """Repository for RequirementDocument aggregate root."""
    
    async def create_document(
        self,
        project_id: UUID,
        filename: str,
        content_type: str,
        raw_text: str,
    ) -> RequirementDocument:
        doc = RequirementDocument(
            project_id=project_id,
            filename=filename,
            content_type=content_type,
            raw_text=raw_text,
        )
        self.session.add(doc)
        await self.session.flush()
        return doc
    
    async def get_document_by_id(self, document_id: UUID) -> Optional[RequirementDocument]:
        result = await self.session.execute(
            select(RequirementDocument).where(RequirementDocument.id == document_id)
        )
        return result.scalar_one_or_none()
    
    async def get_documents_by_project(self, project_id: UUID) -> List[RequirementDocument]:
        result = await self.session.execute(
            select(RequirementDocument).where(RequirementDocument.project_id == project_id)
        )
        return list(result.scalars().all())
    
    async def update_document(self, document_id: UUID, **kwargs) -> Optional[RequirementDocument]:
        await self.session.execute(
            update(RequirementDocument)
            .where(RequirementDocument.id == document_id)
            .values(**kwargs)
        )
        return await self.get_document_by_id(document_id)
    
    async def delete_document(self, document_id: UUID) -> bool:
        result = await self.session.execute(
            delete(RequirementDocument).where(RequirementDocument.id == document_id)
        )
        return result.rowcount > 0
    
    # Normalized Requirements
    async def create_normalized_requirement(
        self,
        document_id: UUID,
        requirement_id: str,
        requirement_type: str,
        description: str,
        priority: Optional[str] = None,
        category: Optional[str] = None,
    ) -> NormalizedRequirement:
        req = NormalizedRequirement(
            document_id=document_id,
            requirement_id=requirement_id,
            requirement_type=requirement_type,
            description=description,
            priority=priority,
            category=category,
        )
        self.session.add(req)
        await self.session.flush()
        return req
    
    async def get_requirements_by_document(self, document_id: UUID) -> List[NormalizedRequirement]:
        result = await self.session.execute(
            select(NormalizedRequirement)
            .where(NormalizedRequirement.document_id == document_id)
        )
        return list(result.scalars().all())


class ArchitectureRepository(BaseRepository):
    """Repository for ArchitectureBaseline aggregate root."""
    
    async def create(
        self,
        project_id: UUID,
        name: str,
        version: int = 1,
        description: Optional[str] = None,
        components: Optional[list] = None,
        data_models: Optional[list] = None,
        api_definitions: Optional[list] = None,
    ) -> ArchitectureBaseline:
        baseline = ArchitectureBaseline(
            project_id=project_id,
            name=name,
            version=version,
            description=description,
            components=components,
            data_models=data_models,
            api_definitions=api_definitions,
        )
        self.session.add(baseline)
        await self.session.flush()
        return baseline
    
    async def get_by_id(self, baseline_id: UUID) -> Optional[ArchitectureBaseline]:
        result = await self.session.execute(
            select(ArchitectureBaseline).where(ArchitectureBaseline.id == baseline_id)
        )
        return result.scalar_one_or_none()
    
    async def get_active_by_project(self, project_id: UUID) -> Optional[ArchitectureBaseline]:
        """Get the active baseline for a project.
        Returns the most recently created active baseline if multiple exist (handles legacy data).
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
        return result.scalars().first()
    
    async def get_all_by_project(self, project_id: UUID) -> List[ArchitectureBaseline]:
        result = await self.session.execute(
            select(ArchitectureBaseline)
            .where(ArchitectureBaseline.project_id == project_id)
            .order_by(ArchitectureBaseline.version.desc())
        )
        return list(result.scalars().all())
    
    async def update(self, baseline_id: UUID, **kwargs) -> Optional[ArchitectureBaseline]:
        await self.session.execute(
            update(ArchitectureBaseline)
            .where(ArchitectureBaseline.id == baseline_id)
            .values(**kwargs)
        )
        return await self.get_by_id(baseline_id)
    
    async def deactivate_all(self, project_id: UUID) -> None:
        """Deactivate all baselines for a project before setting a new active one."""
        await self.session.execute(
            update(ArchitectureBaseline)
            .where(ArchitectureBaseline.project_id == project_id)
            .values(is_active=False)
        )
    
    async def delete(self, baseline_id: UUID) -> bool:
        result = await self.session.execute(
            delete(ArchitectureBaseline).where(ArchitectureBaseline.id == baseline_id)
        )
        return result.rowcount > 0

class DecisionRepository(BaseRepository):
    """Repository for Decision aggregate root."""
    
    async def create(
        self,
        project_id: UUID,
        title: str,
        requirement_document_id: Optional[UUID] = None,
        architecture_baseline_id: Optional[UUID] = None,
    ) -> Decision:
        decision = Decision(
            project_id=project_id,
            title=title,
            requirement_document_id=requirement_document_id,
            architecture_baseline_id=architecture_baseline_id,
        )
        self.session.add(decision)
        await self.session.flush()
        return decision
    
    async def get_by_id(self, decision_id: UUID) -> Optional[Decision]:
        result = await self.session.execute(
            select(Decision).where(Decision.id == decision_id)
        )
        return result.scalar_one_or_none()
    
    async def get_by_id_with_outcome(self, decision_id: UUID) -> Optional[Decision]:
        result = await self.session.execute(
            select(Decision)
            .options(selectinload(Decision.delivery_outcome))
            .where(Decision.id == decision_id)
        )
        return result.scalar_one_or_none()
    
    async def get_by_project(self, project_id: UUID) -> List[Decision]:
        result = await self.session.execute(
            select(Decision).where(Decision.project_id == project_id)
        )
        return list(result.scalars().all())
    
    async def update(self, decision_id: UUID, **kwargs) -> Optional[Decision]:
        await self.session.execute(
            update(Decision).where(Decision.id == decision_id).values(**kwargs)
        )
        return await self.get_by_id(decision_id)
    
    async def delete(self, decision_id: UUID) -> bool:
        result = await self.session.execute(
            delete(Decision).where(Decision.id == decision_id)
        )
        return result.rowcount > 0
    
    # Delivery Outcome
    async def create_outcome(self, decision_id: UUID) -> DeliveryOutcome:
        outcome = DeliveryOutcome(decision_id=decision_id)
        self.session.add(outcome)
        await self.session.flush()
        return outcome
    
    async def update_outcome(self, decision_id: UUID, **kwargs) -> Optional[DeliveryOutcome]:
        await self.session.execute(
            update(DeliveryOutcome)
            .where(DeliveryOutcome.decision_id == decision_id)
            .values(**kwargs)
        )
        result = await self.session.execute(
            select(DeliveryOutcome).where(DeliveryOutcome.decision_id == decision_id)
        )
        return result.scalar_one_or_none()
