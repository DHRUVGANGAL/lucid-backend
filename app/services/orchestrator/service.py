from fastapi import UploadFile
from typing import Optional, List
from uuid import UUID
from dataclasses import asdict
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.parser.factory import ParserFactory
from app.services.context.detector import ContextDetector
from app.services.context.mcp_context import MCPContextService
from app.services.context.mcp_writer import MCPWriteService
from app.services.normalization.service import NormalizationService
from app.services.rules.engine import RuleEngine
from app.services.rules.default_rules import DEFAULT_RULES
from app.services.rules.models import AnalysisContext
from app.services.memory.supermemory import SupermemoryService

from app.agents.requirement import RequirementAgent
from app.agents.architecture import ArchitectureAgent
from app.agents.impact import ImpactDiffAgent
from app.agents.estimation import EstimationAgent, EstimationInput
from app.agents.explanation import ExplanationAgent, ExplanationInput

from app.services.orchestrator.models import Decision
from app.models.enums import ContextType, RiskLevel


class DecisionOrchestrator:
    """
    Orchestrates the full decision pipeline from file upload to decision creation.
    
    Supports two flows:
    - INITIAL_REQUIREMENT: Creates new project, baseline, and decision
    - CHANGE_REQUEST: Uses existing context, creates additive changes
    
    Uses:
    - Repository layer for all DB operations (via MCPWriteService)
    - MCP context services for reads
    - Supermemory for semantic storage
    
    No direct ORM access. No controller logic.
    """
    
    def __init__(self, session: AsyncSession):
        self.session = session
        self._writer = MCPWriteService(session)
        self._reader = MCPContextService(session)
    
    async def run(
        self,
        file: UploadFile,
        project_id: Optional[UUID] = None,
        project_name: Optional[str] = None,
    ) -> Decision:
        """
        Execute the full decision pipeline.
        Routes to appropriate flow based on context type.
        """
        # Parse file
        parser = ParserFactory.get_parser(file.content_type)
        extracted_text = await parser.parse(file)
        filename = file.filename or "untitled"
        content_type = file.content_type or "text/plain"
        
        # Detect context
        detector = ContextDetector()
        context_type, confidence = await detector.detect(extracted_text)
        
        # Route to appropriate flow
        if context_type == ContextType.CHANGE_REQUEST and project_id is not None:
            return await self._run_change_request_flow(
                extracted_text=extracted_text,
                filename=filename,
                content_type=content_type,
                project_id=project_id,
                context_type=context_type,
                confidence=confidence,
            )
        else:
            return await self._run_initial_requirement_flow(
                extracted_text=extracted_text,
                filename=filename,
                content_type=content_type,
                project_id=project_id,
                project_name=project_name,
                context_type=context_type,
                confidence=confidence,
            )
    
    async def _run_initial_requirement_flow(
        self,
        extracted_text: str,
        filename: str,
        content_type: str,
        project_id: Optional[UUID],
        project_name: Optional[str],
        context_type: ContextType,
        confidence: float,
    ) -> Decision:
        """
        Handle INITIAL_REQUIREMENT flow.
        Creates new project (if needed), baseline, and decision.
        """
        # Create project if not provided
        if project_id is None:
            effective_name = project_name or f"Project from {filename}"
            project_id = await self._writer.create_project(
                name=effective_name,
                description=f"Auto-created from document: {filename}"
            )
        
        # Store document
        document_id = await self._writer.persist_requirement_document(
            project_id=project_id,
            filename=filename,
            content_type=content_type,
            raw_text=extracted_text,
            context_type=context_type,
            confidence_score=confidence,
        )
        
        # Normalize
        normalizer = NormalizationService()
        normalized_doc = await normalizer.normalize(extracted_text)
        
        # Apply rules
        context = AnalysisContext(context_type=context_type, normalized_doc=normalized_doc)
        engine = RuleEngine(DEFAULT_RULES)
        rule_results = engine.evaluate(context)
        risk_level = self._map_risk_level(rule_results.risk_level)
        
        # Run agents
        req_agent = RequirementAgent()
        requirements = await req_agent.process(normalized_doc)
        
        # Persist requirements
        await self._persist_requirements(document_id, requirements)
        
        # Architecture
        arch_agent = ArchitectureAgent()
        architecture = await arch_agent.process(requirements)
        
        # Persist NEW baseline (initial = set active)
        baseline_id = await self._persist_architecture(
            project_id, filename, architecture, set_active=True
        )
        
        # Impact, Estimation, Explanation
        impact_agent = ImpactDiffAgent()
        impact = await impact_agent.process(architecture)
        
        est_agent = EstimationAgent()
        estimation = await est_agent.process(EstimationInput(impact=impact, rules=rule_results))
        
        expl_agent = ExplanationAgent()
        explanation = await expl_agent.process(ExplanationInput(
            requirements=requirements,
            architecture=architecture,
            impact=impact,
            estimation=estimation
        ))
        
        # Persist decision
        estimated_hours = self._extract_hours(estimation)
        estimated_cost = self._extract_cost(estimation)
        timeline_weeks = self._extract_timeline(estimation)
        
        decision_id = await self._writer.persist_decision(
            project_id=project_id,
            title=f"Initial Decision: {filename}",
            requirement_document_id=document_id,
            architecture_baseline_id=baseline_id,
            risk_level=risk_level,
            requirements_spec=self._safe_dump(requirements),
            architecture_design=self._safe_dump(architecture),
            impact_analysis=self._safe_dump(impact),
            estimation=self._safe_dump(estimation),
            rule_results=asdict(rule_results),
            executive_summary=self._safe_dump(explanation),
            estimated_hours=estimated_hours,
            estimated_cost=estimated_cost,
            timeline_weeks=timeline_weeks,
        )
        
        # Store in Supermemory
        await self._store_in_supermemory(
            decision_id, project_id, filename, explanation, 
            architecture, rule_results, risk_level, estimated_hours,
            context_type="initial"
        )
        
        return self._build_decision(
            project_id, decision_id, context_type, confidence,
            normalized_doc, rule_results, requirements, architecture,
            impact, estimation, explanation, risk_level
        )
    
    async def _run_change_request_flow(
        self,
        extracted_text: str,
        filename: str,
        content_type: str,
        project_id: UUID,
        context_type: ContextType,
        confidence: float,
    ) -> Decision:
        """
        Handle CHANGE_REQUEST flow.
        Fetches existing context, creates additive changes, links to previous decisions.
        """
        # =====================
        # 1. Fetch existing project context via MCP
        # =====================
        project_context = await self._reader.get_project_context(project_id)
        if project_context is None:
            # Fallback to initial flow if project not found
            return await self._run_initial_requirement_flow(
                extracted_text=extracted_text,
                filename=filename,
                content_type=content_type,
                project_id=project_id,
                project_name=None,
                context_type=context_type,
                confidence=confidence,
            )
        
        # Get existing architecture for diff
        existing_architecture = await self._reader.get_architecture_context(project_id)
        
        # Get previous decisions for linking
        previous_decisions = project_context.locked_decisions
        
        # =====================
        # 2. Store change request document
        # =====================
        document_id = await self._writer.persist_requirement_document(
            project_id=project_id,
            filename=filename,
            content_type=content_type,
            raw_text=extracted_text,
            context_type=context_type,
            confidence_score=confidence,
        )
        
        # =====================
        # 3. Normalize change request
        # =====================
        normalizer = NormalizationService()
        normalized_doc = await normalizer.normalize(extracted_text)
        
        # =====================
        # 4. Apply rules with existing context
        # =====================
        context = AnalysisContext(context_type=context_type, normalized_doc=normalized_doc)
        engine = RuleEngine(DEFAULT_RULES)
        rule_results = engine.evaluate(context)
        risk_level = self._map_risk_level(rule_results.risk_level)
        
        # =====================
        # 5. Extract change requirements
        # =====================
        req_agent = RequirementAgent()
        requirements = await req_agent.process(normalized_doc)
        
        # Persist NEW requirements (additive)
        await self._persist_requirements(document_id, requirements)
        
        # =====================
        # 6. Generate proposed architecture changes
        # =====================
        arch_agent = ArchitectureAgent()
        proposed_architecture = await arch_agent.process(requirements)
        
        # DO NOT overwrite existing baseline - create new INACTIVE version
        new_baseline_id = await self._persist_architecture(
            project_id, f"CR: {filename}", proposed_architecture, set_active=False
        )
        
        # =====================
        # 7. Run Impact Diff Engine
        # =====================
        impact_agent = ImpactDiffAgent()
        
        # Build diff context with existing vs proposed
        diff_context = {
            "existing_architecture": existing_architecture.model_dump() if existing_architecture else None,
            "proposed_changes": proposed_architecture,
            "existing_requirements_count": project_context.total_requirements,
            "previous_decisions": [d.model_dump() for d in previous_decisions[:5]],
        }
        
        # Process impact with context
        impact = await impact_agent.process(proposed_architecture)
        
        # Enhance impact with diff data
        if hasattr(impact, 'model_dump'):
            impact_dict = impact.model_dump()
            impact_dict['change_context'] = {
                'is_change_request': True,
                'baseline_version': existing_architecture.version if existing_architecture else None,
                'previous_decision_count': len(previous_decisions),
                'additive_components': len(proposed_architecture.components) if hasattr(proposed_architecture, 'components') else 0,
            }
        
        # =====================
        # 8. Estimation with historical bias signals
        # =====================
        await self._enrich_estimation_with_history(project_id, rule_results)
        
        est_agent = EstimationAgent()
        estimation = await est_agent.process(EstimationInput(impact=impact, rules=rule_results))
        
        # =====================
        # 9. Generate explanation
        # =====================
        expl_agent = ExplanationAgent()
        explanation = await expl_agent.process(ExplanationInput(
            requirements=requirements,
            architecture=proposed_architecture,
            impact=impact,
            estimation=estimation
        ))
        
        # =====================
        # 10. Persist Decision (linked to previous)
        # =====================
        estimated_hours = self._extract_hours(estimation)
        estimated_cost = self._extract_cost(estimation)
        timeline_weeks = self._extract_timeline(estimation)
        
        # Include reference to previous baseline (no overwrite)
        existing_baseline_id = None
        if existing_architecture:
            existing_baseline_id = existing_architecture.id
        
        decision_id = await self._writer.persist_decision(
            project_id=project_id,
            title=f"Change Request: {filename}",
            requirement_document_id=document_id,
            architecture_baseline_id=existing_baseline_id,  # Link to EXISTING baseline
            risk_level=risk_level,
            requirements_spec=self._safe_dump(requirements),
            architecture_design=self._safe_dump(proposed_architecture),
            impact_analysis={
                **(self._safe_dump(impact) or {}),
                'proposed_baseline_id': str(new_baseline_id),
                'change_type': 'additive',
                'previous_decisions': [str(d.id) for d in previous_decisions[:5]],
            },
            estimation=self._safe_dump(estimation),
            rule_results=asdict(rule_results),
            executive_summary=self._safe_dump(explanation),
            estimated_hours=estimated_hours,
            estimated_cost=estimated_cost,
            timeline_weeks=timeline_weeks,
        )
        
        # =====================
        # 11. Update Supermemory with change patterns
        # =====================
        await self._store_in_supermemory(
            decision_id, project_id, filename, explanation,
            proposed_architecture, rule_results, risk_level, estimated_hours,
            context_type="change_request",
            key_insights=[
                f"Change request on baseline v{existing_architecture.version}" if existing_architecture else "New change request",
                f"Linked to {len(previous_decisions)} prior decisions",
            ]
        )
        
        return self._build_decision(
            project_id, decision_id, context_type, confidence,
            normalized_doc, rule_results, requirements, proposed_architecture,
            impact, estimation, explanation, risk_level
        )
    
    # =====================
    # Helper Methods
    # =====================
    
    def _map_risk_level(self, risk_level_str: str) -> RiskLevel:
        """Map risk level string from RuleResult to RiskLevel enum."""
        mapping = {
            "CRITICAL": RiskLevel.CRITICAL,
            "HIGH": RiskLevel.HIGH,
            "MEDIUM": RiskLevel.MEDIUM,
            "LOW": RiskLevel.LOW,
        }
        return mapping.get(risk_level_str.upper(), RiskLevel.MEDIUM)
    
    def _extract_hours(self, estimation) -> Optional[float]:
        if hasattr(estimation, 'total_hours'):
            return estimation.total_hours
        elif hasattr(estimation, 'estimated_hours'):
            return estimation.estimated_hours
        return None
    
    def _extract_cost(self, estimation) -> Optional[str]:
        """Extract cost estimate from estimation object."""
        if hasattr(estimation, 'cost_estimate'):
            return estimation.cost_estimate
        return None
    
    def _extract_timeline(self, estimation) -> Optional[float]:
        """Extract timeline in weeks from estimation object."""
        if hasattr(estimation, 'timeline_weeks'):
            return estimation.timeline_weeks
        return None
    
    def _safe_dump(self, obj) -> Optional[dict]:
        if obj is None:
            return None
        if hasattr(obj, 'model_dump'):
            return obj.model_dump()
        return None
    
    async def _persist_requirements(self, document_id: UUID, requirements) -> None:
        if not hasattr(requirements, 'functional_requirements'):
            return
        
        req_list = []
        for i, req in enumerate(requirements.functional_requirements):
            req_list.append({
                "requirement_id": f"FR-{i+1:03d}",
                "requirement_type": "functional",
                "description": req.description if hasattr(req, 'description') else str(req),
                "priority": req.priority if hasattr(req, 'priority') else None,
                "category": req.category if hasattr(req, 'category') else None,
            })
        
        if hasattr(requirements, 'non_functional_requirements'):
            for i, req in enumerate(requirements.non_functional_requirements):
                req_list.append({
                    "requirement_id": f"NFR-{i+1:03d}",
                    "requirement_type": "non_functional",
                    "description": req.description if hasattr(req, 'description') else str(req),
                    "priority": req.priority if hasattr(req, 'priority') else None,
                    "category": req.category if hasattr(req, 'category') else None,
                })
        
        await self._writer.persist_normalized_requirements(document_id, req_list)
    
    async def _persist_architecture(
        self, 
        project_id: UUID, 
        filename: str, 
        architecture, 
        set_active: bool
    ) -> UUID:
        components = []
        if hasattr(architecture, 'components'):
            components = [c.model_dump() if hasattr(c, 'model_dump') else c for c in architecture.components]
        
        data_models = []
        if hasattr(architecture, 'data_models'):
            data_models = [d.model_dump() if hasattr(d, 'model_dump') else d for d in architecture.data_models]
        
        api_definitions = []
        if hasattr(architecture, 'api_endpoints'):
            api_definitions = [a.model_dump() if hasattr(a, 'model_dump') else a for a in architecture.api_endpoints]
        
        return await self._writer.persist_architecture_baseline(
            project_id=project_id,
            name=f"Baseline from {filename}",
            components=components,
            data_models=data_models,
            api_definitions=api_definitions,
            description=architecture.system_overview if hasattr(architecture, 'system_overview') else None,
            set_active=set_active,
        )
    
    async def _enrich_estimation_with_history(self, project_id: UUID, rule_results) -> None:
        """Fetch bias signals from Supermemory to improve estimation accuracy."""
        try:
            memory = await SupermemoryService.get_instance()
            recall_result = await memory.recall_by_project(project_id, limit=20)
            
            # Add bias signals to rule results for estimation adjustment
            for signal in recall_result.bias_signals:
                if signal.signal_type == "underestimation":
                    rule_results.flags.append("HISTORICAL_UNDERESTIMATION")
                    rule_results.effort_multiplier = max(rule_results.effort_multiplier, 1.2)
                elif signal.signal_type == "overestimation":
                    rule_results.flags.append("HISTORICAL_OVERESTIMATION")
        except Exception:
            pass
    
    async def _store_in_supermemory(
        self,
        decision_id: UUID,
        project_id: UUID,
        filename: str,
        explanation,
        architecture,
        rule_results,
        risk_level: RiskLevel,
        estimated_hours: Optional[float],
        context_type: str = "initial",
        key_insights: Optional[List[str]] = None,
    ) -> None:
        try:
            memory = await SupermemoryService.get_instance()
            
            # Build summary
            summary_parts = []
            if hasattr(explanation, 'executive_summary'):
                summary_parts.append(explanation.executive_summary)
            if hasattr(explanation, 'key_points'):
                summary_parts.extend(explanation.key_points[:3])
            
            summary = " ".join(summary_parts) if summary_parts else f"Decision for {filename}"
            
            # Build tags
            tags = [context_type]
            if hasattr(architecture, 'technology_stack'):
                tags.extend(architecture.technology_stack[:5])
            if rule_results.flags:
                tags.extend(rule_results.flags[:3])
            
            await memory.store(
                decision_id=decision_id,
                project_id=project_id,
                summary=summary,
                risk_level=risk_level,
                tags=tags,
                key_insights=key_insights or [],
                estimated_hours=estimated_hours,
            )
        except Exception:
            pass
    
    def _build_decision(
        self,
        project_id: UUID,
        decision_id: UUID,
        context_type: ContextType,
        confidence: float,
        normalized_doc,
        rule_results,
        requirements,
        architecture,
        impact,
        estimation,
        explanation,
        risk_level: RiskLevel,
    ) -> Decision:
        return Decision(
            project_id=str(project_id),
            decision_id=str(decision_id),
            context_type=context_type,
            confidence_score=confidence,
            normalized_data=normalized_doc.model_dump(),
            rule_results=asdict(rule_results),
            requirements=requirements,
            architecture=architecture,
            impact=impact,
            estimation=estimation,
            explanation=explanation,
            risk_level=risk_level.value,
        )
