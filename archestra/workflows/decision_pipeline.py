from typing import Dict, Any, List
from archestra.agents.parser_agent import ParserAgent
from archestra.agents.context_agent import ContextAgent
from archestra.agents.architecture_agent import ArchitectureAgent
from archestra.agents.impact_agent import ImpactAgent
from archestra.agents.estimation_agent import EstimationAgent
from archestra.agents.explanation_agent import ExplanationAgent
from app.services.memory.supermemory import SupermemoryService
from fastapi import HTTPException
import logging

logger = logging.getLogger(__name__)

class DecisionPipeline:
    """
    Orchestrates the decision making process by chaining agents.
    """
    
    def __init__(self):
        self.parser_agent = ParserAgent()
        self.context_agent = ContextAgent()
        self.architecture_agent = ArchitectureAgent()
        self.impact_agent = ImpactAgent()
        self.estimation_agent = EstimationAgent()
        self.explanation_agent = ExplanationAgent()

    async def run(self, initial_payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the pipeline.
        
        Args:
            initial_payload: Must contain 'document_text' and 'document_type'.
            
        Returns:
            Dictionary containing all agent outputs.
        """
        shared_context = {}
        
        try:
            # 1. Parser Agent
            logger.info("Running Parser Agent...")
            parser_result = await self.parser_agent.run(initial_payload)
            shared_context['requirements'] = parser_result.get('requirements', [])
            if not shared_context['requirements']:
                logger.warning("Parser Agent returned no requirements - using empty list")
            
            # 1.5 Recall Similar Decisions (Memory)
            similar_decisions = []
            try:
                logger.info("Recalling similar decisions from Supermemory...")
                memory = await SupermemoryService.get_instance()
                # Construct query from first few requirements
                query = " ".join([r.get('description', '') for r in shared_context['requirements'][:3]])
                if query:
                    recall_result = await memory.recall(query, limit=3)
                    similar_decisions = [
                        {"risk_level": e.risk_level.value, "summary": e.summary or "No summary"} 
                        for e in recall_result.entries
                    ]
            except Exception as e:
                logger.warning(f"Memory recall failed (continuing without memory): {str(e)}")
            
            # 2. Context Agent
            logger.info("Running Context Agent...")
            context_result = await self.context_agent.run({
                'requirements': shared_context['requirements'],
                'similar_decisions': similar_decisions
            })
            shared_context.update(context_result)
            
            # 3. Architecture Agent
            logger.info("Running Architecture Agent...")
            arch_result = await self.architecture_agent.run({
                'requirements': shared_context['requirements'],
                'context': {
                    'context_type': shared_context.get('context_type', 'initial_requirement'),
                    'risk_level': shared_context.get('risk_level', 'medium'),
                    'domain': shared_context.get('domain', 'general')
                }
            })
            shared_context.update(arch_result)
            
            # 4. Impact Agent
            logger.info("Running Impact Agent...")
            impact_result = await self.impact_agent.run({
                'architecture': shared_context['architecture'],
                'context': {
                    'context_type': shared_context.get('context_type', 'initial_requirement'),
                    'risk_level': shared_context.get('risk_level', 'medium')
                }
            })
            logger.info(f"Impact Agent returned keys: {list(impact_result.keys()) if isinstance(impact_result, dict) else type(impact_result)}")
            shared_context.update(impact_result)
            shared_context['impact'] = impact_result
            
            # 5. Estimation Agent
            logger.info("Running Estimation Agent...")
            est_result = await self.estimation_agent.run({
                'requirements': shared_context['requirements'],
                'architecture': shared_context['architecture'],
                'impact': {
                    'impacted_modules': shared_context.get('impacted_modules', []),
                    'risk_factors': shared_context.get('risk_factors', []),
                    'breaking_changes': shared_context.get('breaking_changes', False)
                }
            })
            logger.info(f"Estimation Agent returned keys: {list(est_result.keys()) if isinstance(est_result, dict) else type(est_result)}")
            shared_context.update(est_result)
            shared_context['estimation'] = est_result
            
            # 6. Explanation Agent
            logger.info("Running Explanation Agent...")
            expl_result = await self.explanation_agent.run({
                'requirements': shared_context['requirements'],
                'architecture': shared_context['architecture'],
                'impact': {
                    'impacted_modules': shared_context.get('impacted_modules', []),
                    'risk_factors': shared_context.get('risk_factors', []),
                    'breaking_changes': shared_context.get('breaking_changes', False)
                },
                'estimation': {
                    'effort_days': shared_context.get('effort_days', 0),
                    'confidence': shared_context.get('confidence', 'low'),
                    'assumptions': shared_context.get('assumptions', [])
                }
            })
            shared_context.update(expl_result)
            shared_context['explanation'] = expl_result
            
            return shared_context
            
        except HTTPException as e:
            logger.error(f"Pipeline failed at step with HTTP error: {e.detail}")
            raise e
        except Exception as e:
            logger.error(f"Pipeline failed with unexpected error: {str(e)}")
            raise HTTPException(status_code=500, detail=f"Decision pipeline execution failed: {str(e)}")
