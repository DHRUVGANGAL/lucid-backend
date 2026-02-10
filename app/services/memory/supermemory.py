from typing import List, Optional, Dict, Any
from uuid import UUID
from datetime import datetime
import structlog

from qdrant_client import AsyncQdrantClient
from qdrant_client.models import (
    Distance,
    VectorParams,
    PointStruct,
    Filter,
    FieldCondition,
    MatchValue,
    SearchParams,
)

from app.core.config import settings
from app.core.llm.embeddings import EmbeddingClient
from app.services.memory.models import MemoryEntry, BiasSignal, RecallResult
from app.models.enums import RiskLevel

logger = structlog.get_logger(__name__)


class SupermemoryService:
    """
    Production Supermemory service using Qdrant for vector storage
    and Gemini embeddings.
    
    This is a semantic memory layer that:
    - Stores decision summaries as vectors
    - Enables similarity search
    - Detects bias patterns
    - Provides historical insights
    
    NOTE: This does NOT replace the database. All entries reference
    decision_id from the primary database.
    """
    
    VECTOR_SIZE = 3072  # gemini-embedding-001 dimensions
    COLLECTION_NAME = settings.QDRANT_COLLECTION
    
    _instance: "SupermemoryService" = None
    _client: AsyncQdrantClient = None
    _embedding_client: EmbeddingClient = None
    _initialized: bool = False
    
    @classmethod
    async def get_instance(cls) -> "SupermemoryService":
        if cls._instance is None:
            cls._instance = cls()
            await cls._instance._initialize()
        return cls._instance
    
    def __init__(self):
        self._client = AsyncQdrantClient(
            # host=settings.QDRANT_HOST,
            # port=settings.QDRANT_PORT,
            url=settings.QDRANT_URL,
            api_key=settings.QDRANT_API_KEY,
        )
        self._embedding_client = EmbeddingClient.get_instance()
    
    async def _initialize(self):
        """Initialize Qdrant collection if not exists or recreate if vector size changed."""
        if self._initialized:
            return
        
        logger.info("Initializing Supermemory service", collection=self.COLLECTION_NAME)
        
        collections = await self._client.get_collections()
        collection_names = [c.name for c in collections.collections]
        
        if self.COLLECTION_NAME in collection_names:
            # Check if existing collection has the right vector size
            collection_info = await self._client.get_collection(self.COLLECTION_NAME)
            existing_size = collection_info.config.params.vectors.size
            
            if existing_size != self.VECTOR_SIZE:
                logger.warning(
                    "Collection vector size mismatch, recreating collection",
                    existing_size=existing_size,
                    required_size=self.VECTOR_SIZE,
                )
                await self._client.delete_collection(self.COLLECTION_NAME)
                await self._create_collection()
            else:
                logger.info("Collection already exists with correct dimensions", size=existing_size)
                # Ensure payload indexes exist (for Qdrant Cloud)
                await self._create_payload_indexes()
        else:
            await self._create_collection()
        
        self._initialized = True
        logger.info("Supermemory service initialized successfully")
    
    async def _create_collection(self):
        """Create the Qdrant collection with correct vector size and payload indexes."""
        logger.info("Creating Qdrant collection", collection=self.COLLECTION_NAME, vector_size=self.VECTOR_SIZE)
        await self._client.create_collection(
            collection_name=self.COLLECTION_NAME,
            vectors_config=VectorParams(
                size=self.VECTOR_SIZE,
                distance=Distance.COSINE,
            ),
        )
        
        # Create payload indexes for filtering (required for Qdrant Cloud)
        await self._create_payload_indexes()
        logger.info("Collection created successfully")
    
    async def _create_payload_indexes(self):
        """Create payload indexes for efficient filtering."""
        from qdrant_client.models import PayloadSchemaType
        
        indexes_to_create = [
            ("project_id", PayloadSchemaType.KEYWORD),
            ("risk_level", PayloadSchemaType.KEYWORD),
            ("decision_id", PayloadSchemaType.KEYWORD),
        ]
        
        for field_name, field_type in indexes_to_create:
            try:
                await self._client.create_payload_index(
                    collection_name=self.COLLECTION_NAME,
                    field_name=field_name,
                    field_schema=field_type,
                )
                logger.info("Created payload index", field=field_name)
            except Exception as e:
                logger.warning("Failed to create payload index", field=field_name, error=str(e))
    
    # =====================
    # Store Operations
    # =====================
    
    async def store(
        self,
        decision_id: UUID,
        project_id: UUID,
        summary: str,
        risk_level: RiskLevel = RiskLevel.MEDIUM,
        key_insights: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        estimated_hours: Optional[float] = None,
        actual_hours: Optional[float] = None,
    ) -> MemoryEntry:
        """
        Store a semantic summary of a decision in Qdrant.
        
        Args:
            decision_id: Reference to the decision in the database
            project_id: Reference to the project
            summary: Human-readable summary of the decision
            risk_level: Risk level of the decision
            key_insights: Key learnings or insights
            tags: Tags for categorization
            estimated_hours: Original estimation
            actual_hours: Actual hours (for completed decisions)
        
        Returns:
            The stored MemoryEntry
        """
        logger.info(
            "Storing decision in Supermemory",
            decision_id=str(decision_id),
            project_id=str(project_id),
            summary_length=len(summary),
        )
        
        # Generate embedding
        embedding = await self._embedding_client.embed(summary)
        logger.info("Embedding generated", dimensions=len(embedding))
        
        # Prepare payload (no raw text stored)
        payload = {
            "decision_id": str(decision_id),
            "project_id": str(project_id),
            "risk_level": risk_level.value,
            "tags": tags or [],
            "key_insights": key_insights or [],
            "estimated_hours": estimated_hours,
            "actual_hours": actual_hours,
            "created_at": datetime.utcnow().isoformat(),
        }
        
        # Upsert to Qdrant (use decision_id as point ID)
        point = PointStruct(
            id=str(decision_id),
            vector=embedding,
            payload=payload,
        )
        
        await self._client.upsert(
            collection_name=self.COLLECTION_NAME,
            points=[point],
        )
        logger.info("Decision stored in Qdrant successfully", decision_id=str(decision_id))
        
        return MemoryEntry(
            decision_id=decision_id,
            project_id=project_id,
            summary=summary,
            key_insights=key_insights or [],
            tags=tags or [],
            risk_level=risk_level,
            estimated_hours=estimated_hours,
            actual_hours=actual_hours,
            embedding=embedding,
        )
    
    async def update(
        self,
        decision_id: UUID,
        actual_hours: Optional[float] = None,
        key_insights: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
    ) -> bool:
        """
        Update an existing memory entry's payload.
        """
        payload_updates: Dict[str, Any] = {}
        
        if actual_hours is not None:
            payload_updates["actual_hours"] = actual_hours
        if key_insights is not None:
            payload_updates["key_insights"] = key_insights
        if tags is not None:
            payload_updates["tags"] = tags
        
        if not payload_updates:
            return True
        
        await self._client.set_payload(
            collection_name=self.COLLECTION_NAME,
            payload=payload_updates,
            points=[str(decision_id)],
        )
        
        return True
    
    # =====================
    # Recall Operations
    # =====================
    
    async def recall(
        self,
        query: str,
        project_id: Optional[UUID] = None,
        tags: Optional[List[str]] = None,
        limit: int = 10,
    ) -> RecallResult:
        """
        Recall similar decisions based on semantic similarity.
        
        Args:
            query: Natural language query
            project_id: Optional filter by project
            tags: Optional filter by tags
            limit: Maximum number of results
        
        Returns:
            RecallResult with matching entries, bias signals, and patterns
        """
        # Generate query embedding
        query_embedding = await self._embedding_client.embed(query)
        
        # Build filter
        filter_conditions = []
        if project_id:
            filter_conditions.append(
                FieldCondition(
                    key="project_id",
                    match=MatchValue(value=str(project_id)),
                )
            )
        
        search_filter = Filter(must=filter_conditions) if filter_conditions else None
        
        # Search Qdrant
        results = await self._client.search(
            collection_name=self.COLLECTION_NAME,
            query_vector=query_embedding,
            query_filter=search_filter,
            limit=limit,
            with_payload=True,
            search_params=SearchParams(exact=False, hnsw_ef=128),
        )
        
        # Convert to MemoryEntry objects
        entries = self._results_to_entries(results)
        
        # Filter by tags if specified
        if tags:
            entries = [
                e for e in entries
                if any(t in e.tags for t in tags)
            ]
        
        # Detect bias signals
        bias_signals = self._detect_bias_signals(entries)
        
        # Extract patterns
        patterns = self._extract_patterns(entries)
        
        return RecallResult(
            entries=entries,
            bias_signals=bias_signals,
            patterns=patterns,
            total_matches=len(results),
        )
    
    async def recall_by_project(
        self,
        project_id: UUID,
        limit: int = 50,
    ) -> RecallResult:
        """
        Recall all memories for a specific project.
        """
        filter_conditions = [
            FieldCondition(
                key="project_id",
                match=MatchValue(value=str(project_id)),
            )
        ]
        
        try:
            results, _ = await self._client.scroll(
                collection_name=self.COLLECTION_NAME,
                scroll_filter=Filter(must=filter_conditions),
                limit=limit,
                with_payload=True,
                with_vectors=False,
            )
            entries = self._scroll_to_entries(results)
        except Exception as e:
            logger.warning("Failed to scroll collection, returning empty result", error=str(e))
            entries = []
        
        return RecallResult(
            entries=entries,
            bias_signals=self._detect_bias_signals(entries),
            patterns=self._extract_patterns(entries),
            total_matches=len(entries),
        )
    
    async def recall_similar_decisions(
        self,
        decision_id: UUID,
        limit: int = 5,
    ) -> RecallResult:
        """
        Recall decisions similar to a given decision.
        """
        # Retrieve the source point
        points = await self._client.retrieve(
            collection_name=self.COLLECTION_NAME,
            ids=[str(decision_id)],
            with_vectors=True,
        )
        
        if not points:
            return RecallResult(entries=[], total_matches=0)
        
        source_vector = points[0].vector
        
        # Search for similar (exclude self)
        results = await self._client.search(
            collection_name=self.COLLECTION_NAME,
            query_vector=source_vector,
            limit=limit + 1,
            with_payload=True,
        )
        
        # Filter out the source decision
        results = [r for r in results if r.id != str(decision_id)][:limit]
        
        entries = self._results_to_entries(results)
        
        return RecallResult(
            entries=entries,
            bias_signals=self._detect_bias_signals(entries),
            patterns=self._extract_patterns(entries),
            total_matches=len(results),
        )
    
    # =====================
    # Helper Methods
    # =====================
    
    def _results_to_entries(self, results) -> List[MemoryEntry]:
        """Convert Qdrant search results to MemoryEntry objects."""
        entries = []
        for result in results:
            payload = result.payload or {}
            try:
                entry = MemoryEntry(
                    decision_id=UUID(payload.get("decision_id", "")),
                    project_id=UUID(payload.get("project_id", "")),
                    summary="",  # Not stored in Qdrant
                    key_insights=payload.get("key_insights", []),
                    tags=payload.get("tags", []),
                    risk_level=RiskLevel(payload.get("risk_level", "medium")),
                    estimated_hours=payload.get("estimated_hours"),
                    actual_hours=payload.get("actual_hours"),
                    embedding=None,
                )
                entries.append(entry)
            except (ValueError, KeyError):
                continue
        return entries
    
    def _scroll_to_entries(self, points) -> List[MemoryEntry]:
        """Convert Qdrant scroll results to MemoryEntry objects."""
        entries = []
        for point in points:
            payload = point.payload or {}
            try:
                entry = MemoryEntry(
                    decision_id=UUID(payload.get("decision_id", "")),
                    project_id=UUID(payload.get("project_id", "")),
                    summary="",
                    key_insights=payload.get("key_insights", []),
                    tags=payload.get("tags", []),
                    risk_level=RiskLevel(payload.get("risk_level", "medium")),
                    estimated_hours=payload.get("estimated_hours"),
                    actual_hours=payload.get("actual_hours"),
                    embedding=None,
                )
                entries.append(entry)
            except (ValueError, KeyError):
                continue
        return entries
    
    # =====================
    # Bias Detection
    # =====================
    
    def _detect_bias_signals(self, entries: List[MemoryEntry]) -> List[BiasSignal]:
        """
        Analyze entries for bias signals based on historical patterns.
        """
        if not entries:
            return []
        
        signals = []
        
        # Check for underestimation bias
        completed = [e for e in entries if e.actual_hours and e.estimated_hours]
        if completed:
            underestimated = [
                e for e in completed
                if e.actual_hours > e.estimated_hours * 1.2
            ]
            underestimation_rate = len(underestimated) / len(completed)
            
            if underestimation_rate > 0.5:
                signals.append(BiasSignal(
                    signal_type="underestimation",
                    confidence=min(underestimation_rate, 1.0),
                    description=f"Historical pattern shows {underestimation_rate*100:.0f}% of decisions exceed estimates by >20%",
                    supporting_decisions=[e.decision_id for e in underestimated],
                ))
            
            # Check for overestimation
            overestimated = [
                e for e in completed
                if e.actual_hours < e.estimated_hours * 0.8
            ]
            overestimation_rate = len(overestimated) / len(completed)
            
            if overestimation_rate > 0.5:
                signals.append(BiasSignal(
                    signal_type="overestimation",
                    confidence=min(overestimation_rate, 1.0),
                    description=f"Historical pattern shows {overestimation_rate*100:.0f}% of decisions completed <80% of estimated time",
                    supporting_decisions=[e.decision_id for e in overestimated],
                ))
        
        # Check for risk concentration
        high_risk = [
            e for e in entries
            if e.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        ]
        risk_rate = len(high_risk) / len(entries)
        
        if risk_rate > 0.3:
            signals.append(BiasSignal(
                signal_type="risk_concentration",
                confidence=risk_rate,
                description=f"High concentration of high-risk decisions: {risk_rate*100:.0f}% are HIGH or CRITICAL",
                supporting_decisions=[e.decision_id for e in high_risk],
            ))
        
        return signals
    
    def _extract_patterns(self, entries: List[MemoryEntry]) -> List[str]:
        """
        Extract common patterns from entries.
        """
        if not entries:
            return []
        
        patterns = []
        
        # Tag frequency analysis
        tag_counts: Dict[str, int] = {}
        for entry in entries:
            for tag in entry.tags:
                tag_counts[tag] = tag_counts.get(tag, 0) + 1
        
        # Tags appearing in >30% of entries
        threshold = len(entries) * 0.3
        common_tags = [t for t, c in tag_counts.items() if c >= threshold]
        if common_tags:
            patterns.append(f"Common themes: {', '.join(common_tags)}")
        
        # Estimation accuracy analysis
        completed = [e for e in entries if e.actual_hours and e.estimated_hours and e.estimated_hours > 0]
        if completed:
            variances = [
                (e.actual_hours - e.estimated_hours) / e.estimated_hours * 100
                for e in completed
            ]
            avg_variance = sum(variances) / len(variances)
            
            if abs(avg_variance) > 10:
                direction = "over" if avg_variance > 0 else "under"
                patterns.append(f"Average estimation {direction} by {abs(avg_variance):.1f}%")
            
            # Variance spread
            if len(variances) >= 3:
                variance_spread = max(variances) - min(variances)
                if variance_spread > 50:
                    patterns.append(f"High estimation variance: {variance_spread:.0f}% spread between best and worst")
        
        # Risk distribution
        risk_counts = {}
        for entry in entries:
            risk_counts[entry.risk_level.value] = risk_counts.get(entry.risk_level.value, 0) + 1
        
        dominant_risk = max(risk_counts.items(), key=lambda x: x[1])
        if dominant_risk[1] >= len(entries) * 0.5:
            patterns.append(f"Dominant risk level: {dominant_risk[0]} ({dominant_risk[1]}/{len(entries)} decisions)")
        
        return patterns
    
    # =====================
    # Admin Operations
    # =====================
    
    async def delete(self, decision_id: UUID) -> bool:
        """Delete a memory entry."""
        await self._client.delete(
            collection_name=self.COLLECTION_NAME,
            points_selector=[str(decision_id)],
        )
        return True
    
    async def count(self, project_id: Optional[UUID] = None) -> int:
        """Count entries, optionally filtered by project."""
        if project_id:
            result = await self._client.count(
                collection_name=self.COLLECTION_NAME,
                count_filter=Filter(
                    must=[
                        FieldCondition(
                            key="project_id",
                            match=MatchValue(value=str(project_id)),
                        )
                    ]
                ),
            )
        else:
            result = await self._client.count(collection_name=self.COLLECTION_NAME)
        
        return result.count
