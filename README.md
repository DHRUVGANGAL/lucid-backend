# Backend Lucid

**AI-Powered Requirements Analysis & Decision Engine**

An intelligent backend system that analyzes requirement documents, detects project context, generates architecture designs, estimates effort, and manages decisions with full audit trails.

---

## 🎯 Overview

Backend Lucid is a decision intelligence platform that:
- **Parses** uploaded documents (PDF, DOCX, TXT)
- **Detects** context type (Initial Requirement vs Change Request)
- **Normalizes** requirements into structured format
- **Generates** architecture designs and impact analysis
- **Estimates** effort with historical bias correction
- **Stores** semantic memory for pattern recognition

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                           API Layer                                 │
│  ┌──────────┐  ┌──────────────┐  ┌────────────────┐                 │
│  │  Health  │  │ Analyze-File │  │   Decisions    │                 │
│  └──────────┘  └──────────────┘  └────────────────┘                 │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     Decision Orchestrator                           │
│  ┌──────────┐  ┌───────────────┐  ┌──────────────────────────────┐  │
│  │  Parser  │→ │    Decision   │→ │      Archestra Platform      │  │
│  │ Factory  │  │    Pipeline   │  │   (Context, Arch, Impact)    │  │
│  └──────────┘  └───────────────┘  └──────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
     ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
     │ PostgreSQL  │  │   Qdrant    │  │   Archestra  │
     │  (Primary)  │  │  (Vectors)  │  │  (AI Core)   │
     └─────────────┘  └─────────────┘  └─────────────┘
## 🚀 How to Run

### Using Docker (Recommended)

1.  **Configure Environment**:
    Ensure your `.env` file has the `GEMINI_API_KEY` set.

2.  **Start Services**:
    ```bash
    docker-compose up --build -d
    ```

3.  **Access Interfaces**:
    - **Backend API Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)
    - **Archestra UI**: [http://localhost:3000](http://localhost:3000)

4.  **Stop Services**:
    ```bash
    docker-compose down
    ```

---

## 🤖 AI Architecture

We use **Archestra**, an enterprise-grade AI orchestration platform, to decouple AI logic from the backend.

### Why Archestra?
- **Separation of Concerns**: The FastAPI backend handles business logic and persistence, while Archestra manages LLM interactions, prompt engineering, and agent chaining.
- **Traceability**: Every definition, decision, and risk assessment is traceable through Archestra's audit logs.
- **Enterprise Readiness**: Archestra provides a robust runtime for agents with built-in retries, caching, and model gateway management.

### Multi-Agent Workflow
The `decision_pipeline` orchestrates a team of specialized agents:
1. **ParserAgent**: Extracts structured requirements.
2. **ContextAgent**: Determines project intent and risk.
3. **ArchitectureAgent**: Proposes high-level designs.
4. **ImpactAgent**: Analyzes technical and business impact.
5. **EstimationAgent**: Calculates effort and confidence.
6. **ExplanationAgent**: Synthesizes an executive summary.

---

## 📁 Project Structure

```
app/
├── api/v1/
│   ├── endpoints/
│   │   ├── health.py          # Health check
│   │   ├── analyze.py         # File analysis endpoint
│   │   └── decisions.py       # Decision CRUD & approval
│   └── router.py
├── agents/
│   ├── requirement.py         # Requirements extraction
│   ├── architecture.py        # Architecture design
│   ├── impact.py              # Impact analysis
│   ├── estimation.py          # Effort estimation
│   └── explanation.py         # Executive summary
├── services/
│   ├── orchestrator/          # Pipeline coordination
│   ├── context/               # MCP read/write services
│   ├── memory/                # Supermemory (Qdrant)
│   ├── normalization/         # Document normalization
│   ├── parser/                # PDF/DOCX/TXT parsing
│   ├── rules/                 # Deterministic rule engine
│   └── decision/              # Approval & locking logic
├── models/                    # SQLAlchemy ORM models
├── db/
│   ├── session.py             # Async DB session
│   ├── repositories.py        # Data access layer
│   └── base.py                # Base model
├── core/
│   ├── config.py              # Settings (env vars)
│   ├── logging.py             # Structured logging
│   └── llm/                   # LLM client & embeddings
├── middleware/
│   └── tracing.py             # Request ID tracing
└── main.py                    # FastAPI application
```

---

## 🔌 API Endpoints

### Health Check
```
GET /api/v1/health
Response: { "status": "healthy" }
```

### Analyze File
```
POST /api/v1/analyze-file
Content-Type: multipart/form-data

Parameters:
  - file: UploadFile (PDF, DOCX, TXT)
  - project_id: Optional[UUID] - Existing project
  - project_name: Optional[str] - New project name

Response:
{
  "project_id": "uuid",
  "decision_id": "uuid",
  "context_type": "initial_requirement | change_request",
  "confidence_score": 0.85,
  "risk_level": "low | medium | high | critical",
  "normalized_data": {...},
  "rule_results": {...},
  "requirements": {...},
  "architecture": {...},
  "impact": {...},
  "estimation": {...},
  "explanation": {...}
}
```

### Decision Management
```
GET    /api/v1/decisions/{id}          # Get decision
GET    /api/v1/decisions/{id}/status   # Get lock status
POST   /api/v1/decisions/{id}/submit   # Submit for review
POST   /api/v1/decisions/{id}/approve  # Approve (locks)
POST   /api/v1/decisions/{id}/lock     # Mark implemented
POST   /api/v1/decisions/{id}/reject   # Reject
PATCH  /api/v1/decisions/{id}          # Update (if unlocked)
```

---

## 🔄 Pipeline Flows

### Initial Requirement Flow
```
1. Parse Document
2. Detect Context → INITIAL_REQUIREMENT
3. Create Project (if new)
4. Store Document in DB
5. Normalize Requirements
6. Apply Rule Engine
7. Run Agents:
   └── Requirements → Architecture → Impact → Estimation → Explanation
8. Persist Architecture Baseline (ACTIVE)
9. Persist Decision (DRAFT)
10. Store in Supermemory
```

### Change Request Flow
```
1. Parse Document
2. Detect Context → CHANGE_REQUEST
3. Fetch Existing Context (MCP)
   ├── Project context
   ├── Active baseline
   └── Locked decisions
4. Store Document (additive)
5. Generate Proposed Architecture (INACTIVE)
6. Run Impact Diff (existing vs proposed)
7. Recall Supermemory → Bias signals
8. Adjust Estimation (historical correction)
9. Persist Decision (linked to existing baseline)
10. Update Supermemory with patterns
```

---

## 🧠 Supermemory (Semantic Memory)

Vector-based memory layer using **Qdrant** + **Gemini Embeddings** (3072 dimensions).

**Store:**
```python
await memory.store(
    decision_id=uuid,
    project_id=uuid,
    summary="Decision summary text",
    risk_level=RiskLevel.MEDIUM,
    tags=["auth", "api"],
    estimated_hours=40
)
```

**Recall:**
```python
result = await memory.recall(
    query="authentication implementation",
    project_id=uuid,
    limit=10
)
# result.entries - matching decisions
# result.bias_signals - detected patterns
# result.patterns - common themes
```

**Bias Detection:**
| Signal | Condition |
|--------|-----------|
| `underestimation` | >50% of decisions exceeded estimate by >20% |
| `overestimation` | >50% of decisions completed <80% of estimate |
| `risk_concentration` | >30% of decisions are HIGH/CRITICAL |

---

## 📊 Data Models

### Core Entities
- **Project** - Top-level container
- **RequirementDocument** - Uploaded files
- **NormalizedRequirement** - Extracted requirements
- **ArchitectureBaseline** - Versioned designs
- **Decision** - Analysis results with state
- **DeliveryOutcome** - Actual vs estimated metrics

### Decision States
```
DRAFT → PENDING_REVIEW → APPROVED → IMPLEMENTED
                       ↘ REJECTED
```

**Locking Rules:**
- `APPROVED` and `IMPLEMENTED` are **locked**
- Locked decisions return `403 Forbidden` on modification
- All future changes must reference locked decisions

---

## ⚙️ Configuration

Create `.env` file:
```env
# API
PROJECT_NAME=Backend-Lucid
API_V1_STR=/api/v1

# Database
DATABASE_URL=postgresql+asyncpg://user:pass@localhost:5432/lucid

# Gemini (Google AI)
GEMINI_API_KEY=your-gemini-api-key

# Qdrant
QDRANT_HOST=localhost
QDRANT_PORT=6333
QDRANT_COLLECTION=supermemory

# LLM Provider
LLM_PROVIDER=gemini  # Default provider
```

---

## 🚀 Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Start Qdrant (Docker)
docker run -p 6333:6333 qdrant/qdrant

# Start PostgreSQL
docker run -p 5432:5432 -e POSTGRES_PASSWORD=postgres postgres

# Run server
uvicorn app.main:app --reload
```

---

## 📋 Dependencies

```
fastapi
uvicorn[standard]
pydantic-settings
sqlalchemy[asyncio]
asyncpg
google-generativeai
qdrant-client
python-docx
pypdf
structlog
python-multipart
python-dotenv
```

---

## 🔍 Structured Logging

All logs include `request_id` for tracing:
```json
{
  "event": "decision_created",
  "request_id": "a1b2c3d4",
  "decision_id": "uuid",
  "project_id": "uuid",
  "status": "draft",
  "timestamp": "2026-02-06T18:00:00Z"
}
```

Sensitive data (passwords, tokens, embeddings) is automatically **redacted**.

---

## 📝 License

MIT
