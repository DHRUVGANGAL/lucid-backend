import enum

class ContextType(str, enum.Enum):
    INITIAL_REQUIREMENT = "initial_requirement"
    CHANGE_REQUEST = "change_request"
    UNKNOWN = "unknown"

class ProjectStatus(str, enum.Enum):
    ACTIVE = "active"
    ARCHIVED = "archived"
    ON_HOLD = "on_hold"

class DocumentStatus(str, enum.Enum):
    PENDING = "pending"
    ANALYZED = "analyzed"
    APPROVED = "approved"
    REJECTED = "rejected"

class DecisionStatus(str, enum.Enum):
    DRAFT = "draft"
    PENDING_REVIEW = "pending_review"
    APPROVED = "approved"
    REJECTED = "rejected"
    IMPLEMENTED = "implemented"

class DeliveryStatus(str, enum.Enum):
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"

class RiskLevel(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
