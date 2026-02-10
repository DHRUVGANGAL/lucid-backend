import uuid
import structlog
from contextvars import ContextVar
from typing import Optional

# Context variable for request-scoped data
request_id_var: ContextVar[Optional[str]] = ContextVar("request_id", default=None)


def get_request_id() -> Optional[str]:
    """Get the current request ID from context."""
    return request_id_var.get()


def set_request_id(request_id: Optional[str] = None) -> str:
    """Set a request ID in context. Generates one if not provided."""
    rid = request_id or str(uuid.uuid4())[:8]
    request_id_var.set(rid)
    return rid


def add_request_id(logger, method_name, event_dict):
    """Structlog processor to add request_id to all log entries."""
    request_id = get_request_id()
    if request_id:
        event_dict["request_id"] = request_id
    return event_dict


def filter_sensitive_data(logger, method_name, event_dict):
    """Remove sensitive data from logs."""
    sensitive_keys = {
        "password", "token", "api_key", "secret", "authorization",
        "raw_text", "content", "embedding", "credentials"
    }
    
    def _filter(data):
        if isinstance(data, dict):
            return {
                k: "[REDACTED]" if k.lower() in sensitive_keys else _filter(v)
                for k, v in data.items()
            }
        elif isinstance(data, list):
            return [_filter(item) for item in data]
        return data
    
    return _filter(event_dict)


def configure_logging():
    """Configure structlog with processors."""
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            add_request_id,
            filter_sensitive_data,
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.processors.JSONRenderer(),
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )


def get_logger(name: str = __name__) -> structlog.stdlib.BoundLogger:
    """Get a configured logger instance."""
    return structlog.get_logger(name)
