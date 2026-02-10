from fastapi import Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
import structlog

logger = structlog.get_logger()

async def global_exception_handler(request: Request, exc: Exception):
    logger.error("Global exception", error=str(exc))
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal Server Error"},
    )

async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
    )

def _serialize_errors(errors: list) -> list:
    """Serialize validation errors to JSON-safe format."""
    result = []
    for err in errors:
        serialized = {
            "type": err.get("type"),
            "loc": err.get("loc"),
            "msg": err.get("msg"),
        }
        # Convert ctx values to strings if present
        if "ctx" in err:
            ctx = err["ctx"]
            if isinstance(ctx, dict):
                serialized["ctx"] = {k: str(v) for k, v in ctx.items()}
            else:
                serialized["ctx"] = str(ctx)
        result.append(serialized)
    return result

async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": _serialize_errors(exc.errors())},
    )

