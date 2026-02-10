from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
import time

from app.core.logging import set_request_id, get_logger

logger = get_logger(__name__)


class RequestTracingMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add request tracing.
    
    - Generates and propagates request_id
    - Logs request/response info
    - Adds X-Request-ID header to responses
    """
    
    async def dispatch(self, request: Request, call_next) -> Response:
        # Get or generate request ID
        request_id = request.headers.get("X-Request-ID")
        request_id = set_request_id(request_id)
        
        # Log request
        logger.info(
            "request_started",
            method=request.method,
            path=request.url.path,
            query=str(request.query_params) if request.query_params else None,
        )
        
        start_time = time.perf_counter()
        
        try:
            response = await call_next(request)
            
            # Calculate duration
            duration_ms = (time.perf_counter() - start_time) * 1000
            
            # Log response
            logger.info(
                "request_completed",
                method=request.method,
                path=request.url.path,
                status_code=response.status_code,
                duration_ms=round(duration_ms, 2),
            )
            
            # Add request ID to response headers
            response.headers["X-Request-ID"] = request_id
            
            return response
            
        except Exception as e:
            duration_ms = (time.perf_counter() - start_time) * 1000
            
            logger.error(
                "request_failed",
                method=request.method,
                path=request.url.path,
                error=str(e),
                error_type=type(e).__name__,
                duration_ms=round(duration_ms, 2),
            )
            raise
