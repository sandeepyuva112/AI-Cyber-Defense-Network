import time
import json
import logging
from collections import defaultdict
from typing import Any, Optional
from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from datetime import datetime

from app.core.config import settings
from app.db.models.audit_log import AuditLog

logger = logging.getLogger("uvicorn.error")

# --- RATE LIMITING ---
# Simple in-memory rate limiter: client_ip -> list of timestamps
rate_limit_store = defaultdict(list)
RATE_LIMIT_MAX_REQUESTS = 150       # Allow 150 requests
RATE_LIMIT_WINDOW_SECONDS = 60      # per 60 seconds

async def rate_limiter_dependency(request: Request):
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    
    # Prune timestamps outside the window
    timestamps = rate_limit_store[client_ip]
    rate_limit_store[client_ip] = [t for t in timestamps if now - t < RATE_LIMIT_WINDOW_SECONDS]
    
    if len(rate_limit_store[client_ip]) >= RATE_LIMIT_MAX_REQUESTS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please try again later."
        )
    rate_limit_store[client_ip].append(now)

# --- SECURE HEADERS MIDDLEWARE ---
async def secure_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none';"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

# --- AUDIT LOGGING ---
def log_audit(db: Session, actor_user_id: Optional[str], action: str, details: dict[str, Any]) -> None:
    try:
        audit = AuditLog(
            created_at=datetime.utcnow(),
            actor_user_id=actor_user_id,
            action=action,
            details_json=json.dumps(details)
        )
        db.add(audit)
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to log audit event '{action}': {e}")

# --- FILE VALIDATION ---
def validate_uploaded_file(filename: Optional[str], content_type: Optional[str], file_size_bytes: int) -> None:
    # Check max size
    max_bytes = settings.max_upload_size_mb * 1024 * 1024
    if file_size_bytes > max_bytes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File exceeds maximum size limit of {settings.max_upload_size_mb}MB"
        )
        
    # Check file extension compatibility
    if not filename:
        raise HTTPException(status_code=400, detail="Invalid filename")
    lower_name = filename.lower()
    allowed_extensions = (".json", ".csv", ".txt", ".log", ".syslog", ".xml", ".evtx")
    if not any(lower_name.endswith(ext) for ext in allowed_extensions):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported file format. Supported: JSON, CSV, TXT, LOG, SYSLOG, XML, EVTX"
        )

# --- GLOBAL EXCEPTION HANDLING ---
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception on {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An internal server error occurred. Please contact system support."}
    )
