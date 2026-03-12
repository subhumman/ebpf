"""
FastAPI application entry point for eBPF Security Backend.

Provides REST API for:
- Receiving events from Rust agent
- Querying events and alerts for dashboard
- Managing rule configuration
"""

import logging
import os
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import FastAPI, Depends, HTTPException, Query, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from app import models, rules
from app.models import SecurityEvent, Alert, get_db, init_db

# =============================================================================
# Logging Configuration
# =============================================================================

logging.basicConfig(
    level=getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper()),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
    ]
)

logger = logging.getLogger(__name__)


# =============================================================================
# Pydantic Models for API
# =============================================================================

class EventCreate(BaseModel):
    """Request model for receiving events from eBPF agent."""
    
    pid: int = Field(..., ge=1, description="Process ID")
    uid: int = Field(..., ge=0, description="User ID")
    timestamp: int = Field(..., ge=0, description="Kernel timestamp in nanoseconds")
    event_type: int = Field(..., ge=1, le=2, description="1=FileOpen, 2=NetworkConnect")
    filename: Optional[str] = Field(None, max_length=256)
    dest_ip: Optional[str] = Field(None, max_length=45)
    dest_port: Optional[int] = Field(None, ge=0, le=65535)
    hostname: Optional[str] = Field(None, max_length=255)
    agent_version: Optional[str] = Field(None, max_length=32)
    
    @field_validator('dest_ip')
    @classmethod
    def validate_ip(cls, v: Optional[str]) -> Optional[str]:
        """Validate IP address format if provided."""
        if v is None:
            return None
        try:
            # Supports both IPv4 and IPv6
            ipaddress.ip_address(v)
            return v
        except ValueError:
            raise ValueError(f"Invalid IP address: {v}")


class EventResponse(BaseModel):
    """Response model for event queries."""
    
    id: int
    pid: int
    uid: int
    timestamp: int
    event_type: int
    filename: Optional[str]
    dest_ip: Optional[str]
    dest_port: Optional[int]
    created_at: str
    hostname: Optional[str]
    
    class Config:
        from_attributes = True


class AlertResponse(BaseModel):
    """Response model for alerts."""
    
    id: int
    severity: str
    message: str
    rule_id: str
    created_at: str
    is_resolved: bool
    
    class Config:
        from_attributes = True


class StatsResponse(BaseModel):
    """Response model for dashboard statistics."""
    
    total_events: int
    events_last_hour: int
    total_alerts: int
    unresolved_alerts: int
    top_pids: List[dict]  # [{"pid": 1234, "count": 42}, ...]


# =============================================================================
# Application Lifecycle
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Manage application startup and shutdown.
    
    - Startup: Initialize database, log version
    - Shutdown: Cleanup resources
    """
    # Startup
    logger.info(f"Starting eBPF Security Backend v{os.getenv('APP_VERSION', 'dev')}")
    
    try:
        init_db()
        logger.info("Database initialized")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        raise
    
    # Yield control to FastAPI
    yield
    
    # Shutdown
    logger.info("Shutting down...")
    # Add cleanup logic here if needed (e.g., close connections)


# =============================================================================
# FastAPI Application
# =============================================================================

app = FastAPI(
    title="eBPF Security Backend",
    description="REST API for eBPF-based security monitoring system",
    version=os.getenv("APP_VERSION", "0.1.0"),
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS middleware for frontend access
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv(
        "CORS_ORIGINS",
        "http://localhost:3000,http://127.0.0.1:3000"
    ).split(","),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
    expose_headers=["X-Request-Id"],
)


# =============================================================================
# Health & Metadata Endpoints
# =============================================================================

@app.get("/health")
async def health_check():
    """
    Health check endpoint for load balancers and orchestrators.
    
    Returns 200 if application is ready to serve traffic.
    """
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": os.getenv("APP_VERSION", "dev"),
    }


@app.get("/ready")
async def readiness_check(db: Session = Depends(models.get_db)):
    """
    Readiness check - verifies database connectivity.
    
    Returns 200 only if all dependencies are healthy.
    """
    try:
        # Simple query to test DB connection
        db.execute("SELECT 1")
        return {
            "status": "ready",
            "database": "connected",
        }
    except Exception as e:
        logger.error(f"Readiness check failed: {e}")
        raise HTTPException(
            status_code=503,
            detail={"status": "not_ready", "error": str(e)}
        )


@app.get("/rules")
async def list_rules():
    """
    List all loaded security rules with metadata.
    
    Useful for dashboard to show which rules are active.
    """
    return {
        "rules": rules.rule_engine.get_rule_info(),
        "total": len(rules.rule_engine.get_rule_info()),
    }


# =============================================================================
# Event Endpoints (Ingest & Query)
# =============================================================================

@app.post("/api/events", status_code=201)
async def receive_event(
    event: EventCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(models.get_db)
):
    """
    Receive a security event from the eBPF agent.
    
    This endpoint is called by the Rust agent for each captured event.
    Events are stored and evaluated against security rules asynchronously.
    """
    # Convert Pydantic model to SQLAlchemy model
    db_event = SecurityEvent(
        pid=event.pid,
        uid=event.uid,
        timestamp=event.timestamp,
        event_type=event.event_type,
        filename=event.filename,
        dest_ip=event.dest_ip,
        dest_port=event.dest_port,
        hostname=event.hostname,
        agent_version=event.agent_version,
    )
    
    # Save to database
    db.add(db_event)
    db.commit()
    db.refresh(db_event)  # Get the generated ID
    
    logger.debug(f"Stored event {db_event.id} from PID {event.pid}")
    
    # Evaluate rules in background to avoid blocking the agent
    background_tasks.add_task(evaluate_rules, db_event.id, event.dict())
    
    return {"status": "accepted", "event_id": db_event.id}


def evaluate_rules(event_id: int, event_data: dict):
    """
    Background task: Evaluate event against security rules.
    
    Runs asynchronously to avoid delaying event ingestion.
    """
    try:
        alerts = rules.rule_engine.evaluate(event_data)
        
        if alerts:
            logger.info(f"Generated {len(alerts)} alert(s) for event {event_id}")
            
            # Save alerts to database (separate session for background task)
            db = models.SessionLocal()
            try:
                for alert in alerts:
                    db_alert = Alert(
                        event_id=event_id,
                        severity=alert.severity.name.lower(),
                        rule_id=alert.rule_id,
                        message=alert.message,
                    )
                    db.add(db_alert)
                db.commit()
            finally:
                db.close()
                
    except Exception as e:
        logger.error(f"Rule evaluation failed for event {event_id}: {e}", exc_info=True)


@app.get("/api/events", response_model=List[EventResponse])
async def list_events(
    limit: int = Query(100, ge=1, le=1000, description="Max events to return"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    event_type: Optional[int] = Query(None, ge=1, le=2, description="Filter by event type"),
    pid: Optional[int] = Query(None, ge=1, description="Filter by process ID"),
    since: Optional[datetime] = Query(None, description="Only events after this time"),
    db: Session = Depends(models.get_db)
):
    """
    Query security events with filtering and pagination.
    
    Used by dashboard to display recent activity.
    """
    query = db.query(SecurityEvent)
    
    # Apply filters
    if event_type is not None:
        query = query.filter(SecurityEvent.event_type == event_type)
    if pid is not None:
        query = query.filter(SecurityEvent.pid == pid)
    if since is not None:
        query = query.filter(SecurityEvent.created_at >= since)
    
    # Order by newest first, apply pagination
    events = query.order_by(
        SecurityEvent.created_at.desc()
    ).offset(offset).limit(limit).all()
    
    return events


@app.get("/api/events/{event_id}", response_model=EventResponse)
async def get_event(
    event_id: int,
    db: Session = Depends(models.get_db)
):
    """Get a specific event by ID."""
    event = db.query(SecurityEvent).filter(
        SecurityEvent.id == event_id
    ).first()
    
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    
    return event


# =============================================================================
# Alert Endpoints
# =============================================================================

@app.get("/api/alerts", response_model=List[AlertResponse])
async def list_alerts(
    limit: int = Query(50, ge=1, le=500),
    unresolved_only: bool = Query(False, description="Only show unresolved alerts"),
    severity: Optional[str] = Query(None, pattern="^(critical|high|medium|low)$"),
    db: Session = Depends(models.get_db)
):
    """
    Query security alerts with filtering.
    
    Used by dashboard to display active threats.
    """
    query = db.query(Alert)
    
    if unresolved_only:
        query = query.filter(Alert.is_resolved == False)
    if severity is not None:
        query = query.filter(Alert.severity == severity.lower())
    
    alerts = query.order_by(
        Alert.created_at.desc()
    ).limit(limit).all()
    
    return alerts


@app.get("/api/alerts/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: int,
    db: Session = Depends(models.get_db)
):
    """Get a specific alert by ID."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    return alert


@app.post("/api/alerts/{alert_id}/resolve")
async def resolve_alert(
    alert_id: int,
    note: Optional[str] = Query(None, max_length=256),
    db: Session = Depends(models.get_db)
):
    """
    Mark an alert as resolved.
    
    Used by analysts to acknowledge and close alerts.
    """
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    alert.is_resolved = True
    alert.resolved_at = datetime.utcnow()
    alert.resolution_note = note
    db.commit()
    
    logger.info(f"Alert {alert_id} resolved by user")
    return {"status": "resolved", "alert_id": alert_id}


# =============================================================================
# Statistics Endpoint (Dashboard)
# =============================================================================

@app.get("/api/stats", response_model=StatsResponse)
async def get_stats(
    hours: int = Query(24, ge=1, le=168, description="Time window in hours"),
    db: Session = Depends(models.get_db)
):
    """
    Get aggregated statistics for dashboard.
    
    Computes metrics efficiently using database queries.
    """
    since = datetime.utcnow() - timedelta(hours=hours)
    
    # Total events
    total_events = db.query(SecurityEvent).count()
    
    # Events in time window
    events_last_hour = db.query(SecurityEvent).filter(
        SecurityEvent.created_at >= since
    ).count()
    
    # Alert counts
    total_alerts = db.query(Alert).count()
    unresolved_alerts = db.query(Alert).filter(
        Alert.is_resolved == False
    ).count()
    
    # Top PIDs by event count (last 24h)
    top_pids_query = db.query(
        SecurityEvent.pid,
        models.func.count(SecurityEvent.id).label("count")
    ).filter(
        SecurityEvent.created_at >= datetime.utcnow() - timedelta(hours=24)
    ).group_by(
        SecurityEvent.pid
    ).order_by(
        models.func.count(SecurityEvent.id).desc()
    ).limit(5)
    
    top_pids = [{"pid": row.pid, "count": row.count} for row in top_pids_query]
    
    return StatsResponse(
        total_events=total_events,
        events_last_hour=events_last_hour,
        total_alerts=total_alerts,
        unresolved_alerts=unresolved_alerts,
        top_pids=top_pids,
    )


# =============================================================================
# Error Handlers
# =============================================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc: HTTPException):
    """Standardized error response for HTTP exceptions."""
    logger.warning(f"HTTP {exc.status_code}: {exc.detail}")
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail},
    )


@app.exception_handler(Exception)
async def global_exception_handler(request, exc: Exception):
    """Catch-all handler for unexpected errors."""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error"},
    )


# =============================================================================
# Entry Point
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", "8000")),
        workers=int(os.getenv("WORKERS", "1")),
        log_level=os.getenv("LOG_LEVEL", "info").lower(),
        reload=os.getenv("DEBUG", "false").lower() == "true",
    )