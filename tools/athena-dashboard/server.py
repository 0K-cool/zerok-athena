#!/usr/bin/env python3
"""
0K ATHENA Dashboard — WebSocket Backend
========================================
FastAPI server providing real-time agent communication, HITL approval
workflow, and engagement data API for the ATHENA penetration testing dashboard.

Usage:
    cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-dashboard
    .venv/bin/uvicorn server:app --reload --port 8080

Architecture:
    Browser <--WebSocket--> FastAPI <--Events--> ATHENA Agents (Claude Code)

Event Types (server → client):
    agent_thinking    - Agent is reasoning (with thought/reasoning/action)
    tool_start        - Agent started a tool (with tool_id for streaming)
    tool_output_chunk - Streaming output chunk for running tool
    tool_complete     - Tool finished with results (with tool_id)
    phase_update      - Current PTES phase change
    finding           - New vulnerability discovered
    approval_request  - HITL approval needed
    approval_resolved - HITL decision made
    agent_status      - Agent state change
    agent_complete    - Agent finished task
    scan_progress     - Scan progress update
    system            - System messages

Event Types (client → server):
    approve           - Approve HITL request
    reject            - Reject HITL request
    start_agent       - Start an agent task
    stop_agent        - Stop an agent
"""

import asyncio
import json
import os
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# Neo4j imports (optional dependency)
try:
    from neo4j import GraphDatabase
    NEO4J_AVAILABLE = True
except ImportError:
    NEO4J_AVAILABLE = False
    GraphDatabase = None

# Phase C: Kali backend client + orchestrator
from kali_client import KaliClient
from orchestrator import Orchestrator


# ──────────────────────────────────────────────
# Models
# ──────────────────────────────────────────────

class AgentCode(str, Enum):
    PLANNING = "PL"
    ORCHESTRATOR = "OR"
    PASSIVE_OSINT = "PO"
    ACTIVE_RECON = "AR"
    CVE_RESEARCHER = "CV"
    ATTACK_PATH = "AP"
    WEB_VULN_SCANNER = "WV"
    EXPLOIT_CRAFTER = "EC"
    EXPLOITATION = "EX"
    VERIFICATION = "VF"
    POST_EXPLOITATION = "PE"
    DETECTION_VALIDATOR = "DV"
    REPORTING = "RP"


AGENT_NAMES = {
    "PL": "Planning Agent",
    "OR": "Orchestrator",
    "PO": "Passive OSINT",
    "AR": "Active Recon",
    "CV": "CVE Researcher",
    "AP": "Attack Path Analyzer",
    "WV": "Web Vuln Scanner",
    "EC": "Exploit Crafter",
    "EX": "Exploitation",
    "VF": "Verification",
    "PE": "Post-Exploitation",
    "DV": "Detection Validator",
    "RP": "Reporting",
}

AGENT_PTES_PHASE = {
    "PL": 1, "OR": 0, "PO": 2, "AR": 2,
    "CV": 3, "AP": 3, "WV": 4, "EC": 4,
    "EX": 5, "VF": 5, "PE": 6, "DV": 6, "RP": 7,
}


class AgentStatus(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    WAITING = "waiting"       # Waiting for HITL approval
    COMPLETED = "completed"
    ERROR = "error"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class ApprovalRequest(BaseModel):
    id: str
    agent: str
    action: str
    description: str
    risk_level: str
    target: Optional[str] = None
    timestamp: float
    status: ApprovalStatus = ApprovalStatus.PENDING


class Finding(BaseModel):
    id: str
    title: str
    severity: Severity
    category: str
    target: str
    agent: str
    description: str
    cvss: Optional[float] = None
    cve: Optional[str] = None
    evidence: Optional[str] = None
    timestamp: float
    engagement: str


class AgentEvent(BaseModel):
    id: str
    type: str
    agent: str
    content: str
    timestamp: float
    metadata: Optional[dict] = None


class Engagement(BaseModel):
    id: str
    name: str
    target: str
    status: str
    start_date: str
    agents_active: int
    findings_count: int
    phase: str
    authorization: str = "documented"


# ──────────────────────────────────────────────
# Neo4j Connection
# ──────────────────────────────────────────────

NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://kali.linux.vkloud.antsle.us:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASS = os.environ.get("NEO4J_PASS", "athena2026")

neo4j_driver = None
neo4j_available = False

if NEO4J_AVAILABLE:
    try:
        neo4j_driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
        neo4j_driver.verify_connectivity()
        neo4j_available = True
        print(f"  Neo4j:      {NEO4J_URI} ✓")
    except Exception as e:
        print(f"  Neo4j:      Unavailable ({e}) - using mock data")
        neo4j_driver = None
        neo4j_available = False
else:
    print("  Neo4j:      neo4j package not installed - using mock data")


# ──────────────────────────────────────────────
# Kali Backend Configuration
# ──────────────────────────────────────────────

KALI_EXTERNAL_URL = os.environ.get("KALI_EXTERNAL_URL", "http://kali.linux.vkloud.antsle.us:5000")
KALI_INTERNAL_URL = os.environ.get("KALI_INTERNAL_URL", "http://172.26.80.76:5000")
KALI_INTERNAL_API_KEY = os.environ.get("KALI_API_KEY", "")

# Initialize Kali client and orchestrator (set up after state is created below)
kali_client: KaliClient | None = None
orchestrator: Orchestrator | None = None


# ──────────────────────────────────────────────
# State Management
# ──────────────────────────────────────────────

class DashboardState:
    """In-memory state for dashboard. Persists during server lifetime."""

    def __init__(self):
        self.agent_statuses: dict[str, AgentStatus] = {
            code: AgentStatus.IDLE for code in AGENT_NAMES
        }
        self.agent_tasks: dict[str, str] = {}
        self.events: list[AgentEvent] = []
        self.findings: list[Finding] = []
        self.approval_requests: dict[str, ApprovalRequest] = {}
        self.engagements: list[Engagement] = []
        self.connected_clients: set[WebSocket] = set()
        self._event_lock = asyncio.Lock()
        self.active_engagement_id: str | None = None  # Set when engagement is created/selected
        # Demo control
        self.demo_pause_event = asyncio.Event()
        self.demo_pause_event.set()  # Not paused initially
        self.demo_stopped = False
        self.demo_task: asyncio.Task | None = None
        # Phase C: HITL approval blocking + engagement control
        self.approval_events: dict[str, dict] = {}  # approval_id → {event, approved}
        self.engagement_task: asyncio.Task | None = None
        self.engagement_stopped = False

    # Seed methods removed in Phase C — dashboard starts clean.
    # Demo mode (/api/demo/start) generates its own events independently.

    async def broadcast(self, event: dict):
        """Send event to all connected WebSocket clients."""
        message = json.dumps(event)
        disconnected = set()
        for ws in self.connected_clients:
            try:
                await ws.send_text(message)
            except (WebSocketDisconnect, RuntimeError):
                disconnected.add(ws)
        self.connected_clients -= disconnected

    async def add_event(self, event: AgentEvent):
        """Store event and broadcast to clients."""
        async with self._event_lock:
            self.events.append(event)
            # Keep last 500 events in memory
            if len(self.events) > 500:
                self.events = self.events[-500:]
        await self.broadcast({
            "type": event.type,
            "id": event.id,
            "agent": event.agent,
            "agentName": AGENT_NAMES.get(event.agent, event.agent),
            "content": event.content,
            "timestamp": event.timestamp,
            "metadata": event.metadata,
        })

    async def update_agent_status(self, agent: str, status: AgentStatus, task: str = ""):
        """Update agent status and broadcast."""
        self.agent_statuses[agent] = status
        if task:
            self.agent_tasks[agent] = task
        await self.broadcast({
            "type": "agent_status",
            "agent": agent,
            "agentName": AGENT_NAMES.get(agent, agent),
            "status": status.value,
            "task": task or self.agent_tasks.get(agent, ""),
            "timestamp": time.time(),
        })

    async def add_finding(self, finding: Finding):
        """Store finding and broadcast."""
        self.findings.append(finding)
        await self.broadcast({
            "type": "finding",
            "id": finding.id,
            "title": finding.title,
            "severity": finding.severity.value,
            "category": finding.category,
            "target": finding.target,
            "agent": finding.agent,
            "agentName": AGENT_NAMES.get(finding.agent, finding.agent),
            "description": finding.description,
            "cvss": finding.cvss,
            "cve": finding.cve,
            "timestamp": finding.timestamp,
            "engagement": finding.engagement,
        })

    async def request_approval(self, request: ApprovalRequest):
        """Create HITL approval request and broadcast."""
        self.approval_requests[request.id] = request
        await self.update_agent_status(request.agent, AgentStatus.WAITING)
        await self.broadcast({
            "type": "approval_request",
            "id": request.id,
            "agent": request.agent,
            "agentName": AGENT_NAMES.get(request.agent, request.agent),
            "action": request.action,
            "description": request.description,
            "risk_level": request.risk_level,
            "target": request.target,
            "timestamp": request.timestamp,
            "status": request.status.value,
        })

    async def resolve_approval(self, request_id: str, approved: bool, reason: str = ""):
        """Resolve HITL approval and broadcast. Unblocks waiting agents."""
        if request_id not in self.approval_requests:
            return False
        req = self.approval_requests[request_id]
        req.status = ApprovalStatus.APPROVED if approved else ApprovalStatus.REJECTED
        new_status = AgentStatus.RUNNING if approved else AgentStatus.IDLE
        await self.update_agent_status(req.agent, new_status)
        await self.broadcast({
            "type": "approval_resolved",
            "id": request_id,
            "agent": req.agent,
            "agentName": AGENT_NAMES.get(req.agent, req.agent),
            "approved": approved,
            "reason": reason,
            "timestamp": time.time(),
        })
        # Phase C: Unblock the waiting agent's asyncio.Event
        if request_id in self.approval_events:
            self.approval_events[request_id]["approved"] = approved
            self.approval_events[request_id]["event"].set()
        return True


# ──────────────────────────────────────────────
# Application
# ──────────────────────────────────────────────

state = DashboardState()

# Initialize Kali client + orchestrator
kali_client = KaliClient.from_env()
orchestrator = Orchestrator(state, kali_client)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown lifecycle."""
    print("\n  0K ATHENA Dashboard Server")
    print("  ─────────────────────────")
    print("  WebSocket:  ws://localhost:8080/ws")
    print("  Dashboard:  http://localhost:8080")
    print("  API Docs:   http://localhost:8080/docs")
    print("  Agent API:  POST /api/events")
    # Phase C: Check Kali backend connectivity
    health = await kali_client.health_check_all()
    for name, info in health.items():
        status = "✓" if info.get("available") else f"✗ ({info.get('error', 'unreachable')})"
        print(f"  Kali ({name:8s}): {status}")
    tools = kali_client.list_tools()
    print(f"  Tool Registry: {len(tools)} tools loaded")
    print()
    yield
    print("\n  Shutting down ATHENA Dashboard Server...")
    if kali_client:
        await kali_client.close()


app = FastAPI(
    title="0K ATHENA Dashboard API",
    description="Real-time pentest agent orchestration and HITL approval system",
    version="1.0.0",
    lifespan=lifespan,
)


# ──────────────────────────────────────────────
# WebSocket Endpoint
# ──────────────────────────────────────────────

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    """Bidirectional WebSocket for real-time dashboard communication."""
    await ws.accept()
    state.connected_clients.add(ws)

    # Send current state snapshot on connect
    await ws.send_text(json.dumps({
        "type": "state_sync",
        "agents": {
            code: {
                "name": name,
                "status": state.agent_statuses[code].value,
                "task": state.agent_tasks.get(code, ""),
                "phase": AGENT_PTES_PHASE[code],
            }
            for code, name in AGENT_NAMES.items()
        },
        "pending_approvals": [
            {
                "id": req.id,
                "agent": req.agent,
                "agentName": AGENT_NAMES.get(req.agent, req.agent),
                "action": req.action,
                "description": req.description,
                "risk_level": req.risk_level,
                "target": req.target,
                "timestamp": req.timestamp,
                "status": req.status.value,
            }
            for req in state.approval_requests.values()
            if req.status == ApprovalStatus.PENDING
        ],
        "recent_events": [
            {
                "id": e.id,
                "type": e.type,
                "agent": e.agent,
                "agentName": AGENT_NAMES.get(e.agent, e.agent),
                "content": e.content,
                "timestamp": e.timestamp,
                "metadata": e.metadata,
            }
            for e in state.events[-50:]
        ],
        "timestamp": time.time(),
    }))

    try:
        while True:
            raw = await ws.receive_text()
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                await ws.send_text(json.dumps({
                    "type": "error",
                    "content": "Invalid JSON",
                    "timestamp": time.time(),
                }))
                continue

            msg_type = msg.get("type")

            if msg_type == "approve":
                request_id = msg.get("request_id")
                reason = msg.get("reason", "Approved by operator")
                ok = await state.resolve_approval(request_id, True, reason)
                if not ok:
                    await ws.send_text(json.dumps({
                        "type": "error",
                        "content": f"Unknown approval request: {request_id}",
                        "timestamp": time.time(),
                    }))

            elif msg_type == "reject":
                request_id = msg.get("request_id")
                reason = msg.get("reason", "Rejected by operator")
                ok = await state.resolve_approval(request_id, False, reason)
                if not ok:
                    await ws.send_text(json.dumps({
                        "type": "error",
                        "content": f"Unknown approval request: {request_id}",
                        "timestamp": time.time(),
                    }))

            elif msg_type == "operator_command":
                cmd_text = msg.get("content", "").strip()
                if cmd_text:
                    # Broadcast the command so all clients see it
                    await state.broadcast({
                        "type": "operator_command",
                        "content": cmd_text,
                        "timestamp": time.time(),
                    })
                    # Generate an AI acknowledgment response
                    await asyncio.sleep(0.8)
                    response = _generate_command_response(cmd_text)
                    await state.broadcast({
                        "type": "operator_response",
                        "agent": "OR",
                        "agentName": AGENT_NAMES.get("OR", "Orchestrator"),
                        "content": response,
                        "timestamp": time.time(),
                    })

            elif msg_type == "ping":
                await ws.send_text(json.dumps({
                    "type": "pong",
                    "timestamp": time.time(),
                }))

    except WebSocketDisconnect:
        state.connected_clients.discard(ws)
    except Exception:
        state.connected_clients.discard(ws)


# ──────────────────────────────────────────────
# REST API — Agent Events (for Claude Code agents to call)
# ──────────────────────────────────────────────

class EventPayload(BaseModel):
    type: str
    agent: str
    content: str
    metadata: Optional[dict] = None


@app.post("/api/events")
async def post_event(payload: EventPayload):
    """
    Agents post events here. Used by ATHENA agents via curl/httpx.

    Example:
        curl -X POST http://localhost:8080/api/events \\
          -H 'Content-Type: application/json' \\
          -d '{"type":"agent_thinking","agent":"AR","content":"Analyzing Naabu scan results..."}'
    """
    event = AgentEvent(
        id=str(uuid.uuid4())[:8],
        type=payload.type,
        agent=payload.agent,
        content=payload.content,
        timestamp=time.time(),
        metadata=payload.metadata,
    )
    await state.add_event(event)

    # Auto-update agent status based on event type
    if payload.type == "agent_thinking":
        await state.update_agent_status(payload.agent, AgentStatus.RUNNING, payload.content)
    elif payload.type == "agent_complete":
        await state.update_agent_status(payload.agent, AgentStatus.COMPLETED)
    elif payload.type == "agent_error":
        await state.update_agent_status(payload.agent, AgentStatus.ERROR)

    return {"ok": True, "event_id": event.id}


class AgentStatusPayload(BaseModel):
    agent: str
    status: str
    task: Optional[str] = ""


@app.post("/api/agents/status")
async def update_agent_status(payload: AgentStatusPayload):
    """Update agent status directly."""
    try:
        status = AgentStatus(payload.status)
    except ValueError:
        return JSONResponse(
            status_code=400,
            content={"error": f"Invalid status: {payload.status}. Valid: {[s.value for s in AgentStatus]}"}
        )
    await state.update_agent_status(payload.agent, status, payload.task or "")
    return {"ok": True}


class ApprovalPayload(BaseModel):
    agent: str
    action: str
    description: str
    risk_level: str = "high"
    target: Optional[str] = None


@app.post("/api/approvals")
async def create_approval(payload: ApprovalPayload):
    """
    Create a HITL approval request. Dashboard shows popup to operator.

    Example:
        curl -X POST http://localhost:8080/api/approvals \\
          -H 'Content-Type: application/json' \\
          -d '{"agent":"EX","action":"Run SQLMap","description":"SQL injection validation on login form","risk_level":"high","target":"https://target.com/login"}'
    """
    req = ApprovalRequest(
        id=str(uuid.uuid4())[:8],
        agent=payload.agent,
        action=payload.action,
        description=payload.description,
        risk_level=payload.risk_level,
        target=payload.target,
        timestamp=time.time(),
    )
    await state.request_approval(req)
    return {"ok": True, "approval_id": req.id}


@app.post("/api/approvals/{request_id}/resolve")
async def resolve_approval_api(request_id: str, approved: bool = True, reason: str = ""):
    """Resolve a HITL approval via REST (alternative to WebSocket)."""
    ok = await state.resolve_approval(request_id, approved, reason)
    if not ok:
        return JSONResponse(status_code=404, content={"error": "Approval request not found"})
    return {"ok": True}


class FindingPayload(BaseModel):
    title: str
    severity: str
    category: str
    target: str
    agent: str
    description: str
    cvss: Optional[float] = None
    cve: Optional[str] = None
    evidence: Optional[str] = None
    engagement: str = "eng-001"


@app.post("/api/findings")
async def create_finding(payload: FindingPayload):
    """
    Report a new vulnerability finding.

    Example:
        curl -X POST http://localhost:8080/api/findings \\
          -H 'Content-Type: application/json' \\
          -d '{"title":"SQL Injection in login","severity":"critical","category":"A03","target":"https://target.com/login","agent":"WV","description":"Blind SQLi via username parameter","cvss":9.8,"cve":"CVE-2026-1234","engagement":"eng-001"}'
    """
    try:
        sev = Severity(payload.severity)
    except ValueError:
        return JSONResponse(
            status_code=400,
            content={"error": f"Invalid severity: {payload.severity}"}
        )
    finding_id = str(uuid.uuid4())[:8]
    timestamp = time.time()

    # Write to Neo4j if available
    if neo4j_available and neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                session.run("""
                    MERGE (f:Finding {id: $id})
                    SET f.title = $title, f.severity = $severity,
                        f.category = $category, f.target = $target,
                        f.agent = $agent, f.description = $description,
                        f.cvss = $cvss, f.cve = $cve, f.evidence = $evidence,
                        f.timestamp = $timestamp, f.engagement_id = $engagement,
                        f.status = 'open'
                    WITH f
                    MATCH (e:Engagement {id: $engagement})
                    MERGE (f)-[:BELONGS_TO]->(e)
                """, id=finding_id, title=payload.title,
                     severity=payload.severity, category=payload.category,
                     target=payload.target, agent=payload.agent,
                     description=payload.description, cvss=payload.cvss,
                     cve=payload.cve, evidence=payload.evidence,
                     timestamp=timestamp, engagement=payload.engagement)
        except Exception as e:
            print(f"Neo4j finding write error: {e}")

    # Always write to in-memory state for real-time broadcast
    finding = Finding(
        id=finding_id,
        title=payload.title,
        severity=sev,
        category=payload.category,
        target=payload.target,
        agent=payload.agent,
        description=payload.description,
        cvss=payload.cvss,
        cve=payload.cve,
        evidence=payload.evidence,
        timestamp=timestamp,
        engagement=payload.engagement,
    )
    await state.add_finding(finding)
    return {"ok": True, "finding_id": finding_id}


# ──────────────────────────────────────────────
# REST API — Query endpoints
# ──────────────────────────────────────────────

@app.get("/api/agents")
async def get_agents():
    """Get all agent statuses."""
    return {
        code: {
            "name": name,
            "code": code,
            "status": state.agent_statuses[code].value,
            "task": state.agent_tasks.get(code, ""),
            "phase": AGENT_PTES_PHASE[code],
        }
        for code, name in AGENT_NAMES.items()
    }


@app.get("/api/engagements")
async def get_engagements(include_archived: bool = False):
    """Get all engagements from Neo4j or fallback to mock data."""
    if neo4j_available and neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                query = """
                    MATCH (e:Engagement)
                    RETURN e.id AS id, e.name AS name, e.client AS client,
                           e.scope AS scope, e.type AS type, e.status AS status,
                           e.start_date AS start_date
                    ORDER BY e.start_date DESC
                """
                result = session.run(query)
                engagements = []
                for record in result:
                    status = record.get("status", "active")
                    if not include_archived and status == "archived":
                        continue
                    engagements.append({
                        "id": record["id"],
                        "name": record["name"],
                        "client": record.get("client", "Unknown"),
                        "scope": record.get("scope", ""),
                        "type": record.get("type", "external"),
                        "status": status,
                        "start_date": record.get("start_date", ""),
                    })
                return {"engagements": engagements, "source": "neo4j"}
        except Exception as e:
            print(f"Neo4j query error: {e}")
            # Fall through to mock data

    # Fallback: return mock engagements
    all_eng = [e.model_dump() for e in state.engagements]
    if not include_archived:
        all_eng = [e for e in all_eng if e.get("status") != "archived"]
    return {"engagements": all_eng, "source": "mock"}


class CreateEngagementPayload(BaseModel):
    name: str
    client: str
    scope: str
    types: list[str] = ["external"]
    authorization: str = "manual"  # "documented" (SoW/RoE uploaded) or "manual" (operator assertion)


@app.post("/api/engagements/parse-scope")
async def parse_scope_document(file: UploadFile = File(...)):
    """Parse uploaded SoW/RoE document and extract scope information.

    Supports .txt, .md, .pdf (text extraction). Returns extracted scope targets.
    In production this would call an LLM — for now uses regex extraction.
    """
    import re

    content = await file.read()
    try:
        text = content.decode("utf-8", errors="ignore")
    except Exception:
        text = str(content)

    # Extract common scope patterns
    targets = []
    # IP ranges (CIDR)
    targets.extend(re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?\b", text))
    # Domains / wildcards
    targets.extend(re.findall(r"\b\*?\.[a-zA-Z0-9-]+\.[a-zA-Z]{2,}\b", text))
    targets.extend(re.findall(r"\b(?:https?://)?[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?\b", text))
    # Deduplicate and clean
    seen = set()
    unique = []
    for t in targets:
        t_clean = t.strip().lower()
        if t_clean not in seen and len(t_clean) > 3:
            seen.add(t_clean)
            unique.append(t.strip())

    return {
        "ok": True,
        "filename": file.filename,
        "scope_targets": unique[:50],  # Cap at 50
        "scope_text": ", ".join(unique[:50]) if unique else "",
        "raw_length": len(text),
    }


@app.post("/api/engagements")
async def create_engagement(payload: CreateEngagementPayload):
    """Create new engagement in Neo4j or mock data."""
    engagement_id = f"eng-{str(uuid.uuid4())[:6]}"
    start_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    types_str = ",".join(payload.types)

    if neo4j_available and neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                session.run("""
                    CREATE (e:Engagement {
                        id: $id,
                        name: $name,
                        client: $client,
                        scope: $scope,
                        types: $types,
                        authorization: $authorization,
                        status: 'active',
                        start_date: $start_date
                    })
                """, id=engagement_id, name=payload.name, client=payload.client,
                     scope=payload.scope, types=types_str,
                     authorization=payload.authorization, start_date=start_date)

            # Broadcast engagement change
            await state.broadcast({
                "type": "engagement_changed",
                "engagement_id": engagement_id,
                "timestamp": time.time(),
            })

            return {"ok": True, "engagement_id": engagement_id}
        except Exception as e:
            print(f"Neo4j write error: {e}")
            # Fall through to mock

    # Fallback: add to mock list
    new_engagement = Engagement(
        id=engagement_id,
        name=payload.name,
        target=payload.scope,
        status="active",
        start_date=start_date,
        agents_active=0,
        findings_count=0,
        phase="Planning",
        authorization=payload.authorization,
    )
    state.engagements.append(new_engagement)

    await state.broadcast({
        "type": "engagement_changed",
        "engagement_id": engagement_id,
        "timestamp": time.time(),
    })

    return {"ok": True, "engagement_id": engagement_id}


class UpdateEngagementPayload(BaseModel):
    status: str  # "active", "archived", "completed"


@app.patch("/api/engagements/{eid}")
async def update_engagement(eid: str, payload: UpdateEngagementPayload):
    """Update engagement status (archive, complete, reactivate)."""
    if neo4j_available and neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                session.run(
                    "MATCH (e:Engagement {id: $id}) SET e.status = $status",
                    id=eid, status=payload.status,
                )
            await state.broadcast({
                "type": "engagement_changed",
                "engagement_id": eid,
                "timestamp": time.time(),
            })
            return {"ok": True}
        except Exception as e:
            print(f"Neo4j update error: {e}")

    # Fallback: update mock data
    for eng in state.engagements:
        if eng.id == eid:
            eng.status = payload.status
            break
    else:
        return JSONResponse(status_code=404, content={"error": "Engagement not found"})

    await state.broadcast({
        "type": "engagement_changed",
        "engagement_id": eid,
        "timestamp": time.time(),
    })
    return {"ok": True}


@app.delete("/api/engagements/{eid}")
async def delete_engagement(eid: str):
    """Delete an engagement permanently."""
    if neo4j_available and neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                session.run(
                    "MATCH (e:Engagement {id: $id}) DETACH DELETE e",
                    id=eid,
                )
            await state.broadcast({
                "type": "engagement_changed",
                "engagement_id": eid,
                "timestamp": time.time(),
            })
            return {"ok": True}
        except Exception as e:
            print(f"Neo4j delete error: {e}")

    # Fallback: remove from mock data
    state.engagements = [e for e in state.engagements if e.id != eid]

    await state.broadcast({
        "type": "engagement_changed",
        "engagement_id": eid,
        "timestamp": time.time(),
    })
    return {"ok": True}


@app.get("/api/engagements/{eid}/summary")
async def get_engagement_summary(eid: str):
    """Get engagement statistics from Neo4j or mock data."""
    if neo4j_available and neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                result = session.run("""
                    MATCH (e:Engagement {id: $eid})
                    OPTIONAL MATCH (e)<-[:BELONGS_TO]-(h:Host)
                    OPTIONAL MATCH (h)<-[:RUNS_ON]-(s:Service)
                    OPTIONAL MATCH (h)<-[:AFFECTS]-(v:Vulnerability)
                    OPTIONAL MATCH (e)<-[:BELONGS_TO]-(f:Finding)
                    RETURN count(DISTINCT h) AS hosts,
                           count(DISTINCT s) AS services,
                           count(DISTINCT v) AS vulns,
                           count(DISTINCT f) AS findings,
                           collect(DISTINCT f.severity) AS severities
                """, eid=eid)
                record = result.single()
                if record:
                    severities = record["severities"]
                    return {
                        "hosts": record["hosts"],
                        "services": record["services"],
                        "vulnerabilities": record["vulns"],
                        "findings": record["findings"],
                        "severity": {
                            "critical": severities.count("critical"),
                            "high": severities.count("high"),
                            "medium": severities.count("medium"),
                            "low": severities.count("low"),
                        }
                    }
        except Exception as e:
            print(f"Neo4j summary query error: {e}")
            # Fall through to mock

    # Fallback: return mock summary
    eng = next((e for e in state.engagements if e.id == eid), None)
    if not eng:
        return JSONResponse(status_code=404, content={"error": "Engagement not found"})

    return {
        "hosts": 156,
        "services": 89,
        "vulnerabilities": 8,
        "findings": eng.findings_count,
        "severity": {
            "critical": 2,
            "high": 1,
            "medium": 4,
            "low": 0,
        }
    }


@app.get("/api/findings")
async def get_findings(severity: Optional[str] = None, engagement: Optional[str] = None):
    """Get findings from Neo4j or fallback to mock data."""
    if neo4j_available and neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                conditions = []
                params = {}
                if severity:
                    conditions.append("f.severity = $severity")
                    params["severity"] = severity
                if engagement:
                    conditions.append("f.engagement_id = $engagement")
                    params["engagement"] = engagement
                where = " WHERE " + " AND ".join(conditions) if conditions else ""
                query = f"""
                    MATCH (f:Finding){where}
                    RETURN f.id AS id, f.title AS title, f.severity AS severity,
                           f.category AS category, f.target AS target, f.agent AS agent,
                           f.description AS description, f.cvss AS cvss, f.cve AS cve,
                           f.evidence AS evidence, f.timestamp AS timestamp,
                           f.engagement_id AS engagement
                    ORDER BY f.cvss DESC
                """
                result = session.run(query, **params)
                findings = []
                for record in result:
                    findings.append({
                        "id": record["id"],
                        "title": record["title"],
                        "severity": record["severity"],
                        "category": record.get("category", ""),
                        "target": record.get("target", ""),
                        "agent": record.get("agent", ""),
                        "description": record.get("description", ""),
                        "cvss": record.get("cvss"),
                        "cve": record.get("cve"),
                        "evidence": record.get("evidence"),
                        "timestamp": record.get("timestamp", 0),
                        "engagement": record.get("engagement", ""),
                    })
                return {"findings": findings, "source": "neo4j"}
        except Exception as e:
            print(f"Neo4j findings query error: {e}")
            # Fall through to mock

    # Fallback: filter in-memory findings
    results = state.findings
    if severity:
        results = [f for f in results if f.severity.value == severity]
    if engagement:
        results = [f for f in results if f.engagement == engagement]
    return {"findings": [f.model_dump() for f in results], "source": "mock"}


@app.get("/api/engagements/{eid}/findings")
async def get_engagement_findings(eid: str):
    """Get findings for engagement from Neo4j or fallback."""
    if neo4j_available and neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                result = session.run("""
                    MATCH (f:Finding)-[:BELONGS_TO]->(e:Engagement {id: $eid})
                    OPTIONAL MATCH (f)-[:AFFECTS]->(h:Host)
                    WITH f, collect(DISTINCT h.ip) AS affected_hosts
                    OPTIONAL MATCH (f)-[:EVIDENCED_BY]->(ep:EvidencePackage)
                    RETURN f.id AS id, f.title AS title, f.severity AS severity,
                           f.cvss AS cvss, f.status AS status, f.category AS category,
                           f.description AS description, affected_hosts,
                           count(DISTINCT ep) AS evidence_count
                    ORDER BY f.cvss DESC
                """, eid=eid)
                findings = []
                for record in result:
                    findings.append({
                        "id": record["id"],
                        "title": record["title"],
                        "severity": record["severity"],
                        "cvss": record["cvss"],
                        "status": record.get("status", "open"),
                        "category": record.get("category", ""),
                        "description": record.get("description", ""),
                        "affected_hosts": record["affected_hosts"],
                        "evidence_count": record["evidence_count"],
                    })
                return findings
        except Exception as e:
            print(f"Neo4j findings query error: {e}")
            # Fall through to mock

    # Fallback: filter in-memory findings
    results = [f for f in state.findings if f.engagement == eid]
    return [{
        "id": f.id,
        "title": f.title,
        "severity": f.severity.value,
        "cvss": f.cvss,
        "status": "open",
        "category": f.category,
        "description": f.description,
        "affected_hosts": [f.target],
        "evidence_count": 1 if f.evidence else 0,
    } for f in results]


@app.get("/api/engagements/{eid}/findings/{fid}/evidence")
async def get_finding_evidence(eid: str, fid: str):
    """Get evidence packages for a finding from Neo4j or fallback."""
    if neo4j_available and neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                result = session.run("""
                    MATCH (f:Finding {id: $fid})-[:EVIDENCED_BY]->(ep:EvidencePackage)
                    RETURN ep.id AS id, ep.type AS type, ep.timestamp AS timestamp,
                           ep.request AS request, ep.response AS response,
                           ep.screenshot AS screenshot, ep.notes AS notes
                    ORDER BY ep.timestamp DESC
                """, fid=fid)
                evidence = []
                for record in result:
                    evidence.append({
                        "id": record["id"],
                        "type": record["type"],
                        "timestamp": record["timestamp"],
                        "request": record.get("request"),
                        "response": record.get("response"),
                        "screenshot": record.get("screenshot"),
                        "notes": record.get("notes"),
                    })
                return evidence
        except Exception as e:
            print(f"Neo4j evidence query error: {e}")
            # Fall through to mock

    # Fallback: return mock evidence
    return [
        {
            "id": "ev-001",
            "type": "http",
            "timestamp": time.time() - 300,
            "request": "POST /login HTTP/1.1\nHost: portal.acme.com\n\nusername=admin' OR 1=1--&password=test",
            "response": "HTTP/1.1 200 OK\n\n{\"status\":\"success\",\"user\":\"admin\"}",
            "screenshot": None,
            "notes": "Boolean-based blind SQL injection confirmed",
        }
    ]


@app.get("/api/scans")
async def get_scans():
    """Get mock scan data for the Scans view (Phase A — mock only)."""
    return [
        {
            "id": "scan-001",
            "tool": "nmap",
            "tool_display": "Nmap Port Scan",
            "agent": "AR",
            "target": "10.0.0.0/24",
            "status": "completed",
            "started_at": "2026-02-20T10:30:00Z",
            "completed_at": "2026-02-20T10:31:45Z",
            "duration_s": 105,
            "findings_count": 3,
            "ports_found": 47,
            "command": "nmap -sV -sC -p- 10.0.0.0/24",
            "output_preview": "Starting Nmap 7.94 ( https://nmap.org )\nNmap scan report for 10.0.0.5\nHost is up (0.0012s latency).\nPORT     STATE SERVICE  VERSION\n22/tcp   open  ssh      OpenSSH 9.6\n80/tcp   open  http     Apache httpd 2.4.58\n443/tcp  open  ssl/http Apache httpd 2.4.58\n\n47 ports found across 156 hosts",
        },
        {
            "id": "scan-002",
            "tool": "nuclei",
            "tool_display": "Nuclei Vuln Scan",
            "agent": "WV",
            "target": "*.acme.com",
            "status": "completed",
            "started_at": "2026-02-20T10:32:00Z",
            "completed_at": "2026-02-20T10:38:12Z",
            "duration_s": 372,
            "findings_count": 5,
            "templates_matched": 7,
            "command": "nuclei -l targets.txt -severity critical,high,medium -o results.json",
            "output_preview": "                     __     _\n   ____  __  _______/ /__  (_)\n  / __ \\/ / / / ___/ / _ \\/ /\n / / / / /_/ / /__/ /  __/ /\n/_/ /_/\\__,_/\\___/_/\\___/_/ v3.2.0\n\n[INF] Loading 1,247 templates\n[critical] [cve-2026-21345] https://api.acme.com:8080\n[critical] [sqli-blind-boolean] https://portal.acme.com/login\n[high] [xss-reflected] https://portal.acme.com/search\n\n5 findings (2 critical, 1 high, 2 medium)",
        },
        {
            "id": "scan-003",
            "tool": "gobuster",
            "tool_display": "Gobuster Dir Scan",
            "agent": "AR",
            "target": "https://portal.acme.com",
            "status": "completed",
            "started_at": "2026-02-20T10:33:00Z",
            "completed_at": "2026-02-20T10:35:22Z",
            "duration_s": 142,
            "findings_count": 0,
            "dirs_found": 23,
            "command": "gobuster dir -u https://portal.acme.com -w /usr/share/wordlists/dirb/common.txt -t 50",
            "output_preview": "===============================================================\nGobuster v3.6\n===============================================================\n/admin                (Status: 403) [Size: 162]\n/api                  (Status: 301) [Size: 0]\n/uploads              (Status: 200) [Size: 4521]\n/backup               (Status: 403) [Size: 162]\n\n23 directories found",
        },
        {
            "id": "scan-004",
            "tool": "sqlmap",
            "tool_display": "SQLMap Injection Test",
            "agent": "EX",
            "target": "https://portal.acme.com/login",
            "status": "running",
            "started_at": "2026-02-20T10:40:00Z",
            "completed_at": None,
            "duration_s": None,
            "findings_count": 1,
            "command": "sqlmap -u 'https://portal.acme.com/login' --data='username=test&password=test' --technique=B --risk=1 --level=1 --batch",
            "output_preview": "[INFO] testing connection to the target URL\n[INFO] testing 'AND boolean-based blind'\n[INFO] GET parameter 'username' appears to be injectable\n[INFO] fetching database names...",
        },
        {
            "id": "scan-005",
            "tool": "nikto",
            "tool_display": "Nikto Web Scanner",
            "agent": "WV",
            "target": "https://portal.acme.com",
            "status": "completed",
            "started_at": "2026-02-20T10:34:00Z",
            "completed_at": "2026-02-20T10:37:48Z",
            "duration_s": 228,
            "findings_count": 2,
            "command": "nikto -h https://portal.acme.com -Format json -output nikto-results.json",
            "output_preview": "- Nikto v2.5.0\n+ Target IP:          10.0.0.5\n+ Target Hostname:    portal.acme.com\n+ Target Port:        443\n+ Server: Apache/2.4.58\n+ /admin/: Directory indexing found\n+ Apache/2.4.58 appears to be outdated\n+ 2 findings reported",
        },
        {
            "id": "scan-006",
            "tool": "httpx",
            "tool_display": "Httpx Service Probe",
            "agent": "AR",
            "target": "10.0.0.0/24",
            "status": "completed",
            "started_at": "2026-02-20T10:31:50Z",
            "completed_at": "2026-02-20T10:33:15Z",
            "duration_s": 85,
            "findings_count": 0,
            "services_found": 89,
            "command": "httpx -l alive-hosts.txt -tech-detect -status-code -title -json -o httpx-results.json",
            "output_preview": "    __    __  __       _  __\n   / /_  / /_/ /_____ | |/ /\n  / __ \\/ __/ __/ __ \\|   /\n / / / / /_/ /_/ /_/ /   |\n/_/ /_/\\__/\\__/ .___/_/|_| v1.6.0\n\nhttps://portal.acme.com [200] [WordPress 6.4] [PHP/8.1]\nhttps://api.acme.com:8080 [200] [Apache Struts 2.5]\n\n89 web services identified",
        },
        {
            "id": "scan-007",
            "tool": "katana",
            "tool_display": "Katana Web Crawler",
            "agent": "WV",
            "target": "https://app.acme.com",
            "status": "queued",
            "started_at": None,
            "completed_at": None,
            "duration_s": None,
            "findings_count": 0,
            "command": "katana -u https://app.acme.com -depth 3 -js-crawl -headless -o katana-results.txt",
            "output_preview": "Queued — waiting for Nuclei scan to complete",
        },
        {
            "id": "scan-008",
            "tool": "crackmapexec",
            "tool_display": "CrackMapExec SMB",
            "agent": "PE",
            "target": "10.0.0.0/24",
            "status": "error",
            "started_at": "2026-02-20T10:39:00Z",
            "completed_at": "2026-02-20T10:39:03Z",
            "duration_s": 3,
            "findings_count": 0,
            "command": "crackmapexec smb 10.0.0.0/24 --shares",
            "output_preview": "SMB  10.0.0.0/24  445  ERROR  Connection refused — SMB port filtered by firewall\nNo SMB services reachable in target subnet",
        },
    ]


@app.get("/api/reports")
async def get_reports():
    """Get mock report data for the Reports view (Phase A — mock only)."""
    return [
        {
            "id": "rpt-001",
            "title": "Acme Corp External — Executive Summary",
            "type": "executive",
            "engagement": "eng-001",
            "engagement_name": "Acme Corp External",
            "status": "final",
            "created_at": "2026-02-20T14:00:00Z",
            "updated_at": "2026-02-20T16:30:00Z",
            "author": "RP",
            "pages": 8,
            "findings_included": 7,
            "format": "pdf",
            "summary": "Executive overview for C-suite. Risk rating: HIGH. 2 critical, 1 high, 4 medium findings across 156 hosts.",
        },
        {
            "id": "rpt-002",
            "title": "Acme Corp External — Technical Report",
            "type": "technical",
            "engagement": "eng-001",
            "engagement_name": "Acme Corp External",
            "status": "final",
            "created_at": "2026-02-20T14:15:00Z",
            "updated_at": "2026-02-20T17:00:00Z",
            "author": "RP",
            "pages": 42,
            "findings_included": 7,
            "format": "pdf",
            "summary": "Full technical detail with reproduction steps, evidence packages, CVSS scoring, and affected host inventory.",
        },
        {
            "id": "rpt-003",
            "title": "Acme Corp External — Remediation Roadmap",
            "type": "remediation",
            "engagement": "eng-001",
            "engagement_name": "Acme Corp External",
            "status": "review",
            "created_at": "2026-02-20T15:00:00Z",
            "updated_at": "2026-02-20T15:45:00Z",
            "author": "RP",
            "pages": 12,
            "findings_included": 7,
            "format": "pdf",
            "summary": "Prioritized remediation plan with effort estimates, quick wins, and 30/60/90 day milestones.",
        },
        {
            "id": "rpt-004",
            "title": "GlobalBank API — Executive Summary",
            "type": "executive",
            "engagement": "eng-002",
            "engagement_name": "GlobalBank API",
            "status": "draft",
            "created_at": "2026-02-20T16:00:00Z",
            "updated_at": "2026-02-20T16:00:00Z",
            "author": "RP",
            "pages": 5,
            "findings_included": 15,
            "format": "pdf",
            "summary": "Draft executive summary. Engagement still active — findings count may increase.",
        },
        {
            "id": "rpt-005",
            "title": "GlobalBank API — Technical Report",
            "type": "technical",
            "engagement": "eng-002",
            "engagement_name": "GlobalBank API",
            "status": "generating",
            "created_at": "2026-02-20T16:30:00Z",
            "updated_at": "2026-02-20T16:30:00Z",
            "author": "RP",
            "pages": None,
            "findings_included": 15,
            "format": "pdf",
            "summary": "Technical report generation in progress...",
        },
        {
            "id": "rpt-006",
            "title": "Acme Corp External — Full Report",
            "type": "full",
            "engagement": "eng-001",
            "engagement_name": "Acme Corp External",
            "status": "delivered",
            "created_at": "2026-02-18T10:00:00Z",
            "updated_at": "2026-02-19T09:00:00Z",
            "author": "RP",
            "pages": 58,
            "findings_included": 7,
            "format": "pdf",
            "summary": "Combined executive + technical + remediation report. Delivered to client on 2026-02-19.",
        },
    ]


@app.get("/api/approvals")
async def get_approvals(status: Optional[str] = None):
    """Get approval requests with optional status filter."""
    results = list(state.approval_requests.values())
    if status:
        results = [r for r in results if r.status.value == status]
    return [r.model_dump() for r in results]


@app.get("/api/events")
async def get_events(limit: int = 50, agent: Optional[str] = None):
    """Get recent events."""
    results = state.events
    if agent:
        results = [e for e in results if e.agent == agent]
    return [e.model_dump() for e in results[-limit:]]


@app.get("/api/attack-graph")
async def get_attack_graph():
    """Return attack graph data from Neo4j or mock data."""
    if neo4j_available and neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                # Query nodes
                nodes = []
                for label, ntype in [("Host", "host"), ("Service", "service"),
                                      ("Vulnerability", "vulnerability"),
                                      ("Credential", "credential"), ("Finding", "finding")]:
                    result = session.run(
                        f"MATCH (n:{label}) RETURN n, labels(n) AS labels LIMIT 100"
                    )
                    for record in result:
                        node = dict(record["n"])
                        node_id = node.get("id", node.get("ip", node.get("name", str(id(node)))))
                        node_label = node.get("ip", node.get("title", node.get("name", node.get("id", ""))))
                        nodes.append({
                            "id": node_id,
                            "type": ntype,
                            "label": str(node_label),
                            "tooltip": node.get("title", node.get("description", str(node_label))),
                            "properties": {k: str(v) if v is not None else None for k, v in node.items()},
                        })

                # Query edges
                edges = []
                result = session.run("""
                    MATCH (a)-[r]->(b)
                    WHERE type(r) IN ['RUNS_ON', 'AFFECTS', 'EXPLOITS', 'LATERAL_MOVE',
                                       'HARVESTED_FROM', 'EVIDENCED_BY', 'BELONGS_TO']
                    RETURN
                        coalesce(a.id, a.ip, a.name) AS from_id,
                        coalesce(b.id, b.ip, b.name) AS to_id,
                        type(r) AS rel_type
                    LIMIT 500
                """)
                for record in result:
                    edges.append({
                        "from": str(record["from_id"]),
                        "to": str(record["to_id"]),
                        "type": record["rel_type"],
                        "label": record["rel_type"],
                    })

                if nodes:  # Only return Neo4j data if there's actual content
                    return {"nodes": nodes, "edges": edges, "attack_paths": [], "source": "neo4j"}
        except Exception as e:
            print(f"Neo4j attack graph query error: {e}")
            # Fall through to mock

    # Fallback: mock attack graph representing a realistic pentest kill chain
    mock_graph = {
        "nodes": [
            # Hosts
            {"id": "h1", "type": "host", "label": "192.168.1.10", "tooltip": "Web Server (Ubuntu 22.04)",
             "properties": {"ip": "192.168.1.10", "hostname": "web-prod-01", "os": "Ubuntu 22.04 LTS", "status": "compromised", "role": "Web Server"}},
            {"id": "h2", "type": "host", "label": "192.168.1.20", "tooltip": "Database Server (CentOS 8)",
             "properties": {"ip": "192.168.1.20", "hostname": "db-prod-01", "os": "CentOS 8", "status": "compromised", "role": "Database Server"}},
            {"id": "h3", "type": "host", "label": "192.168.1.30", "tooltip": "Mail Server (Exchange 2019)",
             "properties": {"ip": "192.168.1.30", "hostname": "mail-01", "os": "Windows Server 2019", "status": "vulnerable", "role": "Mail Server"}},
            {"id": "h4", "type": "host", "label": "192.168.1.50", "tooltip": "HR Workstation (Win 11)",
             "properties": {"ip": "192.168.1.50", "hostname": "ws-hr-04", "os": "Windows 11 Pro", "status": "compromised", "role": "Workstation"}},
            {"id": "h5", "type": "host", "label": "192.168.1.100", "tooltip": "Domain Controller (Win 2022)",
             "properties": {"ip": "192.168.1.100", "hostname": "dc-01", "os": "Windows Server 2022", "status": "at_risk", "role": "Domain Controller"}},
            # Services
            {"id": "s1", "type": "service", "label": "HTTPS:443", "tooltip": "Nginx 1.24 + Jenkins 2.426",
             "properties": {"port": "443", "protocol": "TCP", "service": "HTTPS", "product": "Nginx 1.24", "version": "1.24.0"}},
            {"id": "s2", "type": "service", "label": "SSH:22", "tooltip": "OpenSSH 9.3p1",
             "properties": {"port": "22", "protocol": "TCP", "service": "SSH", "product": "OpenSSH", "version": "9.3p1"}},
            {"id": "s3", "type": "service", "label": "MySQL:3306", "tooltip": "MySQL 8.0.35",
             "properties": {"port": "3306", "protocol": "TCP", "service": "MySQL", "product": "MySQL", "version": "8.0.35"}},
            {"id": "s4", "type": "service", "label": "SMTP:25", "tooltip": "Exchange SMTP",
             "properties": {"port": "25", "protocol": "TCP", "service": "SMTP", "product": "Microsoft Exchange"}},
            {"id": "s5", "type": "service", "label": "RDP:3389", "tooltip": "Remote Desktop",
             "properties": {"port": "3389", "protocol": "TCP", "service": "RDP", "product": "Microsoft Terminal Services"}},
            {"id": "s6", "type": "service", "label": "LDAP:389", "tooltip": "Active Directory LDAP",
             "properties": {"port": "389", "protocol": "TCP", "service": "LDAP", "product": "Microsoft AD LDAP"}},
            {"id": "s7", "type": "service", "label": "HTTP:8080", "tooltip": "Jenkins CI 2.426",
             "properties": {"port": "8080", "protocol": "TCP", "service": "HTTP", "product": "Jenkins", "version": "2.426"}},
            # Vulnerabilities
            {"id": "v1", "type": "vulnerability", "label": "CVE-2024-23897", "tooltip": "Jenkins CLI Arbitrary File Read (CRITICAL)",
             "properties": {"cve": "CVE-2024-23897", "severity": "CRITICAL", "cvss": "9.8", "title": "Jenkins CLI Arbitrary File Read", "exploited": "Yes"}},
            {"id": "v2", "type": "vulnerability", "label": "SQL Injection", "tooltip": "Blind SQL Injection in login form (HIGH)",
             "properties": {"severity": "HIGH", "cvss": "8.6", "title": "Blind SQL Injection - Login Form", "parameter": "username", "exploited": "Yes"}},
            {"id": "v3", "type": "vulnerability", "label": "CVE-2024-21762", "tooltip": "FortiOS Out-of-Bound Write (CRITICAL)",
             "properties": {"cve": "CVE-2024-21762", "severity": "CRITICAL", "cvss": "9.6", "title": "FortiOS Out-of-Bound Write RCE", "exploited": "No"}},
            {"id": "v4", "type": "vulnerability", "label": "Weak Creds", "tooltip": "Default Jenkins admin credentials (HIGH)",
             "properties": {"severity": "HIGH", "cvss": "7.5", "title": "Default Administrative Credentials", "detail": "admin:admin123", "exploited": "Yes"}},
            {"id": "v5", "type": "vulnerability", "label": "CVE-2023-44487", "tooltip": "HTTP/2 Rapid Reset (MEDIUM)",
             "properties": {"cve": "CVE-2023-44487", "severity": "MEDIUM", "cvss": "5.3", "title": "HTTP/2 Rapid Reset DoS", "exploited": "No"}},
            # Credentials
            {"id": "c1", "type": "credential", "label": "admin@web", "tooltip": "Jenkins admin (from default creds)",
             "properties": {"username": "admin", "source": "Default credentials", "access_level": "Admin", "target": "Jenkins CI"}},
            {"id": "c2", "type": "credential", "label": "sa@db", "tooltip": "MySQL sa (from SQL injection)",
             "properties": {"username": "sa", "source": "SQL Injection data exfil", "access_level": "DBA", "target": "MySQL 8.0"}},
            {"id": "c3", "type": "credential", "label": "CORP\\hr_admin", "tooltip": "Domain user (from workstation memory dump)",
             "properties": {"username": "CORP\\hr_admin", "source": "LSASS memory dump", "access_level": "Domain User", "target": "Active Directory"}},
            # Findings
            {"id": "f1", "type": "finding", "label": "Initial Access", "tooltip": "Initial access via Jenkins default creds",
             "properties": {"title": "Initial Access via Jenkins", "severity": "CRITICAL", "phase": "Initial Access", "technique": "T1078 - Valid Accounts", "status": "Confirmed"}},
            {"id": "f2", "type": "finding", "label": "Data Exfiltration", "tooltip": "Customer PII extracted via SQL injection",
             "properties": {"title": "Database Exfiltration via SQLi", "severity": "CRITICAL", "phase": "Collection", "technique": "T1213 - Data from Information Repositories", "status": "Confirmed"}},
            {"id": "f3", "type": "finding", "label": "Lateral Movement", "tooltip": "Pivoted from web to DB using harvested creds",
             "properties": {"title": "Lateral Movement to Database", "severity": "HIGH", "phase": "Lateral Movement", "technique": "T1021 - Remote Services", "status": "Confirmed"}},
            {"id": "f4", "type": "finding", "label": "Privilege Escalation", "tooltip": "Domain user escalation path identified",
             "properties": {"title": "Domain Privilege Escalation Path", "severity": "HIGH", "phase": "Privilege Escalation", "technique": "T1068 - Exploitation for Privilege Escalation", "status": "Validated"}},
        ],
        "edges": [
            # Services run on hosts
            {"from": "s1", "to": "h1", "type": "RUNS_ON", "label": "RUNS_ON"},
            {"from": "s2", "to": "h1", "type": "RUNS_ON", "label": "RUNS_ON"},
            {"from": "s7", "to": "h1", "type": "RUNS_ON", "label": "RUNS_ON"},
            {"from": "s3", "to": "h2", "type": "RUNS_ON", "label": "RUNS_ON"},
            {"from": "s4", "to": "h3", "type": "RUNS_ON", "label": "RUNS_ON"},
            {"from": "s5", "to": "h4", "type": "RUNS_ON", "label": "RUNS_ON"},
            {"from": "s6", "to": "h5", "type": "RUNS_ON", "label": "RUNS_ON"},
            # Vulnerabilities affect services
            {"from": "v1", "to": "s7", "type": "AFFECTS", "label": "AFFECTS"},
            {"from": "v4", "to": "s7", "type": "AFFECTS", "label": "AFFECTS"},
            {"from": "v5", "to": "s1", "type": "AFFECTS", "label": "AFFECTS"},
            {"from": "v2", "to": "s3", "type": "AFFECTS", "label": "AFFECTS"},
            {"from": "v3", "to": "s4", "type": "AFFECTS", "label": "AFFECTS"},
            # Credentials harvested from exploits
            {"from": "c1", "to": "v4", "type": "HARVESTED_FROM", "label": "HARVESTED"},
            {"from": "c2", "to": "v2", "type": "HARVESTED_FROM", "label": "HARVESTED"},
            {"from": "c3", "to": "h4", "type": "HARVESTED_FROM", "label": "DUMPED"},
            # Attack path / exploitation chain
            {"from": "v4", "to": "h1", "type": "EXPLOITS", "label": "EXPLOITS"},
            {"from": "v1", "to": "h1", "type": "EXPLOITS", "label": "EXPLOITS"},
            {"from": "h1", "to": "h2", "type": "LATERAL_MOVE", "label": "LATERAL"},
            {"from": "v2", "to": "h2", "type": "EXPLOITS", "label": "EXPLOITS"},
            {"from": "h2", "to": "h4", "type": "LATERAL_MOVE", "label": "LATERAL"},
            {"from": "h4", "to": "h5", "type": "LATERAL_MOVE", "label": "LATERAL"},
            # Findings evidence
            {"from": "f1", "to": "v4", "type": "EVIDENCED_BY", "label": "EVIDENCE"},
            {"from": "f2", "to": "v2", "type": "EVIDENCED_BY", "label": "EVIDENCE"},
            {"from": "f3", "to": "h2", "type": "EVIDENCED_BY", "label": "EVIDENCE"},
            {"from": "f4", "to": "h5", "type": "EVIDENCED_BY", "label": "EVIDENCE"},
        ],
        "attack_paths": [
            {"name": "Kill Chain Alpha", "steps": ["Jenkins Default Creds", "Web Server Access", "Lateral to DB", "SQL Data Exfil"]},
            {"name": "Kill Chain Beta", "steps": ["Jenkins CLI RCE", "SSH Key Harvest", "Pivot to Workstation", "LSASS Dump", "DC Access Path"]},
        ],
        "source": "mock",
    }
    return mock_graph


@app.get("/api/status")
async def get_status():
    """Return backend connection status for frontend status indicator."""
    kali_status = {}
    for name, backend in kali_client.backends.items():
        kali_status[name] = {
            "available": backend.available,
            "url": backend.base_url,
            "tools": len(backend.tools),
        }
    return {
        "neo4j": neo4j_available,
        "uri": NEO4J_URI if neo4j_available else None,
        "mode": "connected" if neo4j_available else "mock",
        "neo4j_driver_installed": NEO4J_AVAILABLE,
        "kali": kali_status,
        "tool_registry": len(kali_client.list_tools()),
    }


@app.get("/api/neo4j-config")
async def get_neo4j_config():
    """Return Neo4j connection config for browser-side Neovis.js (read-only credentials)."""
    if not neo4j_available:
        return JSONResponse(
            status_code=503,
            content={"error": "Neo4j not available", "available": False}
        )

    # Return read-only credentials for browser connection
    return {
        "available": True,
        "uri": NEO4J_URI,
        "user": NEO4J_USER,
        "password": NEO4J_PASS,  # TODO: Use read-only user in production
    }


# ──────────────────────────────────────────────
# Phase C: Real Engagement + Backend API
# ──────────────────────────────────────────────

@app.post("/api/engagement/{eid}/start")
async def start_engagement(eid: str, backend: str = ""):
    """Start a real PTES engagement against Kali backends.

    Launches the orchestrator which runs all 7 PTES phases with real tool
    execution on the dual Kali backends. HITL approvals block via asyncio.Event.

    Args:
        eid: Engagement ID (from Neo4j or mock state).
        backend: Force a specific backend ("external" or "internal").
            Overrides auto-detection for all tool executions.
            Use "external" for Antsle bridge targets (e.g. Metasploitable2).

    Demo mode (/api/demo/start) remains independent and unchanged.
    """
    # Validate backend if provided
    if backend and backend not in ("external", "internal"):
        return JSONResponse(status_code=400, content={
            "error": f"Invalid backend '{backend}'. Use 'external' or 'internal'."
        })

    # Verify engagement exists (check Neo4j first, then mock state)
    eng_found = False
    if neo4j_available and neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                result = session.run(
                    "MATCH (e:Engagement {id: $eid}) RETURN e.id AS id",
                    eid=eid,
                )
                record = result.single()
                if record:
                    eng_found = True
        except Exception:
            pass

    if not eng_found:
        eng = next((e for e in state.engagements if e.id == eid), None)
        if not eng:
            return JSONResponse(status_code=404, content={"error": f"Engagement {eid} not found"})

    # Cancel any running engagement
    if state.engagement_task and not state.engagement_task.done():
        state.engagement_stopped = True
        await asyncio.sleep(0.3)
        state.engagement_stopped = False

    state.active_engagement_id = eid
    state.engagement_stopped = False
    state.engagement_task = asyncio.create_task(
        orchestrator.run_engagement(eid, backend_override=backend)
    )
    msg = f"Engagement {eid} started"
    if backend:
        msg += f" (backend forced: {backend})"
    return {"ok": True, "engagement_id": eid, "message": msg}


@app.post("/api/engagement/{eid}/stop")
async def stop_engagement(eid: str):
    """Stop a running engagement."""
    state.engagement_stopped = True
    if state.engagement_task and not state.engagement_task.done():
        # Unblock any waiting HITL approvals so the task can exit
        for evt_data in state.approval_events.values():
            evt_data["approved"] = False
            evt_data["event"].set()
    # Reset agent statuses
    for code in AGENT_NAMES:
        if state.agent_statuses[code] != AgentStatus.IDLE:
            await state.update_agent_status(code, AgentStatus.IDLE)
    await state.broadcast({
        "type": "system",
        "content": f"Engagement {eid} stopped by operator",
        "timestamp": time.time(),
    })
    return {"ok": True, "message": f"Engagement {eid} stopped"}


@app.get("/api/backends")
async def get_backends():
    """Check Kali backend connectivity and available tools."""
    health = await kali_client.health_check_all()
    tools_by_backend = {}
    for name in kali_client.backends:
        tools_by_backend[name] = [
            t["name"] for t in kali_client.list_tools(backend=name)
        ]
    return {
        "health": health,
        "tools_by_backend": tools_by_backend,
        "total_tools": len(kali_client.list_tools()),
    }


@app.get("/api/tools")
async def get_tools(category: str = None, backend: str = None):
    """List available tools from the tool registry with optional filtering."""
    tools = kali_client.list_tools(category=category, backend=backend)
    return {"tools": tools, "count": len(tools)}


@app.post("/api/tools/reload")
async def reload_tools():
    """Hot-reload the tool registry from disk (no server restart needed)."""
    kali_client.reload_registry()
    tools = kali_client.list_tools()
    return {"ok": True, "tools_loaded": len(tools), "message": "Tool registry reloaded"}


# ──────────────────────────────────────────────
# Demo Mode — Simulate agent activity
# ──────────────────────────────────────────────

@app.post("/api/demo/start")
async def start_demo():
    """Start a demo simulation showing agent activity."""
    # Reset control flags
    state.demo_stopped = False
    state.demo_pause_event.set()
    # Cancel any existing demo
    if state.demo_task and not state.demo_task.done():
        state.demo_stopped = True
        state.demo_pause_event.set()
        await asyncio.sleep(0.2)
        state.demo_stopped = False
    state.demo_task = asyncio.create_task(_run_demo_scenario())
    return {"ok": True, "message": "Demo scenario started"}


@app.post("/api/demo/pause")
async def pause_demo():
    """Pause the running demo. Agents hold current state."""
    state.demo_pause_event.clear()
    # Set all running agents to waiting
    for code, status in state.agent_statuses.items():
        if status == AgentStatus.RUNNING:
            await state.update_agent_status(code, AgentStatus.WAITING, "Paused by operator")
    await _emit_system("Engagement paused by operator")
    return {"ok": True, "message": "Demo paused"}


@app.post("/api/demo/resume")
async def resume_demo():
    """Resume a paused demo."""
    # Restore waiting agents to running
    for code, status in state.agent_statuses.items():
        if status == AgentStatus.WAITING:
            await state.update_agent_status(code, AgentStatus.RUNNING, "Resumed")
    state.demo_pause_event.set()
    await _emit_system("Engagement resumed by operator")
    return {"ok": True, "message": "Demo resumed"}


@app.post("/api/demo/stop")
async def stop_demo():
    """Stop the running demo entirely."""
    state.demo_stopped = True
    state.demo_pause_event.set()  # Unblock if paused so task can exit
    # Set all non-idle agents to idle
    for code in AGENT_NAMES:
        if state.agent_statuses[code] != AgentStatus.IDLE:
            await state.update_agent_status(code, AgentStatus.IDLE)
    await _emit_system("Engagement stopped by operator")
    await _emit_phase("STOPPED")
    return {"ok": True, "message": "Demo stopped"}


async def _run_demo_scenario():
    """Simulate a realistic ATHENA engagement workflow with streaming tool output."""

    # ── Phase 1: PLANNING ──
    if not await _demo_checkpoint(): return
    await _emit_phase("PLANNING")
    await state.update_agent_status("PL", AgentStatus.RUNNING, "Validating authorization")
    await _emit_thinking("PL",
        thought="Need to validate Rules of Engagement before any scanning begins.",
        reasoning="Authorization is the first step in PTES methodology. Without confirmed scope, all subsequent scanning could be unauthorized.",
        action="validate_roe")
    await asyncio.sleep(2)

    pl_tool = str(uuid.uuid4())[:8]
    await _emit_tool_start("PL", "Validating authorization scope...", "roe_validator", pl_tool)
    await asyncio.sleep(0.5)
    await _emit_chunk("PL", pl_tool, "Loading Rules of Engagement document...\n")
    await asyncio.sleep(0.3)
    await _emit_chunk("PL", pl_tool, "Scope: *.acme.com, 10.0.0.0/24\n")
    await asyncio.sleep(0.3)
    await _emit_chunk("PL", pl_tool, "Excluded: mail.acme.com, 10.0.0.1 (prod gateway)\n")
    await asyncio.sleep(0.3)
    await _emit_chunk("PL", pl_tool, "Authorization: SIGNED — Valid through 2026-03-15\n")
    await _emit_tool_complete("PL", "Authorization validated. Scope: *.acme.com, 10.0.0.0/24", pl_tool)
    await state.update_agent_status("PL", AgentStatus.COMPLETED)
    await asyncio.sleep(1)

    # ── Phase 2: INTELLIGENCE GATHERING ──
    if not await _demo_checkpoint(): return
    await _emit_phase("INTELLIGENCE GATHERING")
    await state.update_agent_status("OR", AgentStatus.RUNNING, "Dispatching recon agents")
    await _emit_thinking("OR",
        thought="Target scope validated. Time to dispatch recon agents in parallel.",
        reasoning="Running Passive OSINT and Active Recon simultaneously maximizes coverage while minimizing elapsed time.",
        action="dispatch_agents")
    await asyncio.sleep(1.5)

    # Passive OSINT
    await state.update_agent_status("PO", AgentStatus.RUNNING, "Historical URL discovery")
    await _emit_thinking("PO",
        thought="Starting passive reconnaissance against acme.com.",
        reasoning="GAU + Wayback Machine will reveal historical endpoints without touching the target directly.")

    po_tool = str(uuid.uuid4())[:8]
    await _emit_tool_start("PO", "Running GAU against acme.com...", "gau_discover", po_tool)
    await asyncio.sleep(0.5)
    await _emit_chunk("PO", po_tool, "Fetching from Wayback Machine...\n")
    await asyncio.sleep(0.4)
    await _emit_chunk("PO", po_tool, "  [+] 1,247 URLs from web.archive.org\n")
    await asyncio.sleep(0.3)
    await _emit_chunk("PO", po_tool, "Fetching from Common Crawl...\n")
    await asyncio.sleep(0.4)
    await _emit_chunk("PO", po_tool, "  [+] 892 URLs from commoncrawl.org\n")
    await asyncio.sleep(0.3)
    await _emit_chunk("PO", po_tool, "Fetching from AlienVault OTX...\n")
    await asyncio.sleep(0.3)
    await _emit_chunk("PO", po_tool, "  [+] 708 URLs from otx.alienvault.com\n")
    await asyncio.sleep(0.3)
    await _emit_chunk("PO", po_tool, "\nTotal: 2,847 unique URLs\n")
    await asyncio.sleep(0.2)
    await _emit_chunk("PO", po_tool, "  API endpoints: 23\n  Admin paths: 8\n  Login forms: 3\n")
    await _emit_tool_complete("PO", "GAU found 2,847 historical URLs. 23 API endpoints, 8 admin paths.", po_tool)
    await asyncio.sleep(0.5)

    # Active Recon — Naabu (streaming)
    await state.update_agent_status("AR", AgentStatus.RUNNING, "Port scanning")
    await _emit_thinking("AR",
        thought="Starting active network reconnaissance with SYN scanning.",
        reasoning="Naabu SYN scan is fast and stealthy. Will identify all live hosts and open ports in the /24 subnet.",
        action="run_naabu")

    naabu_id = str(uuid.uuid4())[:8]
    await _emit_tool_start("AR", "Running Naabu SYN scan on 10.0.0.0/24...", "naabu_scan", naabu_id)
    await asyncio.sleep(0.4)
    await _emit_chunk("AR", naabu_id, "                  __\n")
    await asyncio.sleep(0.1)
    await _emit_chunk("AR", naabu_id, "  ___  ___  ___ _/ /  __ __\n")
    await asyncio.sleep(0.1)
    await _emit_chunk("AR", naabu_id, " / _ \\/ _ \\/ _ `/ _ \\/ // /\n")
    await asyncio.sleep(0.1)
    await _emit_chunk("AR", naabu_id, "/_//_/\\_,_/\\_,_/_.__/\\_,_/ v2.3.0\n\n")
    await asyncio.sleep(0.3)
    await _emit_chunk("AR", naabu_id, "[INF] Running SYN scan on 10.0.0.0/24\n")
    await asyncio.sleep(0.5)
    await _emit_chunk("AR", naabu_id, "10.0.0.5:22\n10.0.0.5:80\n10.0.0.5:443\n")
    await asyncio.sleep(0.4)
    await _emit_chunk("AR", naabu_id, "10.0.0.12:80\n10.0.0.12:8080\n10.0.0.12:3306\n")
    await asyncio.sleep(0.4)
    await _emit_chunk("AR", naabu_id, "10.0.0.23:22\n10.0.0.23:443\n10.0.0.23:8443\n")
    await asyncio.sleep(0.3)
    await _emit_chunk("AR", naabu_id, "10.0.0.41:80\n10.0.0.41:443\n10.0.0.41:9200\n")
    await asyncio.sleep(0.3)
    await _emit_chunk("AR", naabu_id, "\n[INF] Found 156 hosts alive, 847 ports open\n")
    await asyncio.sleep(0.2)
    await _emit_chunk("AR", naabu_id, "[INF] Top ports: 80(156) 443(142) 8080(34) 22(89) 3306(12)\n")
    await _emit_tool_complete("AR", "Naabu found 156 live hosts, 847 open ports. Top: 80, 443, 8080, 22, 3306.", naabu_id)
    await _emit_stats(hosts=156)
    await asyncio.sleep(1)

    # Active Recon — Httpx
    httpx_id = str(uuid.uuid4())[:8]
    await _emit_tool_start("AR", "Running Httpx on discovered ports...", "httpx_probe", httpx_id)
    await asyncio.sleep(0.3)
    await _emit_chunk("AR", httpx_id, "    __    __  __       _  __\n")
    await asyncio.sleep(0.1)
    await _emit_chunk("AR", httpx_id, "   / /_  / /_/ /_____ | |/ /\n")
    await asyncio.sleep(0.1)
    await _emit_chunk("AR", httpx_id, "  / __ \\/ __/ __/ __ \\|   /\n")
    await asyncio.sleep(0.1)
    await _emit_chunk("AR", httpx_id, " / / / / /_/ /_/ /_/ /   |\n")
    await asyncio.sleep(0.1)
    await _emit_chunk("AR", httpx_id, "/_/ /_/\\__/\\__/ .___/_/|_| v1.6.0\n\n")
    await asyncio.sleep(0.4)
    await _emit_chunk("AR", httpx_id, "https://portal.acme.com [200] [WordPress 6.4] [PHP/8.1]\n")
    await asyncio.sleep(0.3)
    await _emit_chunk("AR", httpx_id, "https://api.acme.com:8080 [200] [Apache Struts 2.5] [Java]\n")
    await asyncio.sleep(0.3)
    await _emit_chunk("AR", httpx_id, "https://app.acme.com [200] [React] [nginx/1.25]\n")
    await asyncio.sleep(0.3)
    await _emit_chunk("AR", httpx_id, "https://admin.acme.com [403] [nginx/1.25]\n")
    await asyncio.sleep(0.2)
    await _emit_chunk("AR", httpx_id, "\n[INF] 89 web services identified\n")
    await asyncio.sleep(0.2)
    await _emit_chunk("AR", httpx_id, "  WordPress: 3 | React SPA: 5 | API: 12 | Static: 69\n")
    await _emit_tool_complete("AR", "Httpx identified 89 web services. WordPress: 3, React SPA: 5, API: 12.", httpx_id)
    await _emit_stats(hosts=156, services=89)

    await state.update_agent_status("PO", AgentStatus.COMPLETED)
    await state.update_agent_status("AR", AgentStatus.COMPLETED)
    await asyncio.sleep(1)

    # ── Phase 3: THREAT MODELING ──
    if not await _demo_checkpoint(): return
    await _emit_phase("THREAT MODELING")
    await state.update_agent_status("CV", AgentStatus.RUNNING, "CVE database queries")
    await _emit_thinking("CV",
        thought="Cross-referencing detected technologies with vulnerability databases.",
        reasoning="Apache Struts 2.5 and WordPress 6.4 are priority targets. Need to check NVD, Exploit-DB, and CISA KEV for known exploits.",
        action="query_nvd")
    await asyncio.sleep(3)

    cv_tool = str(uuid.uuid4())[:8]
    await _emit_tool_start("CV", "Querying NVD, Exploit-DB, CISA KEV...", "cve_lookup", cv_tool)
    await asyncio.sleep(0.4)
    await _emit_chunk("CV", cv_tool, "[NVD] Querying Apache Struts 2.5.x...\n")
    await asyncio.sleep(0.5)
    await _emit_chunk("CV", cv_tool, "  CVE-2026-21345 CVSS:10.0 — RCE via OGNL injection [CISA KEV]\n")
    await asyncio.sleep(0.4)
    await _emit_chunk("CV", cv_tool, "  CVE-2025-48901 CVSS:9.1 — Auth bypass [CISA KEV]\n")
    await asyncio.sleep(0.4)
    await _emit_chunk("CV", cv_tool, "[NVD] Querying WordPress 6.4...\n")
    await asyncio.sleep(0.4)
    await _emit_chunk("CV", cv_tool, "  CVE-2026-10234 CVSS:7.5 — SQLi in REST API\n")
    await asyncio.sleep(0.3)
    await _emit_chunk("CV", cv_tool, "\n[CISA KEV] 3 actively exploited CVEs found\n")
    await _emit_tool_complete("CV", "Found 8 critical CVEs. 3 in CISA KEV. CVE-2026-21345 (Struts RCE) high priority.", cv_tool)
    await state.update_agent_status("CV", AgentStatus.COMPLETED)
    await asyncio.sleep(0.5)

    # Attack Path Analyzer — graph-based kill chain discovery
    await state.update_agent_status("AP", AgentStatus.RUNNING, "Building attack graph")
    await _emit_thinking("AP",
        thought="Constructing multi-step attack paths from CVE data and network topology.",
        reasoning="8 CVEs across 156 hosts create multiple kill chains. Need to identify paths from external-facing services to high-value targets (databases, AD controllers).",
        action="analyze_attack_paths")
    await asyncio.sleep(2)
    await _emit("agent_complete", "AP", "3 critical attack paths identified. Priority: Struts RCE → lateral movement → DB compromise.")
    await state.update_agent_status("AP", AgentStatus.COMPLETED)
    await asyncio.sleep(1)

    # ── Phase 4: VULNERABILITY ANALYSIS ──
    if not await _demo_checkpoint(): return
    await _emit_phase("VULNERABILITY ANALYSIS")
    await state.update_agent_status("WV", AgentStatus.RUNNING, "Nuclei scanning")
    await _emit_thinking("WV",
        thought="Launching Nuclei with critical, high, medium templates against all 89 web targets.",
        reasoning="Nuclei's template-based approach will validate CVE researcher findings and discover additional web vulnerabilities.",
        action="run_nuclei")

    nuclei_id = str(uuid.uuid4())[:8]
    await _emit_tool_start("WV", "Running Nuclei with critical,high,medium templates against 89 targets...", "nuclei_scan", nuclei_id)
    await asyncio.sleep(0.3)
    await _emit_chunk("WV", nuclei_id, "                     __     _\n")
    await asyncio.sleep(0.1)
    await _emit_chunk("WV", nuclei_id, "   ____  __  _______/ /__  (_)\n")
    await asyncio.sleep(0.1)
    await _emit_chunk("WV", nuclei_id, "  / __ \\/ / / / ___/ / _ \\/ /\n")
    await asyncio.sleep(0.1)
    await _emit_chunk("WV", nuclei_id, " / / / / /_/ / /__/ /  __/ /\n")
    await asyncio.sleep(0.1)
    await _emit_chunk("WV", nuclei_id, "/_/ /_/\\__,_/\\___/_/\\___/_/ v3.2.0\n\n")
    await asyncio.sleep(0.3)
    await _emit_chunk("WV", nuclei_id, "[INF] Loading 1,247 templates (critical: 89, high: 234, medium: 924)\n")
    await asyncio.sleep(0.5)
    await _emit_chunk("WV", nuclei_id, "[INF] Targets loaded: 89\n\n")
    await asyncio.sleep(0.8)
    await _emit_chunk("WV", nuclei_id, "[critical] [cve-2026-21345] [http] https://api.acme.com:8080\n")
    await asyncio.sleep(0.5)

    # Finding 1 mid-stream
    await state.add_finding(Finding(
        id=str(uuid.uuid4())[:8],
        title="SQL Injection — Login Form",
        severity=Severity.CRITICAL,
        category="A03",
        target="https://portal.acme.com/login",
        agent="WV",
        description="Blind SQL injection via username parameter. Boolean-based extraction confirmed.",
        cvss=9.8,
        cve=None,
        timestamp=time.time(),
        engagement="eng-001",
    ))

    await _emit_chunk("WV", nuclei_id, "[critical] [sqli-blind-boolean] [http] https://portal.acme.com/login\n")
    await asyncio.sleep(0.6)

    # Finding 2 mid-stream
    await state.add_finding(Finding(
        id=str(uuid.uuid4())[:8],
        title="Apache Struts RCE (CVE-2026-21345)",
        severity=Severity.CRITICAL,
        category="A06",
        target="https://api.acme.com:8080",
        agent="WV",
        description="Remote code execution via OGNL injection in Content-Type header. CISA KEV listed.",
        cvss=10.0,
        cve="CVE-2026-21345",
        timestamp=time.time(),
        engagement="eng-001",
    ))

    await _emit_chunk("WV", nuclei_id, "[high] [xss-reflected] [http] https://portal.acme.com/search?q=test\n")
    await asyncio.sleep(0.5)

    # Finding 3
    await state.add_finding(Finding(
        id=str(uuid.uuid4())[:8],
        title="Cross-Site Scripting (Reflected)",
        severity=Severity.HIGH,
        category="A03",
        target="https://portal.acme.com/search?q=",
        agent="WV",
        description="Reflected XSS in search parameter. No CSP header present.",
        cvss=6.1,
        timestamp=time.time(),
        engagement="eng-001",
    ))

    await _emit_chunk("WV", nuclei_id, "[medium] [cors-misconfiguration] [http] https://api.acme.com:8080\n")
    await asyncio.sleep(0.4)
    await _emit_chunk("WV", nuclei_id, "[medium] [missing-csp] [http] https://portal.acme.com\n")
    await asyncio.sleep(0.3)
    await _emit_chunk("WV", nuclei_id, "[medium] [outdated-nginx] [http] https://admin.acme.com\n")
    await asyncio.sleep(0.3)
    await _emit_chunk("WV", nuclei_id, "[medium] [directory-listing] [http] https://files.acme.com/uploads/\n")
    await asyncio.sleep(0.3)
    await _emit_chunk("WV", nuclei_id, "\n[INF] Scan complete: 2 critical, 1 high, 4 medium\n")
    await _emit_tool_complete("WV", "Nuclei scan complete. 2 critical, 1 high, 4 medium findings.", nuclei_id)
    await _emit_stats(hosts=156, services=89, vulns=7, findings=4)
    await state.update_agent_status("WV", AgentStatus.COMPLETED)
    await asyncio.sleep(0.5)

    # Exploit Crafter — custom payload generation for unmatched vulns
    await state.update_agent_status("EC", AgentStatus.RUNNING, "Crafting custom payloads")
    await _emit_thinking("EC",
        thought="Nuclei confirmed standard CVEs. Checking for edge cases where no pre-built exploit exists.",
        reasoning="The CORS misconfiguration + missing CSP combo could allow chained exploitation. Crafting a custom XSS-to-CSRF payload for the admin panel.")
    await asyncio.sleep(2.5)
    await _emit("agent_complete", "EC", "Custom payload crafted: chained XSS→CSRF for admin panel. Ready for exploitation phase.")
    await state.update_agent_status("EC", AgentStatus.COMPLETED)
    await asyncio.sleep(1)

    # ── Phase 5: EXPLOITATION ── (HITL required)
    if not await _demo_checkpoint(): return
    await _emit_phase("EXPLOITATION")
    await state.update_agent_status("EX", AgentStatus.RUNNING, "Preparing exploitation validation")
    await _emit_thinking("EX",
        thought="Critical SQLi confirmed by Nuclei. Need to validate with SQLMap for proof-of-concept.",
        reasoning="SQLMap in read-only mode (--technique=B --risk=1 --level=1) will confirm the vulnerability without modifying data. HITL approval required per engagement rules.",
        action="request_approval")
    await asyncio.sleep(2)

    # HITL Approval Request
    await state.request_approval(ApprovalRequest(
        id=str(uuid.uuid4())[:8],
        agent="EX",
        action="Run SQLMap (read-only validation)",
        description="Validate blind SQL injection on portal.acme.com/login with SQLMap in read-only mode. No data modification. Target: username parameter.",
        risk_level="high",
        target="https://portal.acme.com/login",
        timestamp=time.time(),
    ))

    # Auto-approve after 15s for demo
    await asyncio.sleep(15)
    for req_id, req in state.approval_requests.items():
        if req.agent == "EX" and req.status == ApprovalStatus.PENDING:
            await state.resolve_approval(req_id, True, "Auto-approved (demo mode)")
            break

    # SQLMap streaming output
    sqlmap_id = str(uuid.uuid4())[:8]
    await _emit_tool_start("EX", "Running SQLMap --technique=B --risk=1 --level=1 (read-only)...", "sqlmap", sqlmap_id)
    await asyncio.sleep(0.3)
    await _emit_chunk("EX", sqlmap_id, "        ___\n")
    await asyncio.sleep(0.1)
    await _emit_chunk("EX", sqlmap_id, "       __H__\n")
    await asyncio.sleep(0.1)
    await _emit_chunk("EX", sqlmap_id, " ___ ___[']_____ ___ ___  {1.8.2}\n")
    await asyncio.sleep(0.1)
    await _emit_chunk("EX", sqlmap_id, "|_ -| . [']     | .'| . |\n")
    await asyncio.sleep(0.1)
    await _emit_chunk("EX", sqlmap_id, "|___|_  [)]_|_|_|__,|  _|\n")
    await asyncio.sleep(0.1)
    await _emit_chunk("EX", sqlmap_id, "      |_|V...       |_|\n\n")
    await asyncio.sleep(0.4)
    await _emit_chunk("EX", sqlmap_id, "[*] starting @ 02:14:33 /2026-02-18/\n\n")
    await asyncio.sleep(0.5)
    await _emit_chunk("EX", sqlmap_id, "[INFO] testing connection to the target URL\n")
    await asyncio.sleep(0.6)
    await _emit_chunk("EX", sqlmap_id, "[INFO] testing 'AND boolean-based blind'\n")
    await asyncio.sleep(0.8)
    await _emit_chunk("EX", sqlmap_id, "[INFO] GET parameter 'username' appears to be 'AND boolean-based blind' injectable\n")
    await asyncio.sleep(0.5)
    await _emit_chunk("EX", sqlmap_id, "[INFO] fetching database names\n")
    await asyncio.sleep(0.6)
    await _emit_chunk("EX", sqlmap_id, "available databases [3]:\n")
    await asyncio.sleep(0.3)
    await _emit_chunk("EX", sqlmap_id, "[*] acme_portal\n[*] acme_api\n[*] information_schema\n\n")
    await asyncio.sleep(0.3)
    await _emit_chunk("EX", sqlmap_id, "back-end DBMS: MySQL >= 8.0\n")
    await _emit_tool_complete("EX", "SQLMap confirmed: MySQL 8.0, 3 databases accessible. Boolean-based blind injection validated.", sqlmap_id)
    await _emit_stats(hosts=156, services=89, vulns=8, findings=5)
    await state.update_agent_status("EX", AgentStatus.COMPLETED)
    await asyncio.sleep(0.5)

    # Verification Agent — independent exploit re-verification
    await state.update_agent_status("VF", AgentStatus.RUNNING, "Re-verifying SQLi exploit")
    await _emit_thinking("VF",
        thought="Independently re-executing SQLMap exploit to verify Exploitation Agent findings.",
        reasoning="The finder is not the verifier. Re-running with fresh session to confirm boolean-based blind SQLi on portal.acme.com/search. Must produce matching evidence.")
    await asyncio.sleep(3)
    await _emit("agent_complete", "VF", "VERIFIED: SQLi confirmed independently. Evidence hash matches. Finding elevated to CONFIRMED status.")
    await state.update_agent_status("VF", AgentStatus.COMPLETED)
    await asyncio.sleep(1)

    # ── Phase 6: POST-EXPLOITATION ──
    if not await _demo_checkpoint(): return
    await _emit_phase("POST-EXPLOITATION")
    await state.update_agent_status("PE", AgentStatus.RUNNING, "Simulating attack paths")
    await _emit_thinking("PE",
        thought="SIMULATION MODE: Mapping potential lateral movement from SQL injection compromise.",
        reasoning="Simulated post-exploitation maps the blast radius without actually pivoting. Shows client the real-world impact of the SQLi finding.")
    await asyncio.sleep(3)

    pe_tool = str(uuid.uuid4())[:8]
    await _emit_tool_start("PE", "Simulating lateral movement paths...", "attack_path_sim", pe_tool)
    await asyncio.sleep(0.4)
    await _emit_chunk("PE", pe_tool, "[SIM] Path 1: DB pivot → internal network via MySQL outfile\n")
    await asyncio.sleep(0.5)
    await _emit_chunk("PE", pe_tool, "[SIM] Path 2: Credential reuse across 12 hosts (password hash extraction)\n")
    await asyncio.sleep(0.5)
    await _emit_chunk("PE", pe_tool, "[SIM] Path 3: Privilege escalation via MySQL UDF injection\n")
    await _emit_tool_complete("PE", "3 attack paths simulated: DB pivot, credential reuse (12 hosts), MySQL UDF escalation.", pe_tool)
    await _emit_stats(hosts=156, services=89, vulns=8, findings=7)
    await state.update_agent_status("PE", AgentStatus.COMPLETED)
    await asyncio.sleep(0.5)

    # Detection Validator — purple team detection coverage
    await state.update_agent_status("DV", AgentStatus.RUNNING, "Checking detection coverage")
    await _emit_thinking("DV",
        thought="Querying client SIEM/EDR for detection of exploitation and post-exploitation activity.",
        reasoning="Need to determine if the SQLi exploitation, lateral movement simulation, and UDF escalation attempts triggered any alerts. Undetected activity is often the most critical finding for the client.")
    await asyncio.sleep(2.5)
    await _emit("agent_complete", "DV", "Detection gaps: SQLi exploitation UNDETECTED by WAF. Lateral movement triggered 1 of 3 EDR rules. UDF escalation UNDETECTED.")
    await state.update_agent_status("DV", AgentStatus.COMPLETED)
    await asyncio.sleep(1)

    # ── Phase 7: REPORTING ──
    if not await _demo_checkpoint(): return
    await _emit_phase("REPORTING")
    await state.update_agent_status("RP", AgentStatus.RUNNING, "Generating report")
    await _emit_thinking("RP",
        thought="Compiling executive summary and technical findings for Acme Corp engagement.",
        reasoning="Report needs executive summary for C-suite, technical details for IT team, and remediation roadmap with priority ordering.")
    await asyncio.sleep(3)

    rp_tool = str(uuid.uuid4())[:8]
    await _emit_tool_start("RP", "Generating pentest report...", "report_generator", rp_tool)
    await asyncio.sleep(0.4)
    await _emit_chunk("RP", rp_tool, "Generating executive summary...\n")
    await asyncio.sleep(0.5)
    await _emit_chunk("RP", rp_tool, "Compiling technical findings (7 total)...\n")
    await asyncio.sleep(0.5)
    await _emit_chunk("RP", rp_tool, "Building remediation roadmap...\n")
    await asyncio.sleep(0.4)
    await _emit_chunk("RP", rp_tool, "Report saved: acme-corp-external-2026-02-18.pdf\n")
    await _emit_tool_complete("RP", "Report generated: 2 critical, 1 high, 4 medium findings. Executive summary + technical detail + remediation roadmap.", rp_tool)
    await state.update_agent_status("RP", AgentStatus.COMPLETED)
    await state.update_agent_status("OR", AgentStatus.COMPLETED, "Engagement complete")

    await _emit_phase("COMPLETE")
    await _emit("system", "OR", "Acme Corp External engagement completed. All 13 agents finished. Report ready for review.")


def _generate_command_response(cmd: str) -> str:
    """Generate a contextual AI acknowledgment for operator commands (demo mode)."""
    cmd_lower = cmd.lower()
    if "pause" in cmd_lower or "stop" in cmd_lower or "halt" in cmd_lower:
        return f"Acknowledged. Pausing active operations. Agents will hold current state until further instructions."
    elif "focus" in cmd_lower or "target" in cmd_lower or "prioritize" in cmd_lower:
        return f"Understood. Redirecting agent focus as requested. Updating task queue and notifying active agents."
    elif "stealth" in cmd_lower or "slow" in cmd_lower or "reduce" in cmd_lower or "rate" in cmd_lower:
        return f"Roger. Adjusting scan parameters to stealth profile. Rate limiting and timing randomization enabled."
    elif "skip" in cmd_lower or "exclude" in cmd_lower or "ignore" in cmd_lower:
        return f"Confirmed. Adding exclusions to scope. Active agents will avoid specified targets."
    elif "report" in cmd_lower or "status" in cmd_lower or "summary" in cmd_lower:
        return f"Generating status update. Compiling findings from all active agents..."
    elif "resume" in cmd_lower or "continue" in cmd_lower or "proceed" in cmd_lower:
        return f"Resuming operations. All paused agents re-entering active state."
    else:
        return f"Command received. Routing to relevant agents for execution."


async def _emit(event_type: str, agent: str, content: str, metadata: dict = None):
    """Helper to emit an event."""
    event = AgentEvent(
        id=str(uuid.uuid4())[:8],
        type=event_type,
        agent=agent,
        content=content,
        timestamp=time.time(),
        metadata=metadata,
    )
    await state.add_event(event)


async def _emit_thinking(agent: str, thought: str, reasoning: str, action: str = ""):
    """Emit agent_thinking with structured thought/reasoning/action fields."""
    metadata = {"thought": thought, "reasoning": reasoning}
    if action:
        metadata["action"] = action
    await _emit("agent_thinking", agent, thought, metadata)


async def _emit_tool_start(agent: str, content: str, tool: str, tool_id: str):
    """Emit tool_start with tool_id for streaming correlation."""
    await _emit("tool_start", agent, content, {"tool": tool, "tool_id": tool_id})


async def _emit_chunk(agent: str, tool_id: str, chunk: str):
    """Emit a streaming output chunk for a running tool."""
    await state.broadcast({
        "type": "tool_output_chunk",
        "agent": agent,
        "agentName": AGENT_NAMES.get(agent, agent),
        "tool_id": tool_id,
        "chunk": chunk,
        "timestamp": time.time(),
    })


async def _emit_tool_complete(agent: str, content: str, tool_id: str):
    """Emit tool_complete with tool_id to close out the streaming card."""
    await _emit("tool_complete", agent, content, {"tool_id": tool_id})


async def _emit_phase(phase: str):
    """Emit phase_update to all clients."""
    await state.broadcast({
        "type": "phase_update",
        "phase": phase,
        "timestamp": time.time(),
    })


async def _emit_system(message: str):
    """Emit a system message to the timeline."""
    await state.broadcast({
        "type": "system",
        "content": message,
        "agent": "OR",
        "agentName": "Orchestrator",
        "timestamp": time.time(),
    })


async def _demo_checkpoint():
    """Check pause/stop state. Returns True if demo should continue, False if stopped."""
    if state.demo_stopped:
        return False
    await state.demo_pause_event.wait()  # Blocks if paused
    return not state.demo_stopped


async def _emit_stats(hosts=None, services=None, vulns=None, findings=None):
    """Emit stat_update to update engagement statistics in real-time."""
    data = {"type": "stat_update", "timestamp": time.time()}
    if hosts is not None:
        data["hosts"] = hosts
    if services is not None:
        data["services"] = services
    if vulns is not None:
        data["vulns"] = vulns
    if findings is not None:
        data["findings"] = findings
    await state.broadcast(data)


# ──────────────────────────────────────────────
# Serve Dashboard
# ──────────────────────────────────────────────

DASHBOARD_DIR = Path(__file__).parent


@app.get("/")
async def serve_dashboard():
    """Serve the ATHENA dashboard."""
    return FileResponse(DASHBOARD_DIR / "index.html")


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {
        "status": "ok",
        "server": "0K ATHENA Dashboard",
        "version": "2.0.0",
        "phase": "C",
        "connected_clients": len(state.connected_clients),
        "agents": {code: state.agent_statuses[code].value for code in AGENT_NAMES},
        "neo4j": neo4j_available,
        "kali_backends": {
            name: backend.available for name, backend in kali_client.backends.items()
        },
        "tools_registered": len(kali_client.list_tools()),
        "timestamp": time.time(),
    }
