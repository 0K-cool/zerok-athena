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
import re
import shutil
import subprocess
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
    # Phase E: Web App Testing & Attack Path Chaining
    JS_ANALYZER = "JS"
    PARAM_DISCOVERY = "PD"
    WEBAPP_FUZZER = "WA"
    AUTH_TESTER = "AT"
    API_ATTACKER = "AA"
    LATERAL_MOVER = "LM"


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
    # Phase E
    "JS": "JS Analyzer",
    "PD": "Param Discovery",
    "WA": "Web App Fuzzer",
    "AT": "Auth Tester",
    "AA": "API Attacker",
    "LM": "Lateral Mover",
}

AGENT_PTES_PHASE = {
    "PL": 1, "OR": 0, "PO": 2, "AR": 2,
    "CV": 3, "AP": 3, "WV": 4, "EC": 4,
    "EX": 5, "VF": 5, "PE": 6, "DV": 6, "RP": 7,
    # Phase E
    "JS": 2, "PD": 4, "WA": 4, "AT": 4, "AA": 5, "LM": 6,
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
    type: str = "external"
    status: str
    start_date: str
    agents_active: int
    findings_count: int
    phase: str
    authorization: str = "documented"


# ──────────────────────────────────────────────
# Neo4j Connection
# ──────────────────────────────────────────────

NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://your-kali-host:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASS = os.environ.get("NEO4J_PASS", "$NEO4J_PASS")

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

KALI_EXTERNAL_URL = os.environ.get("KALI_EXTERNAL_URL", "http://your-kali-host:5000")
KALI_INTERNAL_URL = os.environ.get("KALI_INTERNAL_URL", "http://your-internal-kali:5000")
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
        self.scans: list[dict] = []
        self._credentials: dict[str, list[dict]] = {}  # engagement_id → [credential records]
        self._reports: list[dict] = []  # Reports registered via POST /api/reports
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
        self.engagement_pause_event = asyncio.Event()
        self.engagement_pause_event.set()  # Not paused initially
        # Phase E: Active engagement context for attack chain queries
        self.active_orchestrator_ctx = None

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

    async def add_credential(self, engagement_id: str, credential: dict):
        """Record a harvested credential and broadcast to clients."""
        if engagement_id not in self._credentials:
            self._credentials[engagement_id] = []
        credential["timestamp"] = time.time()
        self._credentials[engagement_id].append(credential)
        await self.broadcast({
            "type": "credential_harvested",
            "engagement": engagement_id,
            "credential": credential,
            "timestamp": time.time(),
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
        "engagement_active": (state.engagement_task is not None and not state.engagement_task.done()) or (_ai_process is not None and _ai_process.poll() is None),
        "engagement_paused": not state.engagement_pause_event.is_set() if (state.engagement_task and not state.engagement_task.done()) else False,
        "active_engagement_id": state.active_engagement_id,
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
    # Tool event fields — auto-packaged into metadata for frontend compatibility
    tool_id: Optional[str] = None
    tool_name: Optional[str] = None
    target: Optional[str] = None
    output: Optional[str] = None
    duration_s: Optional[float] = None
    findings_count: Optional[int] = None
    chunk: Optional[str] = None


@app.post("/api/events")
async def post_event(payload: EventPayload):
    """
    Agents post events here. Used by ATHENA agents via curl/httpx.

    For tool events, agents can send tool fields at top level — they are
    auto-packaged into metadata so the frontend renders expandable tool cards.

    Examples:
        # Thinking event
        curl -X POST http://localhost:8080/api/events \\
          -H 'Content-Type: application/json' \\
          -d '{"type":"agent_thinking","agent":"AR","content":"Analyzing scan results..."}'

        # Tool start (creates expandable card in AI drawer)
        curl -X POST http://localhost:8080/api/events \\
          -H 'Content-Type: application/json' \\
          -d '{"type":"tool_start","agent":"AR","tool_id":"nmap-1","tool_name":"nmap_scan","target":"10.1.1.13","content":"Starting Nmap scan"}'

        # Tool complete (fills output in card)
        curl -X POST http://localhost:8080/api/events \\
          -H 'Content-Type: application/json' \\
          -d '{"type":"tool_complete","agent":"AR","tool_id":"nmap-1","tool_name":"nmap_scan","content":"Scan done","output":"PORT STATE SERVICE\\n22/tcp open ssh\\n80/tcp open http","duration_s":12}'
    """

    # Auto-package top-level tool fields into metadata for frontend rendering
    meta = dict(payload.metadata or {})
    if payload.type in ("tool_start", "tool_complete"):
        if payload.tool_id:
            meta["tool_id"] = payload.tool_id
        if payload.tool_name:
            meta["tool"] = payload.tool_name
        if payload.target:
            meta["target"] = payload.target
        if payload.output:
            meta["output"] = payload.output
        if payload.duration_s is not None:
            meta["duration_s"] = payload.duration_s
        if payload.findings_count is not None:
            meta["findings_count"] = payload.findings_count

    event = AgentEvent(
        id=str(uuid.uuid4())[:8],
        type=payload.type,
        agent=payload.agent,
        content=payload.content,
        timestamp=time.time(),
        metadata=meta if meta else None,
    )

    # For tool_output_chunk, broadcast with top-level fields (frontend expects this)
    if payload.type == "tool_output_chunk" and payload.tool_id and payload.chunk:
        await state.broadcast({
            "type": "tool_output_chunk",
            "tool_id": payload.tool_id,
            "chunk": payload.chunk,
            "agent": payload.agent,
            "timestamp": time.time(),
        })
        return {"ok": True, "event_id": event.id}

    await state.add_event(event)

    # Auto-update agent status based on event type
    if payload.type == "agent_thinking":
        await state.update_agent_status(payload.agent, AgentStatus.RUNNING, payload.content)
    elif payload.type == "tool_start":
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


@app.post("/api/stats")
async def post_stats(request: dict):
    """Push stat updates from AI agents (hosts, services, vulns, findings counts).

    Broadcasts stat_update so dashboard KPIs update in real-time.
    Example:
        curl -X POST http://localhost:8080/api/stats \\
          -H 'Content-Type: application/json' \\
          -d '{"hosts":1,"services":23,"vulns":6,"findings":6}'
    """
    await state.broadcast({
        "type": "stat_update",
        "hosts": request.get("hosts", 0),
        "services": request.get("services", 0),
        "vulns": request.get("vulns", 0),
        "findings": request.get("findings", 0),
        "timestamp": time.time(),
    })
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


@app.get("/api/approvals/{request_id}")
async def get_approval_status(request_id: str):
    """
    Poll approval status (for external Claude Code agents).

    Agents POST to /api/approvals to create a request, then poll this endpoint
    until resolved=true. Returns approved=true/false once the operator decides.

    Example:
        curl http://localhost:8080/api/approvals/abc123
    """
    if request_id not in state.approval_requests:
        return JSONResponse(status_code=404, content={"error": "Approval request not found"})
    req = state.approval_requests[request_id]
    resolved = req.status != ApprovalStatus.PENDING
    return {
        "id": request_id,
        "agent": req.agent,
        "action": req.action,
        "target": req.target,
        "risk_level": req.risk_level,
        "resolved": resolved,
        "approved": req.status == ApprovalStatus.APPROVED if resolved else None,
        "status": req.status.value,
    }


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
    # Explicit relationship hints (optional — extracted from target if not provided)
    host_ip: Optional[str] = None
    service_port: Optional[int] = None
    service_protocol: Optional[str] = "tcp"
    technique_ids: Optional[list[str]] = None


def _extract_host_port(target: str) -> tuple[str | None, int | None]:
    """Extract host IP and port from various target formats.

    Handles: '10.1.1.20:3389', 'http://10.1.1.20/path', 'http://10.1.1.20:8080/path'
    Returns: (host_ip, port) — port is None for standard HTTP/HTTPS or when not specified.
    """
    if not target:
        return None, None

    ip_pattern = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
    ip_match = ip_pattern.search(target)
    if not ip_match:
        return None, None

    host_ip = ip_match.group(1)

    # Try to extract explicit port
    port = None
    # URL format: http://IP:PORT/path
    url_port = re.search(r"://[^/]*?:(\d+)", target)
    if url_port:
        p = int(url_port.group(1))
        if p not in (80, 443):  # Only track non-standard ports explicitly
            port = p
    elif "://" not in target:
        # Raw format: IP:PORT
        raw_port = re.search(r":(\d+)", target)
        if raw_port:
            port = int(raw_port.group(1))

    # Infer port from protocol
    if port is None:
        if target.startswith("https://"):
            port = 443
        elif target.startswith("http://"):
            port = 80

    return host_ip, port


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

    # Write to Neo4j if available — smart endpoint auto-creates relationships
    # Pattern: MERGE nodes individually, then MERGE relationships (BloodHound pattern)
    host_ip = payload.host_ip or _extract_host_port(payload.target)[0]
    svc_port = payload.service_port or _extract_host_port(payload.target)[1]
    svc_proto = payload.service_protocol or "tcp"

    if neo4j_available and neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                # Step 1: Create/update Finding node
                session.run("""
                    MERGE (f:Finding {id: $id})
                    SET f.title = $title, f.severity = $severity,
                        f.category = $category, f.target = $target,
                        f.agent = $agent, f.description = $description,
                        f.cvss = $cvss, f.cve = $cve, f.evidence = $evidence,
                        f.timestamp = $timestamp, f.engagement_id = $engagement,
                        f.status = 'open'
                """, id=finding_id, title=payload.title,
                     severity=payload.severity, category=payload.category,
                     target=payload.target, agent=payload.agent,
                     description=payload.description, cvss=payload.cvss,
                     cve=payload.cve, evidence=payload.evidence,
                     timestamp=timestamp, engagement=payload.engagement)

                # Step 2: Auto-create Host + FOUND_ON edge (MERGE = idempotent)
                if host_ip:
                    session.run("""
                        MERGE (h:Host {ip: $host_ip})
                        ON CREATE SET h.engagement_id = $engagement,
                                      h.status = 'alive',
                                      h.first_seen = datetime()
                        ON MATCH SET h.last_seen = datetime()
                        WITH h
                        MATCH (f:Finding {id: $finding_id})
                        MERGE (f)-[:FOUND_ON]->(h)
                    """, host_ip=host_ip, engagement=payload.engagement,
                         finding_id=finding_id)

                # Step 3: Auto-create Service + HAS_SERVICE + link Finding to Service
                if host_ip and svc_port:
                    svc_name = "http" if svc_port in (80, 443) else f"port-{svc_port}"
                    session.run("""
                        MERGE (h:Host {ip: $host_ip})
                        MERGE (s:Service {host_ip: $host_ip, port: $port})
                        ON CREATE SET s.name = $svc_name,
                                      s.protocol = $protocol,
                                      s.engagement_id = $engagement,
                                      s.state = 'open',
                                      s.first_seen = datetime()
                        ON MATCH SET s.last_seen = datetime()
                        MERGE (h)-[:HAS_SERVICE]->(s)
                        WITH s
                        MATCH (f:Finding {id: $finding_id})
                        MERGE (f)-[:AFFECTS]->(s)
                    """, host_ip=host_ip, port=svc_port, svc_name=svc_name,
                         protocol=svc_proto, engagement=payload.engagement,
                         finding_id=finding_id)

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

    # Broadcast stat_update so KPI cards update in real-time
    eid = payload.engagement or state.active_engagement_id
    if eid:
        eng_findings = [f for f in state.findings if f.engagement == eid]
        # Count unique hosts from findings targets
        hosts = set()
        for f in eng_findings:
            if f.target:
                host = f.target.split(":")[0].split("/")[0]
                if host:
                    hosts.add(host)
        await state.broadcast({
            "type": "stat_update",
            "hosts": len(hosts),
            "findings": len(eng_findings),
            "services": 0,  # Will be updated by scan agents
            "vulns": len([f for f in eng_findings if f.severity.value in ("critical", "high")]),
            "timestamp": time.time(),
        })

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
                    OPTIONAL MATCH (e)<-[:BELONGS_TO]-(f:Finding)
                    RETURN e.id AS id, e.name AS name, e.client AS client,
                           e.scope AS scope, e.types AS type, e.status AS status,
                           e.start_date AS start_date,
                           count(DISTINCT f) AS findings_count
                    ORDER BY e.start_date DESC
                """
                result = session.run(query)
                engagements = []
                for record in result:
                    status = record.get("status", "active")
                    if not include_archived and status == "archived":
                        continue
                    # Determine phase: if this is the active AI engagement, show "AI Mode"
                    eid = record["id"]
                    phase = "Active" if status == "active" else "—"
                    if eid == state.active_engagement_id:
                        phase = "AI Mode"
                    engagements.append({
                        "id": eid,
                        "name": record["name"],
                        "client": record.get("client", "Unknown"),
                        "scope": record.get("scope", ""),
                        "target": record.get("scope", ""),
                        "type": record.get("type", "external"),
                        "status": status,
                        "start_date": record.get("start_date", ""),
                        "findings_count": max(
                            record.get("findings_count", 0),
                            len([f for f in state.findings if f.engagement == eid]),
                        ),
                        "phase": phase,
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
        type=types_str,
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
                    WITH e, count(DISTINCT h) AS hosts,
                         count(DISTINCT s) AS services,
                         count(DISTINCT v) AS vulns
                    OPTIONAL MATCH (e)<-[:BELONGS_TO]-(f:Finding)
                    RETURN hosts, services, vulns,
                           count(DISTINCT f) AS findings,
                           count(DISTINCT CASE WHEN f.severity = 'critical' THEN f END) AS sev_critical,
                           count(DISTINCT CASE WHEN f.severity = 'high' THEN f END) AS sev_high,
                           count(DISTINCT CASE WHEN f.severity = 'medium' THEN f END) AS sev_medium,
                           count(DISTINCT CASE WHEN f.severity = 'low' THEN f END) AS sev_low,
                           count(DISTINCT CASE WHEN f.category IN [
                               'Validated Exploit', 'Exploitation', 'Injection',
                               'Lateral Movement'
                           ] OR f.evidence IS NOT NULL THEN f END) AS exploits
                """, eid=eid)
                record = result.single()
                if record:
                    neo4j_hosts = record["hosts"]
                    neo4j_services = record["services"]
                    neo4j_findings = record["findings"]
                    # If Neo4j has real Host/Service data, use it; otherwise supplement from in-memory state
                    if neo4j_hosts > 0 or neo4j_findings > 0:
                        # Supplement: if Neo4j has findings but no Host nodes, derive from in-memory findings
                        mem_findings = [f for f in state.findings if f.engagement == eid]
                        mem_hosts = set()
                        for f in mem_findings:
                            if f.target:
                                h = f.target.split(":")[0].split("/")[0]
                                if h:
                                    mem_hosts.add(h)
                        mem_ports = sum(s.get("findings_count", 0) for s in state.scans
                                        if s.get("engagement_id") == eid and s.get("tool") in ("nmap_scan", "naabu_scan"))
                        # Use max of Neo4j and in-memory severity counts (handles missing BELONGS_TO)
                        mem_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
                        mem_exploits = 0
                        for f in mem_findings:
                            s = f.severity.value if hasattr(f.severity, 'value') else str(f.severity).lower()
                            if s in mem_sev:
                                mem_sev[s] += 1
                            if f.evidence or (f.category and f.category.lower() in ('validated exploit', 'exploitation', 'injection')):
                                mem_exploits += 1
                        return {
                            "hosts": max(neo4j_hosts, len(mem_hosts)),
                            "services": max(neo4j_services, mem_ports),
                            "vulnerabilities": record["vulns"],
                            "findings": max(neo4j_findings, len(mem_findings)),
                            "exploits": max(record["exploits"], mem_exploits),
                            "severity": {
                                "critical": max(record["sev_critical"], mem_sev["critical"]),
                                "high": max(record["sev_high"], mem_sev["high"]),
                                "medium": max(record["sev_medium"], mem_sev["medium"]),
                                "low": max(record["sev_low"], mem_sev["low"]),
                            }
                        }
        except Exception as e:
            print(f"Neo4j summary query error: {e}")
            # Fall through to mock

    # Fallback: compute summary from in-memory state (works for AI mode without Neo4j Host/Service nodes)
    eng_findings = [f for f in state.findings if f.engagement == eid]
    # Count unique hosts from finding targets
    hosts = set()
    for f in eng_findings:
        if f.target:
            host = f.target.split(":")[0].split("/")[0]
            if host:
                hosts.add(host)
    # Count open ports from scan data
    eng_scans = [s for s in state.scans if s.get("engagement_id") == eid]
    total_ports = sum(s.get("findings_count", 0) for s in eng_scans if s.get("tool") in ("nmap_scan", "naabu_scan"))
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    exploits = 0
    for f in eng_findings:
        s = f.severity.value if hasattr(f.severity, 'value') else str(f.severity).lower()
        if s in sev_counts:
            sev_counts[s] += 1
        if f.evidence or (f.category and f.category.lower() in ('validated exploit', 'exploitation', 'injection')):
            exploits += 1

    return {
        "hosts": len(hosts),
        "services": total_ports,
        "vulnerabilities": len([f for f in eng_findings if sev_counts.get(f.severity.value if hasattr(f.severity, 'value') else '', 0) >= 0]),
        "findings": len(eng_findings),
        "exploits": exploits,
        "severity": sev_counts,
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
                           f.description AS description, f.target AS target,
                           f.evidence AS evidence, affected_hosts,
                           count(DISTINCT ep) AS evidence_count
                    ORDER BY f.cvss DESC
                """, eid=eid)
                findings = []
                for record in result:
                    # Derive affected_hosts from target if no AFFECTS relationships
                    hosts = record["affected_hosts"]
                    if not hosts and record.get("target"):
                        # Extract host IP from target like "10.1.1.13:21"
                        host_part = record["target"].split(":")[0] if ":" in record["target"] else record["target"]
                        hosts = [host_part]
                    # Derive evidence_count from evidence text if no EVIDENCED_BY relationships
                    ev_count = record["evidence_count"]
                    if ev_count == 0 and record.get("evidence"):
                        ev_count = 1
                    findings.append({
                        "id": record["id"],
                        "title": record["title"],
                        "severity": record["severity"],
                        "cvss": record["cvss"],
                        "status": record.get("status", "open"),
                        "category": record.get("category", ""),
                        "description": record.get("description", ""),
                        "affected_hosts": hosts,
                        "evidence_count": ev_count,
                    })
                # If Neo4j returned data, use it; otherwise fall through to in-memory
                if findings:
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


@app.get("/api/engagements/{eid}/vuln-severity")
async def get_vuln_severity(eid: str):
    """Get Vulnerability node counts by severity for the donut chart."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    total = 0
    if neo4j_available and neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                result = session.run("""
                    MATCH (v:Vulnerability)-[:AFFECTS]->(h:Host)-[:BELONGS_TO]->(e:Engagement {id: $eid})
                    RETURN toLower(v.severity) AS severity, count(DISTINCT v) AS cnt
                """, eid=eid)
                for record in result:
                    sev = (record["severity"] or "info").lower()
                    cnt = record["cnt"]
                    if sev in counts:
                        counts[sev] += cnt
                    else:
                        counts["info"] += cnt
                    total += cnt
        except Exception as e:
            print(f"Neo4j vuln-severity error: {e}")

    # Fallback: compute from in-memory findings when Neo4j returned nothing
    if total == 0:
        mem_findings = [f for f in state.findings if f.engagement == eid]
        for f in mem_findings:
            sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity).lower()
            if sev in counts:
                counts[sev] += 1
            else:
                counts["info"] += 1
            total += 1

    return {"severity": counts, "total": total}


@app.get("/api/engagements/{eid}/exploit-stats")
async def get_exploit_stats(eid: str):
    """Get exploitation statistics: discovered vulns, confirmed exploits, MTTE."""
    discovered = 0
    confirmed = 0
    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    mtte_seconds = 0
    per_finding_times = []

    if neo4j_available and neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                result = session.run("""
                    MATCH (e:Engagement {id: $eid})
                    OPTIONAL MATCH (e)<-[:BELONGS_TO]-(f:Finding)
                    WITH e, collect(f) AS all_findings
                    RETURN size(all_findings) AS total_findings,
                           size([x IN all_findings WHERE x.category IN
                               ['Validated Exploit', 'Exploitation', 'Injection',
                                'Authentication Bypass', 'Lateral Movement']]) AS exploit_count,
                           [x IN all_findings WHERE x.category IN
                               ['Validated Exploit', 'Exploitation', 'Injection',
                                'Authentication Bypass', 'Lateral Movement'] |
                               {title: x.title, severity: x.severity, timestamp: x.timestamp}] AS exploit_details
                """, eid=eid)
                record = result.single()
                if record and record["total_findings"] > 0:
                    discovered = record["total_findings"]
                    confirmed = record["exploit_count"]
                    for ex in (record["exploit_details"] or []):
                        sev = (ex.get("severity") or "medium").lower()
                        if sev in by_severity:
                            by_severity[sev] += 1
        except Exception as e:
            print(f"Neo4j exploit-stats error: {e}")

    # Supplement from in-memory state (handles both: Neo4j returned 0 discovered, OR
    # Neo4j categories didn't match OWASP codes but evidence exists)
    mem_findings = [f for f in state.findings if f.engagement == eid]
    if discovered == 0:
        discovered = len(mem_findings)
    if confirmed == 0 and mem_findings:
        exploit_cats = {'validated exploit', 'exploitation', 'injection',
                        'authentication bypass', 'lateral movement'}
        for f in mem_findings:
            cat = (f.category or '').lower()
            # Count as confirmed exploit if: category matches OR has evidence
            is_exploit = any(ec in cat for ec in exploit_cats) or bool(f.evidence)
            if is_exploit:
                confirmed += 1
                sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity).lower()
                if sev in by_severity:
                    by_severity[sev] += 1

    success_rate = round((confirmed / max(discovered, 1)) * 100, 1)

    # MTTE: estimate from timestamp spread of findings (simplified)
    mem_findings = [f for f in state.findings if f.engagement == eid]
    exploit_cats = {'validated exploit', 'exploitation', 'injection',
                    'authentication bypass', 'lateral movement'}
    timestamps = sorted([f.timestamp for f in mem_findings])
    exploit_findings = [f for f in mem_findings
                        if any(ec in (f.category or '').lower() for ec in exploit_cats) or bool(f.evidence)]
    if timestamps and exploit_findings:
        start_ts = timestamps[0]
        for ef in exploit_findings:
            delta = int(ef.timestamp - start_ts)
            per_finding_times.append({"title": ef.title, "time_s": max(0, delta)})
        if per_finding_times:
            mtte_seconds = int(sum(t["time_s"] for t in per_finding_times) / len(per_finding_times))

    # Format MTTE display
    if mtte_seconds > 0:
        mins, secs = divmod(mtte_seconds, 60)
        mtte_display = f"{mins}m {secs:02d}s" if mins else f"{secs}s"
    else:
        mtte_display = "—"

    return {
        "discovered_vulns": discovered,
        "confirmed_exploits": confirmed,
        "success_rate": success_rate,
        "by_severity": by_severity,
        "mtte_seconds": mtte_seconds,
        "mtte_display": mtte_display,
        "per_finding": per_finding_times[:10],
    }


@app.get("/api/engagements/{eid}/services-summary")
async def get_services_summary(eid: str):
    """Get services/ports distribution for an engagement."""
    services = []

    if neo4j_available and neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                result = session.run("""
                    MATCH (s:Service)-[:RUNS_ON]->(h:Host)-[:BELONGS_TO]->(e:Engagement {id: $eid})
                    RETURN s.port AS port, s.name AS name,
                           count(DISTINCT h) AS host_count,
                           collect(DISTINCT s.version)[..3] AS versions
                    ORDER BY host_count DESC
                    LIMIT 8
                """, eid=eid)
                for record in result:
                    services.append({
                        "port": record["port"],
                        "name": record["name"] or f"port-{record['port']}",
                        "count": record["host_count"],
                        "versions": [v for v in (record["versions"] or []) if v],
                    })
        except Exception as e:
            print(f"Neo4j services-summary error: {e}")

    # Fallback: derive from in-memory findings targets
    if not services:
        port_counts = {}
        for f in state.findings:
            if f.engagement != eid:
                continue
            target = f.target or ""
            import re
            port_match = re.search(r':(\d+)', target)
            if port_match:
                port = int(port_match.group(1))
                name = {80: 'http', 443: 'https', 22: 'ssh', 3306: 'mysql',
                        8080: 'http-proxy', 445: 'smb', 21: 'ftp', 8443: 'https-alt',
                        3632: 'distccd', 8180: 'http-alt', 5432: 'postgresql',
                        1099: 'rmiregistry', 5900: 'vnc'}.get(port, f'port-{port}')
                if port not in port_counts:
                    port_counts[port] = {"port": port, "name": name, "count": 0, "versions": []}
                port_counts[port]["count"] += 1
        services = sorted(port_counts.values(), key=lambda x: x["count"], reverse=True)[:8]

    return services


@app.post("/api/engagements/{eid}/credentials")
async def add_engagement_credential(eid: str, payload: dict):
    """Add a harvested credential to an engagement (REST API for AI agents)."""
    await state.add_credential(eid, payload)
    return {"status": "ok", "message": "Credential recorded"}


@app.get("/api/engagements/{eid}/credentials")
async def get_engagement_credentials(eid: str):
    """Get harvested credentials for an engagement (in-memory + Neo4j fallback)."""
    raw_credentials = list(getattr(state, '_credentials', {}).get(eid, []))

    # Neo4j fallback — merge any Credential nodes not already in memory
    if neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                result = session.run("""
                    MATCH (c:Credential {engagement_id: $eid})
                    OPTIONAL MATCH (c)-[:YIELDED|HARVESTED_FROM]-(src)
                    RETURN c, coalesce(src.ip, src.title, src.name) AS source
                """, eid=eid)
                in_memory_keys = set()
                for mc in raw_credentials:
                    in_memory_keys.add(f"{mc.get('username','')}:{mc.get('host','')}:{mc.get('service','')}")
                for record in result:
                    node = dict(record["c"])
                    key = f"{node.get('username','')}:{node.get('host','')}:{node.get('service','')}"
                    if key not in in_memory_keys:
                        cred = {
                            "username": node.get("username", ""),
                            "host": node.get("host", ""),
                            "service": node.get("service", ""),
                            "type": node.get("type", "exploited"),
                            "access_level": node.get("access_level", "unknown"),
                            "source": record["source"] or node.get("source", ""),
                            "timestamp": node.get("discovered_at", time.time()),
                        }
                        raw_credentials.append(cred)
        except Exception:
            pass  # Neo4j unavailable — use in-memory only

    # Filter out entries with "unknown" usernames — those are NOT real credentials
    credentials = [
        c for c in raw_credentials
        if c.get("username") and c["username"].lower() not in ("unknown", "", "none")
    ]

    total = len(credentials)
    default_weak = sum(1 for c in credentials if c.get("type") in ("default", "weak"))
    unique_accounts = len(set(
        c.get("username", "") for c in credentials
    ))

    # Build per-host summary for the frontend
    hosts_accessed = {}
    for c in credentials:
        h = c.get("host", "unknown")
        if h not in hosts_accessed:
            hosts_accessed[h] = {"host": h, "services": set(), "access_levels": set()}
        hosts_accessed[h]["services"].add(c.get("service", ""))
        hosts_accessed[h]["access_levels"].add(c.get("access_level", "user"))
    # Convert sets to lists for JSON
    for v in hosts_accessed.values():
        v["services"] = list(v["services"])
        v["access_levels"] = list(v["access_levels"])

    return {
        "credentials": credentials,
        "total": total,
        "default_weak": default_weak,
        "unique_accounts": unique_accounts,
        "hosts_accessed": list(hosts_accessed.values()),
    }


@app.get("/api/engagements/{eid}/attack-chains")
async def get_attack_chains(eid: str):
    """Get discovered attack chains for an engagement."""
    chains = []

    # Check in-memory state from active orchestrator
    if state.active_orchestrator_ctx and state.active_orchestrator_ctx.engagement_id == eid:
        chains = state.active_orchestrator_ctx.attack_chains

    # Also query Neo4j for persisted chains
    if neo4j_available and neo4j_driver and not chains:
        try:
            with neo4j_driver.session() as session:
                result = session.run("""
                    MATCH (f1:Finding {engagement_id: $eid})-[r:LEADS_TO]->(f2:Finding)
                    RETURN f1.id AS src_id, f1.title AS src_title,
                           f1.agent AS src_agent, f1.severity AS src_severity,
                           f2.id AS dst_id, f2.title AS dst_title,
                           f2.agent AS dst_agent, f2.severity AS dst_severity,
                           r.chain_id AS chain_id, r.chain_severity AS chain_severity
                    ORDER BY r.chain_id
                """, eid=eid)
                chain_map = {}
                for record in result:
                    cid = record["chain_id"]
                    if cid not in chain_map:
                        chain_map[cid] = {
                            "id": cid,
                            "name": record["src_title"],
                            "steps": [],
                            "severity": record["chain_severity"] or "high",
                            "impact": "",
                        }
                    chain = chain_map[cid]
                    # Add source step if not already there
                    if not any(s["finding_id"] == record["src_id"] for s in chain["steps"]):
                        chain["steps"].append({
                            "agent": record["src_agent"],
                            "finding_id": record["src_id"],
                            "description": record["src_title"],
                        })
                    # Add destination step
                    if not any(s["finding_id"] == record["dst_id"] for s in chain["steps"]):
                        chain["steps"].append({
                            "agent": record["dst_agent"],
                            "finding_id": record["dst_id"],
                            "description": record["dst_title"],
                        })
                chains = list(chain_map.values())
        except Exception as e:
            logger.warning("Neo4j attack chain query error: %s", e)

    return {
        "chains": chains,
        "total": len(chains),
        "critical_chains": sum(1 for c in chains if c.get("severity") == "critical"),
    }


@app.get("/api/engagements/{eid}/web-findings")
async def get_web_findings(eid: str):
    """Get web-app-specific findings (XSS, injection, auth bypass, IDOR)."""
    web_categories = {
        "Cross-Site Scripting", "Authentication", "Authorization",
        "Injection", "Information Disclosure", "Lateral Movement",
        "Web Vulnerability", "Web Server",
    }

    web_findings = [
        {
            "id": f.id,
            "title": f.title,
            "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
            "category": f.category,
            "target": f.target,
            "agent": f.agent,
            "description": f.description,
            "cvss": f.cvss,
            "cve": f.cve,
            "timestamp": f.timestamp,
        }
        for f in state.findings
        if (
            getattr(f, "engagement", "") == eid
            and getattr(f, "category", "") in web_categories
        )
    ]

    # Group by category for summary
    category_counts = {}
    for wf in web_findings:
        cat = wf["category"]
        category_counts[cat] = category_counts.get(cat, 0) + 1

    return {
        "findings": web_findings,
        "total": len(web_findings),
        "by_category": category_counts,
    }


@app.delete("/api/engagements/{eid}/findings")
async def clear_engagement_findings(eid: str):
    """Delete all findings and evidence for an engagement."""
    deleted = 0

    # Clear from Neo4j
    if neo4j_available and neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                # Count first
                result = session.run("""
                    MATCH (f:Finding)-[:BELONGS_TO]->(e:Engagement {id: $eid})
                    RETURN count(f) AS cnt
                """, eid=eid)
                record = result.single()
                deleted = record["cnt"] if record else 0

                # Delete evidence packages then findings
                session.run("""
                    MATCH (f:Finding)-[:BELONGS_TO]->(e:Engagement {id: $eid})
                    OPTIONAL MATCH (f)-[:EVIDENCED_BY]->(ep:EvidencePackage)
                    DETACH DELETE ep
                """, eid=eid)
                session.run("""
                    MATCH (f:Finding)-[:BELONGS_TO]->(e:Engagement {id: $eid})
                    DETACH DELETE f
                """, eid=eid)
        except Exception as e:
            print(f"Neo4j clear findings error: {e}")

    # Clear from in-memory state
    before = len(state.findings)
    state.findings = [f for f in state.findings if f.engagement != eid]
    deleted = max(deleted, before - len(state.findings))

    return {"deleted": deleted, "engagement": eid}


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
async def get_scans(engagement: Optional[str] = None):
    """Get scan history from tool executions during engagements."""
    scans = state.scans
    if engagement:
        scans = [s for s in scans if s.get("engagement_id") == engagement]
    return scans


@app.post("/api/scans")
async def create_scan(request: dict):
    """Register a scan from an external AI agent (Phase E: AI Mode).

    Expected fields:
        tool (str): Tool name (e.g. "nmap_scan")
        target (str): Scan target
        agent (str): Agent code (e.g. "AR")
        engagement_id (str): Engagement ID
        status (str, optional): "running" (default), "completed", "error"
        tool_display (str, optional): Human-readable tool name
        duration_s (int, optional): Duration in seconds
        output_preview (str, optional): Truncated output
        findings_count (int, optional): Number of findings from this scan
        command (str, optional): Command string for display
    """
    scan_id = f"scan-{uuid.uuid4().hex[:8]}"
    now_iso = datetime.now(timezone.utc).isoformat()
    scan_record = {
        "id": scan_id,
        "tool": request.get("tool", "unknown"),
        "tool_display": request.get("tool_display", request.get("tool", "Unknown Tool")),
        "target": request.get("target", ""),
        "agent": request.get("agent", ""),
        "status": request.get("status", "running"),
        "duration_s": request.get("duration_s", 0),
        "findings_count": request.get("findings_count", 0),
        "started_at": request.get("started_at", now_iso),
        "completed_at": request.get("completed_at"),
        "engagement_id": request.get("engagement_id", state.active_engagement_id or ""),
        "output_preview": request.get("output_preview", ""),
        "command": request.get("command", request.get("tool_display", "")),
    }
    state.scans.append(scan_record)

    # Broadcast so Scans page updates in real-time
    await state.broadcast({
        "type": "scan_update",
        "scan": scan_record,
        "timestamp": time.time(),
    })

    return {"id": scan_id, "status": scan_record["status"]}


@app.patch("/api/scans/{scan_id}")
async def update_scan(scan_id: str, request: dict):
    """Update an existing scan record (e.g. mark completed with results).

    Updatable fields: status, duration_s, findings_count, output_preview, completed_at
    """
    scan = next((s for s in state.scans if s["id"] == scan_id), None)
    if not scan:
        return JSONResponse(status_code=404, content={"error": "Scan not found"})

    for field in ("status", "duration_s", "findings_count", "output_preview", "completed_at"):
        if field in request:
            scan[field] = request[field]

    # Auto-set completed_at if status changed to completed/error
    if request.get("status") in ("completed", "error") and not scan.get("completed_at"):
        scan["completed_at"] = datetime.now(timezone.utc).isoformat()

    # Broadcast update
    event_type = "scan_complete" if scan["status"] in ("completed", "error") else "scan_update"
    await state.broadcast({
        "type": event_type,
        "scan": scan,
        "timestamp": time.time(),
    })

    return {"id": scan_id, "status": scan["status"]}


@app.delete("/api/scans")
async def delete_scans(engagement: Optional[str] = None):
    """Delete scan records, optionally filtered by engagement."""
    if engagement:
        before = len(state.scans)
        state.scans = [s for s in state.scans if s.get("engagement_id") != engagement]
        deleted = before - len(state.scans)
    else:
        deleted = len(state.scans)
        state.scans.clear()
    return {"deleted": deleted}


def _read_report_meta(reporting_dir: Path) -> dict:
    """Read persisted report metadata from .report-meta.json."""
    meta_file = reporting_dir / ".report-meta.json"
    if meta_file.exists():
        try:
            return json.loads(meta_file.read_text())
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def _write_report_meta(reporting_dir: Path, meta: dict) -> None:
    """Write report metadata to .report-meta.json."""
    meta_file = reporting_dir / ".report-meta.json"
    meta_file.write_text(json.dumps(meta, indent=2))


def _find_report_dir(athena_dir: Path, report_id: str) -> tuple[Path | None, Path | None]:
    """Find the reporting directory and file for a given report ID."""
    engagements_dir = athena_dir / "engagements" / "active"
    if not engagements_dir.exists():
        return None, None
    for eng_dir in engagements_dir.iterdir():
        if not eng_dir.is_dir():
            continue
        reporting_dir = eng_dir / "09-reporting"
        if not reporting_dir.exists():
            continue
        for report_file in reporting_dir.iterdir():
            if report_file.is_file() and f"file-{report_file.stem}" == report_id:
                return reporting_dir, report_file
    return None, None


@app.get("/api/reports")
async def get_reports(engagement: Optional[str] = None, include_archived: bool = False):
    """Get reports by scanning engagement 09-reporting/ directories and in-memory state."""
    eid = engagement or state.active_engagement_id
    reports = list(state._reports)  # In-memory reports from POST

    # Also scan filesystem for report files in engagement directories
    athena_dir = Path(__file__).parent.parent.parent  # ATHENA project root
    engagements_dir = athena_dir / "engagements" / "active"
    if engagements_dir.exists():
        for eng_dir in engagements_dir.iterdir():
            if not eng_dir.is_dir():
                continue
            # Match engagement ID if provided (dir name starts with eid)
            if eid and not eng_dir.name.startswith(eid):
                continue
            reporting_dir = eng_dir / "09-reporting"
            if not reporting_dir.exists():
                continue
            # Load persisted metadata for this reporting directory
            meta = _read_report_meta(reporting_dir)
            for report_file in reporting_dir.iterdir():
                if report_file.is_file() and report_file.suffix in (".md", ".pdf", ".docx", ".html"):
                    file_id = f"file-{report_file.stem}"
                    # Skip if already registered via POST
                    if any(r.get("id") == file_id for r in reports):
                        continue
                    stat = report_file.stat()
                    # Derive engagement name from directory (e.g. eng-46fdb6_2026-02-24_WebApp → WebApp)
                    parts = eng_dir.name.split("_")
                    eng_name = parts[-1] if len(parts) >= 3 else eng_dir.name
                    # Apply persisted metadata (status, etc.)
                    saved = meta.get(file_id, {})
                    reports.append({
                        "id": file_id,
                        "title": saved.get("title") or report_file.stem.replace("-", " ").replace("_", " ").title(),
                        "type": saved.get("type") or (
                            "technical" if "technical" in report_file.stem.lower() else
                            "executive" if "executive" in report_file.stem.lower() else
                            "remediation" if "remediation" in report_file.stem.lower() else "pentest"),
                        "status": saved.get("status", "draft"),
                        "pages": saved.get("pages"),
                        "findings_included": saved.get("findings_included"),
                        "engagement_id": eid or parts[0],
                        "engagement_name": eng_name,
                        "author": saved.get("author", "AI Generated"),
                        "format": report_file.suffix.lstrip(".").upper(),
                        "file_path": str(report_file.relative_to(athena_dir)),
                        "updated_at": saved.get("updated_at") or time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(stat.st_mtime)),
                        "created_at": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(stat.st_ctime)),
                    })

    # Filter out archived reports unless explicitly requested
    if not include_archived:
        reports = [r for r in reports if r.get("status") != "archived"]

    return reports


@app.post("/api/reports")
async def create_report(payload: dict):
    """Register a report from an AI agent or manual creation."""
    report_id = payload.get("id", f"rpt-{str(uuid.uuid4())[:8]}")
    now = time.strftime("%Y-%m-%dT%H:%M:%S")
    report = {
        "id": report_id,
        "title": payload.get("title", "Untitled Report"),
        "type": payload.get("type", "pentest"),
        "status": payload.get("status", "draft"),
        "pages": payload.get("pages"),
        "findings_included": payload.get("findings_included") or payload.get("findings"),
        "engagement_id": payload.get("engagement_id", state.active_engagement_id),
        "engagement_name": payload.get("engagement_name", ""),
        "author": payload.get("author", "AI Generated"),
        "format": payload.get("format", "MD"),
        "file_path": payload.get("file_path"),
        "summary": payload.get("summary"),
        "updated_at": now,
        "created_at": now,
    }
    state._reports.append(report)

    # Broadcast so sidebar badge updates
    await state.broadcast({
        "type": "report_created",
        "report": report,
    })

    return {"ok": True, "report_id": report_id}


@app.get("/api/reports/{report_id}/download")
async def download_report(report_id: str):
    """Download a report file by ID."""
    athena_dir = Path(__file__).parent.parent.parent
    # Check in-memory reports first, then scan filesystem
    all_reports = list(state._reports)
    # Also scan filesystem
    engagements_dir = athena_dir / "engagements" / "active"
    if engagements_dir.exists():
        for eng_dir in engagements_dir.iterdir():
            if not eng_dir.is_dir():
                continue
            reporting_dir = eng_dir / "09-reporting"
            if not reporting_dir.exists():
                continue
            for report_file in reporting_dir.iterdir():
                if report_file.is_file() and report_file.suffix in (".md", ".pdf", ".docx", ".html"):
                    file_id = f"file-{report_file.stem}"
                    if file_id == report_id:
                        return FileResponse(
                            str(report_file),
                            filename=report_file.name,
                            media_type="application/octet-stream",
                        )
    # Check in-memory reports with file_path
    for r in all_reports:
        if r.get("id") == report_id and r.get("file_path"):
            fp = athena_dir / r["file_path"]
            if fp.exists():
                return FileResponse(
                    str(fp),
                    filename=fp.name,
                    media_type="application/octet-stream",
                )
    return JSONResponse({"error": "Report not found"}, status_code=404)


@app.delete("/api/reports/{report_id}")
async def delete_report(report_id: str):
    """Delete a single report by ID (removes file from disk + metadata)."""
    athena_dir = Path(__file__).parent.parent.parent
    # Try filesystem reports
    reporting_dir, report_file = _find_report_dir(athena_dir, report_id)
    if reporting_dir and report_file:
        report_file.unlink()
        # Clean up metadata entry
        meta = _read_report_meta(reporting_dir)
        meta.pop(report_id, None)
        _write_report_meta(reporting_dir, meta)
        state._reports = [r for r in state._reports if r.get("id") != report_id]
        return {"ok": True, "deleted": 1}
    # Try in-memory reports with file_path
    for r in list(state._reports):
        if r.get("id") == report_id:
            if r.get("file_path"):
                fp = athena_dir / r["file_path"]
                if fp.exists():
                    fp.unlink()
            state._reports = [x for x in state._reports if x.get("id") != report_id]
            return {"ok": True, "deleted": 1}
    return JSONResponse({"error": "Report not found"}, status_code=404)


@app.patch("/api/reports/{report_id}")
async def update_report(report_id: str, payload: dict):
    """Update report status (archive, mark final, etc.). Persists to .report-meta.json."""
    athena_dir = Path(__file__).parent.parent.parent
    new_status = payload.get("status")
    if not new_status:
        return JSONResponse({"error": "status required"}, status_code=400)

    # Handle archive — persist status in metadata (don't move files to avoid multi-extension issues)
    if new_status == "archived":
        reporting_dir, report_file = _find_report_dir(athena_dir, report_id)
        if reporting_dir:
            meta = _read_report_meta(reporting_dir)
            # Mark ALL files with this stem as archived
            stem = report_file.stem if report_file else report_id.replace("file-", "")
            for f in reporting_dir.iterdir():
                if f.is_file() and f.stem == stem:
                    fid = f"file-{f.stem}"
                    if fid not in meta:
                        meta[fid] = {}
                    meta[fid]["status"] = "archived"
                    meta[fid]["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
            _write_report_meta(reporting_dir, meta)
            state._reports = [r for r in state._reports if r.get("id") != report_id]
            return {"ok": True, "status": "archived"}

    # Persist status to filesystem metadata for file-based reports
    reporting_dir, _ = _find_report_dir(athena_dir, report_id)
    if reporting_dir:
        meta = _read_report_meta(reporting_dir)
        if report_id not in meta:
            meta[report_id] = {}
        meta[report_id]["status"] = new_status
        meta[report_id]["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        _write_report_meta(reporting_dir, meta)
        return {"ok": True, "status": new_status}

    # Update in-memory reports (from POST)
    for r in state._reports:
        if r.get("id") == report_id:
            r["status"] = new_status
            r["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
            return {"ok": True, "status": new_status}

    return JSONResponse({"error": "Report not found"}, status_code=404)


@app.delete("/api/reports")
async def delete_all_reports(engagement: Optional[str] = None):
    """Delete all reports for an engagement (or all reports)."""
    eid = engagement or state.active_engagement_id
    athena_dir = Path(__file__).parent.parent.parent
    deleted = 0

    # Delete filesystem reports
    engagements_dir = athena_dir / "engagements" / "active"
    if engagements_dir.exists():
        for eng_dir in engagements_dir.iterdir():
            if not eng_dir.is_dir():
                continue
            if eid and not eng_dir.name.startswith(eid):
                continue
            reporting_dir = eng_dir / "09-reporting"
            if not reporting_dir.exists():
                continue
            for report_file in reporting_dir.iterdir():
                if report_file.is_file() and report_file.suffix in (".md", ".pdf", ".docx", ".html"):
                    report_file.unlink()
                    deleted += 1

    # Clear in-memory reports
    if eid:
        before = len(state._reports)
        state._reports = [r for r in state._reports if r.get("engagement_id") != eid]
        deleted += before - len(state._reports)
    else:
        deleted += len(state._reports)
        state._reports.clear()

    return {"ok": True, "deleted": deleted}


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


def _synthesize_graph_from_findings(existing_nodes: list, existing_edges: list) -> tuple:
    """Synthesize a basic attack graph from in-memory findings when Neo4j lacks Host/Service nodes.

    Creates: Host nodes, Service nodes (from finding targets), and edges connecting them.
    Preserves any existing Finding nodes from Neo4j.
    """
    nodes = list(existing_nodes)
    edges = list(existing_edges)
    existing_ids = {n["id"] for n in nodes}

    eid = state.active_engagement_id
    eng_findings = [f for f in state.findings if f.engagement == eid] if eid else state.findings

    # Extract unique hosts and services from findings
    hosts = {}  # ip -> set of (port, service_name)
    for f in eng_findings:
        if not f.target:
            continue
        parts = f.target.split(":")
        ip = parts[0].split("/")[0]
        port = parts[1] if len(parts) > 1 else None
        if ip not in hosts:
            hosts[ip] = set()
        if port:
            hosts[ip].add((port, f.title[:30]))

    # Create Host nodes
    for ip in hosts:
        if ip not in existing_ids:
            nodes.append({
                "id": ip, "type": "host", "label": ip,
                "tooltip": f"Host {ip}", "properties": {"ip": ip},
            })
            existing_ids.add(ip)

    # Create Service nodes and edges
    for ip, services in hosts.items():
        for port, svc_name in services:
            svc_id = f"{ip}:{port}"
            if svc_id not in existing_ids:
                nodes.append({
                    "id": svc_id, "type": "service", "label": f":{port}",
                    "tooltip": f"Service on port {port}",
                    "properties": {"port": port, "host_ip": ip},
                })
                existing_ids.add(svc_id)
                edges.append({"from": svc_id, "to": ip, "type": "RUNS_ON", "label": "RUNS_ON"})

    # Create Finding nodes (from in-memory) and edges to hosts
    for f in eng_findings:
        fid = f"finding-{f.id}"
        if fid not in existing_ids:
            sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity).lower()
            nodes.append({
                "id": fid, "type": "finding", "label": f.title[:40],
                "tooltip": f.description or f.title,
                "properties": {"severity": sev, "cvss": str(f.cvss or ""), "cve": f.cve or ""},
            })
            existing_ids.add(fid)
        # Edge: Finding AFFECTS Host
        if f.target:
            ip = f.target.split(":")[0].split("/")[0]
            if ip in existing_ids:
                edges.append({"from": fid, "to": ip, "type": "AFFECTS", "label": "AFFECTS"})
            # Edge: Finding AFFECTS Service (if port specified)
            parts = f.target.split(":")
            if len(parts) > 1:
                svc_id = f"{parts[0]}:{parts[1]}"
                if svc_id in existing_ids:
                    edges.append({"from": fid, "to": svc_id, "type": "AFFECTS", "label": "AFFECTS"})

    return nodes, edges


def _connect_orphaned_nodes(nodes: list, edges: list) -> tuple[list, list]:
    """Auto-connect orphaned findings/vulns to hosts and clean up broken edges.

    1. Remove BELONGS_TO edges (point to engagement IDs, not visible nodes)
    2. Extract host IPs from finding/vuln target URLs and connect via FOUND_ON
    3. Connect vulnerabilities to services via HAS_VULN based on port in target
    4. Deduplicate finding+vuln pairs that describe the same issue
    """
    import re

    node_ids = {n["id"] for n in nodes}
    host_ips = {n["id"] for n in nodes if n["type"] == "host"}
    service_ids = {n["id"]: n for n in nodes if n["type"] == "service"}

    # Track which nodes already have structural edges (not BELONGS_TO)
    connected_nodes = set()
    for e in edges:
        if e["type"] != "BELONGS_TO":
            connected_nodes.add(e["from"])
            connected_nodes.add(e["to"])

    # 1. Remove BELONGS_TO edges (they point to engagement IDs, not graph nodes)
    edges = [e for e in edges if e["type"] != "BELONGS_TO"]

    # 2. Extract host IP from target property and connect orphaned findings/vulns
    ip_pattern = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
    port_pattern = re.compile(r":(\d+)")

    for n in nodes:
        if n["type"] not in ("finding", "vulnerability"):
            continue
        if n["id"] in connected_nodes:
            continue  # Already connected

        props = n.get("properties", {})
        target = props.get("target", "") or props.get("affected_host", "") or ""
        # Also check description for IP if target is empty
        if not target:
            target = props.get("description", "") or ""

        ip_match = ip_pattern.search(target)
        if not ip_match:
            # Fallback: if there's only one host, connect to it
            if len(host_ips) == 1:
                host_ip = list(host_ips)[0]
            else:
                continue
        else:
            host_ip = ip_match.group(1)

        if host_ip not in node_ids:
            continue

        edge_type = "FOUND_ON" if n["type"] == "finding" else "HAS_VULN"
        # For vulns, edge goes host -> vuln; for findings, finding -> host
        if n["type"] == "vulnerability":
            # Try to connect to service if port is in target
            port_match = port_pattern.search(target)
            if port_match:
                port = port_match.group(1)
                # Find matching service
                for sid, snode in service_ids.items():
                    if snode.get("properties", {}).get("port") == port and snode.get("properties", {}).get("host_ip") == host_ip:
                        edges.append({"from": sid, "to": n["id"], "type": "HAS_VULN", "label": "HAS_VULN"})
                        connected_nodes.add(n["id"])
                        break
                else:
                    edges.append({"from": host_ip, "to": n["id"], "type": "HAS_VULN", "label": "HAS_VULN"})
                    connected_nodes.add(n["id"])
            else:
                # Connect to first HTTP service if exists, else host
                http_svc = next((sid for sid, s in service_ids.items()
                                 if s.get("properties", {}).get("host_ip") == host_ip
                                 and "http" in (s.get("properties", {}).get("name", "") or "").lower()), None)
                if http_svc:
                    edges.append({"from": http_svc, "to": n["id"], "type": "HAS_VULN", "label": "HAS_VULN"})
                else:
                    edges.append({"from": host_ip, "to": n["id"], "type": "HAS_VULN", "label": "HAS_VULN"})
                connected_nodes.add(n["id"])
        else:
            # Finding -> Host via FOUND_ON
            edges.append({"from": n["id"], "to": host_ip, "type": "FOUND_ON", "label": "FOUND_ON"})
            connected_nodes.add(n["id"])

    return nodes, edges


@app.get("/api/attack-graph")
async def get_attack_graph(engagement: Optional[str] = None):
    """Return attack graph data from Neo4j or mock data."""
    eid = engagement or state.active_engagement_id
    if neo4j_available and neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                # Query nodes — scope to engagement if available
                nodes = []
                for label, ntype in [("Host", "host"), ("Service", "service"),
                                      ("Vulnerability", "vulnerability"),
                                      ("Credential", "credential"), ("Finding", "finding"),
                                      ("AttackPath", "attack_path")]:
                    if eid:
                        result = session.run(
                            f"MATCH (n:{label}) WHERE n.engagement_id = $eid RETURN n, labels(n) AS labels LIMIT 100",
                            eid=eid,
                        )
                    else:
                        result = session.run(
                            f"MATCH (n:{label}) RETURN n, labels(n) AS labels LIMIT 100"
                        )
                    for record in result:
                        node = dict(record["n"])
                        node_id = node.get("id", node.get("ip", node.get("name", str(id(node)))))
                        # Services need port in ID to avoid collisions
                        # (e.g. netbios-ssn on port 139 and 445)
                        if ntype == "service" and node.get("port"):
                            node_id = f"{node.get('name', '')}:{node['port']}"
                        node_label = node.get("ip", node.get("title", node.get("name", node.get("id", ""))))
                        nodes.append({
                            "id": node_id,
                            "type": ntype,
                            "label": str(node_label),
                            "tooltip": node.get("title", node.get("description", str(node_label))),
                            "properties": {k: str(v) if v is not None else None for k, v in node.items()},
                        })

                # Query edges — scoped to engagement if available
                edges = []
                edge_query = """
                    MATCH (a)-[r]->(b)
                    WHERE type(r) IN [
                        'RUNS_ON', 'AFFECTS', 'EXPLOITS', 'LATERAL_MOVE',
                        'HARVESTED_FROM', 'EVIDENCED_BY', 'BELONGS_TO',
                        'HAS_SERVICE', 'HAS_VULN', 'CONFIRMED_BY', 'EXPLOITED_BY',
                        'VERIFIED_BY', 'YIELDED', 'LEADS_TO', 'STARTS_AT', 'HAS_URL',
                        'FOUND_ON'
                    ]
                """
                if eid:
                    edge_query += """
                    AND (a.engagement_id = $eid OR b.engagement_id = $eid
                         OR a.engagement_id IS NULL OR b.engagement_id IS NULL)
                    """
                edge_query += """
                    RETURN
                        coalesce(a.id, a.ip, a.name) AS from_id,
                        coalesce(b.id, b.ip, b.name) AS to_id,
                        type(r) AS rel_type,
                        labels(a) AS from_labels,
                        a.port AS from_port,
                        labels(b) AS to_labels,
                        b.port AS to_port
                    LIMIT 500
                """
                result = session.run(edge_query, eid=eid) if eid else session.run(edge_query)
                for record in result:
                    from_id = str(record["from_id"])
                    to_id = str(record["to_id"])
                    # Service edges need port-qualified IDs to match nodes
                    if "Service" in (record["from_labels"] or []) and record["from_port"]:
                        from_id = f"{from_id}:{record['from_port']}"
                    if "Service" in (record["to_labels"] or []) and record["to_port"]:
                        to_id = f"{to_id}:{record['to_port']}"
                    edges.append({
                        "from": from_id,
                        "to": to_id,
                        "type": record["rel_type"],
                        "label": record["rel_type"],
                    })

                # If we have findings but no Host/Service nodes (AI mode), synthesize graph from in-memory
                host_count = sum(1 for n in nodes if n["type"] == "host")
                finding_count = sum(1 for n in nodes if n["type"] == "finding")
                if finding_count > 0 and host_count == 0:
                    nodes, edges = _synthesize_graph_from_findings(nodes, edges)

                # Post-process: auto-connect orphaned findings/vulns to hosts
                nodes, edges = _connect_orphaned_nodes(nodes, edges)

                return {"nodes": nodes, "edges": edges, "attack_paths": [], "source": "neo4j"}
        except Exception as e:
            print(f"Neo4j attack graph query error: {e}")

    # Fallback: synthesize graph from in-memory findings
    eid = state.active_engagement_id
    if eid and state.findings:
        nodes, edges = _synthesize_graph_from_findings([], [])
        if nodes:
            return {"nodes": nodes, "edges": edges, "attack_paths": [], "source": "memory"}

    # No data yet — return empty graph
    return {"nodes": [], "edges": [], "attack_paths": [], "source": "empty"}


@app.delete("/api/engagements/{eid}/graph")
async def delete_engagement_graph(eid: str):
    """Delete all graph data (hosts, services, vulns, credentials, findings, evidence) for an engagement."""
    deleted = 0

    if neo4j_available and neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                # Count nodes before deletion (engagement-scoped)
                result = session.run("""
                    MATCH (n {engagement_id: $eid})
                    WHERE NOT n:Engagement
                    RETURN count(n) AS cnt
                """, eid=eid)
                record = result.single()
                deleted = record["cnt"] if record else 0

                if deleted > 0:
                    # Delete nodes scoped to this engagement
                    session.run("""
                        MATCH (n {engagement_id: $eid})
                        WHERE NOT n:Engagement
                        DETACH DELETE n
                    """, eid=eid)
                else:
                    # Fallback: delete ALL non-Engagement nodes (legacy/unscoped data)
                    result = session.run("""
                        MATCH (n)
                        WHERE NOT n:Engagement
                        RETURN count(n) AS cnt
                    """)
                    record = result.single()
                    deleted = record["cnt"] if record else 0
                    if deleted > 0:
                        session.run("""
                            MATCH (n)
                            WHERE NOT n:Engagement
                            DETACH DELETE n
                        """)
        except Exception as e:
            print(f"Neo4j delete graph error: {e}")

    # Clear in-memory findings for this engagement
    state.findings = [f for f in state.findings if f.engagement != eid]

    # Clear scans for this engagement
    state.scans = [s for s in state.scans if s.get("engagement_id") != eid]

    # Clear runtime state (agents, events, credentials) for this engagement
    # Events don't carry engagement_id in metadata, so clear all events
    # (they're ephemeral timeline data, not persistent records)
    state.events.clear()
    state._credentials.pop(eid, None)
    # Reset agent statuses to idle
    for code in state.agent_statuses:
        state.agent_statuses[code] = AgentStatus.IDLE
    state.agent_tasks.clear()

    # Broadcast clear_timeline to all connected clients so their AI drawers reset
    await state.broadcast({
        "type": "clear_timeline",
        "engagement": eid,
        "timestamp": time.time(),
    })

    return {"deleted": deleted, "engagement": eid}


@app.post("/api/engagements/{eid}/reset-state")
async def reset_engagement_state(eid: str):
    """Reset runtime state (agents, events, credentials) for an engagement without deleting graph data."""
    # Reset agents to idle
    for code in state.agent_statuses:
        state.agent_statuses[code] = AgentStatus.IDLE
    state.agent_tasks.clear()

    # Clear events
    state.events.clear()

    # Clear credentials
    state._credentials.pop(eid, None)

    # Clear in-memory findings
    state.findings = [f for f in state.findings if f.engagement != eid]

    # Broadcast reset
    await state.broadcast({
        "type": "engagement_reset",
        "engagement_id": eid,
        "timestamp": time.time(),
    })

    return {"ok": True, "engagement": eid}


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
    state.engagement_pause_event.set()  # Ensure not paused from previous run

    # Reset engagement status to active in Neo4j and broadcast (in case of re-run)
    if neo4j_available and neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                session.run(
                    "MATCH (e:Engagement {id: $eid}) SET e.status = 'active'",
                    eid=eid,
                )
        except Exception:
            pass
    await state.broadcast({
        "type": "engagement_status",
        "engagement_id": eid,
        "status": "active",
        "timestamp": time.time(),
    })

    state.engagement_task = asyncio.create_task(
        orchestrator.run_engagement(eid, backend_override=backend)
    )
    msg = f"Engagement {eid} started"
    if backend:
        msg += f" (backend forced: {backend})"
    return {"ok": True, "engagement_id": eid, "message": msg}


# ──────────────────────────────────────────────
# Phase E: AI Mode — Claude Code Agent Teams
# ──────────────────────────────────────────────

_ai_process: subprocess.Popen | None = None


async def _stream_ai_output(eid: str, process: subprocess.Popen):
    """Read Claude Code streaming JSON output and forward events to dashboard."""
    loop = asyncio.get_event_loop()
    agent_code = "OR"
    tool_count = 0

    try:
        while True:
            line = await loop.run_in_executor(None, process.stdout.readline)
            if not line:
                break
            line_str = line.decode("utf-8", errors="replace").strip()
            if not line_str:
                continue

            # Try parsing as JSON (stream-json format)
            try:
                event = json.loads(line_str)
                etype = event.get("type", "")

                # Tool use — broadcast as tool_start
                if etype == "tool_use":
                    tool_name = event.get("name", "unknown")
                    tool_count += 1
                    # Detect agent from tool name
                    if "kali" in tool_name:
                        agent_code = "OR"
                    await state.add_event(AgentEvent(
                        id=str(uuid.uuid4())[:8],
                        type="tool_start",
                        agent=agent_code,
                        content=f"Calling {tool_name}",
                        timestamp=time.time(),
                        metadata={"tool": tool_name},
                    ))

                # Tool result — broadcast as tool_complete
                elif etype == "tool_result":
                    content = str(event.get("content", ""))[:500]
                    await state.add_event(AgentEvent(
                        id=str(uuid.uuid4())[:8],
                        type="tool_complete",
                        agent=agent_code,
                        content=content,
                        timestamp=time.time(),
                    ))

                # Assistant text — broadcast as thinking/system
                elif etype == "assistant":
                    text = ""
                    message = event.get("message", {})
                    for block in message.get("content", []):
                        if isinstance(block, dict) and block.get("type") == "text":
                            text += block.get("text", "")
                    if text:
                        await state.add_event(AgentEvent(
                            id=str(uuid.uuid4())[:8],
                            type="system",
                            agent="OR",
                            content=text[:1000],
                            timestamp=time.time(),
                        ))

                # Final result
                elif etype == "result":
                    result_text = event.get("result", "")
                    if result_text:
                        await state.add_event(AgentEvent(
                            id=str(uuid.uuid4())[:8],
                            type="system",
                            agent="OR",
                            content=f"AI engagement complete. {str(result_text)[:500]}",
                            timestamp=time.time(),
                        ))

            except json.JSONDecodeError:
                # Plain text output — forward as system event
                if len(line_str) > 5:
                    await state.add_event(AgentEvent(
                        id=str(uuid.uuid4())[:8],
                        type="system",
                        agent="OR",
                        content=line_str[:500],
                        timestamp=time.time(),
                    ))

    except Exception as e:
        await state.add_event(AgentEvent(
            id=str(uuid.uuid4())[:8],
            type="system",
            agent="OR",
            content=f"AI stream error: {str(e)[:200]}",
            timestamp=time.time(),
        ))

    # Read stderr for errors
    try:
        stderr = await loop.run_in_executor(None, process.stderr.read)
        if stderr:
            stderr_str = stderr.decode("utf-8", errors="replace").strip()
            if stderr_str:
                await state.add_event(AgentEvent(
                    id=str(uuid.uuid4())[:8],
                    type="system",
                    agent="OR",
                    content=f"AI process stderr: {stderr_str[:500]}",
                    timestamp=time.time(),
                ))
    except Exception:
        pass

    # Mark engagement complete
    exit_code = process.wait()
    await state.add_event(AgentEvent(
        id=str(uuid.uuid4())[:8],
        type="system",
        agent="OR",
        content=f"AI process exited (code {exit_code}). {tool_count} tool calls made.",
        timestamp=time.time(),
    ))


@app.post("/api/engagement/{eid}/start-ai")
async def start_engagement_ai(eid: str, backend: str = "external", target: str = ""):
    """Start an AI-powered PTES engagement using Claude Code.

    Spawns a headless Claude Code process that orchestrates the full
    PTES methodology, streaming events back to the dashboard in real-time.

    Works both from the dashboard GUI and from CLI (/athena-engage).
    """
    global _ai_process

    if not target:
        # Try to get target from in-memory engagement data
        eng = next((e for e in state.engagements if e.id == eid), None)
        if eng:
            target = eng.target
        # Fallback: check Neo4j
        if not target and neo4j_available and neo4j_driver:
            try:
                with neo4j_driver.session() as session:
                    result = session.run(
                        "MATCH (e:Engagement {id: $eid}) RETURN e.scope AS scope",
                        eid=eid,
                    )
                    record = result.single()
                    if record and record.get("scope"):
                        target = record["scope"]
            except Exception:
                pass
        if not target:
            return JSONResponse(status_code=400, content={
                "error": "Target scope required. Pass ?target=<ip/cidr/url>"
            })

    # Kill any existing AI process
    if _ai_process and _ai_process.poll() is None:
        _ai_process.terminate()
        try:
            _ai_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _ai_process.kill()

    # Set engagement active
    state.active_engagement_id = eid
    state.engagement_stopped = False

    # Broadcast AI mode system event
    await state.add_event(AgentEvent(
        id=str(uuid.uuid4())[:8],
        type="system",
        agent="OR",
        content=f"AI Mode activated. Claude Code will execute PTES phases 1-7 against {target}. HITL approval required for exploitation.",
        timestamp=time.time(),
    ))

    # Broadcast engagement_active so dashboard shows running badge
    await state.broadcast({
        "type": "engagement_started",
        "engagement_id": eid,
        "mode": "ai",
        "engagement_active": True,
        "timestamp": time.time(),
    })

    # Build comprehensive orchestration prompt
    athena_dir = str(Path(__file__).resolve().parent.parent.parent)
    prompt = f"""You are the ATHENA AI pentesting orchestrator for engagement {eid}.

TARGET: {target}
DASHBOARD: http://localhost:8080
ENGAGEMENT ID: {eid}
BACKEND: Use kali_{backend} MCP tools
AUTHORIZATION: This is an authorized penetration test.

Execute a full PTES penetration test following these phases:

PHASE 1 - RECONNAISSANCE:
- Update agent LEDs: POST http://localhost:8080/api/events with {{"type":"agent_status","agent":"PO","status":"running"}}
- Run nmap scan via kali_{backend} MCP tools against {target}
- Run httpx probe if web ports found
- Register each scan: POST http://localhost:8080/api/scans with tool name, status, output
- Write Host and Service nodes to Neo4j via athena_neo4j MCP
- POST findings to http://localhost:8080/api/engagements/{eid}/findings

PHASE 2 - VULNERABILITY ANALYSIS:
- Update agent LEDs for CV, WV, AP
- Run nuclei scan against discovered web services
- Run nikto scan
- Write Vulnerability nodes to Neo4j
- POST findings with severity levels

PHASE 3 - EXPLOITATION (HITL REQUIRED):
- For any exploitable vulnerabilities, POST approval request:
  POST http://localhost:8080/api/approvals with action, description, risk_level
- Poll GET http://localhost:8080/api/approvals/{{id}} until approved or rejected
- Only execute exploitation tools if approved
- Write ExploitResult and Credential nodes to Neo4j
- POST credentials: POST http://localhost:8080/api/engagements/{eid}/credentials

PHASE 4-7 - VERIFICATION, POST-EXPLOIT, CLEANUP, REPORTING:
- Verify findings independently
- Document all results
- Mark engagement complete

CRITICAL RULES:
- Register EVERY tool execution as a scan via POST /api/scans BEFORE running and PATCH /api/scans/{{id}} AFTER
- Include REAL raw tool output in scan output_preview (never AI summaries)
- POST agent status events to update dashboard LEDs in real-time
- Write all findings to Neo4j with engagement_id: {eid}
"""

    # Spawn Claude Code headlessly with streaming output
    # Use absolute path — shell functions not available in subprocess
    claude_bin = os.environ.get("CLAUDE_BIN", os.path.expanduser("~/.local/bin/claude"))
    cmd = [
        claude_bin,
        "-p", prompt,
        "--output-format", "stream-json",
        "--verbose",
        "--dangerously-skip-permissions",
        "--model", "sonnet",
        "--allowedTools",
        ",".join([
            "Bash", "Read", "Write", "Edit",
            "mcp__kali_external__*", "mcp__kali_internal__*",
            "mcp__athena_neo4j__*",
        ]),
    ]

    try:
        # Filter CLAUDECODE to avoid "nested session" error when spawned
        # from inside a running Claude Code session (official Anthropic bypass)
        clean_env = {k: v for k, v in os.environ.items() if k != "CLAUDECODE"}
        _ai_process = subprocess.Popen(
            cmd,
            cwd=athena_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=clean_env,
        )
    except FileNotFoundError:
        await state.add_event(AgentEvent(
            id=str(uuid.uuid4())[:8],
            type="system",
            agent="OR",
            content="ERROR: Claude CLI not found. Install Claude Code: npm install -g @anthropic-ai/claude-code",
            timestamp=time.time(),
        ))
        return JSONResponse(status_code=500, content={
            "error": "Claude CLI not found. Ensure 'claude' is in PATH."
        })

    # Start background task to stream output to dashboard
    asyncio.create_task(_stream_ai_output(eid, _ai_process))

    await state.add_event(AgentEvent(
        id=str(uuid.uuid4())[:8],
        type="system",
        agent="OR",
        content=f"Claude Code process started (PID {_ai_process.pid}). Streaming output to dashboard...",
        timestamp=time.time(),
    ))

    return {
        "ok": True,
        "engagement_id": eid,
        "mode": "ai",
        "pid": _ai_process.pid,
        "message": f"AI engagement started (PID {_ai_process.pid}) against {target}",
    }


@app.post("/api/engagement/{eid}/stop")
async def stop_engagement(eid: str):
    """Stop a running engagement and kill all active processes."""
    global _ai_process
    state.engagement_stopped = True
    state.engagement_pause_event.set()  # Unblock if paused so task can exit

    # 0. Kill AI mode process if running
    if _ai_process and _ai_process.poll() is None:
        _ai_process.terminate()
        try:
            _ai_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _ai_process.kill()
        _ai_process = None

    # 1. Unblock any waiting HITL approvals so the task can exit
    for evt_data in state.approval_events.values():
        evt_data["approved"] = False
        evt_data["event"].set()

    # 2. Cancel the orchestrator asyncio task (cancels in-flight httpx requests)
    if state.engagement_task and not state.engagement_task.done():
        state.engagement_task.cancel()

    # 3. Kill active processes on all Kali backends
    kill_results = await kali_client.kill_all()

    # 4. Cancel in-flight scans — broadcast tool_complete with cancelled status
    cancelled_scans = []
    for scan in state.scans:
        if scan.get("status") == "running" and scan.get("engagement_id") == eid:
            scan["status"] = "cancelled"
            scan["completed_at"] = datetime.now(timezone.utc).isoformat()
            cancelled_scans.append(scan)
            # Broadcast tool_complete so frontend cleans up the running card
            tool_id = scan["id"].replace("scan-", "")
            await state.add_event(AgentEvent(
                id=str(uuid.uuid4())[:8],
                type="tool_complete",
                agent=scan.get("agent", ""),
                content="Cancelled by operator",
                timestamp=time.time(),
                metadata={"tool_id": tool_id, "cancelled": True, "elapsed_s": 0, "success": False},
            ))
            # Also update scan on Scans page
            await state.broadcast({
                "type": "scan_update",
                "scan": scan,
                "timestamp": time.time(),
            })

    # 5. Reset agent statuses
    for code in AGENT_NAMES:
        if state.agent_statuses[code] != AgentStatus.IDLE:
            await state.update_agent_status(code, AgentStatus.IDLE)

    # 6. Set engagement status to completed in Neo4j + broadcast
    if neo4j_available and neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                session.run(
                    "MATCH (e:Engagement {id: $eid}) SET e.status = 'completed'",
                    eid=eid,
                )
        except Exception:
            pass
    await state.broadcast({
        "type": "engagement_status",
        "engagement_id": eid,
        "status": "completed",
        "timestamp": time.time(),
    })

    await state.broadcast({
        "type": "system",
        "content": f"Engagement {eid} stopped by operator. Active processes killed.",
        "timestamp": time.time(),
    })
    return {"ok": True, "message": f"Engagement {eid} stopped", "kill_results": kill_results}


@app.post("/api/engagement/{eid}/pause")
async def pause_engagement(eid: str):
    """Pause a running engagement. Kills in-flight Kali processes immediately."""
    state.engagement_pause_event.clear()  # Block at next checkpoint

    # Kill running processes on Kali backends so long-running tools (Nuclei, Nmap)
    # actually stop instead of continuing for minutes until completion.
    kill_results = {}
    if kali_client:
        try:
            kill_results = await kali_client.kill_all()
        except Exception:
            pass

    # Mark running scans as paused
    for scan in state.scans:
        if scan.get("status") == "running" and scan.get("engagement_id") == eid:
            scan["status"] = "paused"
            await state.broadcast({
                "type": "scan_update", "scan": scan, "timestamp": time.time(),
            })

    # Mark running agents as waiting
    for code in AGENT_NAMES:
        if state.agent_statuses[code] == AgentStatus.RUNNING:
            await state.update_agent_status(code, AgentStatus.WAITING, "Paused by operator")
    await state.broadcast({
        "type": "system",
        "content": f"Engagement {eid} paused by operator",
        "timestamp": time.time(),
    })
    return {"ok": True, "message": f"Engagement {eid} paused", "kill_results": kill_results}


@app.post("/api/engagement/{eid}/resume")
async def resume_engagement(eid: str):
    """Resume a paused engagement. Paused scans will be re-run by the orchestrator."""
    # Don't cancel paused scans — the orchestrator's run_tool() retry loop
    # detects scan_record["status"] == "paused" and re-executes the tool.
    # This ensures we don't miss vulns from interrupted scans.

    # Restore operator-paused agents to RUNNING so chips turn red again
    # Only restore agents that were paused by the operator (not genuinely HITL-waiting)
    for code in AGENT_NAMES:
        if (state.agent_statuses[code] == AgentStatus.WAITING
                and state.agent_tasks.get(code) == "Paused by operator"):
            await state.update_agent_status(code, AgentStatus.RUNNING, "Resumed")

    state.engagement_pause_event.set()  # Unblock waiting agents
    await state.broadcast({
        "type": "system",
        "content": f"Engagement {eid} resumed by operator",
        "timestamp": time.time(),
    })
    return {"ok": True, "message": f"Engagement {eid} resumed"}


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
