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
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel


# ──────────────────────────────────────────────
# Models
# ──────────────────────────────────────────────

class AgentCode(str, Enum):
    PLANNING = "PL"
    ORCHESTRATOR = "OR"
    PASSIVE_OSINT = "PO"
    ACTIVE_RECON = "AR"
    CVE_RESEARCHER = "CV"
    WEB_VULN_SCANNER = "WV"
    EXPLOITATION = "EX"
    POST_EXPLOITATION = "PE"
    REPORTING = "RP"


AGENT_NAMES = {
    "PL": "Planning Agent",
    "OR": "Orchestrator",
    "PO": "Passive OSINT",
    "AR": "Active Recon",
    "CV": "CVE Researcher",
    "WV": "Web Vuln Scanner",
    "EX": "Exploitation",
    "PE": "Post-Exploitation",
    "RP": "Reporting",
}

AGENT_PTES_PHASE = {
    "PL": 1, "OR": 0, "PO": 2, "AR": 2,
    "CV": 3, "WV": 4, "EX": 5, "PE": 6, "RP": 7,
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
        self.engagements: list[Engagement] = self._seed_engagements()
        self.connected_clients: set[WebSocket] = set()
        self._event_lock = asyncio.Lock()

    def _seed_engagements(self) -> list[Engagement]:
        """Seed with demo engagements matching dashboard stat cards."""
        return [
            Engagement(
                id="eng-001", name="Acme Corp External",
                target="*.acme.com", status="active",
                start_date="2026-02-10", agents_active=3,
                findings_count=23, phase="Vulnerability Analysis"
            ),
            Engagement(
                id="eng-002", name="GlobalBank API",
                target="api.globalbank.test", status="active",
                start_date="2026-02-14", agents_active=2,
                findings_count=15, phase="Intelligence Gathering"
            ),
            Engagement(
                id="eng-003", name="HealthCo Web App",
                target="portal.healthco.test", status="active",
                start_date="2026-02-16", agents_active=1,
                findings_count=9, phase="Threat Modeling"
            ),
        ]

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
        """Resolve HITL approval and broadcast."""
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
        return True


# ──────────────────────────────────────────────
# Application
# ──────────────────────────────────────────────

state = DashboardState()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown lifecycle."""
    print("\n  0K ATHENA Dashboard Server")
    print("  ─────────────────────────")
    print("  WebSocket:  ws://localhost:8080/ws")
    print("  Dashboard:  http://localhost:8080")
    print("  API Docs:   http://localhost:8080/docs")
    print("  Agent API:  POST /api/events")
    print()
    yield
    print("\n  Shutting down ATHENA Dashboard Server...")


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
    finding = Finding(
        id=str(uuid.uuid4())[:8],
        title=payload.title,
        severity=sev,
        category=payload.category,
        target=payload.target,
        agent=payload.agent,
        description=payload.description,
        cvss=payload.cvss,
        cve=payload.cve,
        evidence=payload.evidence,
        timestamp=time.time(),
        engagement=payload.engagement,
    )
    await state.add_finding(finding)
    return {"ok": True, "finding_id": finding.id}


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
async def get_engagements():
    """Get all engagements."""
    return [e.model_dump() for e in state.engagements]


@app.get("/api/findings")
async def get_findings(severity: Optional[str] = None, engagement: Optional[str] = None):
    """Get findings with optional filters."""
    results = state.findings
    if severity:
        results = [f for f in results if f.severity.value == severity]
    if engagement:
        results = [f for f in results if f.engagement == engagement]
    return [f.model_dump() for f in results]


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


# ──────────────────────────────────────────────
# Demo Mode — Simulate agent activity
# ──────────────────────────────────────────────

@app.post("/api/demo/start")
async def start_demo():
    """
    Start a demo simulation showing agent activity.
    Useful for testing the dashboard without real agents.
    """
    asyncio.create_task(_run_demo_scenario())
    return {"ok": True, "message": "Demo scenario started"}


async def _run_demo_scenario():
    """Simulate a realistic ATHENA engagement workflow with streaming tool output."""

    # ── Phase 1: PLANNING ──
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

    await state.update_agent_status("PO", AgentStatus.COMPLETED)
    await state.update_agent_status("AR", AgentStatus.COMPLETED)
    await asyncio.sleep(1)

    # ── Phase 3: THREAT MODELING ──
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
    await asyncio.sleep(1)

    # ── Phase 4: VULNERABILITY ANALYSIS ──
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
    await state.update_agent_status("WV", AgentStatus.COMPLETED)
    await asyncio.sleep(2)

    # ── Phase 5: EXPLOITATION ── (HITL required)
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
    await state.update_agent_status("EX", AgentStatus.COMPLETED)
    await asyncio.sleep(2)

    # ── Phase 6: POST-EXPLOITATION ──
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
    await state.update_agent_status("PE", AgentStatus.COMPLETED)
    await asyncio.sleep(1)

    # ── Phase 7: REPORTING ──
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
    await _emit("system", "OR", "Acme Corp External engagement completed. All 9 agents finished. Report ready for review.")


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
        "version": "1.0.0",
        "connected_clients": len(state.connected_clients),
        "agents": {code: state.agent_statuses[code].value for code in AGENT_NAMES},
        "timestamp": time.time(),
    }
