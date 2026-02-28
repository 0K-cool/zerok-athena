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
import hashlib
import json
import yaml
import mimetypes
import os
import re
import shutil
import subprocess
import time
import uuid
import zipfile
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from enum import Enum
from io import BytesIO
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, Form, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from PIL import Image
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

# Phase F: Claude Agent SDK wrapper (optional — falls back to subprocess if unavailable)
try:
    from sdk_agent import AthenaAgentSession
    SDK_AVAILABLE = True
except ImportError:
    SDK_AVAILABLE = False
    AthenaAgentSession = None


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
    # Phase F: Strategy Agent (Red Team Lead) + Source Code Analyst
    STRATEGY = "ST"
    SOURCE_CODE = "SC"


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
    # Phase F
    "ST": "Strategy",
    "SC": "Source Code Analyst",
}

AGENT_PTES_PHASE = {
    "PL": 1, "OR": 0, "PO": 2, "AR": 2,
    "CV": 3, "AP": 3, "WV": 4, "EC": 4,
    "EX": 5, "VF": 5, "PE": 6, "DV": 6, "RP": 7,
    # Phase E
    "JS": 2, "PD": 4, "WA": 4, "AT": 4, "AA": 5, "LM": 6,
    # Phase F: Cross-phase (runs at phase gates)
    "ST": 0,
    # Phase F: Source Code Analyst (vuln analysis phase)
    "SC": 3,
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

# Evidence directory structure
EVIDENCE_SUBFOLDERS = ["screenshots", "screenshots/thumbnails", "http-pairs", "command-output", "tool-logs", "response-diffs"]

ALLOWED_ARTIFACT_TYPES = {"screenshot", "http_pair", "command_output", "tool_log", "response_diff"}
MAX_ARTIFACT_SIZE = 2 * 1024 * 1024  # 2MB
THUMBNAIL_WIDTH = 300
THUMBNAIL_QUALITY = 75

def ensure_evidence_dirs(engagement_id: str) -> Path:
    """Create evidence directory structure for an engagement. Returns the evidence root."""
    athena_dir = Path(__file__).parent.parent.parent
    # Search for engagement dir by prefix match
    active_dir = athena_dir / "engagements" / "active"
    if active_dir.exists():
        matches = list(active_dir.glob(f"{engagement_id}*"))
        if matches:
            evidence_root = matches[0] / "08-evidence"
        else:
            evidence_root = active_dir / engagement_id / "08-evidence"
    else:
        evidence_root = athena_dir / "engagements" / "active" / engagement_id / "08-evidence"
    for subfolder in EVIDENCE_SUBFOLDERS:
        (evidence_root / subfolder).mkdir(parents=True, exist_ok=True)
    return evidence_root

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
        # Persist event to Neo4j for cross-restart durability
        if neo4j_available and neo4j_driver:
            try:
                with neo4j_driver.session() as session:
                    session.run("""
                        CREATE (ev:Event {
                            id: $id, type: $type, agent: $agent,
                            content: $content, timestamp: $timestamp,
                            engagement_id: $engagement_id,
                            metadata_json: $metadata_json
                        })
                    """, id=event.id, type=event.type, agent=event.agent,
                         content=event.content, timestamp=event.timestamp,
                         engagement_id=event.metadata.get("engagement", "") if event.metadata else "",
                         metadata_json=json.dumps(event.metadata) if event.metadata else "{}")
            except Exception as e:
                print(f"Neo4j event write error: {e}")
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


def restore_state_from_neo4j():
    """Restore agent statuses and active engagement from Neo4j on server start."""
    if not (neo4j_available and neo4j_driver):
        return
    try:
        with neo4j_driver.session() as session:
            # Find most recent active engagement
            result = session.run("""
                MATCH (e:Engagement {status: 'active'})
                RETURN e.id AS id ORDER BY e.start_date DESC LIMIT 1
            """)
            record = result.single()
            if record:
                state.active_engagement_id = record["id"]

            # Restore agent statuses from latest events per agent
            if state.active_engagement_id:
                result = session.run("""
                    MATCH (ev:Event {engagement_id: $eid})
                    WHERE ev.type IN ['agent_status', 'scan_complete', 'finding', 'phase_change']
                    WITH ev ORDER BY ev.timestamp DESC
                    WITH ev.agent AS agent, collect(ev)[0] AS latest
                    RETURN agent, latest.type AS type, latest.content AS content
                """, eid=state.active_engagement_id)
                for record in result:
                    agent_code = record["agent"]
                    if agent_code in state.agent_statuses:
                        evt_type = record["type"]
                        content = record.get("content", "")
                        if evt_type == "agent_status" and "complete" in (content or "").lower():
                            state.agent_statuses[agent_code] = AgentStatus.COMPLETED
                        elif evt_type in ("scan_complete", "finding"):
                            state.agent_statuses[agent_code] = AgentStatus.COMPLETED
                        if content:
                            state.agent_tasks[agent_code] = content
    except Exception as e:
        print(f"State restore from Neo4j error: {e}")


# Run on module load to recover state across restarts
restore_state_from_neo4j()

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
        "engagement_active": (state.engagement_task is not None and not state.engagement_task.done()) or (_ai_process is not None and _ai_process.poll() is None) or (_active_sdk_session is not None and _active_sdk_session.is_running),
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
                    # Phase F: Forward to SDK session for real AI response
                    if _active_sdk_session and _active_sdk_session.session_id:
                        asyncio.create_task(_handle_sdk_operator_command(cmd_text))
                    else:
                        # Fallback: canned response if no SDK session
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
    # Phase F: Strategy Agent events
    elif payload.type == "strategy_thinking":
        await state.update_agent_status("ST", AgentStatus.RUNNING, payload.content)
    elif payload.type == "strategy_decision":
        await state.update_agent_status("ST", AgentStatus.COMPLETED, payload.content)
    # Phase F2: Bilateral message events (posted via /api/messages, but also renderable here)
    elif payload.type == "agent_message":
        await state.update_agent_status(payload.agent, AgentStatus.RUNNING, payload.content)

    return {"ok": True, "event_id": event.id}


# ── F2: Bilateral Agent Communication ──────────────────────────

class AgentMessagePayload(BaseModel):
    """Bilateral message between agents (F2)."""
    from_agent: str
    to_agent: str
    msg_type: str  # discovery, vulnerability, credential, verification, strategy, pivot
    priority: str = "medium"  # low, medium, high, critical
    content: str
    neo4j_ref: Optional[str] = None
    metadata: Optional[dict] = None

# Communication rules: who can message whom and for what
AGENT_COMM_RULES: dict[str, list[str]] = {
    # Event → allowed recipients
    "discovery":      ["CV", "WV", "AP", "SC", "ST"],  # Recon agents → vuln + code + strategy
    "vulnerability":  ["EX", "EC", "VF", "ST"],        # Vuln agents → exploit + verify + strategy
    "credential":     ["PE", "LM", "ST"],              # Exploit → post-exploit + strategy
    "verification":   ["ST", "RP"],                    # Verify → strategy + report
    "strategy":       list(AGENT_NAMES.keys()),        # Strategy → anyone
    "pivot":          ["PO", "AR", "WV", "SC", "ST"],  # PostExploit → recon + code + strategy
    "code_finding":   ["VF", "EX", "EC", "ST"],        # SC → verify + exploit + strategy
}

# Rate limit: max messages per agent per engagement phase
AGENT_MSG_RATE_LIMIT = 5
_agent_msg_counts: dict[str, int] = {}  # "agent:phase" → count


@app.post("/api/messages")
async def post_agent_message(payload: AgentMessagePayload):
    """
    Bilateral agent-to-agent message (F2).

    Agents send direct messages to each other when discoveries change the
    attack surface. Replaces hub-and-spoke with event-driven mesh.

    Example:
        curl -X POST http://localhost:8080/api/messages \\
          -H 'Content-Type: application/json' \\
          -d '{"from_agent":"AR","to_agent":"WV","msg_type":"discovery",
               "priority":"high","content":"Internal API at :8443/api/v2 — no auth required",
               "neo4j_ref":"svc-abc123"}'
    """
    # Validate agents exist
    if payload.from_agent not in AGENT_NAMES:
        return JSONResponse(status_code=400, content={"error": f"Unknown sender: {payload.from_agent}"})
    if payload.to_agent not in AGENT_NAMES:
        return JSONResponse(status_code=400, content={"error": f"Unknown recipient: {payload.to_agent}"})
    if payload.from_agent == payload.to_agent:
        return JSONResponse(status_code=400, content={"error": "Agent cannot message itself"})

    # Validate message type
    if payload.msg_type not in AGENT_COMM_RULES:
        return JSONResponse(status_code=400, content={
            "error": f"Unknown msg_type: {payload.msg_type}. Valid: {list(AGENT_COMM_RULES.keys())}"
        })

    # Validate communication rule (recipient allowed for this message type)
    allowed = AGENT_COMM_RULES[payload.msg_type]
    if payload.to_agent not in allowed:
        return JSONResponse(status_code=400, content={
            "error": f"{payload.from_agent} cannot send '{payload.msg_type}' to {payload.to_agent}. "
                     f"Allowed recipients: {allowed}"
        })

    # Rate limit per agent per phase
    current_phase = state.engagement_phase if hasattr(state, 'engagement_phase') else 0
    rate_key = f"{payload.from_agent}:{current_phase}"
    count = _agent_msg_counts.get(rate_key, 0)
    if count >= AGENT_MSG_RATE_LIMIT:
        return JSONResponse(status_code=429, content={
            "error": f"Rate limit: {payload.from_agent} has sent {AGENT_MSG_RATE_LIMIT} "
                     f"messages this phase (max {AGENT_MSG_RATE_LIMIT})"
        })
    _agent_msg_counts[rate_key] = count + 1

    # Build metadata
    meta = dict(payload.metadata or {})
    meta["from_agent"] = payload.from_agent
    meta["to_agent"] = payload.to_agent
    meta["msg_type"] = payload.msg_type
    meta["priority"] = payload.priority
    if payload.neo4j_ref:
        meta["neo4j_ref"] = payload.neo4j_ref

    # Create event
    event = AgentEvent(
        id=str(uuid.uuid4())[:8],
        type="agent_message",
        agent=payload.from_agent,
        content=payload.content,
        timestamp=time.time(),
        metadata=meta,
    )
    await state.add_event(event)

    return {
        "ok": True,
        "event_id": event.id,
        "from": payload.from_agent,
        "to": payload.to_agent,
        "msg_type": payload.msg_type,
        "rate_remaining": AGENT_MSG_RATE_LIMIT - (count + 1),
    }


@app.get("/api/messages")
async def get_agent_messages(
    agent: Optional[str] = None,
    msg_type: Optional[str] = None,
    limit: int = 50,
):
    """
    Get bilateral messages, optionally filtered by agent or type.

    Query params:
      ?agent=AR          — messages involving AR (sent or received)
      ?msg_type=discovery — only discovery messages
      ?limit=20          — max results (default 50)
    """
    messages = []
    for evt in reversed(state.events):
        if evt.type != "agent_message":
            continue
        meta = evt.metadata or {}
        if agent and agent not in (meta.get("from_agent"), meta.get("to_agent")):
            continue
        if msg_type and meta.get("msg_type") != msg_type:
            continue
        messages.append({
            "id": evt.id,
            "from_agent": meta.get("from_agent"),
            "to_agent": meta.get("to_agent"),
            "msg_type": meta.get("msg_type"),
            "priority": meta.get("priority"),
            "content": evt.content,
            "neo4j_ref": meta.get("neo4j_ref"),
            "timestamp": evt.timestamp,
        })
        if len(messages) >= limit:
            break
    return {"messages": messages, "count": len(messages)}


@app.delete("/api/messages/rate-limits")
async def reset_message_rate_limits():
    """Reset bilateral message rate limits (called on phase transition)."""
    _agent_msg_counts.clear()
    return {"ok": True, "message": "Rate limits reset"}


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

    Only one approval can be PENDING at a time. If a pending approval exists,
    returns 429 so the agent waits before requesting another.

    Example:
        curl -X POST http://localhost:8080/api/approvals \\
          -H 'Content-Type: application/json' \\
          -d '{"agent":"EX","action":"Run SQLMap","description":"SQL injection validation on login form","risk_level":"high","target":"https://target.com/login"}'
    """
    # Enforce single pending approval — agents must wait for human decision
    pending = [r for r in state.approval_requests.values() if r.status == ApprovalStatus.PENDING]
    if pending:
        return JSONResponse(status_code=429, content={
            "error": "An approval is already pending. Wait for the operator to approve or reject it before requesting another.",
            "pending_id": pending[0].id,
            "pending_action": pending[0].action,
        })

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


# ── F3: Validation Pipeline ("The Moat") ─────────────────────

class VerificationStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    CONFIRMED = "confirmed"      # PoC works 3/3
    LIKELY = "likely"            # 2/3 or strong indicators
    UNVERIFIED = "unverified"    # Couldn't reproduce
    FALSE_POSITIVE = "false_positive"


class VerificationMethod(str, Enum):
    INDEPENDENT_RETEST = "independent_retest"  # Different tool than discovery
    CANARY_CALLBACK = "canary_callback"        # OOB via interactsh
    POC_EXECUTION = "poc_execution"            # Run generated PoC script
    CODE_REVIEW = "code_review"                # SC agent confirms in source
    MANUAL = "manual"                          # Operator manual verification


class VerificationRequest(BaseModel):
    """Submit a finding for verification through The Moat."""
    finding_id: str
    engagement_id: str = "eng-001"
    priority: str = "medium"  # low, medium, high, critical
    methods: Optional[list[str]] = None  # Override auto-selected methods
    canary_url: Optional[str] = None     # Pre-generated interactsh URL
    source_path: Optional[str] = None    # Source code path for code_review


class VerificationResult(BaseModel):
    """Result of a verification attempt."""
    finding_id: str
    verification_id: str
    status: str  # VerificationStatus value
    method: str  # VerificationMethod value
    confidence: float  # 0.0 - 1.0
    poc_script: Optional[str] = None       # Runnable PoC command
    poc_output: Optional[str] = None       # PoC execution output
    evidence_package: Optional[dict] = None  # {screenshot, response, trace}
    impact_demonstrated: Optional[str] = None
    canary_id: Optional[str] = None        # interactsh correlation ID
    canary_callback: Optional[dict] = None  # Callback details if received
    reproduction_results: Optional[list[dict]] = None  # 3x reproduction
    notes: Optional[str] = None
    timestamp: float = 0.0


# Verification method selection by vulnerability category
VULN_VERIFICATION_METHODS: dict[str, list[str]] = {
    # OWASP category → recommended verification methods
    "A01": ["independent_retest", "poc_execution"],                    # Broken Access Control
    "A02": ["independent_retest", "poc_execution"],                    # Cryptographic Failures
    "A03": ["independent_retest", "poc_execution", "canary_callback"], # Injection (SQLi, XSS, etc.)
    "A04": ["independent_retest", "poc_execution"],                    # Insecure Design
    "A05": ["independent_retest", "poc_execution"],                    # Security Misconfiguration
    "A06": ["independent_retest"],                                      # Vulnerable Components
    "A07": ["independent_retest", "poc_execution"],                    # Auth Failures
    "A08": ["independent_retest", "code_review"],                      # Software/Data Integrity
    "A09": ["independent_retest"],                                      # Logging Failures
    "A10": ["independent_retest", "canary_callback"],                  # SSRF
    # Specific vuln types (more granular)
    "sqli":       ["independent_retest", "poc_execution", "canary_callback"],
    "xss":        ["independent_retest", "poc_execution", "canary_callback"],
    "rce":        ["independent_retest", "poc_execution", "canary_callback"],
    "ssrf":       ["canary_callback", "independent_retest"],
    "lfi":        ["independent_retest", "poc_execution"],
    "idor":       ["independent_retest", "poc_execution"],
    "auth_bypass": ["independent_retest", "poc_execution"],
    "file_upload": ["independent_retest", "poc_execution", "canary_callback"],
    "xxe":        ["canary_callback", "independent_retest"],
    "default":    ["independent_retest", "poc_execution"],
}

# Alternative tools for independent re-testing
RETEST_ALTERNATIVES: dict[str, list[str]] = {
    # If discovered by tool X, verify with one of these alternatives
    "nuclei":     ["curl", "httpx", "sqlmap"],
    "sqlmap":     ["curl", "nuclei", "custom_script"],
    "nikto":      ["curl", "nuclei", "httpx"],
    "ffuf":       ["curl", "gobuster", "nuclei"],
    "nmap":       ["masscan", "netcat", "curl"],
    "gobuster":   ["ffuf", "dirsearch", "curl"],
    "wpscan":     ["nuclei", "curl", "custom_script"],
    "xsstrike":   ["curl", "nuclei", "custom_script"],
    "dalfox":     ["curl", "xsstrike", "nuclei"],
    "semgrep":    ["bandit", "codeql", "manual"],
    "bandit":     ["semgrep", "codeql", "manual"],
    "default":    ["curl", "nuclei", "custom_script"],
}

# In-memory verification store
_verifications: dict[str, dict] = {}  # verification_id → verification data
_finding_verifications: dict[str, list[str]] = {}  # finding_id → [verification_ids]


@app.post("/api/verify")
async def submit_verification(req: VerificationRequest):
    """
    Submit a finding for verification through The Moat.

    The Moat ensures every finding has independent verification before
    it goes into the final report. This endpoint queues the verification
    and returns recommended methods.

    Example:
        curl -X POST http://localhost:8080/api/verify \\
          -H 'Content-Type: application/json' \\
          -d '{"finding_id":"abc123","engagement_id":"eng-001","priority":"high"}'
    """
    # Look up the finding
    finding = None
    for f in state.findings:
        if f.id == req.finding_id:
            finding = f
            break
    if not finding:
        return JSONResponse(status_code=404, content={"error": f"Finding {req.finding_id} not found"})

    verification_id = f"vrf-{str(uuid.uuid4())[:8]}"

    # Auto-select verification methods based on vuln category
    category = finding.category.lower() if finding.category else "default"
    methods = req.methods or VULN_VERIFICATION_METHODS.get(
        category, VULN_VERIFICATION_METHODS["default"]
    )

    # Determine alternative tool for independent retest
    discovery_agent = finding.agent
    alt_tools = RETEST_ALTERNATIVES.get(discovery_agent, RETEST_ALTERNATIVES["default"])

    verification = {
        "id": verification_id,
        "finding_id": req.finding_id,
        "engagement_id": req.engagement_id,
        "finding_title": finding.title,
        "finding_severity": finding.severity.value,
        "finding_category": finding.category,
        "finding_target": finding.target,
        "discovery_agent": finding.agent,
        "status": VerificationStatus.PENDING.value,
        "priority": req.priority,
        "methods": methods,
        "alt_tools": alt_tools,
        "canary_url": req.canary_url,
        "source_path": req.source_path,
        "results": [],
        "final_confidence": 0.0,
        "final_status": VerificationStatus.PENDING.value,
        "created_at": time.time(),
        "updated_at": time.time(),
    }

    _verifications[verification_id] = verification
    _finding_verifications.setdefault(req.finding_id, []).append(verification_id)

    # Emit verification event
    await _emit("verification_queued", "VF", f"Queued: {finding.title}", {
        "verification_id": verification_id,
        "finding_id": req.finding_id,
        "methods": methods,
        "priority": req.priority,
    })

    # Update VF agent status
    await state.update_agent_status("VF", AgentStatus.RUNNING,
        f"Verifying: {finding.title}")

    return {
        "ok": True,
        "verification_id": verification_id,
        "finding_id": req.finding_id,
        "recommended_methods": methods,
        "alt_tools": alt_tools,
        "canary_url": req.canary_url,
    }


@app.post("/api/verify/{verification_id}/result")
async def submit_verification_result(verification_id: str, result: VerificationResult):
    """
    Submit a verification result (called by VF agent after each verification attempt).

    The VF agent runs the verification and reports back with evidence.

    Example:
        curl -X POST http://localhost:8080/api/verify/vrf-abc123/result \\
          -H 'Content-Type: application/json' \\
          -d '{"finding_id":"abc123","verification_id":"vrf-abc123",
               "status":"confirmed","method":"poc_execution",
               "confidence":0.95,"poc_script":"curl -X POST ...",
               "impact_demonstrated":"Full auth bypass"}'
    """
    if verification_id not in _verifications:
        return JSONResponse(status_code=404, content={
            "error": f"Verification {verification_id} not found"
        })

    v = _verifications[verification_id]
    result.timestamp = time.time()
    v["results"].append(result.model_dump())
    v["updated_at"] = time.time()
    v["status"] = VerificationStatus.IN_PROGRESS.value

    # Calculate aggregate confidence from all results
    results = v["results"]
    confirmed_count = sum(1 for r in results if r["status"] == "confirmed")
    total_attempts = len(results)

    if total_attempts >= 3 and confirmed_count >= 3:
        v["final_status"] = VerificationStatus.CONFIRMED.value
        v["final_confidence"] = max(r["confidence"] for r in results)
    elif total_attempts >= 2 and confirmed_count >= 2:
        v["final_status"] = VerificationStatus.LIKELY.value
        v["final_confidence"] = sum(r["confidence"] for r in results) / total_attempts
    elif confirmed_count >= 1:
        v["final_status"] = VerificationStatus.LIKELY.value
        v["final_confidence"] = sum(r["confidence"] for r in results) / total_attempts
    elif total_attempts >= 3 and confirmed_count == 0:
        v["final_status"] = VerificationStatus.UNVERIFIED.value
        v["final_confidence"] = 0.0
    # else: still in progress

    # Update Neo4j Finding node with verification data
    if neo4j_available and neo4j_driver and result.status in ("confirmed", "likely"):
        try:
            with neo4j_driver.session() as session:
                session.run("""
                    MATCH (f:Finding {id: $finding_id})
                    SET f.verified = $verified,
                        f.verification_status = $status,
                        f.confidence = $confidence,
                        f.poc_script = $poc_script,
                        f.impact_demonstrated = $impact,
                        f.verification_id = $vrf_id,
                        f.verified_at = datetime()
                """, finding_id=result.finding_id,
                     verified=result.status == "confirmed",
                     status=result.status,
                     confidence=result.confidence,
                     poc_script=result.poc_script,
                     impact=result.impact_demonstrated,
                     vrf_id=verification_id)
        except Exception as e:
            print(f"Neo4j verification update error: {e}")

    # Emit verification result event
    status_label = result.status.upper()
    event_content = f"{status_label}: {v['finding_title']} ({result.method}, {result.confidence:.0%})"
    await _emit("verification_result", "VF", event_content, {
        "verification_id": verification_id,
        "finding_id": result.finding_id,
        "status": result.status,
        "method": result.method,
        "confidence": result.confidence,
        "poc_script": result.poc_script,
        "impact": result.impact_demonstrated,
        "attempt": total_attempts,
        "confirmed_count": confirmed_count,
    })

    # If verification complete (3 attempts or confirmed), update agent status
    if v["final_status"] in ("confirmed", "unverified", "false_positive"):
        status_msg = f"{'CONFIRMED' if v['final_status'] == 'confirmed' else 'UNVERIFIED'}: {v['finding_title']}"
        await state.update_agent_status("VF", AgentStatus.COMPLETED, status_msg)

    return {
        "ok": True,
        "verification_id": verification_id,
        "attempt": total_attempts,
        "result_status": result.status,
        "aggregate": {
            "final_status": v["final_status"],
            "final_confidence": v["final_confidence"],
            "confirmed_count": confirmed_count,
            "total_attempts": total_attempts,
        },
    }


@app.post("/api/verify/{verification_id}/canary")
async def report_canary_callback(verification_id: str, callback: dict):
    """
    Report an interactsh/OOB canary callback (called by canary monitor).

    When a canary URL is triggered by the target, this endpoint records
    the callback as verification evidence.

    Example:
        curl -X POST http://localhost:8080/api/verify/vrf-abc123/canary \\
          -H 'Content-Type: application/json' \\
          -d '{"canary_id":"abc.oast.fun","protocol":"http",
               "source_ip":"10.1.1.20","timestamp":1709000000,
               "raw_request":"GET / HTTP/1.1..."}'
    """
    if verification_id not in _verifications:
        return JSONResponse(status_code=404, content={
            "error": f"Verification {verification_id} not found"
        })

    v = _verifications[verification_id]
    callback["received_at"] = time.time()

    # Auto-create a confirmed result from canary callback
    canary_result = VerificationResult(
        finding_id=v["finding_id"],
        verification_id=verification_id,
        status=VerificationStatus.CONFIRMED.value,
        method=VerificationMethod.CANARY_CALLBACK.value,
        confidence=0.95,  # Canary callbacks are high-confidence
        canary_id=callback.get("canary_id"),
        canary_callback=callback,
        impact_demonstrated=f"OOB callback received from {callback.get('source_ip', 'target')} via {callback.get('protocol', 'unknown')}",
        notes=f"Canary triggered: {callback.get('canary_id', 'unknown')}",
        timestamp=time.time(),
    )

    # Process as a regular verification result
    v["results"].append(canary_result.model_dump())
    v["updated_at"] = time.time()
    v["final_status"] = VerificationStatus.CONFIRMED.value
    v["final_confidence"] = 0.95

    # Update Neo4j
    if neo4j_available and neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                session.run("""
                    MATCH (f:Finding {id: $finding_id})
                    SET f.verified = true,
                        f.verification_status = 'confirmed',
                        f.confidence = 0.95,
                        f.canary_callback = true,
                        f.impact_demonstrated = $impact,
                        f.verified_at = datetime()
                """, finding_id=v["finding_id"],
                     impact=canary_result.impact_demonstrated)
        except Exception as e:
            print(f"Neo4j canary update error: {e}")

    # Emit high-priority event
    await _emit("verification_result", "VF",
        f"CANARY CONFIRMED: {v['finding_title']} — OOB callback received", {
            "verification_id": verification_id,
            "finding_id": v["finding_id"],
            "status": "confirmed",
            "method": "canary_callback",
            "confidence": 0.95,
            "canary": callback,
        })

    await state.update_agent_status("VF", AgentStatus.COMPLETED,
        f"CANARY CONFIRMED: {v['finding_title']}")

    return {
        "ok": True,
        "verification_id": verification_id,
        "status": "confirmed",
        "confidence": 0.95,
        "canary_callback": callback,
    }


@app.get("/api/verify")
async def get_verifications(
    finding_id: Optional[str] = None,
    status: Optional[str] = None,
    engagement_id: Optional[str] = None,
    limit: int = 50,
):
    """
    Get verification records, optionally filtered.

    Query params:
      ?finding_id=abc123       — verifications for a specific finding
      ?status=confirmed        — only confirmed verifications
      ?engagement_id=eng-001   — filter by engagement
    """
    results = []
    for v in sorted(_verifications.values(), key=lambda x: x["updated_at"], reverse=True):
        if finding_id and v["finding_id"] != finding_id:
            continue
        if status and v["final_status"] != status:
            continue
        if engagement_id and v.get("engagement_id") != engagement_id:
            continue
        results.append(v)
        if len(results) >= limit:
            break
    return {
        "verifications": results,
        "count": len(results),
        "summary": {
            "confirmed": sum(1 for v in _verifications.values() if v["final_status"] == "confirmed"),
            "likely": sum(1 for v in _verifications.values() if v["final_status"] == "likely"),
            "unverified": sum(1 for v in _verifications.values() if v["final_status"] == "unverified"),
            "pending": sum(1 for v in _verifications.values() if v["final_status"] == "pending"),
            "in_progress": sum(1 for v in _verifications.values() if v["final_status"] == "in_progress"),
        },
    }


@app.get("/api/verify/{verification_id}")
async def get_verification(verification_id: str):
    """Get a single verification record with full details."""
    if verification_id not in _verifications:
        return JSONResponse(status_code=404, content={
            "error": f"Verification {verification_id} not found"
        })
    return _verifications[verification_id]


# ── F4: CTF Mode ──────────────────────────────────────────────

class CTFCategory(str, Enum):
    WEB = "web"
    CRYPTO = "crypto"
    FORENSICS = "forensics"
    REVERSE = "reverse"
    PWNABLE = "pwnable"
    MISC = "misc"
    OSINT = "osint"


class ChallengeStatus(str, Enum):
    UNSOLVED = "unsolved"
    IN_PROGRESS = "in_progress"
    SOLVED = "solved"
    SKIPPED = "skipped"


class CTFChallenge(BaseModel):
    """A single CTF challenge."""
    id: str
    name: str
    category: CTFCategory
    points: int = 0
    description: str = ""
    url: Optional[str] = None       # Challenge URL (for web challenges)
    files: Optional[list[str]] = None  # Downloadable files
    hints: Optional[list[str]] = None  # Unlocked hints
    status: ChallengeStatus = ChallengeStatus.UNSOLVED
    flag: Optional[str] = None       # Captured flag value
    solved_by: Optional[str] = None  # Agent that solved it
    solved_at: Optional[float] = None
    tool_calls: int = 0              # Track tool call count for early-stopping
    assigned_agent: Optional[str] = None  # Agent currently working on it


class CTFSession(BaseModel):
    """CTF engagement session state."""
    engagement_id: str
    competition_name: str = ""
    time_limit_minutes: int = 0     # 0 = unlimited
    started_at: float
    challenges: list[CTFChallenge] = []
    total_points: int = 0
    captured_points: int = 0
    flags_captured: int = 0
    active: bool = True


# Common CTF flag patterns (compiled once)
FLAG_PATTERNS = [
    re.compile(r"flag\{[^}]+\}", re.IGNORECASE),
    re.compile(r"CTF\{[^}]+\}", re.IGNORECASE),
    re.compile(r"picoCTF\{[^}]+\}"),
    re.compile(r"HTB\{[^}]+\}"),
    re.compile(r"THM\{[^}]+\}"),         # TryHackMe
    re.compile(r"FLAG-[A-Za-z0-9\-]+"),  # SANS style
    re.compile(r"0xL4BS\{[^}]+\}"),      # ZeroK Labs internal CTFs
]

# Max tool calls before pivoting to next challenge
CTF_EARLY_STOP_THRESHOLD = 40

# Category-specific agent assignments
CTF_CATEGORY_AGENTS: dict[str, list[str]] = {
    "web":       ["WV", "JS", "AT", "AA", "EC", "EX"],
    "crypto":    ["SC", "EC", "EX"],
    "forensics": ["PO", "SC", "AR"],
    "reverse":   ["SC", "EC"],
    "pwnable":   ["EC", "EX", "SC"],
    "misc":      ["PO", "AR", "SC", "EC"],
    "osint":     ["PO", "AR"],
}

# Challenge auto-classification keywords
CTF_CATEGORY_KEYWORDS: dict[str, list[str]] = {
    "web": ["sql", "xss", "injection", "cookie", "session", "jwt", "http",
            "api", "login", "admin", "upload", "ssti", "ssrf", "csrf",
            "deserialization", "lfi", "rfi", "traversal", "redirect"],
    "crypto": ["rsa", "aes", "cipher", "encrypt", "decrypt", "key", "hash",
               "base64", "xor", "modular", "prime", "padding"],
    "forensics": ["pcap", "wireshark", "volatility", "memory", "disk",
                  "image", "steganography", "exif", "metadata", "carve",
                  "strings", "binwalk", "autopsy"],
    "reverse": ["binary", "elf", "pe", "disassemble", "decompile", "ghidra",
                "ida", "gdb", "assembly", "obfuscated", "packed"],
    "pwnable": ["buffer overflow", "bof", "rop", "shellcode", "heap",
                "stack", "format string", "canary", "pie", "aslr", "nx"],
    "osint": ["find", "locate", "who", "where", "social", "geolocation",
              "metadata", "public", "open source"],
}

# In-memory CTF state
_ctf_session: dict | None = None  # Active CTF session


def classify_challenge(name: str, description: str) -> str:
    """Auto-classify a challenge based on name + description keywords."""
    text = f"{name} {description}".lower()
    scores: dict[str, int] = {}
    for category, keywords in CTF_CATEGORY_KEYWORDS.items():
        scores[category] = sum(1 for kw in keywords if kw in text)
    if not scores or max(scores.values()) == 0:
        return "misc"
    return max(scores, key=scores.get)


def detect_flags(text: str) -> list[str]:
    """Extract CTF flags from text using compiled patterns."""
    flags = []
    for pattern in FLAG_PATTERNS:
        flags.extend(pattern.findall(text))
    return list(set(flags))  # Deduplicate


@app.post("/api/ctf/start")
async def start_ctf_session(
    engagement_id: str = "eng-001",
    competition_name: str = "",
    time_limit_minutes: int = 0,
):
    """
    Start a CTF mode session.

    This switches the engagement into CTF mode — optimized for
    jeopardy-style flag capture with time pressure.
    """
    global _ctf_session

    _ctf_session = {
        "engagement_id": engagement_id,
        "competition_name": competition_name or f"CTF-{engagement_id}",
        "time_limit_minutes": time_limit_minutes,
        "started_at": time.time(),
        "challenges": {},  # challenge_id → challenge dict
        "total_points": 0,
        "captured_points": 0,
        "flags_captured": 0,
        "active": True,
    }

    await state.add_event(AgentEvent(
        id=str(uuid.uuid4())[:8],
        type="system",
        agent="ST",
        content=f"CTF MODE ACTIVATED — {competition_name or 'Competition'}. "
                f"Time limit: {time_limit_minutes}m." if time_limit_minutes
                else f"CTF MODE ACTIVATED — {competition_name or 'Competition'}. No time limit.",
        timestamp=time.time(),
        metadata={"ctf_mode": True, "competition": competition_name},
    ))

    await state.broadcast({
        "type": "ctf_started",
        "engagement_id": engagement_id,
        "competition_name": competition_name,
        "time_limit_minutes": time_limit_minutes,
        "started_at": _ctf_session["started_at"],
        "timestamp": time.time(),
    })

    return {
        "ok": True,
        "session": {
            "engagement_id": engagement_id,
            "competition_name": _ctf_session["competition_name"],
            "time_limit_minutes": time_limit_minutes,
            "started_at": _ctf_session["started_at"],
        },
    }


@app.post("/api/ctf/stop")
async def stop_ctf_session():
    """Stop the active CTF session and return final scoreboard."""
    global _ctf_session
    if not _ctf_session:
        return JSONResponse(status_code=404, content={"error": "No active CTF session"})

    _ctf_session["active"] = False
    elapsed = time.time() - _ctf_session["started_at"]

    summary = {
        "competition": _ctf_session["competition_name"],
        "duration_minutes": round(elapsed / 60, 1),
        "challenges_total": len(_ctf_session["challenges"]),
        "challenges_solved": sum(
            1 for c in _ctf_session["challenges"].values()
            if c["status"] == "solved"
        ),
        "flags_captured": _ctf_session["flags_captured"],
        "total_points": _ctf_session["total_points"],
        "captured_points": _ctf_session["captured_points"],
    }

    await _emit("system", "ST",
        f"CTF SESSION ENDED — {summary['challenges_solved']}/{summary['challenges_total']} solved, "
        f"{summary['captured_points']}/{summary['total_points']} pts in {summary['duration_minutes']}m")

    await state.broadcast({
        "type": "ctf_stopped",
        "summary": summary,
        "timestamp": time.time(),
    })

    result = {"ok": True, "summary": summary}
    _ctf_session = None
    return result


@app.post("/api/ctf/challenges")
async def add_ctf_challenge(challenge: CTFChallenge):
    """
    Add a challenge to the active CTF session.

    If no category is set, auto-classifies based on name/description.
    """
    if not _ctf_session or not _ctf_session["active"]:
        return JSONResponse(status_code=400, content={
            "error": "No active CTF session. Start one with POST /api/ctf/start"
        })

    # Auto-classify if category is misc and description suggests otherwise
    if challenge.category == CTFCategory.MISC and challenge.description:
        detected = classify_challenge(challenge.name, challenge.description)
        if detected != "misc":
            challenge.category = CTFCategory(detected)

    ch = challenge.model_dump()
    ch["tool_calls"] = 0
    _ctf_session["challenges"][challenge.id] = ch
    _ctf_session["total_points"] += challenge.points

    # Auto-assign primary agent based on category
    agents = CTF_CATEGORY_AGENTS.get(challenge.category.value, ["EC"])
    ch["assigned_agent"] = agents[0] if agents else "EC"

    await _emit("system", "ST",
        f"Challenge added: [{challenge.category.value.upper()}] {challenge.name} "
        f"({challenge.points}pts) → assigned to {ch['assigned_agent']}",
        {"ctf_challenge_id": challenge.id, "category": challenge.category.value})

    await state.broadcast({
        "type": "ctf_challenge_added",
        "challenge": ch,
        "timestamp": time.time(),
    })

    return {"ok": True, "challenge_id": challenge.id, "assigned_agent": ch["assigned_agent"]}


@app.post("/api/ctf/challenges/batch")
async def add_ctf_challenges_batch(challenges: list[CTFChallenge]):
    """Add multiple challenges at once (e.g., import from CTFd API)."""
    if not _ctf_session or not _ctf_session["active"]:
        return JSONResponse(status_code=400, content={
            "error": "No active CTF session"
        })

    added = []
    for challenge in challenges:
        if challenge.category == CTFCategory.MISC and challenge.description:
            detected = classify_challenge(challenge.name, challenge.description)
            if detected != "misc":
                challenge.category = CTFCategory(detected)

        ch = challenge.model_dump()
        ch["tool_calls"] = 0
        agents = CTF_CATEGORY_AGENTS.get(challenge.category.value, ["EC"])
        ch["assigned_agent"] = agents[0] if agents else "EC"
        _ctf_session["challenges"][challenge.id] = ch
        _ctf_session["total_points"] += challenge.points
        added.append({"id": challenge.id, "assigned_agent": ch["assigned_agent"]})

    await _emit("system", "ST",
        f"Batch import: {len(added)} challenges added ({_ctf_session['total_points']}pts total)")

    await state.broadcast({
        "type": "ctf_challenges_batch",
        "count": len(added),
        "total_points": _ctf_session["total_points"],
        "timestamp": time.time(),
    })

    return {"ok": True, "added": added, "total_challenges": len(_ctf_session["challenges"])}


@app.post("/api/ctf/flag")
async def submit_ctf_flag(
    challenge_id: str,
    flag: str,
    agent: str = "EX",
):
    """
    Submit a captured flag for a challenge.

    Called by agents when they detect a flag in tool output, or manually
    by the operator.
    """
    if not _ctf_session or not _ctf_session["active"]:
        return JSONResponse(status_code=400, content={
            "error": "No active CTF session"
        })

    ch = _ctf_session["challenges"].get(challenge_id)
    if not ch:
        return JSONResponse(status_code=404, content={
            "error": f"Challenge {challenge_id} not found"
        })

    if ch["status"] == "solved":
        return {"ok": True, "already_solved": True, "flag": ch["flag"]}

    # Record the flag capture
    ch["status"] = "solved"
    ch["flag"] = flag
    ch["solved_by"] = agent
    ch["solved_at"] = time.time()
    _ctf_session["flags_captured"] += 1
    _ctf_session["captured_points"] += ch["points"]

    # Neo4j persistence
    if neo4j_available and neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                session.run("""
                    MERGE (ch:CTFChallenge {id: $cid})
                    SET ch.name = $name,
                        ch.category = $category,
                        ch.points = $points,
                        ch.status = 'solved',
                        ch.flag = $flag,
                        ch.solved_by = $agent,
                        ch.solved_at = datetime(),
                        ch.engagement_id = $eid
                """, cid=challenge_id, name=ch["name"],
                     category=ch["category"], points=ch["points"],
                     flag=flag, agent=agent,
                     eid=_ctf_session["engagement_id"])
        except Exception as e:
            print(f"Neo4j CTF flag error: {e}")

    elapsed = time.time() - _ctf_session["started_at"]
    await _emit("system", agent,
        f"FLAG CAPTURED: {ch['name']} ({ch['points']}pts) — "
        f"{_ctf_session['flags_captured']} flags, "
        f"{_ctf_session['captured_points']}/{_ctf_session['total_points']}pts "
        f"@ {elapsed/60:.1f}m",
        {"ctf_flag": True, "challenge_id": challenge_id, "points": ch["points"]})

    await state.broadcast({
        "type": "ctf_flag_captured",
        "challenge_id": challenge_id,
        "challenge_name": ch["name"],
        "category": ch["category"],
        "points": ch["points"],
        "flag": flag,
        "agent": agent,
        "flags_total": _ctf_session["flags_captured"],
        "points_total": _ctf_session["captured_points"],
        "points_max": _ctf_session["total_points"],
        "timestamp": time.time(),
    })

    return {
        "ok": True,
        "challenge_id": challenge_id,
        "points": ch["points"],
        "flags_captured": _ctf_session["flags_captured"],
        "captured_points": _ctf_session["captured_points"],
    }


@app.post("/api/ctf/challenges/{challenge_id}/hint")
async def add_ctf_hint(challenge_id: str, hint: str):
    """Add a hint to a challenge (when hints are released mid-competition)."""
    if not _ctf_session or not _ctf_session["active"]:
        return JSONResponse(status_code=400, content={"error": "No active CTF session"})

    ch = _ctf_session["challenges"].get(challenge_id)
    if not ch:
        return JSONResponse(status_code=404, content={"error": f"Challenge {challenge_id} not found"})

    if ch["hints"] is None:
        ch["hints"] = []
    ch["hints"].append(hint)

    await _emit("system", "ST",
        f"HINT for {ch['name']}: {hint[:100]}{'...' if len(hint) > 100 else ''}",
        {"ctf_hint": True, "challenge_id": challenge_id})

    await state.broadcast({
        "type": "ctf_hint_added",
        "challenge_id": challenge_id,
        "hint_number": len(ch["hints"]),
        "timestamp": time.time(),
    })

    return {"ok": True, "hints_count": len(ch["hints"])}


@app.post("/api/ctf/challenges/{challenge_id}/skip")
async def skip_ctf_challenge(challenge_id: str, reason: str = ""):
    """Skip a challenge (manual or from early-stopping threshold)."""
    if not _ctf_session or not _ctf_session["active"]:
        return JSONResponse(status_code=400, content={"error": "No active CTF session"})

    ch = _ctf_session["challenges"].get(challenge_id)
    if not ch:
        return JSONResponse(status_code=404, content={"error": f"Challenge {challenge_id} not found"})

    ch["status"] = "skipped"
    skip_reason = reason or f"Exceeded {CTF_EARLY_STOP_THRESHOLD} tool calls without progress"

    await _emit("system", "ST",
        f"SKIPPING {ch['name']}: {skip_reason}",
        {"ctf_skip": True, "challenge_id": challenge_id, "tool_calls": ch["tool_calls"]})

    await state.broadcast({
        "type": "ctf_challenge_skipped",
        "challenge_id": challenge_id,
        "reason": skip_reason,
        "timestamp": time.time(),
    })

    return {"ok": True, "skipped": challenge_id}


@app.post("/api/ctf/challenges/{challenge_id}/tool_call")
async def increment_ctf_tool_calls(challenge_id: str):
    """
    Increment tool call counter for a challenge (called by SDK event handler).

    Returns early-stop signal if threshold exceeded.
    """
    if not _ctf_session or not _ctf_session["active"]:
        return {"ok": True, "early_stop": False}

    ch = _ctf_session["challenges"].get(challenge_id)
    if not ch:
        return {"ok": True, "early_stop": False}

    ch["tool_calls"] += 1

    if ch["tool_calls"] >= CTF_EARLY_STOP_THRESHOLD and ch["status"] != "solved":
        return {
            "ok": True,
            "early_stop": True,
            "tool_calls": ch["tool_calls"],
            "threshold": CTF_EARLY_STOP_THRESHOLD,
            "message": f"Challenge {ch['name']} hit {CTF_EARLY_STOP_THRESHOLD} tool calls — recommend pivoting",
        }

    return {"ok": True, "early_stop": False, "tool_calls": ch["tool_calls"]}


@app.get("/api/ctf")
async def get_ctf_session():
    """Get the current CTF session state including scoreboard."""
    if not _ctf_session:
        return JSONResponse(status_code=404, content={"error": "No active CTF session"})

    elapsed = time.time() - _ctf_session["started_at"]
    time_remaining = None
    if _ctf_session["time_limit_minutes"] > 0:
        time_remaining = max(0, _ctf_session["time_limit_minutes"] * 60 - elapsed)

    challenges_by_category: dict[str, list] = {}
    for ch in _ctf_session["challenges"].values():
        cat = ch["category"]
        if cat not in challenges_by_category:
            challenges_by_category[cat] = []
        challenges_by_category[cat].append(ch)

    return {
        "session": {
            "engagement_id": _ctf_session["engagement_id"],
            "competition_name": _ctf_session["competition_name"],
            "active": _ctf_session["active"],
            "started_at": _ctf_session["started_at"],
            "elapsed_minutes": round(elapsed / 60, 1),
            "time_remaining_seconds": time_remaining,
        },
        "scoreboard": {
            "flags_captured": _ctf_session["flags_captured"],
            "captured_points": _ctf_session["captured_points"],
            "total_points": _ctf_session["total_points"],
            "completion_pct": round(
                _ctf_session["captured_points"] / _ctf_session["total_points"] * 100, 1
            ) if _ctf_session["total_points"] > 0 else 0,
        },
        "challenges": _ctf_session["challenges"],
        "by_category": challenges_by_category,
    }


@app.get("/api/ctf/flags")
async def get_ctf_flags():
    """Get all captured flags."""
    if not _ctf_session:
        return JSONResponse(status_code=404, content={"error": "No active CTF session"})

    solved = [
        ch for ch in _ctf_session["challenges"].values()
        if ch["status"] == "solved"
    ]
    solved.sort(key=lambda c: c.get("solved_at", 0))

    return {
        "flags": solved,
        "count": len(solved),
        "points": sum(c["points"] for c in solved),
    }


@app.post("/api/ctf/detect-flags")
async def detect_flags_in_text(text: str):
    """
    Detect CTF flags in arbitrary text (used by SDK event handler).

    Returns extracted flags if any match known patterns.
    """
    flags = detect_flags(text)
    return {"flags": flags, "count": len(flags)}


# ── F5: Cost Optimization & Early-Stopping ────────────────────

# Per-agent budget allocation (from MAPTA research: failed attempts cost 5x more)
AGENT_BUDGETS: dict[str, dict] = {
    # Recon agents — need broad scanning
    "PO": {"max_tool_calls": 60, "max_cost": 0.75, "label": "Passive OSINT"},
    "AR": {"max_tool_calls": 60, "max_cost": 0.75, "label": "Active Recon"},
    # Vuln analysis — standard
    "CV": {"max_tool_calls": 40, "max_cost": 0.50, "label": "CVE Researcher"},
    "AP": {"max_tool_calls": 40, "max_cost": 0.50, "label": "Attack Path"},
    "WV": {"max_tool_calls": 40, "max_cost": 0.50, "label": "Web Vuln Scanner"},
    "SC": {"max_tool_calls": 40, "max_cost": 0.50, "label": "Source Code Analyst"},
    # Exploitation — higher per-call cost (Opus reasoning)
    "EC": {"max_tool_calls": 30, "max_cost": 1.00, "label": "Exploit Crafter"},
    "EX": {"max_tool_calls": 30, "max_cost": 1.00, "label": "Exploitation"},
    # Verification — focused re-testing
    "VF": {"max_tool_calls": 20, "max_cost": 0.30, "label": "Verification"},
    # Post-exploitation — depends on access
    "PE": {"max_tool_calls": 40, "max_cost": 0.50, "label": "Post-Exploitation"},
    "LM": {"max_tool_calls": 40, "max_cost": 0.50, "label": "Lateral Mover"},
    # Strategy — pure reasoning, few tools
    "ST": {"max_tool_calls": 10, "max_cost": 0.50, "label": "Strategy"},
    # Reporting — writing-heavy (Opus)
    "RP": {"max_tool_calls": 15, "max_cost": 0.75, "label": "Reporting"},
    # Web app testing agents
    "JS": {"max_tool_calls": 40, "max_cost": 0.50, "label": "JS Analyzer"},
    "PD": {"max_tool_calls": 40, "max_cost": 0.50, "label": "Param Discovery"},
    "WA": {"max_tool_calls": 40, "max_cost": 0.50, "label": "Web App Fuzzer"},
    "AT": {"max_tool_calls": 40, "max_cost": 0.50, "label": "Auth Tester"},
    "AA": {"max_tool_calls": 40, "max_cost": 0.50, "label": "API Attacker"},
    "DV": {"max_tool_calls": 30, "max_cost": 0.50, "label": "Detection Validator"},
    # Management agents — minimal tools
    "PL": {"max_tool_calls": 10, "max_cost": 0.30, "label": "Planning"},
    "OR": {"max_tool_calls": 10, "max_cost": 0.30, "label": "Orchestrator"},
}

# Default budget for unlisted agents
DEFAULT_BUDGET = {"max_tool_calls": 40, "max_cost": 0.50}

# Token pricing: Sonnet 4.6 rates (per million tokens)
# SDK agents use Sonnet by default, Opus for Strategy/Exploit
PRICING = {
    "sonnet": {"input": 3.0, "output": 15.0},
    "opus":   {"input": 15.0, "output": 75.0},
}
OPUS_AGENTS = {"ST", "EC", "EX", "RP"}  # Agents that use Opus

# In-memory budget tracking: agent_code → {tool_calls, estimated_cost, findings}
_agent_budgets: dict[str, dict] = {}
_engagement_cost: float = 0.0


def _get_agent_budget(agent: str) -> dict:
    """Get or initialize budget tracker for an agent."""
    if agent not in _agent_budgets:
        limits = AGENT_BUDGETS.get(agent, DEFAULT_BUDGET)
        _agent_budgets[agent] = {
            "agent": agent,
            "tool_calls": 0,
            "estimated_cost": 0.0,
            "findings_count": 0,
            "max_tool_calls": limits["max_tool_calls"],
            "max_cost": limits["max_cost"],
            "exhausted": False,
            "warnings_sent": 0,
        }
    return _agent_budgets[agent]


def _estimate_tool_cost(agent: str) -> float:
    """Estimate cost of a single tool call based on agent type.

    Average tool call: ~500 input tokens, ~1500 output tokens.
    MCP tool calls may be cheaper (less output), reasoning heavier.
    """
    pricing = PRICING["opus"] if agent in OPUS_AGENTS else PRICING["sonnet"]
    input_cost = 500 * pricing["input"] / 1_000_000
    output_cost = 1500 * pricing["output"] / 1_000_000
    return input_cost + output_cost


@app.post("/api/budget/tool-call")
async def record_budget_tool_call(agent: str, finding: bool = False):
    """
    Record a tool call against an agent's budget.

    Called by the SDK event handler on each tool_complete.
    Returns budget status including early-stop signal.
    """
    global _engagement_cost

    budget = _get_agent_budget(agent)
    budget["tool_calls"] += 1
    cost = _estimate_tool_cost(agent)
    budget["estimated_cost"] += cost
    _engagement_cost += cost

    if finding:
        budget["findings_count"] += 1

    pct_calls = budget["tool_calls"] / budget["max_tool_calls"] * 100
    pct_cost = budget["estimated_cost"] / budget["max_cost"] * 100 if budget["max_cost"] > 0 else 0

    response = {
        "ok": True,
        "agent": agent,
        "tool_calls": budget["tool_calls"],
        "max_tool_calls": budget["max_tool_calls"],
        "estimated_cost": round(budget["estimated_cost"], 4),
        "max_cost": budget["max_cost"],
        "pct_calls": round(pct_calls, 1),
        "pct_cost": round(pct_cost, 1),
        "engagement_cost": round(_engagement_cost, 4),
        "early_stop": False,
        "warning": None,
    }

    # 80% warning threshold
    if pct_calls >= 80 and budget["warnings_sent"] == 0:
        budget["warnings_sent"] = 1
        response["warning"] = "approaching_limit"
        await _emit("system", agent,
            f"BUDGET WARNING: {AGENT_NAMES.get(agent, agent)} at "
            f"{budget['tool_calls']}/{budget['max_tool_calls']} tool calls "
            f"(${budget['estimated_cost']:.3f}/${budget['max_cost']})",
            {"budget_warning": True, "pct_calls": pct_calls})

    # Budget exhausted
    if budget["tool_calls"] >= budget["max_tool_calls"] or \
       budget["estimated_cost"] >= budget["max_cost"]:
        budget["exhausted"] = True
        response["early_stop"] = True

        if budget["warnings_sent"] < 2:
            budget["warnings_sent"] = 2
            action = "with findings" if budget["findings_count"] > 0 else "WITHOUT findings"
            await _emit("system", agent,
                f"BUDGET EXHAUSTED: {AGENT_NAMES.get(agent, agent)} — "
                f"{budget['tool_calls']} calls, ${budget['estimated_cost']:.3f} "
                f"({action}). Strategy Agent notified.",
                {"budget_exhausted": True, "findings_count": budget["findings_count"]})

            await state.broadcast({
                "type": "budget_exhausted",
                "agent": agent,
                "agentName": AGENT_NAMES.get(agent, agent),
                "tool_calls": budget["tool_calls"],
                "estimated_cost": round(budget["estimated_cost"], 4),
                "findings_count": budget["findings_count"],
                "timestamp": time.time(),
            })

    # Broadcast cost update for dashboard (throttled: every 5 tool calls)
    if budget["tool_calls"] % 5 == 0:
        await state.broadcast({
            "type": "cost_update",
            "agent": agent,
            "tool_calls": budget["tool_calls"],
            "max_tool_calls": budget["max_tool_calls"],
            "estimated_cost": round(budget["estimated_cost"], 4),
            "max_cost": budget["max_cost"],
            "engagement_cost": round(_engagement_cost, 4),
            "timestamp": time.time(),
        })

    return response


@app.post("/api/budget/extend")
async def extend_agent_budget(
    agent: str,
    extra_tool_calls: int = 20,
    extra_cost: float = 0.25,
):
    """
    Extend an agent's budget (called by Strategy Agent or operator).

    Use when an agent is making progress but hit its limit.
    """
    budget = _get_agent_budget(agent)
    budget["max_tool_calls"] += extra_tool_calls
    budget["max_cost"] += extra_cost
    budget["exhausted"] = False
    budget["warnings_sent"] = 0

    await _emit("system", "ST",
        f"Budget extended for {AGENT_NAMES.get(agent, agent)}: "
        f"+{extra_tool_calls} calls, +${extra_cost:.2f} "
        f"(new limit: {budget['max_tool_calls']} calls, ${budget['max_cost']:.2f})",
        {"budget_extended": True, "agent": agent})

    return {
        "ok": True,
        "agent": agent,
        "max_tool_calls": budget["max_tool_calls"],
        "max_cost": budget["max_cost"],
    }


@app.get("/api/budget")
async def get_budgets():
    """Get all agent budget status and total engagement cost."""
    agents = {}
    for code in AGENT_NAMES:
        b = _get_agent_budget(code)
        agents[code] = {
            "name": AGENT_NAMES[code],
            "tool_calls": b["tool_calls"],
            "max_tool_calls": b["max_tool_calls"],
            "estimated_cost": round(b["estimated_cost"], 4),
            "max_cost": b["max_cost"],
            "pct_calls": round(b["tool_calls"] / b["max_tool_calls"] * 100, 1) if b["max_tool_calls"] > 0 else 0,
            "findings_count": b["findings_count"],
            "exhausted": b["exhausted"],
        }
    return {
        "agents": agents,
        "engagement_cost": round(_engagement_cost, 4),
        "active_agents": sum(1 for b in _agent_budgets.values() if b["tool_calls"] > 0),
        "exhausted_agents": sum(1 for b in _agent_budgets.values() if b["exhausted"]),
    }


@app.get("/api/budget/{agent}")
async def get_agent_budget(agent: str):
    """Get budget status for a specific agent."""
    if agent not in AGENT_NAMES:
        return JSONResponse(status_code=404, content={"error": f"Unknown agent: {agent}"})
    b = _get_agent_budget(agent)
    return {
        "agent": agent,
        "name": AGENT_NAMES[agent],
        "tool_calls": b["tool_calls"],
        "max_tool_calls": b["max_tool_calls"],
        "estimated_cost": round(b["estimated_cost"], 4),
        "max_cost": b["max_cost"],
        "pct_calls": round(b["tool_calls"] / b["max_tool_calls"] * 100, 1),
        "findings_count": b["findings_count"],
        "exhausted": b["exhausted"],
    }


@app.post("/api/budget/reset")
async def reset_budgets():
    """Reset all agent budgets (called on new engagement)."""
    global _agent_budgets, _engagement_cost
    _agent_budgets = {}
    _engagement_cost = 0.0
    return {"ok": True, "message": "All budgets reset"}


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
                    OPTIONAL MATCH (f:Finding {engagement_id: e.id})
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
    evidence_mode: str = "exploitable"  # "exploitable" (only confirmed vulns) or "all" (capture everything)
    scope_doc: str = ""  # Full raw text from uploaded SoW/RoE — injected into agent prompt for scope enforcement
    client_industry: str = "general"  # healthcare, financial, government, saas, critical_infra, ai_ml, eu_regulated, general


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
        "raw_text": text[:10000],  # Full document text for agent prompt injection (capped at 10KB)
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
                        scope_doc: $scope_doc,
                        types: $types,
                        authorization: $authorization,
                        evidence_mode: $evidence_mode,
                        client_industry: $client_industry,
                        status: 'active',
                        start_date: $start_date
                    })
                """, id=engagement_id, name=payload.name, client=payload.client,
                     scope=payload.scope, scope_doc=payload.scope_doc, types=types_str,
                     authorization=payload.authorization,
                     evidence_mode=payload.evidence_mode,
                     client_industry=payload.client_industry, start_date=start_date)

            ensure_evidence_dirs(engagement_id)

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
    ensure_evidence_dirs(engagement_id)

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
                    OPTIONAL MATCH (h:Host {engagement_id: $eid})
                    OPTIONAL MATCH (h)-[:HAS_SERVICE]->(s:Service)
                    OPTIONAL MATCH (v:Vulnerability {engagement_id: $eid})
                    WITH e, count(DISTINCT h) AS hosts,
                         count(DISTINCT s) AS services,
                         count(DISTINCT v) AS vulns
                    OPTIONAL MATCH (f:Finding {engagement_id: $eid})
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
    # Fallback: parse port counts from nmap/naabu output if findings_count was 0
    if total_ports == 0:
        import re
        for s in eng_scans:
            if s.get("tool") in ("nmap_scan", "naabu_scan") and s.get("output_preview"):
                port_matches = re.findall(r'PORT\s+\d+', s["output_preview"])
                total_ports += len(port_matches)
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
                # BUG-009: Get engagement scope as fallback for affected_hosts
                engagement_scope = ""
                try:
                    scope_rec = session.run(
                        "MATCH (e:Engagement {id: $eid}) RETURN e.scope AS scope",
                        eid=eid
                    ).single()
                    if scope_rec and scope_rec.get("scope"):
                        engagement_scope = scope_rec["scope"]
                except Exception:
                    pass

                # BUG-010: Count total evidence artifacts for this engagement
                total_artifacts = 0
                try:
                    art_rec = session.run(
                        "MATCH (a:Artifact {engagement_id: $eid}) RETURN count(a) AS cnt",
                        eid=eid
                    ).single()
                    if art_rec:
                        total_artifacts = art_rec["cnt"]
                except Exception:
                    pass

                result = session.run("""
                    MATCH (f:Finding {engagement_id: $eid})
                    OPTIONAL MATCH (f)-[:FOUND_ON]->(h:Host)
                    WITH f, collect(DISTINCT h.ip) AS affected_hosts
                    OPTIONAL MATCH (f)-[:EVIDENCED_BY]->(ep:EvidencePackage)
                    OPTIONAL MATCH (f)-[:HAS_ARTIFACT]->(art:Artifact)
                    RETURN f.id AS id, f.title AS title, f.severity AS severity,
                           f.cvss AS cvss, f.status AS status, f.category AS category,
                           f.description AS description, f.target AS target,
                           f.evidence AS evidence, affected_hosts,
                           count(DISTINCT ep) + count(DISTINCT art) AS evidence_count
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
                    # BUG-009: Fall back to engagement scope if still no hosts
                    if not hosts and engagement_scope:
                        scope_host = engagement_scope.split(":")[0] if ":" in engagement_scope else engagement_scope
                        # Clean up — scope might be a URL like "http://target:port"
                        scope_host = scope_host.replace("http://", "").replace("https://", "")
                        if scope_host:
                            hosts = [scope_host]
                    # Derive evidence_count from evidence text if no EVIDENCED_BY relationships
                    ev_count = record["evidence_count"]
                    if ev_count == 0 and record.get("evidence"):
                        ev_count = 1
                    # BUG-010: If still 0 but engagement has artifacts, show total for visibility
                    if ev_count == 0 and total_artifacts > 0:
                        ev_count = total_artifacts
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

                # BUG-016: Also include Vulnerability nodes not yet promoted to Findings
                # The AI often creates Vulnerability nodes during scanning but doesn't
                # always create formal Finding nodes for each one
                vuln_result = session.run("""
                    MATCH (v:Vulnerability {engagement_id: $eid})
                    OPTIONAL MATCH (f:Finding {engagement_id: $eid})
                    WHERE f.title = v.name OR (f.cve IS NOT NULL AND f.cve = v.cve)
                    WITH v, f
                    WHERE f IS NULL
                    RETURN v.id AS id, COALESCE(v.name, v.title, 'Untitled') AS title,
                           toLower(COALESCE(v.severity, 'info')) AS severity,
                           v.cvss AS cvss, 'discovered' AS status,
                           COALESCE(v.category, '') AS category,
                           COALESCE(v.description, '') AS description,
                           v.target AS target, null AS evidence
                    ORDER BY v.cvss DESC
                """, eid=eid)

                for record in vuln_result:
                    host_part = ""
                    t = record.get("target", "")
                    if t:
                        host_part = t.split(":")[0] if ":" in t else t
                    findings.append({
                        "id": record["id"],
                        "title": record["title"],
                        "severity": record["severity"],
                        "cvss": record.get("cvss"),
                        "status": "discovered",
                        "category": record.get("category", ""),
                        "description": record.get("description", ""),
                        "affected_hosts": [host_part] if host_part else [],
                        "evidence_count": 0,
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
                    MATCH (v:Vulnerability {engagement_id: $eid})
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
                    OPTIONAL MATCH (f:Finding {engagement_id: $eid})
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

    # MTTE: compute from Neo4j finding timestamps when in-memory is empty
    if not per_finding_times and neo4j_available and neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                result = session.run("""
                    MATCH (f:Finding {engagement_id: $eid})
                    WHERE f.timestamp IS NOT NULL
                    RETURN f.title AS title, f.timestamp AS ts, f.category AS category,
                           f.evidence AS evidence
                    ORDER BY f.timestamp ASC
                """, eid=eid)
                all_ts = []
                exploit_cats_neo = {'validated exploit', 'exploitation', 'injection',
                                    'authentication bypass', 'lateral movement'}
                neo4j_exploit_findings = []
                for record in result:
                    all_ts.append(record["ts"])
                    cat = (record["category"] or "").lower()
                    if any(ec in cat for ec in exploit_cats_neo) or record.get("evidence"):
                        neo4j_exploit_findings.append({"title": record["title"], "ts": record["ts"]})
                if all_ts and neo4j_exploit_findings:
                    start_ts = all_ts[0]
                    for ef in neo4j_exploit_findings:
                        delta = int(ef["ts"] - start_ts)
                        per_finding_times.append({"title": ef["title"], "time_s": max(0, delta)})
                    mtte_seconds = int(sum(t["time_s"] for t in per_finding_times) / len(per_finding_times))
        except Exception as e:
            print(f"Neo4j MTTE query error: {e}")

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
                    MATCH (s:Service {engagement_id: $eid})
                    OPTIONAL MATCH (s)<-[:HAS_SERVICE]-(h:Host)
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

    # Fallback: query AttackPath nodes when no LEADS_TO relationships exist
    if not chains and neo4j_available and neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                result = session.run("""
                    MATCH (ap:AttackPath {engagement_id: $eid})
                    RETURN ap.id AS id, ap.title AS title, ap.description AS description,
                           ap.severity AS severity, ap.impact AS impact
                """, eid=eid)
                for record in result:
                    chains.append({
                        "id": record["id"],
                        "name": record["title"],
                        "severity": record.get("severity") or "critical",
                        "impact": record.get("impact") or record.get("description") or "",
                        "steps": [],
                    })
        except Exception as e:
            logger.warning("Neo4j AttackPath query error: %s", e)

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
                    MATCH (f:Finding {engagement_id: $eid})
                    RETURN count(f) AS cnt
                """, eid=eid)
                record = result.single()
                deleted = record["cnt"] if record else 0

                # Delete evidence packages then findings
                session.run("""
                    MATCH (f:Finding {engagement_id: $eid})
                    OPTIONAL MATCH (f)-[:EVIDENCED_BY]->(ep:EvidencePackage)
                    DETACH DELETE ep
                """, eid=eid)
                session.run("""
                    MATCH (f:Finding {engagement_id: $eid})
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
    """Get evidence packages AND artifacts for a finding from Neo4j or fallback.

    Queries both EVIDENCED_BY and SUPPORTS relationships for EvidencePackages
    (handling agent inconsistency), plus HAS_ARTIFACT for Artifact nodes.
    """
    if neo4j_available and neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                # Query EvidencePackages via both relationship names (agent inconsistency)
                ep_result = session.run("""
                    MATCH (f:Finding {id: $fid})
                    OPTIONAL MATCH (f)-[:EVIDENCED_BY]->(ep1:EvidencePackage)
                    OPTIONAL MATCH (f)-[:SUPPORTS]->(ep2:EvidencePackage)
                    WITH collect(DISTINCT ep1) + collect(DISTINCT ep2) AS all_eps
                    UNWIND all_eps AS ep
                    WITH ep WHERE ep IS NOT NULL
                    RETURN ep.id AS id, ep.type AS type, ep.timestamp AS timestamp,
                           ep.http_pairs AS http_pairs,
                           ep.output_evidence AS output_evidence,
                           ep.response_diff AS response_diff,
                           ep.timing_baseline_ms AS timing_baseline_ms,
                           ep.timing_exploit_ms AS timing_exploit_ms,
                           ep.confidence AS confidence,
                           ep.status AS status,
                           ep.verified_by AS verified_by,
                           ep.request AS request,
                           ep.response AS response,
                           ep.screenshot AS screenshot,
                           ep.notes AS notes
                    ORDER BY ep.timestamp DESC
                """, fid=fid)
                evidence_packages = []
                for record in ep_result:
                    evidence_packages.append({
                        "id": record["id"],
                        "type": record.get("type"),
                        "timestamp": record.get("timestamp"),
                        "http_pairs": record.get("http_pairs"),
                        "output_evidence": record.get("output_evidence"),
                        "response_diff": record.get("response_diff"),
                        "timing_baseline_ms": record.get("timing_baseline_ms"),
                        "timing_exploit_ms": record.get("timing_exploit_ms"),
                        "confidence": record.get("confidence"),
                        "status": record.get("status"),
                        "verified_by": record.get("verified_by"),
                        "request": record.get("request"),
                        "response": record.get("response"),
                        "screenshot": record.get("screenshot"),
                        "notes": record.get("notes"),
                    })

                # Query Artifacts via HAS_ARTIFACT
                art_result = session.run("""
                    MATCH (f:Finding {id: $fid})-[:HAS_ARTIFACT]->(a:Artifact)
                    RETURN a.id AS id, a.type AS type, a.timestamp AS timestamp,
                           a.file_path AS file_path, a.file_hash AS file_hash,
                           a.file_size AS file_size, a.mime_type AS mime_type,
                           a.caption AS caption, a.agent AS agent, a.backend AS backend,
                           a.capture_mode AS capture_mode, a.thumbnail_path AS thumbnail_path,
                           a.engagement_id AS engagement_id, a.finding_id AS finding_id
                    ORDER BY a.timestamp DESC
                """, fid=fid)
                artifacts = []
                for record in art_result:
                    artifacts.append({
                        "id": record["id"],
                        "type": record.get("type"),
                        "timestamp": record.get("timestamp"),
                        "file_path": record.get("file_path"),
                        "file_hash": record.get("file_hash"),
                        "file_size": record.get("file_size"),
                        "mime_type": record.get("mime_type"),
                        "caption": record.get("caption"),
                        "agent": record.get("agent"),
                        "backend": record.get("backend"),
                        "capture_mode": record.get("capture_mode"),
                        "thumbnail_path": record.get("thumbnail_path"),
                        "engagement_id": record.get("engagement_id"),
                        "finding_id": record.get("finding_id"),
                        "file_url": f"/api/artifacts/{record['id']}/file",
                        "thumbnail_url": f"/api/artifacts/{record['id']}/thumbnail" if record.get("thumbnail_path") else None,
                    })

                return {
                    "evidence_packages": evidence_packages,
                    "artifacts": artifacts,
                    "source": "neo4j",
                }
        except Exception as e:
            print(f"Neo4j evidence query error: {e}")
            # Fall through to mock

    # Fallback: return mock evidence
    return {
        "evidence_packages": [
            {
                "id": "ev-001",
                "type": "http",
                "timestamp": time.time() - 300,
                "request": "POST /login HTTP/1.1\nHost: portal.acme.com\n\nusername=admin' OR 1=1--&password=test",
                "response": "HTTP/1.1 200 OK\n\n{\"status\":\"success\",\"user\":\"admin\"}",
                "screenshot": None,
                "notes": "Boolean-based blind SQL injection confirmed",
                "http_pairs": None,
                "output_evidence": None,
                "response_diff": None,
                "timing_baseline_ms": None,
                "timing_exploit_ms": None,
                "confidence": None,
                "status": "open",
                "verified_by": None,
            }
        ],
        "artifacts": [],
        "source": "mock",
    }


# ──────────────────────────────────────────────
# REST API — Artifact Upload & Management (Task 2)
# ──────────────────────────────────────────────

@app.post("/api/artifacts")
async def upload_artifact(
    file: UploadFile = File(...),
    finding_id: str = Form(...),
    engagement_id: str = Form(...),
    type: str = Form(...),
    caption: str = Form(""),
    agent: str = Form(""),
    backend: str = Form(""),
    capture_mode: str = Form("manual"),
    evidence_package_id: Optional[str] = Form(None),
):
    """Upload a binary artifact (screenshot, HTTP pair, command output, etc.) for a finding.

    Saves to the engagement's 08-evidence directory, generates thumbnails for
    screenshots, stores metadata in Neo4j, and links to the Finding node.
    """
    # Validate artifact type
    if type not in ALLOWED_ARTIFACT_TYPES:
        return JSONResponse(
            status_code=400,
            content={"error": f"Invalid artifact type '{type}'. Allowed: {sorted(ALLOWED_ARTIFACT_TYPES)}"},
        )

    # Read file content and check size
    content = await file.read()
    if len(content) > MAX_ARTIFACT_SIZE:
        return JSONResponse(
            status_code=413,
            content={"error": f"File too large ({len(content)} bytes). Max {MAX_ARTIFACT_SIZE} bytes."},
        )

    # Compute SHA-256 hash
    file_hash = hashlib.sha256(content).hexdigest()

    # Detect MIME type
    mime_type = file.content_type or "application/octet-stream"
    ext = Path(file.filename or "artifact").suffix.lower() or ".bin"
    if not ext or ext == ".bin":
        guessed = mimetypes.guess_extension(mime_type)
        if guessed:
            ext = guessed

    # Build safe caption for filename (alphanumeric + dashes, max 32 chars)
    safe_caption = re.sub(r"[^a-zA-Z0-9-]", "-", caption)[:32].strip("-") or "artifact"

    # Query Finding severity and category for filename context
    finding_severity = "unknown"
    finding_category = "uncategorized"
    if neo4j_available and neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                result = session.run(
                    "MATCH (f:Finding {id: $fid}) RETURN f.severity AS severity, f.category AS category",
                    fid=finding_id,
                )
                record = result.single()
                if record:
                    finding_severity = (record.get("severity") or "unknown").lower()
                    finding_category = re.sub(r"[^a-zA-Z0-9-]", "-", record.get("category") or "uncategorized").lower()[:24]
        except Exception as e:
            print(f"Neo4j finding lookup error: {e}")

    # Generate artifact ID and timestamp
    artifact_id = uuid.uuid4().hex[:8]
    timestamp = time.time()
    ts_str = datetime.utcnow().strftime("%Y%m%d-%H%M%S")

    # Build filename
    filename = f"{artifact_id}-{finding_severity}-{finding_category}-{safe_caption}-{ts_str}{ext}"

    # Determine subdirectory based on type
    type_to_subdir = {
        "screenshot": "screenshots",
        "http_pair": "http-pairs",
        "command_output": "command-output",
        "tool_log": "tool-logs",
        "response_diff": "response-diffs",
    }
    subdir = type_to_subdir.get(type, "command-output")

    # Ensure evidence directories exist and get root
    evidence_root = ensure_evidence_dirs(engagement_id)
    dest_path = evidence_root / subdir / filename

    # Write file to disk
    dest_path.write_bytes(content)

    # Compute relative path (relative to athena_dir = 3 levels up from server.py)
    athena_dir = Path(__file__).parent.parent.parent
    try:
        rel_path = str(dest_path.relative_to(athena_dir))
    except ValueError:
        rel_path = str(dest_path)

    # Generate thumbnail for screenshots (Pillow, 300px wide, JPEG 75%)
    thumbnail_path = None
    thumbnail_rel = None
    if type == "screenshot":
        try:
            img = Image.open(BytesIO(content))
            ratio = THUMBNAIL_WIDTH / img.width
            new_height = int(img.height * ratio)
            thumb = img.resize((THUMBNAIL_WIDTH, new_height), Image.LANCZOS)
            thumb_filename = f"{artifact_id}-thumb.jpg"
            thumb_dest = evidence_root / "screenshots" / "thumbnails" / thumb_filename
            thumb_bytes = BytesIO()
            thumb.convert("RGB").save(thumb_bytes, format="JPEG", quality=THUMBNAIL_QUALITY)
            thumb_dest.write_bytes(thumb_bytes.getvalue())
            try:
                thumbnail_rel = str(thumb_dest.relative_to(athena_dir))
            except ValueError:
                thumbnail_rel = str(thumb_dest)
            thumbnail_path = thumbnail_rel
        except Exception as e:
            print(f"Thumbnail generation error: {e}")

    # Persist to Neo4j
    if neo4j_available and neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                # Create Artifact node
                session.run("""
                    CREATE (a:Artifact {
                        id: $id,
                        engagement_id: $engagement_id,
                        finding_id: $finding_id,
                        evidence_package_id: $evidence_package_id,
                        type: $type,
                        file_path: $file_path,
                        file_hash: $file_hash,
                        file_size: $file_size,
                        mime_type: $mime_type,
                        caption: $caption,
                        agent: $agent,
                        backend: $backend,
                        capture_mode: $capture_mode,
                        thumbnail_path: $thumbnail_path,
                        timestamp: $timestamp
                    })
                """,
                id=artifact_id,
                engagement_id=engagement_id,
                finding_id=finding_id,
                evidence_package_id=evidence_package_id,
                type=type,
                file_path=rel_path,
                file_hash=file_hash,
                file_size=len(content),
                mime_type=mime_type,
                caption=caption,
                agent=agent,
                backend=backend,
                capture_mode=capture_mode,
                thumbnail_path=thumbnail_path,
                timestamp=timestamp,
                )

                # Link Finding -> Artifact
                session.run("""
                    MATCH (f:Finding {id: $fid}), (a:Artifact {id: $aid})
                    MERGE (f)-[:HAS_ARTIFACT]->(a)
                """, fid=finding_id, aid=artifact_id)

                # Link EvidencePackage -> Artifact if provided
                if evidence_package_id:
                    session.run("""
                        MATCH (ep:EvidencePackage {id: $epid}), (a:Artifact {id: $aid})
                        MERGE (ep)-[:HAS_ARTIFACT]->(a)
                    """, epid=evidence_package_id, aid=artifact_id)

        except Exception as e:
            print(f"Neo4j artifact write error: {e}")

    return {
        "ok": True,
        "artifact_id": artifact_id,
        "file_path": rel_path,
        "file_hash": f"sha256:{file_hash}",
        "file_size": len(content),
        "mime_type": mime_type,
        "thumbnail_path": thumbnail_path,
        "file_url": f"/api/artifacts/{artifact_id}/file",
        "thumbnail_url": f"/api/artifacts/{artifact_id}/thumbnail" if thumbnail_path else None,
        "timestamp": timestamp,
    }


# ──────────────────────────────────────────────
# REST API — Artifact Query + File Serving (Task 3)
# ──────────────────────────────────────────────

@app.get("/api/artifacts")
async def list_artifacts(
    engagement_id: Optional[str] = None,
    finding_id: Optional[str] = None,
    type: Optional[str] = None,
    backend: Optional[str] = None,
    capture_mode: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
):
    """List artifacts with optional filters."""
    if neo4j_available and neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                conditions = []
                params: dict = {"limit": limit, "offset": offset}
                if engagement_id:
                    conditions.append("a.engagement_id = $engagement_id")
                    params["engagement_id"] = engagement_id
                if finding_id:
                    conditions.append("a.finding_id = $finding_id")
                    params["finding_id"] = finding_id
                if type:
                    conditions.append("a.type = $type")
                    params["type"] = type
                if backend:
                    conditions.append("a.backend = $backend")
                    params["backend"] = backend
                if capture_mode:
                    conditions.append("a.capture_mode = $capture_mode")
                    params["capture_mode"] = capture_mode

                where_clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""
                query = f"""
                    MATCH (a:Artifact) {where_clause}
                    OPTIONAL MATCH (f:Finding {{id: a.finding_id}})
                    RETURN a.id AS id, a.type AS type, a.timestamp AS timestamp,
                           a.file_path AS file_path, a.file_hash AS file_hash,
                           a.file_size AS file_size, a.mime_type AS mime_type,
                           a.caption AS caption, a.agent AS agent, a.backend AS backend,
                           a.capture_mode AS capture_mode, a.thumbnail_path AS thumbnail_path,
                           a.engagement_id AS engagement_id, a.finding_id AS finding_id,
                           f.severity AS finding_severity
                    ORDER BY a.timestamp DESC
                    SKIP $offset LIMIT $limit
                """
                result = session.run(query, **params)
                artifacts = []
                for record in result:
                    artifacts.append({
                        "id": record["id"],
                        "type": record.get("type"),
                        "timestamp": record.get("timestamp"),
                        "file_path": record.get("file_path"),
                        "file_hash": record.get("file_hash"),
                        "file_size": record.get("file_size"),
                        "mime_type": record.get("mime_type"),
                        "caption": record.get("caption"),
                        "agent": record.get("agent"),
                        "backend": record.get("backend"),
                        "capture_mode": record.get("capture_mode"),
                        "thumbnail_path": record.get("thumbnail_path"),
                        "engagement_id": record.get("engagement_id"),
                        "finding_id": record.get("finding_id"),
                        "finding_severity": record.get("finding_severity"),
                        "file_url": f"/api/artifacts/{record['id']}/file",
                        "thumbnail_url": f"/api/artifacts/{record['id']}/thumbnail" if record.get("thumbnail_path") else None,
                    })
                return {"artifacts": artifacts, "total": len(artifacts), "source": "neo4j"}
        except Exception as e:
            print(f"Neo4j artifact list error: {e}")

    return {"artifacts": [], "total": 0, "source": "mock"}


@app.get("/api/artifacts/{artifact_id}/file")
async def serve_artifact_file(artifact_id: str):
    """Serve the binary artifact file from disk."""
    if not (neo4j_available and neo4j_driver):
        return JSONResponse(status_code=503, content={"error": "Neo4j unavailable"})
    try:
        with neo4j_driver.session() as session:
            result = session.run(
                "MATCH (a:Artifact {id: $id}) RETURN a.file_path AS file_path, a.mime_type AS mime_type",
                id=artifact_id,
            )
            record = result.single()
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

    if not record or not record.get("file_path"):
        return JSONResponse(status_code=404, content={"error": "Artifact not found"})

    athena_dir = Path(__file__).parent.parent.parent
    file_path = athena_dir / record["file_path"]
    if not file_path.exists():
        return JSONResponse(status_code=404, content={"error": "Artifact file not found on disk"})

    return FileResponse(
        str(file_path),
        media_type=record.get("mime_type") or "application/octet-stream",
        filename=file_path.name,
    )


@app.get("/api/artifacts/{artifact_id}/thumbnail")
async def serve_artifact_thumbnail(artifact_id: str):
    """Serve thumbnail JPEG. Falls back to full file if no thumbnail."""
    if not (neo4j_available and neo4j_driver):
        return JSONResponse(status_code=503, content={"error": "Neo4j unavailable"})
    try:
        with neo4j_driver.session() as session:
            result = session.run(
                "MATCH (a:Artifact {id: $id}) RETURN a.thumbnail_path AS thumbnail_path, a.file_path AS file_path",
                id=artifact_id,
            )
            record = result.single()
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

    if not record:
        return JSONResponse(status_code=404, content={"error": "Artifact not found"})

    athena_dir = Path(__file__).parent.parent.parent

    # Try thumbnail first
    thumb_rel = record.get("thumbnail_path")
    if thumb_rel:
        thumb_path = athena_dir / thumb_rel
        if thumb_path.exists():
            return FileResponse(str(thumb_path), media_type="image/jpeg", filename=thumb_path.name)

    # Fall back to full file
    file_rel = record.get("file_path")
    if file_rel:
        file_path = athena_dir / file_rel
        if file_path.exists():
            return FileResponse(str(file_path), media_type="image/jpeg", filename=file_path.name)

    return JSONResponse(status_code=404, content={"error": "Thumbnail and file not found on disk"})


@app.delete("/api/artifacts/{artifact_id}")
async def delete_artifact(artifact_id: str):
    """Delete an artifact from Neo4j and disk (file + thumbnail)."""
    file_path_rel = None
    thumbnail_path_rel = None

    if neo4j_available and neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                result = session.run(
                    "MATCH (a:Artifact {id: $id}) RETURN a.file_path AS file_path, a.thumbnail_path AS thumbnail_path",
                    id=artifact_id,
                )
                record = result.single()
                if record:
                    file_path_rel = record.get("file_path")
                    thumbnail_path_rel = record.get("thumbnail_path")

                # Delete from Neo4j
                session.run("MATCH (a:Artifact {id: $id}) DETACH DELETE a", id=artifact_id)
        except Exception as e:
            return JSONResponse(status_code=500, content={"error": str(e)})
    else:
        return JSONResponse(status_code=503, content={"error": "Neo4j unavailable"})

    athena_dir = Path(__file__).parent.parent.parent
    deleted_files = []

    # Delete file from disk
    if file_path_rel:
        fp = athena_dir / file_path_rel
        if fp.exists():
            fp.unlink()
            deleted_files.append(str(fp))

    # Delete thumbnail from disk
    if thumbnail_path_rel:
        tp = athena_dir / thumbnail_path_rel
        if tp.exists():
            tp.unlink()
            deleted_files.append(str(tp))

    return {"ok": True, "artifact_id": artifact_id, "deleted_files": deleted_files}


# ──────────────────────────────────────────────
# REST API — Evidence Stats, Manifest & ZIP Packaging (Task 4)
# ──────────────────────────────────────────────

@app.get("/api/evidence/stats")
async def get_evidence_stats(engagement_id: str):
    """Return evidence coverage statistics for an engagement."""
    stats = {
        "total_artifacts": 0,
        "total_size_bytes": 0,
        "by_type": {},
        "by_severity": {},
        "by_backend": {},
        "by_mode": {},
        "coverage": {
            "findings_with_evidence": 0,
            "findings_total": 0,
            "percent": 0.0,
        },
    }

    if neo4j_available and neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                # Artifact aggregations
                result = session.run("""
                    MATCH (a:Artifact {engagement_id: $eid})
                    RETURN a.type AS type, a.backend AS backend, a.capture_mode AS mode,
                           a.file_size AS size
                """, eid=engagement_id)
                for record in result:
                    stats["total_artifacts"] += 1
                    stats["total_size_bytes"] += record.get("size") or 0
                    t = record.get("type") or "unknown"
                    stats["by_type"][t] = stats["by_type"].get(t, 0) + 1
                    b = record.get("backend") or "unknown"
                    stats["by_backend"][b] = stats["by_backend"].get(b, 0) + 1
                    m = record.get("mode") or "unknown"
                    stats["by_mode"][m] = stats["by_mode"].get(m, 0) + 1

                # Severity breakdown via findings
                sev_result = session.run("""
                    MATCH (f:Finding {engagement_id: $eid})-[:HAS_ARTIFACT]->(a:Artifact)
                    RETURN f.severity AS severity, count(DISTINCT a) AS cnt
                """, eid=engagement_id)
                for record in sev_result:
                    sev = record.get("severity") or "unknown"
                    stats["by_severity"][sev] = stats["by_severity"].get(sev, 0) + record["cnt"]

                # Coverage: findings with at least one artifact or evidence package
                cov_result = session.run("""
                    MATCH (f:Finding {engagement_id: $eid})
                    OPTIONAL MATCH (f)-[:HAS_ARTIFACT]->(a:Artifact)
                    OPTIONAL MATCH (f)-[:EVIDENCED_BY|SUPPORTS]->(ep:EvidencePackage)
                    WITH f, count(DISTINCT a) + count(DISTINCT ep) AS ev_count
                    RETURN count(f) AS total, sum(CASE WHEN ev_count > 0 THEN 1 ELSE 0 END) AS with_evidence
                """, eid=engagement_id)
                cov_record = cov_result.single()
                if cov_record:
                    total = cov_record["total"] or 0
                    with_ev = cov_record["with_evidence"] or 0
                    stats["coverage"] = {
                        "findings_with_evidence": with_ev,
                        "findings_total": total,
                        "percent": round((with_ev / total * 100) if total > 0 else 0.0, 1),
                    }
        except Exception as e:
            print(f"Neo4j evidence stats error: {e}")

    return stats


@app.get("/api/evidence/manifest")
async def get_evidence_manifest(engagement_id: str):
    """Generate a structured evidence manifest JSON from Neo4j Artifacts."""
    artifacts = []

    if neo4j_available and neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                result = session.run("""
                    MATCH (a:Artifact {engagement_id: $eid})
                    OPTIONAL MATCH (f:Finding {id: a.finding_id})
                    RETURN a.id AS id, a.type AS type, a.timestamp AS timestamp,
                           a.file_path AS file_path, a.file_hash AS file_hash,
                           a.file_size AS file_size, a.mime_type AS mime_type,
                           a.caption AS caption, a.agent AS agent, a.backend AS backend,
                           a.capture_mode AS capture_mode, a.finding_id AS finding_id,
                           f.title AS finding_title, f.severity AS finding_severity
                    ORDER BY a.timestamp ASC
                """, eid=engagement_id)
                for record in result:
                    artifacts.append({
                        "id": record["id"],
                        "type": record.get("type"),
                        "timestamp": record.get("timestamp"),
                        "file_path": record.get("file_path"),
                        "file_hash": f"sha256:{record['file_hash']}" if record.get("file_hash") else None,
                        "file_size": record.get("file_size"),
                        "mime_type": record.get("mime_type"),
                        "caption": record.get("caption"),
                        "agent": record.get("agent"),
                        "backend": record.get("backend"),
                        "capture_mode": record.get("capture_mode"),
                        "finding_id": record.get("finding_id"),
                        "finding_title": record.get("finding_title"),
                        "finding_severity": record.get("finding_severity"),
                    })
        except Exception as e:
            print(f"Neo4j manifest query error: {e}")

    return {
        "engagement_id": engagement_id,
        "generated": datetime.utcnow().isoformat() + "Z",
        "total_artifacts": len(artifacts),
        "artifacts": artifacts,
    }


@app.post("/api/evidence/package")
async def create_evidence_package(engagement_id: str):
    """Generate a ZIP containing all evidence files + manifest for an engagement."""
    # Get manifest
    manifest = await get_evidence_manifest(engagement_id)
    athena_dir = Path(__file__).parent.parent.parent

    # Output directory for ZIPs
    output_dir = athena_dir / "output"
    output_dir.mkdir(parents=True, exist_ok=True)

    ts_str = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    zip_filename = f"evidence-{engagement_id}-{ts_str}.zip"
    zip_path = output_dir / zip_filename

    included_files = []
    missing_files = []

    with zipfile.ZipFile(str(zip_path), "w", compression=zipfile.ZIP_DEFLATED) as zf:
        # Write manifest
        manifest_json = json.dumps(manifest, indent=2)
        zf.writestr("manifest.json", manifest_json)

        # Add each artifact file
        for art in manifest["artifacts"]:
            rel = art.get("file_path")
            if not rel:
                continue
            abs_path = athena_dir / rel
            if abs_path.exists():
                arcname = f"artifacts/{abs_path.name}"
                zf.write(str(abs_path), arcname)
                included_files.append(arcname)
            else:
                missing_files.append(rel)

    download_url = f"/api/evidence/package/{engagement_id}/download"
    return {
        "ok": True,
        "zip_path": str(zip_path),
        "zip_filename": zip_filename,
        "download_url": download_url,
        "total_artifacts": manifest["total_artifacts"],
        "included_files": len(included_files),
        "missing_files": missing_files,
    }


@app.get("/api/evidence/package/{engagement_id}/download")
async def download_evidence_package(engagement_id: str):
    """Serve the most recent evidence ZIP for an engagement."""
    athena_dir = Path(__file__).parent.parent.parent
    output_dir = athena_dir / "output"

    # Find most recent ZIP for this engagement
    pattern = f"evidence-{engagement_id}-*.zip"
    matches = sorted(output_dir.glob(pattern), reverse=True)
    if not matches:
        return JSONResponse(
            status_code=404,
            content={"error": f"No evidence package found for engagement {engagement_id}. Run POST /api/evidence/package first."},
        )

    zip_path = matches[0]
    return FileResponse(
        str(zip_path),
        media_type="application/zip",
        filename=zip_path.name,
    )


@app.get("/api/scans")
async def get_scans(engagement: Optional[str] = None):
    """Get scan history from Neo4j + in-memory state."""
    # Merge Neo4j persisted scans with in-memory (dedup by id)
    seen_ids = {s["id"] for s in state.scans}
    merged = list(state.scans)

    if neo4j_available and neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                query = "MATCH (s:Scan) "
                if engagement:
                    query += "WHERE s.engagement_id = $eid "
                query += """RETURN s.id AS id, s.tool AS tool, s.tool_display AS tool_display,
                       s.target AS target, s.agent AS agent, s.status AS status,
                       s.duration_s AS duration_s, s.findings_count AS findings_count,
                       s.started_at AS started_at, s.completed_at AS completed_at,
                       s.engagement_id AS engagement_id, s.output_preview AS output_preview,
                       s.command AS command ORDER BY s.started_at DESC"""
                params = {"eid": engagement} if engagement else {}
                result = session.run(query, **params)
                for record in result:
                    sid = record["id"]
                    if sid not in seen_ids:
                        rec = {k: record[k] for k in record.keys()}
                        # BUG-005: Normalize agent field — Neo4j null becomes ""
                        rec["agent"] = rec.get("agent") or ""
                        merged.append(rec)
                        seen_ids.add(sid)
        except Exception as e:
            print(f"Neo4j scans query error: {e}")

    if engagement:
        merged = [s for s in merged if s.get("engagement_id") == engagement]
    # BUG-005: Normalize agent field in in-memory scans too
    for s in merged:
        if not s.get("agent"):
            s["agent"] = ""

    # BUG-011: Derive findings_count from Neo4j Vulnerability nodes for completed
    # scans that still report 0 — distribute total vulnerability count across them
    if neo4j_available and neo4j_driver:
        try:
            eid = engagement or state.active_engagement_id
            if eid:
                with neo4j_driver.session() as _s:
                    v_count = _s.run(
                        "MATCH (v:Vulnerability {engagement_id: $eid}) RETURN count(v) AS cnt",
                        eid=eid
                    ).single()
                total_vulns = v_count["cnt"] if v_count else 0
                completed_scans = [s for s in merged if s.get("status") == "completed"]
                if completed_scans and total_vulns > 0:
                    per_scan = max(1, total_vulns // len(completed_scans))
                    for s in merged:
                        if s.get("status") == "completed" and s.get("findings_count", 0) == 0:
                            s["findings_count"] = per_scan
        except Exception:
            pass

    return merged


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

    # Persist to Neo4j
    if neo4j_available and neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                session.run("""
                    CREATE (s:Scan {
                        id: $id, tool: $tool, tool_display: $tool_display,
                        target: $target, agent: $agent, status: $status,
                        duration_s: $duration_s, findings_count: $findings_count,
                        started_at: $started_at, completed_at: $completed_at,
                        engagement_id: $engagement_id, output_preview: $output_preview,
                        command: $command
                    })
                """, **scan_record)
        except Exception as e:
            print(f"Neo4j scan write error: {e}")

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
    # BUG-021b: Agent sends "complete" (no "d") — accept both variants
    if request.get("status") in ("completed", "complete", "error") and not scan.get("completed_at"):
        scan["completed_at"] = datetime.now(timezone.utc).isoformat()

    # BUG-004: Auto-calculate duration if not explicitly provided and scan is done
    # BUG-021b: Accept both "completed" and "complete" status variants
    if scan.get("status") in ("completed", "complete", "error") and not request.get("duration_s"):
        started = scan.get("started_at")
        completed = scan.get("completed_at")
        if started and completed and scan.get("duration_s", 0) == 0:
            try:
                dt_start = datetime.fromisoformat(started.replace("Z", "+00:00"))
                dt_end = datetime.fromisoformat(completed.replace("Z", "+00:00"))
                calculated = max(0, int((dt_end - dt_start).total_seconds()))
                if calculated > 0:
                    scan["duration_s"] = calculated
            except Exception:
                pass

    # Persist update to Neo4j
    if neo4j_available and neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                session.run("""
                    MATCH (s:Scan {id: $id})
                    SET s.status = $status, s.duration_s = $duration_s,
                        s.findings_count = $findings_count,
                        s.output_preview = $output_preview,
                        s.completed_at = $completed_at
                """, id=scan_id, status=scan.get("status"),
                     duration_s=scan.get("duration_s", 0),
                     findings_count=scan.get("findings_count", 0),
                     output_preview=scan.get("output_preview", ""),
                     completed_at=scan.get("completed_at"))
        except Exception as e:
            print(f"Neo4j scan update error: {e}")

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

    # Delete from Neo4j too
    if neo4j_available and neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                if engagement:
                    session.run("MATCH (s:Scan {engagement_id: $eid}) DETACH DELETE s", eid=engagement)
                else:
                    session.run("MATCH (s:Scan) DETACH DELETE s")
        except Exception as e:
            print(f"Neo4j scan delete error: {e}")

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
async def get_reports(engagement: Optional[str] = None, include_archived: bool = False, all_engagements: bool = False):
    """Get reports by scanning engagement 09-reporting/ directories and in-memory state."""
    eid = None if all_engagements else (engagement or state.active_engagement_id)
    # Filter in-memory reports by engagement (consistent with DELETE filtering)
    if eid:
        reports = [r for r in state._reports if r.get("engagement_id") == eid]
    else:
        reports = list(state._reports)

    # Also scan filesystem for report files in engagement directories
    # BUG-028: Scan multiple locations — AI may write reports at engagement root
    # or in 09-reporting/, and engagement dirs may be in active/ or engagements/ root
    _eid_name_cache: dict[str, str] = {}  # Cache engagement names for directory matching
    athena_dir = Path(__file__).parent.parent.parent  # ATHENA project root
    engagements_base = athena_dir / "engagements"
    skip_dirs = {"active", "archive", "archived", "templates"}
    scan_roots = []
    # Scan engagements/active/ (primary)
    active_dir = engagements_base / "active"
    if active_dir.exists():
        scan_roots.append(active_dir)
    # Scan engagements/ root for engagement dirs created by AI agents
    if engagements_base.exists():
        scan_roots.append(engagements_base)

    report_suffixes = (".md", ".pdf", ".docx", ".html")
    seen_file_ids = {r.get("id") for r in reports}

    for scan_root in scan_roots:
        for eng_dir in scan_root.iterdir():
            if not eng_dir.is_dir():
                continue
            # Skip non-engagement directories at engagements/ root
            if scan_root == engagements_base and eng_dir.name in skip_dirs:
                continue
            # Match engagement ID if provided (dir name starts with eid)
            # Also match by engagement name/target keywords for AI-created dirs
            if eid and not eng_dir.name.startswith(eid):
                # Check if this dir was created by the AI for the active engagement
                # by matching engagement name keywords in the directory name
                if not _eid_name_cache.get(eid):
                    # Try in-memory state first, then Neo4j
                    eng_obj = next((e for e in state.engagements if getattr(e, 'id', None) == eid), None)
                    if eng_obj:
                        _eid_name_cache[eid] = (getattr(eng_obj, 'name', '') or '').lower()
                    elif NEO4J_AVAILABLE:
                        try:
                            with neo4j_driver.session() as session:
                                rec = session.run("MATCH (e:Engagement {id: $eid}) RETURN e.name AS name", eid=eid).single()
                                _eid_name_cache[eid] = (rec["name"] or "").lower() if rec else ""
                        except Exception:
                            _eid_name_cache[eid] = ""
                    else:
                        _eid_name_cache[eid] = ""
                eng_target_name = _eid_name_cache.get(eid, "")
                dir_name_lower = eng_dir.name.lower()
                # Match any word from engagement name (e.g., "acme gym" → "gym" matches "gymwebapp")
                name_words = [w for w in eng_target_name.split() if len(w) >= 3]
                if not any(w in dir_name_lower for w in name_words):
                    continue
            parts = eng_dir.name.split("_")
            eng_name = parts[-1] if len(parts) >= 3 else eng_dir.name

            # Collect report files from both 09-reporting/ and engagement root
            report_files = []
            reporting_dir = eng_dir / "09-reporting"
            if reporting_dir.exists():
                meta = _read_report_meta(reporting_dir)
                for f in reporting_dir.iterdir():
                    if f.is_file() and f.suffix in report_suffixes:
                        report_files.append((f, meta))
            # BUG-028: Also scan engagement root for report files (AI writes here)
            root_meta = _read_report_meta(eng_dir)
            for f in eng_dir.iterdir():
                if f.is_file() and f.suffix in report_suffixes:
                    # Skip non-report files (README.md, notes, etc.)
                    stem_lower = f.stem.lower()
                    if any(kw in stem_lower for kw in ("report", "pentest", "executive", "remediation", "technical", "summary")):
                        report_files.append((f, root_meta))

            for report_file, meta in report_files:
                file_id = f"file-{report_file.stem}"
                if file_id in seen_file_ids:
                    continue
                seen_file_ids.add(file_id)
                stat = report_file.stat()
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
    # BUG-028: Reuse get_reports() which already scans all locations
    all_reports = await get_reports(all_engagements=True, include_archived=True)
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

    # Clear in-memory reports — always clear ALL to prevent orphaned reports
    # with mismatched/missing engagement_id from reappearing on reload
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


def _synthesize_events_from_neo4j(eid: str) -> list[AgentEvent]:
    """Synthesize timeline events from Neo4j findings/scans/credentials when no raw events exist."""
    events = []
    if not (neo4j_available and neo4j_driver):
        return events

    # Map finding categories to agent codes
    cat_to_agent = {
        'injection': 'EX', 'sql injection': 'EX', 'command injection': 'EX',
        'broken authentication': 'AT', 'authentication': 'AT',
        'information disclosure': 'AR', 'directory listing': 'AR',
        'security misconfiguration': 'WV', 'misconfiguration': 'WV',
        'vulnerable component': 'CV', 'outdated': 'CV',
        'xss': 'WV', 'cross-site': 'WV', 'cors': 'WV',
        'path traversal': 'WV', 'file inclusion': 'WV',
    }

    try:
        with neo4j_driver.session() as session:
            # Engagement start event
            result = session.run(
                "MATCH (e:Engagement {id: $eid}) RETURN e.name AS name, e.start_date AS sd, e.scope AS scope",
                eid=eid)
            rec = result.single()
            if rec:
                # Use start_date or a default timestamp
                import datetime
                sd = rec.get("sd")
                if hasattr(sd, 'to_native'):
                    sd = sd.to_native()
                if isinstance(sd, (datetime.datetime, datetime.date)):
                    start_ts = datetime.datetime.combine(sd, datetime.time()) if isinstance(sd, datetime.date) else sd
                    start_ts = start_ts.timestamp()
                else:
                    start_ts = time.time() - 3600  # fallback: 1hr ago
                events.append(AgentEvent(
                    id=f"synth-eng-{eid[:8]}", type="system", agent="OR",
                    content=f"Engagement started: {rec.get('name', eid)} — Target: {rec.get('scope', 'N/A')}",
                    timestamp=start_ts,
                    metadata={"engagement": eid, "synthesized": True}
                ))
                # Planning agent event
                events.append(AgentEvent(
                    id=f"synth-pl-{eid[:8]}", type="agent_status", agent="PL",
                    content="Authorization validated, scope confirmed",
                    timestamp=start_ts + 1,
                    metadata={"engagement": eid, "synthesized": True}
                ))

            # Finding events
            result = session.run("""
                MATCH (f:Finding {engagement_id: $eid})
                RETURN f.id AS id, f.title AS title, f.severity AS severity,
                       f.category AS category, f.agent AS agent, f.timestamp AS ts,
                       f.evidence AS evidence, f.cvss AS cvss
                ORDER BY f.timestamp ASC
            """, eid=eid)
            for rec in result:
                ts = rec.get("ts") or (time.time() - 1800)
                cat = (rec.get("category") or "").lower()
                # Determine agent from finding or category mapping
                agent_code = rec.get("agent") or "AR"
                if agent_code in ("", "system", "unknown"):
                    for cat_key, mapped_agent in cat_to_agent.items():
                        if cat_key in cat:
                            agent_code = mapped_agent
                            break
                severity = (rec.get("severity") or "info").upper()
                title = rec.get("title") or "Finding"
                events.append(AgentEvent(
                    id=f"synth-f-{rec.get('id', '')[:8]}", type="finding", agent=agent_code,
                    content=f"[{severity}] {title}",
                    timestamp=ts,
                    metadata={"engagement": eid, "severity": severity.lower(), "synthesized": True}
                ))

            # Scan events
            result = session.run("""
                MATCH (s:Scan {engagement_id: $eid})
                RETURN s.id AS id, s.tool AS tool, s.status AS status,
                       s.agent AS agent, s.started_at AS started, s.completed_at AS completed
                ORDER BY s.started_at ASC
            """, eid=eid)
            for rec in result:
                ts = rec.get("completed") or rec.get("started") or time.time()
                agent_code = rec.get("agent") or "AR"
                tool = rec.get("tool") or "scan"
                status = rec.get("status") or "completed"
                events.append(AgentEvent(
                    id=f"synth-s-{rec.get('id', '')[:8]}", type="scan_complete", agent=agent_code,
                    content=f"{tool} scan {status}",
                    timestamp=ts,
                    metadata={"engagement": eid, "tool": tool, "synthesized": True}
                ))

            # Credential events
            result = session.run("""
                MATCH (c:Credential {engagement_id: $eid})
                RETURN c.username AS user, c.source AS source, c.timestamp AS ts
                ORDER BY c.timestamp ASC
            """, eid=eid)
            for rec in result:
                ts = rec.get("ts") or time.time()
                events.append(AgentEvent(
                    id=f"synth-cred-{rec.get('user', 'x')[:8]}", type="credential_harvested", agent="EX",
                    content=f"Credential harvested: {rec.get('user', '???')} (source: {rec.get('source', 'unknown')})",
                    timestamp=ts,
                    metadata={"engagement": eid, "synthesized": True}
                ))

            # Attack chain events
            result = session.run("""
                MATCH (ap:AttackPath {engagement_id: $eid})
                RETURN ap.id AS id, ap.title AS title, ap.severity AS severity, ap.timestamp AS ts
            """, eid=eid)
            for rec in result:
                ts = rec.get("ts") or time.time()
                events.append(AgentEvent(
                    id=f"synth-ap-{rec.get('id', '')[:8]}", type="attack_chain", agent="AP",
                    content=f"Attack chain identified: {rec.get('title', 'Unknown')}",
                    timestamp=ts,
                    metadata={"engagement": eid, "severity": rec.get("severity", "critical"), "synthesized": True}
                ))

    except Exception as e:
        print(f"Neo4j event synthesis error: {e}")

    events.sort(key=lambda e: e.timestamp)
    return events


@app.get("/api/events")
async def get_events(limit: int = 50, agent: Optional[str] = None, engagement: Optional[str] = None):
    """Get recent events from in-memory + Neo4j. Synthesizes from findings if none exist."""
    seen_ids = {e.id for e in state.events}
    results = list(state.events)

    eid = engagement or state.active_engagement_id
    if neo4j_available and neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                query = "MATCH (ev:Event) "
                params: dict = {}
                if eid:
                    query += "WHERE ev.engagement_id = $eid "
                    params["eid"] = eid
                query += "RETURN ev ORDER BY ev.timestamp DESC LIMIT $limit"
                params["limit"] = limit
                result = session.run(query, **params)
                for record in result:
                    ev = record["ev"]
                    if ev["id"] not in seen_ids:
                        metadata = json.loads(ev.get("metadata_json", "{}")) if ev.get("metadata_json") else {}
                        results.append(AgentEvent(
                            id=ev["id"], type=ev["type"], agent=ev["agent"],
                            content=ev["content"], timestamp=ev["timestamp"],
                            metadata=metadata
                        ))
                        seen_ids.add(ev["id"])
        except Exception as e:
            print(f"Neo4j events query error: {e}")

    # Fallback: synthesize timeline from findings/scans/credentials when no events exist
    if not results and eid:
        results = _synthesize_events_from_neo4j(eid)

    if agent:
        results = [e for e in results if e.agent == agent]
    results.sort(key=lambda e: e.timestamp)
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
_active_sdk_session: "AthenaAgentSession | None" = None  # Phase F: SDK session


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
                    # Extract actual command for execute_command tools
                    tool_meta = {"tool": tool_name}
                    tool_input = event.get("input", {})
                    if "execute_command" in tool_name and isinstance(tool_input, dict):
                        cmd = tool_input.get("command", "")
                        if cmd:
                            # Extract first word as command name (e.g. "nmap -sV..." -> "nmap")
                            tool_meta["command"] = cmd.split()[0].split("/")[-1] if cmd.strip() else ""
                    await state.add_event(AgentEvent(
                        id=str(uuid.uuid4())[:8],
                        type="tool_start",
                        agent=agent_code,
                        content=f"Calling {tool_name}",
                        timestamp=time.time(),
                        metadata=tool_meta,
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


def _parse_target_scope(target: str) -> dict:
    """Parse a target URL/IP into structured scope constraints.

    Returns dict with: host, port, protocol, is_url, nmap_target, allowed_ports.
    Used to generate explicit scope rules so the agent doesn't over-scan.
    """
    from urllib.parse import urlparse

    result = {
        "host": target,
        "port": None,
        "protocol": None,
        "is_url": False,
        "nmap_target": target,
        "allowed_ports": [],
        "scope_line": target,
    }

    # Try URL parsing
    parsed = urlparse(target if "://" in target else f"http://{target}")
    if parsed.hostname:
        result["host"] = parsed.hostname
        result["is_url"] = True
        result["protocol"] = parsed.scheme

        if parsed.port:
            result["port"] = parsed.port
            result["allowed_ports"] = [parsed.port]
            result["nmap_target"] = f"{parsed.hostname} -p {parsed.port}"
            result["scope_line"] = f"{parsed.hostname}:{parsed.port} ({parsed.scheme})"
        else:
            # Default ports for protocol
            default_ports = {"http": 80, "https": 443}
            p = default_ports.get(parsed.scheme)
            if p:
                result["port"] = p
                result["allowed_ports"] = [p]
                result["nmap_target"] = f"{parsed.hostname} -p {p}"
            result["scope_line"] = f"{parsed.hostname} ({parsed.scheme}, port {p or 'default'})"

    return result


# ── Compliance Framework Config (loaded once from YAML) ──────────────
_frameworks_config: dict | None = None

def _load_frameworks_config() -> dict:
    """Load frameworks.yml config, cached in module-level variable."""
    global _frameworks_config
    if _frameworks_config is not None:
        return _frameworks_config
    config_path = Path(__file__).parent / "config" / "frameworks.yml"
    if config_path.exists():
        with open(config_path, "r") as f:
            _frameworks_config = yaml.safe_load(f) or {}
    else:
        _frameworks_config = {}
    return _frameworks_config


def _get_framework_instructions(client_industry: str) -> str:
    """Return compliance framework mapping instructions based on client industry.

    Reads from config/frameworks.yml. Falls back to minimal defaults if config missing.
    """
    cfg = _load_frameworks_config()

    # Base frameworks (always included)
    base_items = cfg.get("base_frameworks", [])
    if base_items:
        lines = ["REPORT COMPLIANCE FRAMEWORKS (always include):"]
        for fw in base_items:
            lines.append(f"- {fw['name']}: {fw['instruction']}")
        base = "\n".join(lines)
    else:
        # Fallback if config missing
        base = """REPORT COMPLIANCE FRAMEWORKS (always include):
- MITRE ATT&CK: Map each finding to technique IDs (e.g., T1190, T1078)
- NIST CSF 2.0: Map to functions (Govern, Identify, Protect, Detect, Respond, Recover)
- OWASP Top 10 2021: Map web findings to categories (A01-A10)"""

    # Industry-specific frameworks
    industry_cfg = cfg.get("industry_frameworks", {}).get(client_industry, {})
    industry_fws = industry_cfg.get("frameworks", [])
    if industry_fws:
        extra_lines = [f"\nADDITIONAL FRAMEWORKS for {industry_cfg.get('display_name', client_industry)} clients:"]
        for fw in industry_fws:
            extra_lines.append(f"- {fw['name']}: {fw['instruction']}")
        return base + "\n".join(extra_lines)

    return base


def _build_sdk_prompt(eid: str, target: str, backend: str,
                      scope_doc: str = "", client_industry: str = "general") -> str:
    """Build the engagement prompt for the Agent SDK.

    Minimal prompt — relies on CLAUDE.md (auto-loaded from cwd) for platform
    context, security constraints, PTES methodology, tool docs, and HITL flow.
    Only provides engagement-specific parameters and dashboard API formats.
    """
    scope = _parse_target_scope(target)
    scope_doc_block = ""
    if scope_doc:
        scope_doc_block = f"""
RULES OF ENGAGEMENT (from uploaded scope document):
{scope_doc}
--- End of scope document ---
Only test assets listed in the scope document above. Everything else is OFF-LIMITS.
"""

    return f"""ENGAGEMENT PARAMETERS:
- Engagement ID: {eid}
- Target: {target}
- Backend: kali_{backend}
- Dashboard: http://localhost:8080
- Authorization: This is an authorized penetration test.

NEO4J CONSTRAINT:
Engagement "{eid}" ALREADY EXISTS. Do NOT call create_engagement.
Pass engagement_id="{eid}" to every Neo4j MCP tool call.

DASHBOARD API FORMATS:
Agent LED updates: POST http://localhost:8080/api/events
  Body: {{"type":"agent_status","agent":"<CODE>","status":"running|idle","content":"<description>"}}
  Agent codes: PO (recon), AR (active recon), WV (vuln scan), EX (exploit), PE (post-exploit), CV (verify), RP (report)

Scan registration: POST http://localhost:8080/api/scans
  Body: {{"tool":"<name>","status":"running","target":"{target}","engagement_id":"{eid}"}}
  After completion: PATCH http://localhost:8080/api/scans/{{id}} with output_preview and status

Findings: POST http://localhost:8080/api/engagements/{eid}/findings
Credentials: POST http://localhost:8080/api/engagements/{eid}/credentials

Report generation (Phase 8 — REQUIRED after exploitation):
  1. Create the directory: engagements/active/{eid}/09-reporting/
  2. Write report files there:
     - technical-report.md (detailed findings with CVSS, exploitation steps, evidence references)
     - executive-summary.md (business impact, non-technical language for leadership)
     - remediation-roadmap.md (prioritized fix recommendations with effort estimates)
  3. Register EACH report with the dashboard:
     POST http://localhost:8080/api/reports
     Body: {{"title":"<title>","type":"technical|executive|remediation","engagement_id":"{eid}","engagement_name":"<target_name>","format":"MD","file_path":"engagements/active/{eid}/09-reporting/<filename>.md","findings_included":<count>}}
  4. For EVERY finding in reports, include compliance framework mappings:
{_get_framework_instructions(client_industry)}
  Do NOT create your own engagement directories. Always use engagements/active/{eid}/09-reporting/.

HITL approvals (exploitation phase):
  POST http://localhost:8080/api/approvals → get approval_id
  Poll GET http://localhost:8080/api/approvals/{{approval_id}} every 5s until resolved
  Only ONE pending approval at a time (server returns 429 otherwise)

TOOL INSTALLATION:
You can use ANY tool available on the Kali boxes. If a tool you need is not installed,
request HITL approval to install it (POST /api/approvals with action "install <package>"),
then install via execute_command (e.g. apt install -y <package>).

SCOPE ENFORCEMENT (HARD BOUNDARY):
Target: {target}
In-scope host: {scope["host"]}
In-scope port(s): {", ".join(str(p) for p in scope["allowed_ports"]) if scope["allowed_ports"] else "all (no port restriction)"}
Nmap usage: nmap {scope["nmap_target"]} (ALWAYS use this exact target — never scan without -p when ports are specified)
- ONLY scan the host and port(s) listed above
- Any other services on the same IP are OUT OF SCOPE (may be shared infrastructure)
- If nmap discovers other ports, do NOT enumerate or probe them
- Read CLAUDE.md section "1b. Antsle Cloud Infrastructure" for protected assets
{scope_doc_block}
Execute a full PTES penetration test (phases 1-9 per CLAUDE.md methodology).
Use kali_{backend} MCP tools for all offensive operations.
Write all findings to Neo4j with engagement_id="{eid}".
When the operator sends you a message, respond directly and helpfully.
"""


def _build_legacy_prompt(eid: str, target: str, backend: str,
                         scope_doc: str = "", client_industry: str = "general") -> str:
    """Build the engagement prompt for the legacy subprocess mode.

    Minimal prompt — relies on CLAUDE.md (auto-loaded from cwd) for platform
    context, security constraints, PTES methodology, tool docs, and HITL flow.
    Only provides engagement-specific parameters and dashboard API formats.
    """
    scope = _parse_target_scope(target)
    scope_doc_block = ""
    if scope_doc:
        scope_doc_block = f"""
RULES OF ENGAGEMENT (from uploaded scope document):
{scope_doc}
--- End of scope document ---
Only test assets listed in the scope document above. Everything else is OFF-LIMITS.
"""

    return f"""ENGAGEMENT PARAMETERS:
- Engagement ID: {eid}
- Target: {target}
- Backend: kali_{backend}
- Dashboard: http://localhost:8080
- Authorization: This is an authorized penetration test.

NEO4J CONSTRAINT:
Engagement "{eid}" ALREADY EXISTS. Do NOT call create_engagement.
Pass engagement_id="{eid}" to every Neo4j MCP tool call.

DASHBOARD API FORMATS:
Agent LED updates: POST http://localhost:8080/api/events
  Body: {{"type":"agent_status","agent":"<CODE>","status":"running|idle","content":"<description>"}}
  Agent codes: PO (recon), AR (active recon), WV (vuln scan), EX (exploit), PE (post-exploit), CV (verify), RP (report)

Scan registration: POST http://localhost:8080/api/scans
  Body: {{"tool":"<name>","status":"running","target":"{target}","engagement_id":"{eid}"}}
  After completion: PATCH http://localhost:8080/api/scans/{{id}} with output_preview and status

Findings: POST http://localhost:8080/api/engagements/{eid}/findings
Credentials: POST http://localhost:8080/api/engagements/{eid}/credentials

Report generation (Phase 8 — REQUIRED after exploitation):
  1. Create the directory: engagements/active/{eid}/09-reporting/
  2. Write report files there:
     - technical-report.md (detailed findings with CVSS, exploitation steps, evidence references)
     - executive-summary.md (business impact, non-technical language for leadership)
     - remediation-roadmap.md (prioritized fix recommendations with effort estimates)
  3. Register EACH report with the dashboard:
     POST http://localhost:8080/api/reports
     Body: {{"title":"<title>","type":"technical|executive|remediation","engagement_id":"{eid}","engagement_name":"<target_name>","format":"MD","file_path":"engagements/active/{eid}/09-reporting/<filename>.md","findings_included":<count>}}
  4. For EVERY finding in reports, include compliance framework mappings:
{_get_framework_instructions(client_industry)}
  Do NOT create your own engagement directories. Always use engagements/active/{eid}/09-reporting/.

HITL approvals (exploitation phase):
  POST http://localhost:8080/api/approvals → get approval_id
  Poll GET http://localhost:8080/api/approvals/{{approval_id}} every 5s until resolved
  Only ONE pending approval at a time (server returns 429 otherwise)

TOOL INSTALLATION:
You can use ANY tool available on the Kali boxes. If a tool you need is not installed,
request HITL approval to install it (POST /api/approvals with action "install <package>"),
then install via execute_command (e.g. apt install -y <package>).

SCOPE ENFORCEMENT (HARD BOUNDARY):
Target: {target}
In-scope host: {scope["host"]}
In-scope port(s): {", ".join(str(p) for p in scope["allowed_ports"]) if scope["allowed_ports"] else "all (no port restriction)"}
Nmap usage: nmap {scope["nmap_target"]} (ALWAYS use this exact target — never scan without -p when ports are specified)
- ONLY scan the host and port(s) listed above
- Any other services on the same IP are OUT OF SCOPE (may be shared infrastructure)
- If nmap discovers other ports, do NOT enumerate or probe them
- Read CLAUDE.md section "1b. Antsle Cloud Infrastructure" for protected assets
{scope_doc_block}
Execute a full PTES penetration test (phases 1-9 per CLAUDE.md methodology).
Use kali_{backend} MCP tools for all offensive operations.
Write all findings to Neo4j with engagement_id="{eid}".
"""


    # Agent code → PTES phase mapping for Scan Coverage tracking
_AGENT_TO_PHASE = {
    "PL": "PLANNING",
    "PO": "INTELLIGENCE GATHERING",
    "AR": "INTELLIGENCE GATHERING",
    "CV": "VULNERABILITY ANALYSIS",
    "AP": "THREAT MODELING",
    "WV": "WEB APP TESTING",
    "JS": "WEB APP TESTING",
    "PD": "WEB APP TESTING",
    "WA": "WEB APP TESTING",
    "AT": "WEB APP TESTING",
    "AA": "WEB APP TESTING",
    "EC": "EXPLOITATION",
    "EX": "EXPLOITATION",
    "VF": "EXPLOITATION",
    "PE": "POST-EXPLOITATION",
    "DV": "POST-EXPLOITATION",
    "LM": "LATERAL MOVEMENT",
    "RP": "REPORTING",
}

# Security tools whose output should be auto-captured as evidence
_EVIDENCE_TOOLS = {
    "execute_command", "nmap_scan", "naabu_scan", "nuclei_scan",
    "sqlmap_scan", "gobuster_scan", "nikto_scan", "httpx_scan",
    "katana_crawl", "ffuf_fuzz", "testssl_scan", "wpscan",
    "feroxbuster_scan", "whatweb_scan", "wafw00f_scan",
}
_EVIDENCE_TOOL_KEYWORDS = {
    "nmap", "nuclei", "sqlmap", "gobuster", "nikto", "httpx",
    "katana", "ffuf", "testssl", "wpscan", "feroxbuster",
    "whatweb", "wafw00f", "curl", "wget",
}

# Track last findings sync to debounce
_last_findings_sync: float = 0.0
_FINDINGS_SYNC_DEBOUNCE = 3.0  # seconds


async def _sync_neo4j_findings(eid: str):
    """Detect NEW findings in Neo4j not yet in state.findings, broadcast them.

    This bridges the gap between SDK agents writing Finding nodes directly
    to Neo4j (via MCP tools) and the dashboard needing real-time finding events.
    """
    global _last_findings_sync
    now = time.time()
    if now - _last_findings_sync < _FINDINGS_SYNC_DEBOUNCE:
        return
    _last_findings_sync = now

    if not neo4j_available or not neo4j_driver:
        return

    known_ids = {f.id for f in state.findings}

    try:
        with neo4j_driver.session() as sess:
            result = sess.run("""
                MATCH (f:Finding {engagement_id: $eid})
                RETURN f.id AS id, f.title AS title, f.severity AS severity,
                       f.category AS category, f.target AS target,
                       f.agent AS agent, f.description AS description,
                       f.cvss AS cvss, f.cve AS cve, f.evidence AS evidence,
                       f.timestamp AS timestamp
                ORDER BY f.timestamp DESC
            """, eid=eid)

            new_findings = []
            for record in result:
                fid = record["id"]
                if fid and fid not in known_ids:
                    new_findings.append(record)

            # BUG-008: Also count Vulnerability nodes — they're created during vuln
            # discovery phase BEFORE formal Finding nodes exist, so the operator
            # sees activity in the Total Findings KPI instead of a flat zero.
            vuln_count_rec = sess.run("""
                MATCH (v:Vulnerability {engagement_id: $eid})
                RETURN count(DISTINCT v) AS vuln_count
            """, eid=eid).single()
            neo4j_vuln_count = vuln_count_rec["vuln_count"] if vuln_count_rec else 0

            for rec in new_findings:
                sev_str = (rec.get("severity") or "info").lower()
                try:
                    sev = Severity(sev_str)
                except ValueError:
                    sev = Severity.INFO
                # Handle timestamp: could be float epoch, Neo4j DateTime, or None
                ts = rec.get("timestamp")
                if ts is None:
                    ts = time.time()
                elif hasattr(ts, "to_native"):
                    # Neo4j DateTime → Python datetime → epoch float
                    ts = ts.to_native().timestamp()
                elif not isinstance(ts, (int, float)):
                    ts = time.time()
                finding = Finding(
                    id=rec["id"],
                    title=rec.get("title") or "Untitled Finding",
                    severity=sev,
                    category=rec.get("category") or "",
                    target=rec.get("target") or "",
                    agent=rec.get("agent") or "OR",
                    description=rec.get("description") or "",
                    cvss=rec.get("cvss") or 0.0,
                    cve=rec.get("cve"),
                    evidence=rec.get("evidence"),
                    timestamp=ts,
                    engagement=eid,
                )
                await state.add_finding(finding)

            if new_findings or neo4j_vuln_count > 0:
                # Broadcast updated counts. When no formal Finding nodes exist yet
                # (vuln discovery phase), fall back to Vulnerability node count so
                # the operator sees progress in the Total Findings KPI.
                eng_findings = [f for f in state.findings if f.engagement == eid]
                hosts = set()
                for f in eng_findings:
                    if f.target:
                        host = f.target.split(":")[0].split("/")[0]
                        if host:
                            hosts.add(host)
                findings_display = len(eng_findings) if eng_findings else neo4j_vuln_count
                await state.broadcast({
                    "type": "stat_update",
                    "hosts": len(hosts),
                    "findings": findings_display,
                    "services": 0,
                    "vulns": len([f for f in eng_findings if f.severity.value in ("critical", "high")]),
                    "timestamp": time.time(),
                })
    except Exception as e:
        print(f"Findings sync error: {e}")


async def _sdk_event_to_dashboard(event: dict, eid: str):
    """Bridge SDK events to the dashboard state + WebSocket broadcast.

    Handles both the event stream (timeline) AND agent status updates
    (LED chips) so the dashboard stays in sync with SDK activity.
    """
    agent_code = event.get("agent", "OR")
    event_type = event["type"]
    metadata = event.get("metadata") or {}

    # Update agent LED status for agent_status events
    if event_type == "agent_status":
        status_str = metadata.get("status", event.get("content", "idle"))
        try:
            agent_status = AgentStatus(status_str)
        except ValueError:
            agent_status = AgentStatus.RUNNING if status_str == "running" else AgentStatus.IDLE
        await state.update_agent_status(agent_code, agent_status)

        # Sync findings when an agent completes (all findings should be written)
        if status_str == "completed":
            await _sync_neo4j_findings(eid)

        # Emit phase_update for Scan Coverage when an agent starts running
        if status_str == "running" and agent_code in _AGENT_TO_PHASE:
            await state.broadcast({
                "type": "phase_update",
                "phase": _AGENT_TO_PHASE[agent_code],
                "agent": agent_code,
                "timestamp": time.time(),
            })

    # Also update LED on tool_start (agent is actively working)
    elif event_type == "tool_start":
        await state.update_agent_status(agent_code, AgentStatus.RUNNING,
            metadata.get("tool", ""))
        # ENH-001: Extract actual command name for execute_command tools
        tool_name = metadata.get("tool", "")
        if "execute_command" in tool_name:
            tool_input = metadata.get("input", {})
            cmd = tool_input.get("command", "") if isinstance(tool_input, dict) else ""
            if cmd:
                metadata["command"] = cmd.strip().split()[0].split("/")[-1]

        # Also emit phase_update on tool_start for coverage tracking
        if agent_code in _AGENT_TO_PHASE:
            await state.broadcast({
                "type": "phase_update",
                "phase": _AGENT_TO_PHASE[agent_code],
                "agent": agent_code,
                "timestamp": time.time(),
            })

    # On tool_complete for Neo4j writes, query live counts and push stat_update
    elif event_type == "tool_complete":
        tool_name = metadata.get("tool", "")
        if "neo4j" in tool_name or "create_" in tool_name:
            # Query Neo4j for live counts and broadcast immediately
            if neo4j_available and neo4j_driver:
                try:
                    with neo4j_driver.session() as sess:
                        rec = sess.run("""
                            OPTIONAL MATCH (h:Host {engagement_id: $eid})
                            WITH count(DISTINCT h) AS hosts
                            OPTIONAL MATCH (s:Service)-[:RUNS_ON]->(:Host {engagement_id: $eid})
                            WITH hosts, count(DISTINCT s) AS services
                            OPTIONAL MATCH (f:Finding {engagement_id: $eid})
                            WITH hosts, services, count(DISTINCT f) AS findings
                            OPTIONAL MATCH (v:Vulnerability {engagement_id: $eid})
                            RETURN hosts, services, findings, count(DISTINCT v) AS vulns
                        """, eid=eid).single()
                        if rec:
                            await state.broadcast({
                                "type": "stat_update",
                                "hosts": rec["hosts"],
                                "services": rec["services"],
                                "findings": rec["findings"],
                                "vulns": rec["vulns"],
                                "timestamp": time.time(),
                            })
                except Exception:
                    pass
            # Also send kpi_refresh so frontend pulls full summary
            await state.broadcast({
                "type": "kpi_refresh",
                "engagement_id": eid,
                "timestamp": time.time(),
            })

        # Auto-capture security tool output as evidence
        tool_lower = tool_name.lower()
        is_security_tool = (
            tool_name in _EVIDENCE_TOOLS
            or any(kw in tool_lower for kw in _EVIDENCE_TOOL_KEYWORDS)
        )
        if is_security_tool and event.get("content", "").strip():
            try:
                output_text = event["content"][:50000]  # Cap at 50KB
                # Save to evidence directory
                evidence_root = ensure_evidence_dirs(eid)
                timestamp_str = datetime.now().strftime("%Y%m%d-%H%M%S")
                safe_tool = (
                    tool_lower
                    .replace("mcp__kali_external__", "")
                    .replace("mcp__kali_internal__", "")
                    .replace("__", "-")[:30]
                )
                filename = f"{safe_tool}-{timestamp_str}.txt"
                filepath = evidence_root / "command-output" / filename
                filepath.write_text(output_text, encoding="utf-8")
                file_size = filepath.stat().st_size
                file_hash = hashlib.sha256(output_text.encode()).hexdigest()

                # Compute correct relative path from ATHENA project root
                athena_dir = Path(__file__).parent.parent.parent
                try:
                    rel_path = str(filepath.relative_to(athena_dir))
                except ValueError:
                    rel_path = str(filepath)

                # Create Artifact node in Neo4j and link to Engagement + Findings
                if neo4j_available and neo4j_driver:
                    artifact_id = f"art-{uuid.uuid4().hex[:8]}"
                    with neo4j_driver.session() as sess:
                        sess.run("""
                            CREATE (a:Artifact {
                                id: $aid, engagement_id: $eid,
                                type: 'command_output', file_path: $path,
                                file_hash: $hash, file_size: $size,
                                mime_type: 'text/plain', caption: $caption,
                                agent: $agent, backend: 'external',
                                capture_mode: 'exploitable', timestamp: datetime()
                            })
                            WITH a
                            MATCH (e:Engagement {id: $eid})
                            MERGE (e)-[:HAS_EVIDENCE]->(a)
                            WITH a
                            OPTIONAL MATCH (f:Finding {engagement_id: $eid})
                            WHERE NOT exists((f)-[:HAS_ARTIFACT]->(:Artifact {type: 'command_output', caption: $caption}))
                            WITH a, f ORDER BY f.created_at DESC LIMIT 1
                            FOREACH (_ IN CASE WHEN f IS NOT NULL THEN [1] ELSE [] END |
                                MERGE (f)-[:HAS_ARTIFACT]->(a)
                            )
                            RETURN a
                        """, {
                            "aid": artifact_id, "eid": eid,
                            "path": rel_path, "hash": file_hash,
                            "size": file_size,
                            "caption": f"Auto-captured {safe_tool} output",
                            "agent": agent_code,
                        })

                    # Broadcast evidence update
                    await state.broadcast({
                        "type": "stat_update",
                        "evidence_count": 1,  # Incremental
                        "timestamp": time.time(),
                    })
            except Exception as e:
                print(f"Evidence auto-capture error: {e}")

        # Sync new findings from Neo4j on every tool_complete (debounced)
        await _sync_neo4j_findings(eid)

    # Add to event timeline
    await state.add_event(AgentEvent(
        id=str(uuid.uuid4())[:8],
        type=event_type,
        agent=agent_code,
        content=event.get("content", ""),
        timestamp=event.get("timestamp", time.time()),
        metadata=metadata,
    ))


@app.post("/api/engagement/{eid}/start-ai")
async def start_engagement_ai(
    eid: str,
    backend: str = "external",
    target: str = "",
    mode: str = "sdk",
):
    """Start an AI-powered PTES engagement.

    Modes:
        - sdk (default): Uses Claude Agent SDK for interactive multi-turn control.
          Operator commands reach the AI via session resume. HITL approvals use
          REST-based polling (proven reliable). Events stream to dashboard in real-time.
        - legacy: Spawns Claude CLI as subprocess (Phase E behavior).

    Works from dashboard GUI and CLI (/athena-engage).
    """
    global _ai_process, _active_sdk_session

    scope_doc = ""
    client_industry = "general"
    if not target:
        eng = next((e for e in state.engagements if e.id == eid), None)
        if eng:
            target = eng.target
        if neo4j_available and neo4j_driver:
            try:
                with neo4j_driver.session() as session:
                    result = session.run(
                        "MATCH (e:Engagement {id: $eid}) RETURN e.scope AS scope, e.scope_doc AS scope_doc, e.client_industry AS client_industry",
                        eid=eid,
                    )
                    record = result.single()
                    if record:
                        if not target and record.get("scope"):
                            target = record["scope"]
                        if record.get("scope_doc"):
                            scope_doc = record["scope_doc"]
                        if record.get("client_industry"):
                            client_industry = record["client_industry"]
            except Exception:
                pass
        if not target:
            return JSONResponse(status_code=400, content={
                "error": "Target scope required. Pass ?target=<ip/cidr/url>"
            })
    elif neo4j_available and neo4j_driver:
        # Target was provided, but still fetch scope_doc and client_industry from Neo4j
        try:
            with neo4j_driver.session() as session:
                result = session.run(
                    "MATCH (e:Engagement {id: $eid}) RETURN e.scope_doc AS scope_doc, e.client_industry AS client_industry",
                    eid=eid,
                )
                record = result.single()
                if record:
                    if record.get("scope_doc"):
                        scope_doc = record["scope_doc"]
                    if record.get("client_industry"):
                        client_industry = record["client_industry"]
        except Exception:
            pass

    # Stop any existing session/process
    if _active_sdk_session and _active_sdk_session.is_running:
        await _active_sdk_session.stop()
        _active_sdk_session = None
    if _ai_process and _ai_process.poll() is None:
        _ai_process.terminate()
        try:
            _ai_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _ai_process.kill()
        _ai_process = None

    # Set engagement active
    state.active_engagement_id = eid
    state.engagement_stopped = False

    # Update Neo4j engagement status to active
    if neo4j_available and neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                session.run(
                    "MATCH (e:Engagement {id: $eid}) SET e.status = 'active'",
                    eid=eid,
                )
        except Exception:
            pass

    # Broadcast AI mode system event
    use_sdk = (mode == "sdk" and SDK_AVAILABLE)
    mode_label = "Agent SDK" if use_sdk else "subprocess (legacy)"
    scope_info = f" Scope document loaded ({len(scope_doc)} chars)." if scope_doc else " No scope document — using target URL constraints only."
    await state.add_event(AgentEvent(
        id=str(uuid.uuid4())[:8],
        type="system",
        agent="OR",
        content=f"AI Mode activated ({mode_label}). Executing PTES phases 1-7 against {target}. HITL required for exploitation.{scope_info}",
        timestamp=time.time(),
    ))

    await state.broadcast({
        "type": "engagement_started",
        "engagement_id": eid,
        "mode": "ai-sdk" if use_sdk else "ai",
        "engagement_active": True,
        "timestamp": time.time(),
    })

    athena_dir = str(Path(__file__).resolve().parent.parent.parent)

    # ── SDK Mode (Phase F) ──────────────────────
    if use_sdk:
        prompt = _build_sdk_prompt(eid, target, backend, scope_doc=scope_doc, client_industry=client_industry)
        _active_sdk_session = AthenaAgentSession(
            engagement_id=eid,
            target=target,
            backend=backend,
            athena_root=athena_dir,
        )
        _active_sdk_session.set_event_callback(
            lambda evt: _sdk_event_to_dashboard(evt, eid)
        )

        # F4: Enable CTF mode if a CTF session is active
        if _ctf_session and _ctf_session["active"]:
            _active_sdk_session.enable_ctf_mode()

        try:
            await _active_sdk_session.start(prompt)
        except Exception as e:
            _active_sdk_session = None
            return JSONResponse(status_code=500, content={
                "error": f"SDK session failed to start: {str(e)[:300]}"
            })

        await state.add_event(AgentEvent(
            id=str(uuid.uuid4())[:8],
            type="system",
            agent="OR",
            content=f"Agent SDK session started. Streaming events to dashboard...",
            timestamp=time.time(),
        ))

        return {
            "ok": True,
            "engagement_id": eid,
            "mode": "ai-sdk",
            "message": f"AI engagement started (Agent SDK) against {target}",
        }

    # ── Legacy Subprocess Mode (Phase E fallback) ──
    prompt = _build_legacy_prompt(eid, target, backend, scope_doc=scope_doc, client_industry=client_industry)
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
    global _ai_process, _active_sdk_session
    state.engagement_stopped = True
    state.engagement_pause_event.set()  # Unblock if paused so task can exit

    # 0a. Stop SDK session if running (Phase F)
    if _active_sdk_session and _active_sdk_session.is_running:
        await _active_sdk_session.stop()
        _active_sdk_session = None

    # 0b. Kill legacy subprocess if running (Phase E)
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
        "metadata": {"control": "engagement_stopped"},
        "timestamp": time.time(),
    })
    return {"ok": True, "message": f"Engagement {eid} stopped", "kill_results": kill_results}


@app.post("/api/engagement/{eid}/cleanup-orphans")
async def cleanup_orphan_scans(eid: str):
    """Mark any running scans as aborted for an engagement that ended unexpectedly.

    Called by the SDK agent in its finally block to clean up scans that were
    dispatched to Kali backends but never completed because the agent session
    crashed or ended prematurely.
    """
    cleaned = []
    now_iso = datetime.now(timezone.utc).isoformat()

    # Clean in-memory scans
    for scan in state.scans:
        if scan.get("status") == "running" and scan.get("engagement_id") == eid:
            scan["status"] = "aborted"
            scan["completed_at"] = now_iso
            # BUG-021: Calculate duration from started_at to now
            started = scan.get("started_at")
            if started and scan.get("duration_s", 0) == 0:
                try:
                    dt_start = datetime.fromisoformat(started.replace("Z", "+00:00"))
                    dt_end = datetime.fromisoformat(now_iso.replace("Z", "+00:00"))
                    scan["duration_s"] = max(0, int((dt_end - dt_start).total_seconds()))
                except Exception:
                    pass
            cleaned.append(scan["id"])
            await state.broadcast({
                "type": "scan_complete",
                "scan": scan,
                "timestamp": time.time(),
            })

    # Clean Neo4j scans
    if neo4j_available and neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                result = session.run("""
                    MATCH (s:Scan {engagement_id: $eid})
                    WHERE s.status = 'running'
                    SET s.status = 'aborted', s.completed_at = $now,
                        s.duration_s = CASE WHEN s.started_at IS NOT NULL
                            THEN duration.between(datetime(s.started_at), datetime($now)).seconds
                            ELSE 0 END
                    RETURN s.id AS id
                """, eid=eid, now=now_iso)
                for record in result:
                    sid = record["id"]
                    if sid not in cleaned:
                        cleaned.append(sid)
        except Exception as e:
            print(f"Neo4j orphan cleanup error: {e}")

    if cleaned:
        await state.broadcast({
            "type": "system",
            "content": f"Cleaned up {len(cleaned)} orphaned scan(s): {', '.join(cleaned)}",
            "timestamp": time.time(),
        })

    return {"ok": True, "cleaned": cleaned}


@app.post("/api/engagement/{eid}/pause")
async def pause_engagement(eid: str):
    """Pause a running engagement. Kills in-flight Kali processes immediately."""
    # Phase F: Pause SDK session
    if _active_sdk_session and _active_sdk_session.is_running:
        await _active_sdk_session.pause()

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
        "metadata": {"control": "engagement_paused"},
        "timestamp": time.time(),
    })
    return {"ok": True, "message": f"Engagement {eid} paused", "kill_results": kill_results}


@app.post("/api/engagement/{eid}/resume")
async def resume_engagement(eid: str):
    """Resume a paused engagement. Paused scans will be re-run by the orchestrator."""
    # Phase F: Resume SDK session
    if _active_sdk_session and _active_sdk_session.is_paused:
        await _active_sdk_session.resume()

    # Restore operator-paused agents to RUNNING so chips turn red again
    for code in AGENT_NAMES:
        if (state.agent_statuses[code] == AgentStatus.WAITING
                and state.agent_tasks.get(code) == "Paused by operator"):
            await state.update_agent_status(code, AgentStatus.RUNNING, "Resumed")

    state.engagement_pause_event.set()  # Unblock waiting agents
    await state.broadcast({
        "type": "system",
        "content": f"Engagement {eid} resumed by operator",
        "metadata": {"control": "engagement_resumed"},
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


async def _handle_sdk_operator_command(cmd_text: str):
    """Forward an operator command to the active SDK session.

    The response flows through the SDK event stream → _sdk_event_to_dashboard
    → dashboard WebSocket. We also broadcast an operator_response event
    to confirm the command was received.

    If the session ended (is_running=False), auto-resume it with the command.
    """
    try:
        # If session ended but still has session_id, auto-resume
        if not _active_sdk_session.is_running and _active_sdk_session.session_id:
            await state.broadcast({
                "type": "operator_response",
                "agent": "OR",
                "agentName": AGENT_NAMES.get("OR", "Orchestrator"),
                "content": "Session idle — resuming with your command...",
                "timestamp": time.time(),
            })
            await _active_sdk_session.resume(cmd_text)
            return

        result = await _active_sdk_session.send_command(cmd_text)
        # The detailed AI response comes through the event stream.
        # Broadcast a brief acknowledgment so the operator sees immediate feedback.
        await state.broadcast({
            "type": "operator_response",
            "agent": "OR",
            "agentName": AGENT_NAMES.get("OR", "Orchestrator"),
            "content": result or "Command forwarded to AI team.",
            "timestamp": time.time(),
        })
    except Exception as e:
        await state.broadcast({
            "type": "operator_response",
            "agent": "OR",
            "agentName": AGENT_NAMES.get("OR", "Orchestrator"),
            "content": f"Error forwarding command: {str(e)[:200]}",
            "timestamp": time.time(),
        })


def _generate_command_response(cmd: str) -> str:
    """Generate a contextual AI acknowledgment for operator commands with live stats (legacy fallback)."""
    cmd_lower = cmd.lower()
    if "pause" in cmd_lower or "stop" in cmd_lower or "halt" in cmd_lower:
        return "Acknowledged. Pausing active operations. Agents will hold current state until further instructions."
    elif "focus" in cmd_lower or "target" in cmd_lower or "prioritize" in cmd_lower:
        return "Understood. Redirecting agent focus as requested. Updating task queue and notifying active agents."
    elif "stealth" in cmd_lower or "slow" in cmd_lower or "reduce" in cmd_lower or "rate" in cmd_lower:
        return "Roger. Adjusting scan parameters to stealth profile. Rate limiting and timing randomization enabled."
    elif "skip" in cmd_lower or "exclude" in cmd_lower or "ignore" in cmd_lower:
        return "Confirmed. Adding exclusions to scope. Active agents will avoid specified targets."
    elif "resume" in cmd_lower or "continue" in cmd_lower or "proceed" in cmd_lower:
        return "Resuming operations. All paused agents re-entering active state."
    elif any(w in cmd_lower for w in ("report", "status", "summary", "how", "doing", "update", "progress", "sitrep", "what")):
        # Generate live status from in-memory state
        eid = state.active_engagement_id
        findings = [f for f in state.findings if f.engagement == eid] if eid else []
        scans = [s for s in state.scans if s.get("engagement_id") == eid] if eid else []
        sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            s = f.severity.value if hasattr(f.severity, 'value') else str(f.severity).lower()
            if s in sev:
                sev[s] += 1
        active_agents = [a for a, s in state.agent_status.items() if s.lower() in ("running", "thinking")]
        parts = [f"**Status:** {len(findings)} findings ({sev['critical']}C/{sev['high']}H/{sev['medium']}M/{sev['low']}L), {len(scans)} scans completed."]
        if active_agents:
            names = [AGENT_NAMES.get(a, a) for a in active_agents]
            parts.append(f"**Active agents:** {', '.join(names)}.")
        else:
            parts.append("**All agents:** Idle — awaiting next phase or instructions.")
        if findings:
            latest = findings[-1]
            parts.append(f"**Last finding:** [{latest.severity.value.upper() if hasattr(latest.severity, 'value') else latest.severity}] {latest.title}")
        return " ".join(parts)
    else:
        return "Command received. Routing to relevant agents for execution."


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


@app.get("/favicon.svg")
async def serve_favicon():
    """Serve the favicon."""
    return FileResponse(DASHBOARD_DIR / "favicon.svg", media_type="image/svg+xml")


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
