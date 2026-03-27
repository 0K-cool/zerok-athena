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
import logging
import yaml
import mimetypes
import os
import re
import shutil
import time
import uuid
import zipfile
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from enum import Enum
from io import BytesIO
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from fastapi import Body, FastAPI, File, Form, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from PIL import Image
from pydantic import BaseModel

# Load .env file (env vars take priority over .env values)
load_dotenv(Path(__file__).parent / ".env")

# Neo4j imports (optional dependency)
try:
    from neo4j import GraphDatabase
    NEO4J_AVAILABLE = True
except ImportError:
    NEO4J_AVAILABLE = False
    GraphDatabase = None

# Phase C: Kali backend client
from kali_client import KaliClient
from langfuse_integration import init_langfuse, shutdown_langfuse
from graphiti_integration import init_graphiti, shutdown_graphiti

# Phase F: Claude Agent SDK wrapper
try:
    from sdk_agent import AthenaAgentSession
    SDK_AVAILABLE = True
except ImportError:
    SDK_AVAILABLE = False
    AthenaAgentSession = None

# Phase F1a: Multi-agent session manager
try:
    from agent_session_manager import AgentSessionManager, _is_blocking_command
    MULTI_AGENT_AVAILABLE = True
except ImportError:
    MULTI_AGENT_AVAILABLE = False
    AgentSessionManager = None

    def _is_blocking_command(command: str) -> bool:
        return False


# ──────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("athena.dashboard")


# ──────────────────────────────────────────────
# Async Neo4j Helper (prevents blocking event loop)
# ──────────────────────────────────────────────

async def neo4j_exec(fn):
    """Run a sync Neo4j function in a thread pool to avoid blocking the async event loop.

    Usage:
        result = await neo4j_exec(lambda: _my_sync_neo4j_work())
    """
    return await asyncio.to_thread(fn)


# ──────────────────────────────────────────────
# Models
# ──────────────────────────────────────────────

class AgentCode(str, Enum):
    STRATEGY = "ST"
    PASSIVE_RECON = "PR"
    ACTIVE_RECON = "AR"
    WEB_VULN_SCANNER = "WV"
    DEEP_ANALYSIS = "DA"
    PROBE_EXECUTOR = "PX"
    EXPLOITATION = "EX"
    VERIFICATION = "VF"
    REPORTING = "RP"


AGENT_NAMES = {
    "ST": "Strategy",
    "PR": "Passive Recon",
    "AR": "Active Recon",
    "WV": "Web Vuln Scanner",
    "DA": "Deep Analysis",
    "PX": "Probe Executor",
    "EX": "Exploitation",
    "PE": "Post-Exploitation",
    "VF": "Verification",
    "RP": "Reporting",
}

AGENT_PTES_PHASE = {
    "ST": 0,   # Cross-phase (runs at phase gates)
    "PR": 1,   # Intelligence Gathering (passive)
    "AR": 2,   # Information Gathering (active)
    "WV": 4,   # Vulnerability Analysis
    "DA": 4,   # Deep Analysis (between vuln scan and exploitation)
    "PX": 4,   # Probe Executor (targeted probing)
    "EX": 5,   # Exploitation
    "PE": 6,   # Post-Exploitation
    "VF": 5,   # Verification
    "RP": 7,   # Reporting
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
    fingerprint: Optional[str] = None
    discovered_at: Optional[float] = None
    confirmed_at: Optional[float] = None


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
    started_at: Optional[float] = None
    completed_at: Optional[float] = None


# ──────────────────────────────────────────────
# Neo4j Connection
# ──────────────────────────────────────────────

NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://kali.linux.vkloud.antsle.us:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASS = os.environ.get("NEO4J_PASS", "")
if not NEO4J_PASS:
    logger.warning("NEO4J_PASS not set — Neo4j authentication will fail. Set via environment variable.")

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
        # CRIT-1 fix: verify_connectivity() moved to lifespan to avoid blocking at import
        print(f"  Neo4j:      driver created (connectivity check deferred to startup)")
    except Exception as e:
        print(f"  Neo4j:      Unavailable ({e}) - using mock data")
        neo4j_driver = None
        neo4j_available = False
else:
    print("  Neo4j:      neo4j package not installed - using mock data")


# ──────────────────────────────────────────────
# ATHENA Config File Loader
# ──────────────────────────────────────────────

def _load_athena_config() -> dict:
    """Load athena-config.yaml with ${ENV_VAR:default} substitution."""
    config_path = Path(__file__).parent / "athena-config.yaml"
    if not config_path.exists():
        return {}
    try:
        with open(config_path) as f:
            raw = f.read()

        def _env_sub(m):
            var = m.group(1)
            if ':' in var:
                name, default = var.split(':', 1)
                return os.environ.get(name, default)
            return os.environ.get(var, '')

        resolved = re.sub(r'\$\{([^}]+)\}', _env_sub, raw)
        return yaml.safe_load(resolved) or {}
    except Exception as e:
        print(f"Warning: Failed to load athena-config.yaml: {e}")
        return {}


_ATHENA_CONFIG = _load_athena_config()
_cfg = _ATHENA_CONFIG.get('athena', {})


# ──────────────────────────────────────────────
# Kali Backend Configuration
# ──────────────────────────────────────────────

KALI_EXTERNAL_URL = os.environ.get("KALI_EXTERNAL_URL", "http://kali.linux.vkloud.antsle.us:5000")
KALI_INTERNAL_URL = os.environ.get("KALI_INTERNAL_URL", "http://172.26.80.76:5000")
KALI_INTERNAL_API_KEY = os.environ.get("KALI_API_KEY", "")

# BUG-040: Kali backend IPs — never register these as target hosts
_KALI_BACKEND_IPS: set[str] = set()
try:
    from urllib.parse import urlparse as _urlparse
    import socket as _socket
    for _url in [KALI_EXTERNAL_URL, KALI_INTERNAL_URL]:
        _parsed = _urlparse(_url)
        _host = _parsed.hostname or ""
        if _host:
            # Try to resolve hostname to IP
            try:
                _resolved = _socket.gethostbyname(_host)
                _KALI_BACKEND_IPS.add(_resolved)
            except _socket.gaierror:
                pass
            # Also add the raw hostname in case it's already an IP
            _KALI_BACKEND_IPS.add(_host)
    _KALI_BACKEND_IPS.discard("")
except Exception:
    pass  # Non-critical — worst case, no filtering

# Initialize Kali client (set up after state is created below)
kali_client: KaliClient | None = None


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
        # BUG-M1: Per-phase rate limiting needs this attribute
        self.engagement_phase: int = 0

    # Seed methods removed in Phase C — dashboard starts clean.
    # Demo mode (/api/demo/start) generates its own events independently.

    async def broadcast(self, event: dict):
        """Send event to all connected WebSocket clients."""
        message = json.dumps(event)
        disconnected = set()
        for ws in list(self.connected_clients):  # BUG-C1: snapshot to avoid RuntimeError during async iteration
            try:
                await ws.send_text(message)
            except asyncio.CancelledError:
                raise  # HIGH-7: propagate cancellation, don't swallow it
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
            def _write_event():
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
                         engagement_id=(
                             (event.metadata or {}).get("engagement", "")
                             or (event.metadata or {}).get("engagement_id", "")
                             or state.active_engagement_id
                             or ""
                         ),
                         metadata_json=json.dumps(event.metadata) if event.metadata else "{}")
            try:
                await neo4j_exec(_write_event)
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
            "discovered_at": finding.discovered_at,
            "confirmed_at": finding.confirmed_at,
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
        # Persist Credential node + HARVESTED_FROM edge to Neo4j
        if neo4j_available and neo4j_driver:
            _cred = credential
            _eid = engagement_id
            def _write_cred():
                with neo4j_driver.session() as session:
                    session.run("""
                        MERGE (c:Credential {
                            username: $username,
                            engagement_id: $eid,
                            host: $host,
                            service: $service
                        })
                        ON CREATE SET c.id = 'cred-' + substring(randomUUID(), 0, 16)
                        SET c.password = $password,
                            c.type = $ctype,
                            c.access_level = $access_level,
                            c.discovered_by = $discovered_by,
                            c.timestamp = $ts,
                            c.description = $description
                        WITH c
                        OPTIONAL MATCH (h:Host {ip: $host, engagement_id: $eid})
                        WITH c, h
                        OPTIONAL MATCH (h2:Host {ip: $host}) WHERE h IS NULL
                        WITH c, COALESCE(h, h2) AS host
                        FOREACH (_ IN CASE WHEN host IS NOT NULL THEN [1] ELSE [] END |
                            MERGE (c)-[:HARVESTED_FROM]->(host)
                        )
                    """, {
                        "username": _cred.get("username", ""),
                        "eid": _eid,
                        "host": _cred.get("host", ""),
                        "service": _cred.get("service", ""),
                        "password": _cred.get("password", ""),
                        "ctype": _cred.get("type", ""),
                        "access_level": _cred.get("access_level", ""),
                        "discovered_by": _cred.get("discovered_by", ""),
                        "ts": _cred.get("timestamp", 0),
                        "description": _cred.get("description", ""),
                    })
            try:
                await neo4j_exec(_write_cred)
            except Exception as e:
                print(f"Neo4j credential write error: {e}")

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
                # Check if engagement is still active
                eng_result = session.run(
                    "MATCH (e:Engagement {id: $eid}) RETURN e.status AS status",
                    eid=state.active_engagement_id,
                )
                eng_record = eng_result.single()
                eng_status = eng_record["status"] if eng_record else "completed"

                if eng_status in ("completed", "stopped", "archived"):
                    # Engagement is done — all agents should be IDLE
                    for code in AGENT_NAMES:
                        state.agent_statuses[code] = AgentStatus.IDLE
                        state.agent_tasks[code] = ""
                else:
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


# CRIT-1/MED-1 fix: State restore moved to lifespan to avoid blocking at import

# Initialize Kali client
kali_client = KaliClient.from_env()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown lifecycle."""
    print("\n  0K ATHENA Dashboard Server")
    print("  ─────────────────────────")
    print("  WebSocket:  ws://localhost:8080/ws")
    print("  Dashboard:  http://localhost:8080")
    print("  API Docs:   http://localhost:8080/docs")
    print("  Agent API:  POST /api/events")
    # Phase G: Clean up stale agent workspaces from previous crashes
    if MULTI_AGENT_AVAILABLE:
        from agent_session_manager import WorkspaceManager
        WorkspaceManager.cleanup_stale_workspaces(max_age_hours=2.0)
    # CRIT-1: Verify Neo4j connectivity (moved from module load to async lifespan)
    global neo4j_available
    if neo4j_driver:
        try:
            neo4j_driver.verify_connectivity()
            neo4j_available = True
            print(f"  Neo4j:      {NEO4J_URI} ✓")
        except Exception as e:
            logger.warning(f"Neo4j connectivity check failed: {e}")
            print(f"  Neo4j:      Unavailable ({e}) - using mock data")
            neo4j_available = False
    # MED-1: Restore state from Neo4j (moved from module load to async lifespan)
    restore_state_from_neo4j()
    # Phase C: Check Kali backend connectivity
    health = await kali_client.health_check_all()
    for name, info in health.items():
        status = "✓" if info.get("available") else f"✗ ({info.get('error', 'unreachable')})"
        print(f"  Kali ({name:8s}): {status}")
    tools = kali_client.list_tools()
    print(f"  Tool Registry: {len(tools)} tools loaded")
    # BUG-013: Create Neo4j index for finding fingerprint dedup
    if neo4j_available and neo4j_driver:
        try:
            def _create_indexes():
                with neo4j_driver.session() as session:
                    session.run(
                        "CREATE INDEX finding_fingerprint IF NOT EXISTS "
                        "FOR (f:Finding) ON (f.fingerprint)"
                    )
            await neo4j_exec(_create_indexes)
            print("  Neo4j Index: finding_fingerprint ✓")
            # BUG-002 fix: Unique constraint prevents duplicate findings at write-time
            def _create_fingerprint_constraint():
                with neo4j_driver.session() as session:
                    try:
                        session.run(
                            "CREATE CONSTRAINT finding_fingerprint_unique IF NOT EXISTS "
                            "FOR (f:Finding) REQUIRE (f.fingerprint, f.engagement_id) IS UNIQUE"
                        )
                    except Exception:
                        pass  # Constraint may conflict with existing index on older Neo4j
            await neo4j_exec(_create_fingerprint_constraint)
            print("  Neo4j Constraint: finding_fingerprint_unique ✓")
            # CEI-1: Create indexes for Cross-Engagement Intelligence nodes
            def _create_cei_indexes():
                with neo4j_driver.session() as session:
                    session.run("CREATE INDEX technique_key IF NOT EXISTS FOR (t:TechniqueRecord) ON (t.key)")
                    session.run("CREATE INDEX fp_record_key IF NOT EXISTS FOR (fp:FalsePositiveRecord) ON (fp.key)")
            await neo4j_exec(_create_cei_indexes)
            print("  Neo4j Index: technique_key, fp_record_key ✓")
            # CVE Registry: index + uniqueness constraint for ConfirmedCVE nodes
            def _create_cve_registry_indexes():
                with neo4j_driver.session() as session:
                    session.run("CREATE INDEX confirmed_cve_engagement IF NOT EXISTS FOR (c:ConfirmedCVE) ON (c.engagement_id)")
                    try:
                        session.run("CREATE CONSTRAINT confirmed_cve_unique IF NOT EXISTS FOR (c:ConfirmedCVE) REQUIRE (c.cve, c.engagement_id, c.host) IS UNIQUE")
                    except Exception:
                        pass  # Constraint may conflict on older Neo4j versions
            await neo4j_exec(_create_cve_registry_indexes)
            print("  Neo4j Index/Constraint: confirmed_cve_engagement, confirmed_cve_unique ✓")
            # Backfill EXPLOITS edges for confirmed findings missing them
            def _backfill_exploits():
                with neo4j_driver.session() as session:
                    # Verified findings link to hosts/services via AFFECTS or FOUND_ON.
                    # Create EXPLOITS to the best target (Service preferred, Host as fallback).
                    result = session.run("""
                        MATCH (f:Finding)
                        WHERE f.verified = true AND NOT (f)-[:EXPLOITS]->()
                        OPTIONAL MATCH (f)-[:AFFECTS|FOUND_ON]->(h:Host)-[:HAS_SERVICE]->(s:Service)
                        OPTIONAL MATCH (f)-[:AFFECTS]->(s2:Service)
                        OPTIONAL MATCH (h2:Host {engagement_id: f.engagement_id})
                        WITH f, COALESCE(s2, s, h, h2) AS target
                        WHERE target IS NOT NULL
                        MERGE (f)-[:EXPLOITS]->(target)
                        RETURN count(*) AS created
                    """)
                    return result.single()["created"]
            created = await neo4j_exec(_backfill_exploits)
            if created:
                print(f"  Neo4j Backfill: {created} EXPLOITS edges created ✓")
        except Exception as e:
            print(f"  Neo4j Index: finding_fingerprint ✗ ({e})")
    # H3: Initialize Langfuse observability
    langfuse_ok = await init_langfuse()
    if langfuse_ok:
        logger.info("Langfuse observability active")
    else:
        logger.info("Langfuse disabled — running without LLM observability")
    # H1: Initialize Graphiti cross-session memory
    graphiti_ok = await init_graphiti()
    if graphiti_ok:
        logger.info("Graphiti cross-session memory active")
    else:
        logger.info("Graphiti disabled — running without cross-session memory")
    # Start internet connectivity monitor
    global _network_monitor_task, _stale_scan_monitor_task
    _network_monitor_task = asyncio.create_task(_network_connectivity_monitor())
    _stale_scan_monitor_task = asyncio.create_task(_stale_scan_watchdog())
    print("  Network Monitor: active (checking every 10s)")
    print("  Stale Scan Watchdog: active (threshold: 10min)")
    print()
    yield
    # Stop background monitors
    for task in (_network_monitor_task, _stale_scan_monitor_task):
        if task and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
    # H1: Close Graphiti before Neo4j
    await shutdown_graphiti()
    # H3: Flush Langfuse before shutdown
    await shutdown_langfuse()
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
            for e in list(state.events)[-50:]  # MED-7: snapshot to avoid race with add_event
        ],
        "engagement_active": (state.engagement_task is not None and not state.engagement_task.done()) or (_active_session_manager is not None and _active_session_manager.is_running),
        "engagement_paused": not state.engagement_pause_event.is_set() if (
            (state.engagement_task and not state.engagement_task.done())
            or (_active_session_manager is not None and _active_session_manager.is_running)
        ) else False,
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
                if ok:
                    await _handle_scope_expansion_approval(request_id, True, reason)
                else:
                    await ws.send_text(json.dumps({
                        "type": "error",
                        "content": f"Unknown approval request: {request_id}",
                        "timestamp": time.time(),
                    }))

            elif msg_type == "reject":
                request_id = msg.get("request_id")
                reason = msg.get("reason", "Rejected by operator")
                ok = await state.resolve_approval(request_id, False, reason)
                if ok:
                    await _handle_scope_expansion_approval(request_id, False, reason)
                else:
                    await ws.send_text(json.dumps({
                        "type": "error",
                        "content": f"Unknown approval request: {request_id}",
                        "timestamp": time.time(),
                    }))

            elif msg_type == "operator_command":
                cmd_text = msg.get("content", "").strip()
                if cmd_text:
                    # Store and broadcast the command so it persists on reload
                    op_event = AgentEvent(
                        id=str(uuid.uuid4()),
                        type="operator_command",
                        agent="OP",
                        content=cmd_text,
                        timestamp=time.time(),
                        metadata={"agent_name": "Operator", "engagement": state.active_engagement_id or ""},
                    )
                    await state.add_event(op_event)
                    await state.broadcast({
                        "type": "operator_command",
                        "content": cmd_text,
                        "timestamp": time.time(),
                    })
                    # Phase F1a: Forward to multi-agent session manager (→ ST)
                    if _active_session_manager and _active_session_manager.is_running:
                        asyncio.create_task(_handle_multi_agent_operator_command(cmd_text))
                    else:
                        await state.broadcast({
                            "type": "operator_response",
                            "agent": "ST",
                            "agentName": AGENT_NAMES.get("ST", "Strategy"),
                            "content": "No active AI engagement. Start one from the dashboard.",
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
        # BUG-017: All-agents-done watchdog — auto-stop when ST + RP both complete
        # BUG-025: Route through _auto_stop_with_rp_gate so running-agent check applies
        if payload.agent in ("ST", "RP"):
            eid = state.active_engagement_id
            if eid and _active_session_manager and _active_session_manager.is_running:
                st_done = state.agent_statuses.get("ST") == AgentStatus.COMPLETED
                rp_done = state.agent_statuses.get("RP") == AgentStatus.COMPLETED
                if st_done and rp_done:
                    logger.info(
                        "BUG-017: ST + RP both completed. Auto-stopping engagement %s.", eid
                    )
                    asyncio.create_task(_auto_stop_with_rp_gate(eid))
    elif payload.type == "agent_error":
        await state.update_agent_status(payload.agent, AgentStatus.ERROR)
    # Phase F: Strategy Agent events
    elif payload.type == "strategy_thinking":
        await state.update_agent_status("ST", AgentStatus.RUNNING, payload.content)
    elif payload.type == "strategy_decision":
        await state.update_agent_status("ST", AgentStatus.COMPLETED, payload.content)
        # BUG-045 FIX: Auto-stop engagement when ST declares completion.
        # ST says "Engagement is COMPLETE" but the system didn't detect this as
        # a termination signal — ST kept looping. Now we check for completion
        # keywords and auto-trigger engagement stop.
        _content_upper = (payload.content or "").upper()
        _COMPLETION_KEYWORDS = ["ENGAGEMENT IS COMPLETE", "FULLY COMPLETE",
                                "ENGAGEMENT COMPLETE", "ALL DELIVERABLES PRODUCED",
                                "NO FURTHER AGENTS NEEDED", "ENGAGEMENT WRAPPED UP"]
        if any(kw in _content_upper for kw in _COMPLETION_KEYWORDS):
            eid = state.active_engagement_id
            if eid and _active_session_manager and _active_session_manager.is_running:
                # BUG-016: Gate auto-stop on RP completion before halting
                asyncio.create_task(_auto_stop_with_rp_gate(eid))
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
    "discovery":      ["AR", "WV", "DA", "ST"],         # Recon → active recon + vuln + deep analysis + strategy
    "vulnerability":  ["EX", "VF", "ST"],              # Vuln → exploit + verify + strategy
    "credential":     ["EX", "PE", "ST"],               # Exploit → exploitation + post-exploit + strategy
    "verification":   ["ST", "RP"],                    # Verify → strategy + report
    "strategy":       list(AGENT_NAMES.keys()),        # Strategy → anyone
    "pivot":          ["PR", "AR", "WV", "DA", "ST"],  # PostExploit → recon + deep analysis + strategy
    "code_finding":   ["VF", "EX", "ST"],              # DA → verify + exploit + strategy
}

# Rate limit: max messages per agent per engagement phase
AGENT_MSG_RATE_LIMIT = 5
_agent_msg_counts: dict[str, int] = {}  # "agent:phase" → count
# BUG-005: Pending bilateral messages for agents not yet running
_pending_bilateral_messages: dict[str, list] = {}


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

    # F2: Deliver message to recipient agent's SDK session
    # This is the critical bridge — without this, bilateral messages are
    # display-only in the dashboard and never reach the recipient agent.
    # BUG-005 fix: Use more prominent formatting + store as pending for re-injection
    delivered = False
    if _active_session_manager and _active_session_manager.is_running:
        recipient_session = _active_session_manager.agents.get(payload.to_agent)
        if recipient_session and recipient_session.is_running:
            # BUG-005: Make message more prominent so agent doesn't skip it
            priority_marker = "URGENT " if payload.priority == "high" else ""
            delivery_text = (
                f"\n{'='*60}\n"
                f"{priority_marker}INCOMING MESSAGE from {payload.from_agent} "
                f"[{payload.msg_type}]\n"
                f"{'='*60}\n"
                f"{payload.content}\n"
            )
            if payload.neo4j_ref:
                delivery_text += f"(Neo4j ref: {payload.neo4j_ref})\n"
            delivery_text += (
                f"{'='*60}\n"
                f"ACTION REQUIRED: Acknowledge and incorporate the above "
                f"intelligence into your current task.\n"
            )
            await recipient_session.send_command(delivery_text)
            delivered = True
        else:
            # BUG-005: Agent not running yet — store as pending for injection on spawn
            _pending_bilateral_messages.setdefault(payload.to_agent, []).append({
                "from": payload.from_agent,
                "content": payload.content,
                "msg_type": payload.msg_type,
                "priority": payload.priority,
                "neo4j_ref": payload.neo4j_ref,
                "timestamp": time.time(),
            })
            # Notify ST: recipient not alive — ST decides whether to spawn
            st_session = _active_session_manager.agents.get("ST")
            if st_session and st_session.is_running and payload.from_agent != "ST":
                await st_session.send_command(
                    f"{payload.from_agent} sent a message to {payload.to_agent}, "
                    f"but {payload.to_agent} is NOT running. Message queued.\n"
                    f"Content: {payload.content[:200]}\n"
                    f"DECIDE: Spawn {payload.to_agent} to process this intel? "
                    f"Or absorb it yourself?"
                )

    return {
        "ok": True,
        "event_id": event.id,
        "from": payload.from_agent,
        "to": payload.to_agent,
        "msg_type": payload.msg_type,
        "delivered": delivered,
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
    # Guard: don't allow RUNNING unless a real session exists (prevents P0 replay)
    if status == AgentStatus.RUNNING and _active_session_manager:
        session = _active_session_manager.agents.get(payload.agent)
        if not session or not session.is_running:
            return JSONResponse(status_code=409, content={
                "error": f"Agent {payload.agent} has no active session. "
                         "Cannot set RUNNING — agents are spawned via engagement start."
            })
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


# ── Scope Expansion (HITL-gated) ─────────────────

class ScopeExpansionPayload(BaseModel):
    """Request to expand engagement scope when agents discover new attack surface."""
    agent: str  # Agent requesting expansion
    new_types: list[str]  # Types to add: "web_app", "internal", "external"
    reason: str  # What was discovered
    evidence: str = ""  # Services/URLs found
    target: Optional[str] = None  # Specific target for expansion


# Track pending scope expansion to prevent duplicate HITL requests
_pending_scope_expansion: Optional[str] = None  # Approval ID if pending
# BUG-026: Track autonomous mode globally for scope expansion auto-approve
_is_autonomous: bool = False


@app.get("/api/scope")
async def get_engagement_scope():
    """Get current engagement scope and allowed agent types."""
    allowed = set()
    for t in _engagement_types:
        allowed |= _AGENTS_BY_TYPE.get(t, {"ST", "PR", "AR", "WV", "DA", "PX", "EX", "PE", "VF", "RP"})
    allowed -= _skip_agents  # Remove skipped agents
    return {
        "engagement_types": _engagement_types,
        "allowed_agents": sorted(allowed),
        "expandable_types": [t for t in _AGENTS_BY_TYPE if t not in _engagement_types],
        "pending_expansion": _pending_scope_expansion,
    }


@app.post("/api/scope/expand")
async def request_scope_expansion(payload: ScopeExpansionPayload):
    """Request scope expansion via HITL approval.

    When agents discover attack surface outside the current engagement type
    (e.g., a web app found during external pentest), they POST here.
    Creates a HITL approval request. On approval, engagement types are
    expanded and previously-blocked agents become available.

    Example:
        curl -X POST http://localhost:8080/api/scope/expand \\
          -H 'Content-Type: application/json' \\
          -d '{"agent":"AR","new_types":["web_app"],
               "reason":"HTTP service on port 8080 serves a web application with login form",
               "evidence":"http://10.1.1.20:8080 — HTML response with login page, forms, JavaScript assets",
               "target":"http://10.1.1.20:8080"}'
    """
    global _pending_scope_expansion

    # Validate requested types
    valid_types = set(_AGENTS_BY_TYPE.keys())
    invalid = [t for t in payload.new_types if t not in valid_types]
    if invalid:
        return JSONResponse(status_code=400, content={
            "error": f"Invalid type(s): {invalid}. Valid: {sorted(valid_types)}"
        })

    # Skip if already in scope
    already_in_scope = [t for t in payload.new_types if t in _engagement_types]
    if len(already_in_scope) == len(payload.new_types):
        return {"ok": True, "message": "All requested types already in scope",
                "engagement_types": _engagement_types}

    new_types = [t for t in payload.new_types if t not in _engagement_types]

    # BUG-026: Auto-approve scope expansion in Lab/CTF mode — no HITL gate
    if _is_autonomous and new_types:
        _engagement_types.extend(new_types)
        new_agents = set()
        for t in new_types:
            new_agents |= _AGENTS_BY_TYPE.get(t, set())
        current_allowed = set()
        for t in _engagement_types:
            current_allowed |= _AGENTS_BY_TYPE.get(t, set())
        newly_unlocked = sorted(new_agents - current_allowed)
        types_str = ", ".join(new_types)
        agents_str = ", ".join(
            f"{a} ({AGENT_NAMES.get(a, a)})" for a in newly_unlocked
        ) if newly_unlocked else "no additional agents"
        await _emit("scope_expansion", payload.agent,
            f"AUTO-APPROVED: Scope expanded to include {types_str} "
            f"(autonomous mode). New agents: {agents_str}",
            {"new_types": new_types, "auto_approved": True,
             "newly_unlocked_agents": newly_unlocked})
        return {"ok": True, "auto_approved": True, "new_types": new_types,
                "newly_unlocked_agents": newly_unlocked,
                "engagement_types": _engagement_types,
                "message": "Auto-approved in autonomous mode."}

    # Check for pending expansion request
    if _pending_scope_expansion:
        return JSONResponse(status_code=429, content={
            "error": "A scope expansion request is already pending HITL approval.",
            "pending_id": _pending_scope_expansion,
        })

    # Compute what new agents would become available
    new_agents = set()
    for t in new_types:
        new_agents |= _AGENTS_BY_TYPE.get(t, set())
    current_allowed = set()
    for t in _engagement_types:
        current_allowed |= _AGENTS_BY_TYPE.get(t, set())
    newly_unlocked = sorted(new_agents - current_allowed)

    # Create HITL approval for scope expansion
    types_str = ", ".join(new_types)
    agents_str = ", ".join(f"{a} ({AGENT_NAMES.get(a, a)})" for a in newly_unlocked) if newly_unlocked else "no additional agents"
    approval_id = f"scope-{str(uuid.uuid4())[:8]}"

    req = ApprovalRequest(
        id=approval_id,
        agent=payload.agent,
        action=f"Expand scope to include: {types_str}",
        description=(
            f"SCOPE EXPANSION REQUEST\n\n"
            f"Agent {payload.agent} discovered additional attack surface:\n"
            f"{payload.reason}\n\n"
            f"Evidence: {payload.evidence}\n\n"
            f"Current scope: {', '.join(_engagement_types)}\n"
            f"Requested addition: {types_str}\n"
            f"New agents unlocked: {agents_str}\n\n"
            f"Approve to expand the engagement scope and allow {agents_str} to test this surface."
        ),
        risk_level="medium",
        target=payload.target,
        timestamp=time.time(),
    )
    _pending_scope_expansion = approval_id
    await state.request_approval(req)

    # Emit a scope_expansion_requested event for the timeline
    await _emit("scope_expansion", payload.agent,
        f"Scope expansion requested: add {types_str} testing "
        f"(discovered: {payload.reason[:200]})",
        {"new_types": new_types, "approval_id": approval_id,
         "newly_unlocked_agents": newly_unlocked})

    return {
        "ok": True,
        "approval_id": approval_id,
        "new_types": new_types,
        "newly_unlocked_agents": newly_unlocked,
        "message": "HITL approval requested. Waiting for operator decision.",
    }


@app.post("/api/targets/{ip}/status")
async def update_target_status(ip: str, payload: dict = Body(...)):
    """Update target host status (reachable/filtered/closed/unreachable/rate_limited).

    Called by AR when naabu returns 0 ports after multi-step verification.
    Mode-aware: autonomous auto-skips, supervised asks operator.
    """
    status = payload.get("status", "unknown")  # reachable/filtered/closed/unreachable/rate_limited
    reason = payload.get("reason", "")
    agent = payload.get("agent", "AR")

    # Update Neo4j Host node
    if neo4j_available and neo4j_driver:
        try:
            def _update():
                with neo4j_driver.session() as session:
                    session.run("""
                        MERGE (h:Host {ip: $ip, engagement_id: $eid})
                        SET h.state = $status, h.state_reason = $reason,
                            h.state_updated = datetime()
                    """, ip=ip, status=status, reason=reason,
                         eid=state.active_engagement_id or "")
            await asyncio.to_thread(_update)
        except Exception as e:
            logger.warning("Failed to update target status in Neo4j: %s", e)

    # Create finding for filtered/closed/rate_limited (these are pentest findings)
    if status in ("filtered", "closed", "rate_limited"):
        finding_titles = {
            "filtered": f"All TCP ports filtered on {ip} — default-deny firewall detected",
            "closed": f"Host {ip} active but no services exposed — all ports closed",
            "rate_limited": f"IDS/rate-limiting detected on {ip} — scan results may be incomplete",
        }
        await state.add_event(AgentEvent(
            id=str(uuid.uuid4()), type="finding", agent=agent,
            content=finding_titles.get(status, f"Target {ip} status: {status}"),
            timestamp=time.time(),
            metadata={"severity": "medium" if status == "rate_limited" else "low",
                      "target": ip, "target_status": status}
        ))

    # Broadcast to dashboard
    await state.broadcast({
        "type": "target_status",
        "ip": ip,
        "status": status,
        "reason": reason,
        "agent": agent,
        "timestamp": time.time(),
    })

    # Mode-aware response
    action = "continue"
    if status in ("unreachable", "filtered", "closed"):
        if _is_autonomous or (_ctf_session and _ctf_session.get("active")):
            action = "skip"
            await _emit("system", "ST",
                f"Target {ip} is {status}. Auto-skipping in autonomous mode. {reason}",
                {"target_status": status, "auto_skip": True})
        else:
            # Supervised mode — notify operator
            action = "pending"
            await _emit("system", "ST",
                f"Target {ip} is {status}. Awaiting operator decision (skip/retry/stop). {reason}",
                {"target_status": status, "operator_decision_needed": True})

    return {
        "ok": True,
        "ip": ip,
        "status": status,
        "action": action,
    }


@app.get("/api/targets/{ip}/status")
async def get_target_status(ip: str):
    """Get current status of a target host."""
    if neo4j_available and neo4j_driver:
        try:
            def _query():
                with neo4j_driver.session() as session:
                    result = session.run(
                        "MATCH (h:Host {ip: $ip}) RETURN h.state AS state, h.state_reason AS reason",
                        ip=ip)
                    record = result.single()
                    return {"state": record["state"], "reason": record["reason"]} if record else None
            data = await asyncio.to_thread(_query)
            if data:
                return {"ip": ip, **data}
        except Exception:
            pass
    return {"ip": ip, "state": "unknown", "reason": ""}


# Override resolve_approval to handle scope expansion on approval
_original_resolve_approval = None  # Set after DashboardState instantiation


async def _handle_scope_expansion_approval(request_id: str, approved: bool, reason: str = ""):
    """Post-resolve hook: expand scope if a scope expansion was approved."""
    global _pending_scope_expansion, _engagement_types

    if request_id != _pending_scope_expansion:
        return

    _pending_scope_expansion = None

    if not approved:
        await _emit("system", "ST",
            f"Scope expansion REJECTED by operator. {reason}",
            {"scope_rejected": True})
        # Notify ST that scope expansion was rejected
        if _active_session_manager and _active_session_manager.is_running:
            st = _active_session_manager.agents.get("ST")
            if st and st.is_running:
                await st.send_command(
                    f"Scope expansion was REJECTED by the operator. "
                    f"Reason: {reason or 'No reason given'}. "
                    f"Continue within current scope: {', '.join(_engagement_types)}."
                )
        return

    # Extract new types from the approval request description
    req = state.approval_requests.get(request_id)
    if not req:
        return

    # Parse types from action string: "Expand scope to include: web_app, internal"
    action_types = req.action.replace("Expand scope to include:", "").strip()
    new_types = [t.strip() for t in action_types.split(",") if t.strip() in _AGENTS_BY_TYPE]

    if new_types:
        old_types = list(_engagement_types)
        for t in new_types:
            if t not in _engagement_types:
                _engagement_types.append(t)

        # Update Neo4j engagement node
        try:
            if neo4j_driver:
                def _update_types():
                    with neo4j_driver.session() as session:
                        session.run(
                            "MATCH (e:Engagement {id: $eid}) SET e.types = $types",
                            eid=state.active_engagement_id,
                            types=_engagement_types,
                        )
                await neo4j_exec(_update_types)
        except Exception:
            pass  # Non-critical

        # Compute newly available agents
        new_allowed = set()
        for t in new_types:
            new_allowed |= _AGENTS_BY_TYPE.get(t, set())
        old_allowed = set()
        for t in old_types:
            old_allowed |= _AGENTS_BY_TYPE.get(t, set())
        newly_unlocked = sorted(new_allowed - old_allowed)

        agents_str = ", ".join(f"{a} ({AGENT_NAMES.get(a, a)})" for a in newly_unlocked)

        await _emit("system", "ST",
            f"SCOPE EXPANDED: {', '.join(old_types)} → {', '.join(_engagement_types)}. "
            f"New agents available: {agents_str}",
            {"scope_expanded": True, "new_types": new_types,
             "newly_unlocked": newly_unlocked})

        # Notify ST about expanded scope and available agents
        if _active_session_manager and _active_session_manager.is_running:
            st = _active_session_manager.agents.get("ST")
            if st and st.is_running:
                await st.send_command(
                    f"SCOPE EXPANDED by operator approval.\n"
                    f"Engagement now includes: {', '.join(_engagement_types)}\n"
                    f"New agents available: {agents_str}\n"
                    f"You may now request these agents for the newly discovered attack surface."
                )


class ApprovalPayload(BaseModel):
    agent: str
    action: str
    description: str
    risk_level: str = "high"
    target: Optional[str] = None


class AgentRequestPayload(BaseModel):
    """Request body for spawning a worker agent (called by ST via curl)."""
    agent: str
    task: str = ""
    priority: str = "medium"


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
    # BUG-044: Auto-approve in autonomous/CTF mode — no HITL gates
    if _is_autonomous or (_ctf_session and _ctf_session.get("active")):
        synthetic_id = f"auto-{uuid.uuid4().hex[:8]}"
        await _emit("system", payload.agent,
            f"Auto-approved in {'autonomous' if _is_autonomous else 'CTF'} mode: {payload.action}",
            {"auto_approved": True})
        return {
            "ok": True,
            "approved": True,
            "auto_approved": True,
            "reason": "autonomous mode" if _is_autonomous else "ctf mode",
            "approval_id": synthetic_id,
        }

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
    # BUG-044: Return pre-resolved for auto-approved IDs
    if request_id.startswith("auto-"):
        return {"id": request_id, "status": "approved", "approved": True, "auto_approved": True}

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
async def resolve_approval_api(request_id: str, approved: bool, reason: str = ""):
    """Resolve a HITL approval via REST (alternative to WebSocket)."""
    ok = await state.resolve_approval(request_id, approved, reason)
    if not ok:
        return JSONResponse(status_code=404, content={"error": "Approval request not found"})
    # Handle scope expansion approvals
    await _handle_scope_expansion_approval(request_id, approved, reason)
    # H1: Feed HITL decision into Graphiti
    from graphiti_integration import ingest_episode, is_enabled as graphiti_enabled
    if graphiti_enabled() and state.active_engagement_id:
        import asyncio as _asyncio_hitl
        req = state.approval_requests.get(request_id)
        decision_text = (
            f"Operator {'approved' if approved else 'rejected'}: "
            f"{req.description if req else reason}"
        )
        _asyncio_hitl.ensure_future(ingest_episode(
            engagement_id=state.active_engagement_id,
            name=f"hitl_{request_id[:8]}",
            content=decision_text,
            source_description="Operator HITL decision",
        ))
    return {"ok": True}


class FindingPayload(BaseModel):
    title: str
    severity: str
    category: str = "uncategorized"
    target: str = ""
    agent: str = ""
    description: str = ""
    cvss: Optional[float] = None
    cve: Optional[str] = None
    evidence: Optional[str] = None
    engagement: str = "eng-001"
    scan_id: Optional[str] = None  # Link finding to originating scan
    # Explicit relationship hints (optional — extracted from target if not provided)
    host_ip: Optional[str] = None
    service_port: Optional[int] = None
    service_protocol: Optional[str] = "tcp"
    technique_ids: Optional[list[str]] = None
    # BUG-013: VF evidence fields — store PoC output and script for verification
    poc_output: Optional[str] = None
    poc_script: Optional[str] = None


def _normalize_ts(ts):
    """Convert Neo4j DateTime, python datetime, or numeric value to epoch float."""
    if ts is None:
        return None
    if isinstance(ts, (int, float)):
        return float(ts)
    # neo4j.time.DateTime has .to_native() → python datetime
    if hasattr(ts, 'to_native'):
        return ts.to_native().timestamp()
    # python datetime
    if hasattr(ts, 'timestamp'):
        return ts.timestamp()
    return None


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

    # BUG-042 FIX: Validate IP octets are 0-255 and reject version-like strings.
    # "3.2.8.1" (UnrealIRCd version) was being parsed as a host IP.
    octets = host_ip.split(".")
    if not all(0 <= int(o) <= 255 for o in octets):
        return None, None
    # Reject if preceded by version-like context (word char or 'v')
    match_start = ip_match.start()
    if match_start > 0:
        preceding = target[max(0, match_start - 2):match_start]
        if preceding.rstrip().endswith(('v', 'V')) or (preceding and preceding[-1].isalpha()):
            return None, None

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


# BUG-NEW-008: Validate extracted host so version strings like "3.2.8.1"
# from "UnrealIRCd 3.2.8.1 Backdoor" are not counted as hosts.
_VALID_IP_RE = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')


def _is_version_string_ip(ip: str) -> bool:
    """Return True if the IP looks like a version string (all octets < 20).
    Version strings like '3.2.8.1' (UnrealIRCd) are created directly as Host
    nodes by MCP tools, bypassing _safe_extract_host. This filter catches them
    at query result time. (BUG-036)"""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(int(p) < 20 for p in parts)
    except ValueError:
        return False


def _safe_extract_host(raw: str) -> str:
    """Extract and validate hostname/IP from a finding target string.
    Returns empty string if the result is not a plausible host."""
    if not raw:
        return ""
    raw = raw.strip()
    if raw.startswith(("http://", "https://")):
        from urllib.parse import urlparse
        host = urlparse(raw).hostname or ""
    else:
        host = raw.split(":")[0].split("/")[0].strip()

    # Validate: if it looks like an IP, all octets must be 0-255
    m = _VALID_IP_RE.match(host)
    if m:
        if all(0 <= int(g) <= 255 for g in m.groups()):
            # BUG-036: Reject version strings masquerading as IPs
            # (e.g., "3.2.8.1" for UnrealIRCd). Real target IPs have
            # at least one octet >= 20.
            if all(int(g) < 20 for g in m.groups()):
                return ""
            # BUG-040: Reject Kali backend IPs — never register attack box as target
            if host in _KALI_BACKEND_IPS:
                return ""
            return host
        return ""

    # For hostnames: must have no spaces and at least 1 non-digit char
    if host and " " not in host and not host.replace(".", "").isdigit():
        return host

    return ""


# ── BUG-013: Finding Deduplication ────────────────────────

_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_STATUS_RANK = {"open": 0, "discovered": 1, "confirmed": 2}


def _compute_finding_fingerprint(
    engagement_id: str, title: str, target: str,
    cve: str | None, host_ip: str | None, service_port: int | None,
) -> str:
    """Compute a stable fingerprint for finding deduplication.

    Strategy 1 (CVE-based): engagement + CVE + host_ip + port — strongest match.
    Strategy 2 (title-based): engagement + normalized_title + target — fallback.
    Returns 16-char hex digest (collision probability ~1 in 2^64).
    """
    title_norm = " ".join(title.lower().split())
    if cve and host_ip and service_port:
        key = f"{engagement_id}|{cve.upper()}|{host_ip}|{service_port}"
    else:
        target_norm = (target or "").lower().strip()
        cve_norm = (cve or "").upper().strip()
        key = f"{engagement_id}|{title_norm}|{target_norm}|{cve_norm}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


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

    # BUG-038 FIX: Reject finding titles that look like API errors, not vulnerabilities.
    # Agents sometimes pass raw HTTP error responses as finding titles.
    _title = (payload.title or "").strip()
    _ERROR_PATTERNS = [
        "<html", "<!doctype", "502 bad gateway", "503 service unavailable",
        "504 gateway timeout", "500 internal server error", "connection refused",
        "connection timed out", "errno", "traceback (most recent call last)",
        '{"error":', "api validation error", "failed to fetch",
    ]
    _title_lower = _title.lower()
    if any(pat in _title_lower for pat in _ERROR_PATTERNS):
        return JSONResponse(
            status_code=422,
            content={"error": f"Rejected: title looks like an API error, not a vulnerability: {_title[:100]}"}
        )
    if len(_title) < 5:
        return JSONResponse(
            status_code=422,
            content={"error": "Finding title too short (min 5 characters)"}
        )

    # FIX: Auto-detect agent when not provided
    if not payload.agent:
        _exploit_keywords = ('exploit', 'shell', 'rce', 'backdoor', 'root', 'command execution',
                             'code execution', 'injection', 'bypass', 'meterpreter', 'reverse shell')
        _recon_keywords = ('open port', 'scan', 'discovered', 'fingerprint', 'banner')
        _analysis_keywords = ('cve research', 'cvss', 'debrief', 'hypothesis', 'analysis')
        if any(kw in _title_lower for kw in _exploit_keywords):
            payload.agent = "EX"
        elif any(kw in _title_lower for kw in _recon_keywords):
            payload.agent = "AR"
        elif any(kw in _title_lower for kw in _analysis_keywords):
            payload.agent = "DA"
        else:
            payload.agent = "EX"  # Default to EX for unclassified exploitation findings

    timestamp = time.time()

    # Write to Neo4j if available — smart endpoint auto-creates relationships
    # Pattern: MERGE nodes individually, then MERGE relationships (BloodHound pattern)
    host_ip = payload.host_ip or _extract_host_port(payload.target)[0]
    svc_port = payload.service_port or _extract_host_port(payload.target)[1]
    svc_proto = payload.service_protocol or "tcp"

    # BUG-013: Compute fingerprint for deduplication
    fingerprint = _compute_finding_fingerprint(
        payload.engagement, payload.title, payload.target,
        payload.cve, host_ip, svc_port,
    )

    # BUG-013: Check for existing finding with same fingerprint
    existing = None
    if neo4j_available and neo4j_driver:
        def _check_existing():
            with neo4j_driver.session() as session:
                result = session.run("""
                    MATCH (f:Finding {fingerprint: $fp, engagement_id: $eid})
                    RETURN f.id AS id, f.severity AS severity,
                           f.status AS status, f.evidence AS evidence
                    LIMIT 1
                """, fp=fingerprint, eid=payload.engagement)
                record = result.single()
                return dict(record) if record else None
        try:
            existing = await neo4j_exec(_check_existing)
        except Exception:
            existing = None

    # Also check in-memory state for non-Neo4j dedup
    if not existing:
        for f in state.findings:
            if getattr(f, "fingerprint", None) == fingerprint \
               and f.engagement == payload.engagement:
                existing = {
                    "id": f.id,
                    "severity": f.severity.value if isinstance(f.severity, Enum) else f.severity,
                    "status": "open",
                    "evidence": f.evidence,
                }
                break

    # BUG-013: Merge into existing finding if duplicate detected
    if existing:
        finding_id = existing["id"]
        old_sev = _SEV_RANK.get((existing.get("severity") or "info").lower(), 0)
        new_sev = _SEV_RANK.get(payload.severity.lower(), 0)
        merged_severity = payload.severity if new_sev > old_sev else (
            existing.get("severity") or payload.severity)

        # BUG-013: Only auto-confirm VF findings that include evidence
        if payload.agent == "VF":
            has_evidence = len(payload.description or '') > 100  # Real evidence is substantial
            if has_evidence:
                new_status = "confirmed"
                # Store VF's output as evidence if not already set
                if not payload.evidence and payload.poc_output:
                    payload.evidence = payload.poc_output
            else:
                new_status = "discovered"
        else:
            new_status = "discovered"
        old_status = existing.get("status", "open")
        merged_status = new_status if _STATUS_RANK.get(new_status, 0) > \
            _STATUS_RANK.get(old_status, 0) else old_status

        # BUG-017: Set confirmed_at when status upgrades to confirmed during merge
        merge_confirmed_at = None
        if merged_status == "confirmed" and old_status != "confirmed":
            merge_confirmed_at = timestamp

        old_evidence = existing.get("evidence") or ""
        new_evidence = payload.evidence or ""
        if new_evidence and new_evidence not in old_evidence:
            merged_evidence = (f"{old_evidence}\n---\n[{payload.agent}] {new_evidence}"
                               if old_evidence else new_evidence)
        else:
            merged_evidence = old_evidence

        if neo4j_available and neo4j_driver:
            def _update_existing():
                with neo4j_driver.session() as session:
                    cypher = """
                        MATCH (f:Finding {id: $id})
                        SET f.severity = $severity, f.status = $status,
                            f.evidence = $evidence, f.last_updated = $timestamp,
                            f.contributing_agents =
                                coalesce(f.contributing_agents, []) + $agent
                    """
                    params = dict(id=finding_id, severity=merged_severity,
                         status=merged_status, evidence=merged_evidence,
                         timestamp=timestamp, agent=[payload.agent])
                    if merge_confirmed_at is not None:
                        cypher += ", f.confirmed_at = $confirmed_at"
                        params["confirmed_at"] = merge_confirmed_at
                    session.run(cypher, **params)
            try:
                await neo4j_exec(_update_existing)
            except Exception as e:
                print(f"Neo4j finding merge error: {e}")

        # Update in-memory state
        for f in state.findings:
            if f.id == finding_id:
                if new_sev > old_sev:
                    f.severity = Severity(merged_severity)
                if new_evidence and new_evidence not in (f.evidence or ""):
                    f.evidence = merged_evidence
                if merge_confirmed_at is not None and not f.confirmed_at:
                    f.confirmed_at = merge_confirmed_at
                break

        # Broadcast update so dashboard reflects the merge
        await state.broadcast({
            "type": "finding_updated",
            "finding_id": finding_id,
            "severity": merged_severity,
            "status": merged_status,
            "agent": payload.agent,
            "deduplicated": True,
            "timestamp": timestamp,
        })

        return {
            "ok": True,
            "finding_id": finding_id,
            "deduplicated": True,
            "severity_upgraded": new_sev > old_sev,
            "status": merged_status,
            "message": f"Merged with existing finding {finding_id} (fingerprint match)",
        }

    # No duplicate — create new finding
    finding_id = str(uuid.uuid4())[:8]

    # BUG-003: Auto-estimate CVSS from severity when agent doesn't provide one
    if not payload.cvss:
        _cvss_from_severity = {
            "critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.0,
        }
        payload.cvss = _cvss_from_severity.get(sev, 5.0)

    if neo4j_available and neo4j_driver:
        def _write_finding():
            with neo4j_driver.session() as session:
                # Step 1: Create Finding node with fingerprint
                session.run("""
                    MERGE (f:Finding {fingerprint: $fingerprint, engagement_id: $engagement})
                    ON CREATE SET f.id = $id, f.discovered_at = $discovered_at, f.status = 'open'
                    SET f.title = $title, f.severity = $severity,
                        f.category = $category, f.target = $target,
                        f.agent = $agent, f.description = $description,
                        f.cvss = $cvss, f.cve = $cve, f.evidence = $evidence,
                        f.timestamp = $timestamp, f.engagement_id = $engagement,
                        f.fingerprint = $fingerprint
                """, id=finding_id, title=payload.title,
                     severity=payload.severity, category=payload.category,
                     target=payload.target, agent=payload.agent,
                     description=payload.description, cvss=payload.cvss,
                     cve=payload.cve, evidence=payload.evidence,
                     timestamp=timestamp, engagement=payload.engagement,
                     fingerprint=fingerprint, discovered_at=timestamp)

                # Step 2: Auto-create Host + FOUND_ON edge (MERGE = idempotent)
                if host_ip:
                    session.run("""
                        MERGE (h:Host {ip: $host_ip, engagement_id: $engagement})
                        ON CREATE SET
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
                        MERGE (h:Host {ip: $host_ip, engagement_id: $engagement})
                        MERGE (s:Service {host_ip: $host_ip, port: $port, engagement_id: $engagement})
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

                # Step 4: Link Finding to originating Scan (Fix 5b)
                if payload.scan_id:
                    session.run(
                        "MATCH (s:Scan {id: $sid}), (f:Finding {id: $fid}) "
                        "MERGE (s)-[:HAS_FINDING]->(f)",
                        sid=payload.scan_id, fid=finding_id
                    )
                    session.run(
                        "MATCH (s:Scan {id: $sid}) "
                        "SET s.findings_count = coalesce(s.findings_count, 0) + 1",
                        sid=payload.scan_id
                    )
        try:
            await neo4j_exec(_write_finding)
        except Exception as e:
            print(f"Neo4j finding write error: {e}")

    # BUG-013: For new VF findings, only auto-confirm when evidence is substantial
    vf_confirmed_at = None
    if payload.agent == "VF":
        has_evidence = len(payload.description or '') > 100  # Real evidence is substantial
        if has_evidence:
            vf_confirmed_at = timestamp
            # Store VF's poc_output as evidence if evidence field is empty
            if not payload.evidence and payload.poc_output:
                payload.evidence = payload.poc_output

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
        fingerprint=fingerprint,
        discovered_at=timestamp,
        confirmed_at=vf_confirmed_at,
    )
    await state.add_finding(finding)

    # Fix 3: for new VF findings confirmed at creation, write confirmed_at to Neo4j
    if vf_confirmed_at is not None and neo4j_available and neo4j_driver:
        _fid_confirm = finding_id
        _ts_confirm = vf_confirmed_at
        def _confirm_new_vf_finding():
            with neo4j_driver.session() as session:
                session.run("""
                    MATCH (f:Finding {id: $id})
                    SET f.status = 'confirmed', f.confirmed_at = $confirmed_at
                """, id=_fid_confirm, confirmed_at=_ts_confirm)
        try:
            await neo4j_exec(_confirm_new_vf_finding)
        except Exception as e:
            print(f"Neo4j VF confirm write error: {e}")

    # H1: Feed finding into Graphiti for cross-session memory
    from graphiti_integration import ingest_episode, is_enabled as graphiti_enabled
    if graphiti_enabled():
        import asyncio as _asyncio_h1
        finding_text = (
            f"Finding: {payload.title}\nSeverity: {payload.severity}\n"
            f"Description: {payload.description}\nAffected: {payload.target}\n"
            f"Remediation: {payload.remediation if hasattr(payload, 'remediation') and payload.remediation else 'TBD'}"
        )
        eid_h1 = payload.engagement or state.active_engagement_id
        if eid_h1:
            _asyncio_h1.ensure_future(ingest_episode(
                engagement_id=eid_h1,
                name=f"finding_{finding_id}",
                content=finding_text[:4000],
                source_description="Confirmed finding",
            ))

    # Auto-queue HIGH/CRITICAL findings for VF verification (F3 pipeline)
    await _auto_queue_verification(finding_id, payload.severity, payload.engagement)

    # Fix 5b: Increment in-memory scan findings_count when scan_id provided
    if payload.scan_id:
        for scan in state.scans:
            if scan["id"] == payload.scan_id:
                scan["findings_count"] = scan.get("findings_count", 0) + 1
                break

    # Broadcast stat_update so KPI cards update in real-time
    eid = payload.engagement or state.active_engagement_id
    if eid:
        eng_findings = [f for f in state.findings if f.engagement == eid]
        # Count unique hosts from findings targets
        hosts = set()
        for f in eng_findings:
            if f.target:
                host = _safe_extract_host(f.target)
                if host:
                    hosts.add(host)
        # Extract unique ports from finding targets for Open Ports KPI
        import re as _re_p
        ports = set()
        for f in eng_findings:
            target = f.target or ""
            pm = _re_p.search(r':(\d+)', target)
            if pm:
                pn = int(pm.group(1))
                if 1 <= pn <= 65535:
                    ports.add(pn)
        await state.broadcast({
            "type": "stat_update",
            "hosts": len(hosts),
            "findings": len(eng_findings),
            "services": len(ports),
            "vulns": len([f for f in eng_findings if f.severity.value in ("critical", "high")]),
            "timestamp": time.time(),
        })

    return {"ok": True, "finding_id": finding_id}


@app.get("/api/kpi/mtte")
async def get_mtte(engagement: Optional[str] = None):
    """BUG-017: Mean Time to Exploit — average seconds from discovery to confirmation.
    Reads from Neo4j first (survives restart), falls back to in-memory state.
    Optional `engagement` query param scopes the Cypher query to a specific engagement."""
    deltas = []
    # Try Neo4j first — persisted data survives server restarts
    if neo4j_available and neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                if engagement:
                    result = session.run("""
                        MATCH (f:Finding)
                        WHERE f.discovered_at IS NOT NULL AND f.confirmed_at IS NOT NULL
                          AND f.engagement_id = $engagement_id
                        RETURN f.discovered_at AS d, f.confirmed_at AS c
                    """, engagement_id=engagement)
                else:
                    result = session.run("""
                        MATCH (f:Finding)
                        WHERE f.discovered_at IS NOT NULL AND f.confirmed_at IS NOT NULL
                        RETURN f.discovered_at AS d, f.confirmed_at AS c
                    """)
                for rec in result:
                    d, c = rec["d"], rec["c"]
                    if d and c and c > d:
                        deltas.append(c - d)
        except Exception:
            pass
    # Fall back to in-memory findings
    if not deltas:
        findings_scope = [f for f in state.findings if not engagement or f.engagement == engagement]
        for f in findings_scope:
            d = getattr(f, "discovered_at", None)
            c = getattr(f, "confirmed_at", None)
            if d and c:
                deltas.append(c - d)
    if not deltas:
        return {"mtte_seconds": None, "mtte_display": "\u2014", "sample_size": 0}
    avg = sum(deltas) / len(deltas)
    mins = int(avg // 60)
    secs = int(avg % 60)
    display = f"{mins}m {secs}s" if mins > 0 else f"{secs}s"
    return {"mtte_seconds": round(avg, 2), "mtte_display": display, "sample_size": len(deltas)}


@app.get("/api/experience-brief/{agent_code}")
async def get_experience_brief(agent_code: str):
    """CEI-3: Return condensed experience brief from past engagements for agent context injection."""
    if not neo4j_available or not neo4j_driver:
        return {"brief": "", "techniques": 0}

    try:
        with neo4j_driver.session() as session:
            # Top techniques by success rate (min 3 attempts)
            top_result = session.run("""
                MATCH (t:TechniqueRecord)
                WHERE t.success_rate > 0.3 AND t.total_attempts >= 3
                RETURN t.key AS key, t.tool AS tool, t.success_rate AS rate,
                       t.avg_duration_s AS dur, t.total_attempts AS attempts
                ORDER BY t.success_rate DESC, t.avg_duration_s ASC
                LIMIT 15
            """)
            top_techniques = [dict(r) for r in top_result]

            # Known false positives
            fp_result = session.run("""
                MATCH (fp:FalsePositiveRecord)
                WHERE fp.fp_rate > 0.7 AND fp.total_attempts >= 3
                RETURN fp.key AS key, fp.tool AS tool, fp.common_trigger AS trigger
                LIMIT 10
            """)
            false_positives = [dict(r) for r in fp_result]

            # Experience stats
            stats_result = session.run("""
                MATCH (t:TechniqueRecord)
                RETURN count(t) AS techniques, sum(t.total_attempts) AS total_runs
            """)
            stats = dict(stats_result.single())

        # Build markdown brief
        lines = []
        tech_count = stats.get("techniques") or 0
        run_count = stats.get("total_runs") or 0

        if tech_count == 0:
            return {"brief": "No prior engagement data yet. This is ATHENA's first run.", "techniques": 0}

        lines.append(f"ATHENA has data from {tech_count} techniques across {run_count} tool executions.\n")

        if top_techniques:
            lines.append("**High-confidence techniques (try first):**")
            for t in top_techniques:
                rate_pct = round((t["rate"] or 0) * 100)
                dur = round(t.get("dur") or 0)
                lines.append(f"- {t['key']} — {rate_pct}% success ({t['attempts']} runs, ~{dur}s avg)")

        if false_positives:
            lines.append("\n**Known false positives (skip these):**")
            for fp in false_positives:
                lines.append(f"- {fp['key']} — {fp.get('trigger', 'unknown trigger')}")

        brief = "\n".join(lines)
        return {"brief": brief, "techniques": tech_count}
    except Exception as e:
        logger.warning("CEI experience brief: %s", e)
        return {"brief": "", "techniques": 0}


# ── CEI Dashboard API Endpoints ──────────────────────────────

@app.get("/api/cei/techniques")
async def get_cei_techniques():
    """Return all TechniqueRecord nodes for Intelligence dashboard."""
    if not neo4j_available or not neo4j_driver:
        return {"techniques": [], "available": False}
    try:
        with neo4j_driver.session() as session:
            result = session.run("""
                MATCH (t:TechniqueRecord)
                OPTIONAL MATCH (t)-[:USED_IN]->(e:Engagement)
                RETURN t.key AS key, t.tool AS tool, t.agent AS agent,
                       t.total_attempts AS attempts, t.successes AS successes,
                       t.failures AS failures, t.success_rate AS success_rate,
                       t.avg_duration_s AS avg_duration, t.avg_cost_usd AS avg_cost,
                       toString(t.last_used) AS last_used, t.last_engagement_id AS last_eid,
                       collect(DISTINCT e.id) AS engagement_ids
                ORDER BY t.total_attempts DESC
            """)
            techniques = [dict(r) for r in result]
        return {"techniques": techniques, "available": True}
    except Exception as e:
        logger.warning("CEI techniques endpoint: %s", e)
        return {"techniques": [], "available": False, "error": "Query failed"}


@app.get("/api/cei/false-positives")
async def get_cei_false_positives():
    """Return all FalsePositiveRecord nodes for Intelligence dashboard."""
    if not neo4j_available or not neo4j_driver:
        return {"false_positives": [], "available": False}
    try:
        with neo4j_driver.session() as session:
            result = session.run("""
                MATCH (fp:FalsePositiveRecord)
                RETURN fp.key AS key, fp.tool AS tool, fp.fp_rate AS fp_rate,
                       fp.total_attempts AS attempts, fp.common_trigger AS trigger
                ORDER BY fp.fp_rate DESC
            """)
            fps = [dict(r) for r in result]
        return {"false_positives": fps, "available": True}
    except Exception as e:
        logger.warning("CEI false-positives endpoint: %s", e)
        return {"false_positives": [], "available": False, "error": "Query failed"}


@app.get("/api/cei/engagement-history")
async def get_cei_engagement_history():
    """Return per-engagement stats for Intelligence trend charts."""
    if not neo4j_available or not neo4j_driver:
        return {"engagements": [], "available": False}
    try:
        with neo4j_driver.session() as session:
            result = session.run("""
                MATCH (e:Engagement)
                OPTIONAL MATCH (f:Finding {engagement_id: e.id})
                OPTIONAL MATCH (t:TechniqueRecord)-[:USED_IN]->(e)
                RETURN e.id AS id, e.target AS target, e.status AS status,
                       e.engagement_cost AS cost, e.created_at AS created,
                       count(DISTINCT f) AS findings_count,
                       count(DISTINCT t) AS techniques_used,
                       avg(t.success_rate) AS avg_success_rate
                ORDER BY e.created_at DESC
                LIMIT 20
            """)
            engagements = [dict(r) for r in result]
        return {"engagements": engagements, "available": True}
    except Exception as e:
        logger.warning("CEI engagement history: %s", e)
        return {"engagements": [], "available": False, "error": "Query failed"}


@app.delete("/api/cei")
async def clear_all_cei():
    """Delete ALL cross-engagement intelligence data (TechniqueRecords, FalsePositiveRecords, USED_IN relationships)."""
    deleted = {"techniques": 0, "false_positives": 0}
    if not neo4j_available or not neo4j_driver:
        return JSONResponse(status_code=503, content={"error": "Neo4j unavailable"})
    try:
        with neo4j_driver.session() as session:
            t_result = session.run("MATCH (t:TechniqueRecord) DETACH DELETE t RETURN count(t) AS cnt")
            deleted["techniques"] = t_result.single()["cnt"]
            fp_result = session.run("MATCH (fp:FalsePositiveRecord) DETACH DELETE fp RETURN count(fp) AS cnt")
            deleted["false_positives"] = fp_result.single()["cnt"]
        print(f"[DELETE] CEI cleared: {deleted['techniques']} techniques, {deleted['false_positives']} false positives")
        return {"ok": True, "deleted": deleted}
    except Exception as e:
        print(f"CEI clear error: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})


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
    CODE_REVIEW = "code_review"                # DA agent confirms in source
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

    # BUG-032 FIX: Skip if this finding already has a completed verification.
    # VF was re-verifying confirmed findings in an infinite loop, creating duplicates
    # and blocking RP from ever spawning.
    existing_vrfs = _finding_verifications.get(req.finding_id, [])
    for vrf_id in existing_vrfs:
        vrf = _verifications.get(vrf_id, {})
        if vrf.get("final_status") in ("confirmed", "false_positive", "inconclusive"):
            return {
                "ok": True,
                "verification_id": vrf_id,
                "finding_id": req.finding_id,
                "already_verified": True,
                "final_status": vrf.get("final_status"),
                "message": f"Finding already verified as {vrf.get('final_status')} (verification {vrf_id})",
            }

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

    # Update VF agent status — IDLE not RUNNING: actual RUNNING set by _spawn_agent
    # after the SDK session starts. Premature RUNNING masks the silent-session bug.
    await state.update_agent_status("VF", AgentStatus.IDLE,
        f"Verification queued: {finding.title}")

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

    # BUG-NEW-013: Require evidence for confirmed findings
    if result.status == "confirmed":
        if not getattr(result, 'poc_output', None) and not getattr(result, 'poc_script', None):
            return JSONResponse(status_code=422, content={
                "error": "Confirmed findings require poc_output and poc_script. "
                         "A confirmation without reproduction evidence is not permitted."
            })

    # BUG-010: Ensure verification_id from path is in the result object
    if not result.verification_id or result.verification_id != verification_id:
        result.verification_id = verification_id

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

    # BUG-017: Set confirmed_at on in-memory finding when status is confirmed
    confirmed_ts = None
    if result.status == "confirmed":
        confirmed_ts = time.time()
        for f in state.findings:
            if f.id == result.finding_id and not f.confirmed_at:
                f.confirmed_at = confirmed_ts
                break

    # Auto-capture screenshot for confirmed findings (fire-and-forget)
    if result.status == "confirmed":
        _finding_target = None
        for f in state.findings:
            if f.id == result.finding_id:
                _finding_target = getattr(f, 'target', None)
                break
        if _finding_target and kali_client:
            async def _auto_screenshot():
                try:
                    import base64
                    import io as _io
                    url = _finding_target if _finding_target.startswith(('http://', 'https://')) else f'http://{_finding_target}'
                    client = await kali_client._get_client()
                    # Try each available backend until one succeeds
                    for name, backend in kali_client.backends.items():
                        if not backend.available:
                            continue
                        try:
                            resp = await client.post(
                                f"{backend.base_url}/api/tools/screenshot",
                                json={"url": url},
                                timeout=15,
                            )
                            if resp.status_code == 200:
                                data = resp.json()
                                image_b64 = data.get("image_b64") or data.get("image") or data.get("screenshot")
                                if image_b64:
                                    image_bytes = base64.b64decode(image_b64)
                                    dashboard_base = _DASHBOARD_URL if '_DASHBOARD_URL' in globals() and _DASHBOARD_URL else "http://localhost:8080"
                                    upload_resp = await client.post(
                                        f"{dashboard_base}/api/artifacts",
                                        data={
                                            "finding_id": result.finding_id,
                                            "engagement_id": v.get("engagement_id", ""),
                                            "type": "screenshot",
                                            "caption": f"Auto-captured VF confirmation — {_finding_target}",
                                            "agent": "VF",
                                            "capture_mode": "exploitable",
                                        },
                                        files={"file": (f"vf-{result.finding_id[:8]}.png", _io.BytesIO(image_bytes), "image/png")},
                                    )
                                    logger.info("Auto-screenshot captured for finding %s", result.finding_id)
                                    break
                        except Exception as e:
                            logger.warning("Screenshot from backend %s failed: %s", name, str(e)[:100])
                except Exception as e:
                    logger.warning("Auto-screenshot task failed: %s", str(e)[:100])
            asyncio.ensure_future(_auto_screenshot())

    # Update Neo4j Finding node with verification data
    if neo4j_available and neo4j_driver and result.status in ("confirmed", "likely"):
        confirmed_at_val = confirmed_ts if result.status == "confirmed" else None
        def _update_verification():
            with neo4j_driver.session() as session:
                cypher = """
                    MATCH (f:Finding {id: $finding_id})
                    SET f.verified = $verified,
                        f.verification_status = $status,
                        f.confidence = $confidence,
                        f.poc_script = $poc_script,
                        f.impact_demonstrated = $impact,
                        f.verification_id = $vrf_id,
                        f.verified_at = datetime()
                """
                if confirmed_at_val is not None:
                    cypher += ", f.confirmed_at = $confirmed_at"
                session.run(cypher,
                     finding_id=result.finding_id,
                     verified=result.status == "confirmed",
                     status=result.status,
                     confidence=result.confidence,
                     poc_script=result.poc_script,
                     impact=result.impact_demonstrated,
                     vrf_id=verification_id,
                     confirmed_at=confirmed_at_val)
        try:
            await neo4j_exec(_update_verification)
        except Exception as e:
            print(f"Neo4j verification update error: {e}")

        # Create EvidencePackage node from verification result
        ep_id = f"ep-{uuid.uuid4().hex[:8]}"
        ep_data = result.evidence_package or {}
        def _create_evidence_package():
            with neo4j_driver.session() as session:
                session.run("""
                    MERGE (ep:EvidencePackage {id: $ep_id})
                    SET ep.engagement_id = $eid,
                        ep.type = $method,
                        ep.verification_method = $method,
                        ep.confidence = $confidence,
                        ep.status = $status,
                        ep.verified_by = $agent,
                        ep.http_pairs = $http_pairs,
                        ep.output_evidence = $output_evidence,
                        ep.response_diff = $response_diff,
                        ep.poc_script = $poc_script,
                        ep.poc_output = $poc_output,
                        ep.impact_demonstrated = $impact,
                        ep.notes = $notes,
                        ep.timestamp = datetime()
                    WITH ep
                    MATCH (f:Finding {id: $finding_id})
                    MERGE (f)-[:EVIDENCED_BY]->(ep)
                """,
                ep_id=ep_id,
                eid=v.get("engagement_id", ""),
                method=result.method,
                confidence=str(result.confidence),
                status=result.status,
                agent=f"VF/{verification_id[:8]}",
                http_pairs=ep_data.get("http_pairs"),
                output_evidence=ep_data.get("output_evidence") or result.poc_output,
                response_diff=ep_data.get("response_diff"),
                poc_script=result.poc_script,
                poc_output=result.poc_output,
                impact=result.impact_demonstrated,
                notes=result.notes,
                finding_id=result.finding_id)
        try:
            await neo4j_exec(_create_evidence_package)
        except Exception as e:
            print(f"Neo4j EvidencePackage create error: {e}")

        # Create EXPLOITS relationship when finding is confirmed or likely
        normalized_status = result.status.lower().strip()
        if normalized_status in ("confirmed", "likely"):
            def _create_exploits_edge():
                with neo4j_driver.session() as session:
                    # Try direct AFFECTS→Service first
                    r = session.run("""
                        MATCH (f:Finding {id: $fid})-[:AFFECTS]->(s:Service)
                        MERGE (f)-[:EXPLOITS]->(s)
                        RETURN count(*) AS c
                    """, fid=result.finding_id)
                    if r.single()["c"] == 0:
                        # Fallback: FOUND_ON→Host→HAS_SERVICE→Service
                        r2 = session.run("""
                            MATCH (f:Finding {id: $fid})-[:FOUND_ON]->(h:Host)-[:HAS_SERVICE]->(s:Service)
                            WITH f, head(collect(s)) AS svc
                            WHERE svc IS NOT NULL
                            MERGE (f)-[:EXPLOITS]->(svc)
                            RETURN count(*) AS c
                        """, fid=result.finding_id)
                        if r2.single()["c"] == 0:
                            # Path 3: BUG-039 — fallback to Host when no Service exists
                            # Mirrors startup backfill COALESCE(s2, s, h) pattern
                            r3 = session.run("""
                                MATCH (f:Finding {id: $fid})-[:FOUND_ON]->(h:Host)
                                WITH f, head(collect(h)) AS host
                                WHERE host IS NOT NULL
                                MERGE (f)-[:EXPLOITS]->(host)
                                RETURN count(*) AS created
                            """, fid=result.finding_id)
                            if r3.single()["created"] == 0:
                                # Path 4: Last resort — link to any Host in the same engagement
                                session.run("""
                                    MATCH (f:Finding {id: $fid})
                                    WHERE NOT (f)-[:EXPLOITS]->()
                                      AND f.engagement_id IS NOT NULL
                                    MATCH (h:Host {engagement_id: f.engagement_id})
                                    WITH f, head(collect(h)) AS host
                                    WHERE host IS NOT NULL
                                    MERGE (f)-[:EXPLOITS]->(host)
                                    RETURN count(*) AS created
                                """, fid=result.finding_id)
            try:
                await neo4j_exec(_create_exploits_edge)
            except Exception as e:
                print(f"Neo4j EXPLOITS edge error: {e}")

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

    # Fix 2: propagate confirmed_at into in-memory Finding
    _canary_confirmed_ts = time.time()
    for f in state.findings:
        if f.id == v["finding_id"] and not f.confirmed_at:
            f.confirmed_at = _canary_confirmed_ts
            break

    # Update Neo4j
    if neo4j_available and neo4j_driver:
        _finding_id = v["finding_id"]
        _impact = canary_result.impact_demonstrated
        def _update_canary():
            with neo4j_driver.session() as session:
                session.run("""
                    MATCH (f:Finding {id: $finding_id})
                    SET f.verified = true,
                        f.verification_status = 'confirmed',
                        f.confidence = 0.95,
                        f.canary_callback = true,
                        f.impact_demonstrated = $impact,
                        f.verified_at = datetime(),
                        f.confirmed_at = $confirmed_at
                """, finding_id=_finding_id,
                     impact=_impact,
                     confirmed_at=time.time())
        try:
            await neo4j_exec(_update_canary)
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
    """A single CTF challenge — from benchmark, agent discovery, or manual."""
    id: str = ""  # Auto-generated if not provided
    name: str
    category: CTFCategory = CTFCategory.WEB
    difficulty: int = 1              # 1-3 (XBOW scale)
    points: int = 0
    description: str = ""
    url: Optional[str] = None       # Challenge URL (for web challenges)
    engagement_id: str = "eng-001"
    files: Optional[list[str]] = None  # Downloadable files
    hints: Optional[list[str]] = None  # Unlocked hints
    tags: list[str] = []             # Vuln tags: sqli, xss, ssrf, etc.
    status: ChallengeStatus = ChallengeStatus.UNSOLVED
    flag: Optional[str] = None       # Captured flag value
    solved_by: Optional[str] = None  # Agent that solved it
    solved_at: Optional[float] = None
    tool_calls: int = 0              # Track tool call count for early-stopping
    assigned_agent: Optional[str] = None  # Agent currently working on it
    attempts: int = 0
    time_spent_sec: float = 0.0
    cost_usd: float = 0.0


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


# Common CTF flag patterns (compiled once).
#
# Ordering rationale — most specific first, then general fallbacks:
#   1. XBOW-specific: exact 64-hex SHA-256 digest inside FLAG{...} — matched
#      before the general FLAG/flag IGNORECASE rule so XBOW flags are
#      classified correctly without being swallowed by the catch-all.
#   2. Platform-specific prefixes (CTF, picoCTF, HTB, THM, OWASP, gflag,
#      0xL4BS) — narrower than the final IGNORECASE catch-all.
#   3. SANS-style dash format — no braces, kept near the end.
#   4. General IGNORECASE flag{...} — broadest, must be last to avoid
#      shadowing every entry above it.
#
# Note: FLAG_PATTERNS are tried in order; the FIRST match wins, so keep the
# more specific patterns at the top of the list.
FLAG_PATTERNS = [
    re.compile(r"FLAG\{[a-fA-F0-9]{64}\}"),          # XBOW benchmark (SHA-256, 64 lowercase or uppercase hex chars)
    re.compile(r"CTF\{[^}]+\}", re.IGNORECASE),       # Generic CTF{} prefix
    re.compile(r"picoCTF\{[^}]+\}"),                  # picoCTF platform
    re.compile(r"HTB\{[^}]+\}"),                      # HackTheBox
    re.compile(r"THM\{[^}]+\}"),                      # TryHackMe
    re.compile(r"OWASP\{[^}]+\}"),                    # OWASP challenges
    re.compile(r"gflag\{[^}]+\}", re.IGNORECASE),     # Google CTF / gCTF framework
    re.compile(r"0xL4BS\{[^}]+\}"),                   # ZeroK Labs internal CTFs
    re.compile(r"FLAG-[A-Za-z0-9\-]+"),               # SANS-style dash format (no braces)
    re.compile(r"flag\{[^}]+\}", re.IGNORECASE),      # General catch-all: flag{...} any case
]

# Max tool calls before pivoting to next challenge
CTF_EARLY_STOP_THRESHOLD = 40

# Category-specific agent assignments
CTF_CATEGORY_AGENTS: dict[str, list[str]] = {
    "web":       ["WV", "DA", "EX"],
    "crypto":    ["DA", "EX"],
    "forensics": ["AR", "DA"],
    "reverse":   ["DA", "EX"],
    "pwnable":   ["EX", "DA"],
    "misc":      ["AR", "DA"],
    "osint":     ["PR", "AR"],
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


@app.get("/api/ctf/challenges")
async def list_ctf_challenges(engagement_id: str = ""):
    """List all challenges in the active CTF session."""
    if not _ctf_session or not _ctf_session["active"]:
        return {"challenges": [], "count": 0, "message": "No active CTF session"}
    challenges = list(_ctf_session["challenges"].values())
    return {"challenges": challenges, "count": len(challenges)}


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

    # Auto-generate ID if not provided
    if not challenge.id:
        challenge.id = f"ctf-{uuid.uuid4().hex[:8]}"

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
    agents = CTF_CATEGORY_AGENTS.get(challenge.category.value, ["DA"])
    ch["assigned_agent"] = agents[0] if agents else "DA"

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
        agents = CTF_CATEGORY_AGENTS.get(challenge.category.value, ["DA"])
        ch["assigned_agent"] = agents[0] if agents else "DA"
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
        _cid = challenge_id
        _ch_name = ch["name"]
        _ch_cat = ch["category"]
        _ch_pts = ch["points"]
        _eid = _ctf_session["engagement_id"]
        def _write_ctf_flag():
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
                """, cid=_cid, name=_ch_name,
                     category=_ch_cat, points=_ch_pts,
                     flag=flag, agent=agent,
                     eid=_eid)
        try:
            await neo4j_exec(_write_ctf_flag)
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


@app.post("/api/ctf/benchmark/load")
async def load_benchmark(file_path: str, engagement_id: str = "eng-001"):
    """Load challenges from XBOW-format benchmark.json.

    Expected format per challenge:
      {"name": "XBEN-001", "description": "...", "difficulty": 2,
       "tags": ["sqli"], "port": 8001}

    The benchmark runner (external script) handles Docker compose up/down.
    This endpoint just loads the challenge metadata into ATHENA's CTF state.
    """
    bench_path = Path(file_path)
    if not bench_path.exists():
        return JSONResponse(status_code=404, content={
            "error": f"Benchmark file not found: {file_path}"
        })

    try:
        data = json.loads(bench_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        return JSONResponse(status_code=400, content={
            "error": f"Failed to parse benchmark file: {e}"
        })

    # Accept both {"challenges": [...]} and bare [...]
    challenges_raw = data if isinstance(data, list) else data.get("challenges", [])
    if not challenges_raw:
        return JSONResponse(status_code=400, content={
            "error": "No challenges found in benchmark file"
        })

    # Auto-start CTF session if none active
    if not _ctf_session or not _ctf_session["active"]:
        bench_name = data.get("name", bench_path.stem) if isinstance(data, dict) else bench_path.stem
        await start_ctf_session(
            engagement_id=engagement_id,
            competition_name=f"Benchmark: {bench_name}",
            time_limit_minutes=0,
        )

    loaded = []
    for i, ch_raw in enumerate(challenges_raw):
        ch_name = ch_raw.get("name", f"challenge-{i+1}")
        ch_id = ch_raw.get("id", f"bench-{hashlib.sha256(ch_name.encode()).hexdigest()[:12]}")
        port = ch_raw.get("port", 8000 + i)
        difficulty = ch_raw.get("difficulty", 1)
        tags = ch_raw.get("tags", [])
        description = ch_raw.get("description", "")

        # Auto-classify category from tags
        category = "web"  # default for XBOW
        if tags:
            tag_text = " ".join(tags)
            detected = classify_challenge(ch_name, f"{description} {tag_text}")
            if detected != "misc":
                category = detected

        # Points: 100/200/300 by difficulty (XBOW standard)
        points = ch_raw.get("points", difficulty * 100)

        challenge = CTFChallenge(
            id=ch_id,
            name=ch_name,
            category=CTFCategory(category),
            difficulty=difficulty,
            points=points,
            description=description,
            url=ch_raw.get("url", f"http://localhost:{port}"),
            engagement_id=engagement_id,
            tags=tags,
        )

        ch_dict = challenge.model_dump()
        ch_dict["tool_calls"] = 0
        agents = CTF_CATEGORY_AGENTS.get(category, ["DA"])
        ch_dict["assigned_agent"] = agents[0] if agents else "DA"
        _ctf_session["challenges"][ch_id] = ch_dict
        _ctf_session["total_points"] += points
        loaded.append({"id": ch_id, "name": ch_name, "difficulty": difficulty,
                        "category": category, "points": points})

    await _emit("system", "ST",
        f"BENCHMARK LOADED: {len(loaded)} challenges from {bench_path.name} "
        f"({_ctf_session['total_points']}pts total)",
        {"benchmark_file": str(bench_path.name), "challenges_count": len(loaded)})

    await state.broadcast({
        "type": "ctf_benchmark_loaded",
        "challenges_count": len(loaded),
        "total_points": _ctf_session["total_points"],
        "source": str(bench_path.name),
        "timestamp": time.time(),
    })

    return {
        "ok": True,
        "loaded": len(loaded),
        "total_points": _ctf_session["total_points"],
        "challenges": loaded,
    }


@app.get("/api/ctf/scoreboard")
async def get_ctf_scoreboard(engagement_id: str = ""):
    """Get CTF scoreboard summary (XBOW-compatible format)."""
    if not _ctf_session:
        return JSONResponse(status_code=404, content={"error": "No active CTF session"})

    elapsed = time.time() - _ctf_session["started_at"]
    challenges = _ctf_session["challenges"]
    solved = [c for c in challenges.values() if c.get("status") == "solved"]
    total = len(challenges)
    total_cost = sum(c.get("cost_usd", 0) for c in challenges.values())

    # Per-difficulty breakdown
    by_difficulty: dict[int, dict] = {}
    for ch in challenges.values():
        d = ch.get("difficulty", 1)
        if d not in by_difficulty:
            by_difficulty[d] = {"total": 0, "solved": 0, "points": 0}
        by_difficulty[d]["total"] += 1
        if ch.get("status") == "solved":
            by_difficulty[d]["solved"] += 1
            by_difficulty[d]["points"] += ch.get("points", 0)

    return {
        "engagement_id": _ctf_session["engagement_id"],
        "competition_name": _ctf_session["competition_name"],
        "elapsed_minutes": round(elapsed / 60, 1),
        "challenges_solved": len(solved),
        "challenges_total": total,
        "solve_rate_pct": round(len(solved) / total * 100, 1) if total > 0 else 0,
        "flags_captured": _ctf_session["flags_captured"],
        "captured_points": _ctf_session["captured_points"],
        "total_points": _ctf_session["total_points"],
        "total_cost_usd": round(total_cost, 4),
        "by_difficulty": by_difficulty,
        "solved_challenges": [
            {"id": c["id"], "name": c["name"], "points": c["points"],
             "solved_by": c.get("solved_by"), "solved_at": c.get("solved_at")}
            for c in solved
        ],
    }


# ── Resource-Aware Scaling ──────────────────────────────────────
# Auto-detect host hardware at startup, calculate performance tier,
# adjust max concurrent agents dynamically. Manual override via Settings.

def _detect_system_resources() -> dict:
    """Detect host CPU, RAM, and calculate performance tier."""
    import os
    cpu_cores = os.cpu_count() or 4
    try:
        # macOS + Linux: get total physical memory in bytes
        mem_bytes = os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES')
        ram_gb = round(mem_bytes / (1024 ** 3), 1)
    except (ValueError, AttributeError):
        ram_gb = 8.0  # fallback

    # Performance tiers based on CPU cores and RAM
    if cpu_cores <= 4 and ram_gb <= 8:
        tier = "light"
        max_agents = 3
        parallel_ex = 1
    elif cpu_cores <= 8 and ram_gb <= 16:
        tier = "standard"
        max_agents = 5
        parallel_ex = 1
    elif cpu_cores <= 16 and ram_gb <= 32:
        tier = "performance"
        max_agents = 8
        parallel_ex = 3
    else:
        tier = "beast"
        max_agents = 12
        parallel_ex = 5

    return {
        "cpu_cores": cpu_cores,
        "ram_gb": ram_gb,
        "tier": tier,
        "max_concurrent_agents": max_agents,
        "parallel_ex": parallel_ex,
        "override": None,  # None = auto-detected, string = manual override
    }

_system_resources = _detect_system_resources()
logger.info("System resources detected: %s cores, %.1f GB RAM → tier=%s, max_agents=%d, parallel_ex=%d",
            _system_resources["cpu_cores"], _system_resources["ram_gb"],
            _system_resources["tier"], _system_resources["max_concurrent_agents"],
            _system_resources["parallel_ex"])


# ── F5: Cost Optimization & Early-Stopping ────────────────────

# Per-agent budget allocation (from MAPTA research: failed attempts cost 5x more)
AGENT_BUDGETS: dict[str, dict] = {
    # BUG-013 fix: Per-agent budgets rebalanced so agents don't exhaust before
    # the $20 engagement cap. The engagement cap is the real guardrail — per-agent
    # limits only prevent a single runaway agent from burning the whole budget.
    # Observed: Sonnet ~$0.008/call, Opus ~$0.04/call. At 200 Sonnet calls = $1.60.
    #
    # Strategy — Opus coordinator, lots of Neo4j queries + reasoning
    "ST": {"max_tool_calls": 200, "max_cost": 6.00, "label": "Strategy"},
    # Passive recon — OSINT, subdomain enum, Shodan/Censys (no target contact)
    "PR": {"max_tool_calls": 100, "max_cost": 1.50, "label": "Passive Recon"},
    # Active recon — port scanning, service enum (nmap, httpx, naabu)
    "AR": {"max_tool_calls": 200, "max_cost": 3.00, "label": "Active Recon"},
    # Vuln analysis — moderate scanning + Neo4j queries
    "WV": {"max_tool_calls": 200, "max_cost": 3.00, "label": "Web Vuln Scanner"},
    # Deep analysis — 0-day hunting
    "DA": {"max_tool_calls": 150, "max_cost": 4.00, "label": "Deep Analysis"},
    "PX": {"max_tool_calls": 150, "max_cost": 3.00, "label": "Probe Executor"},
    # Exploitation — higher per-call cost (Opus reasoning)
    "EX": {"max_tool_calls": 150, "max_cost": 4.00, "label": "Exploitation"},
    # Post-exploitation — lateral movement, privesc (Opus)
    "PE": {"max_tool_calls": 100, "max_cost": 3.00, "label": "Post-Exploitation"},
    # Verification — focused re-testing
    "VF": {"max_tool_calls": 100, "max_cost": 2.00, "label": "Verification"},
    # Reporting — writing-heavy (Opus)
    "RP": {"max_tool_calls": 100, "max_cost": 4.00, "label": "Reporting"},
}

# Default budget for unlisted agents
DEFAULT_BUDGET = {"max_tool_calls": 150, "max_cost": 2.50}

# BUG-011/012 fix: Default engagement budget is now $20 (configurable per engagement).
# Pentester can override this when creating an engagement.
ENGAGEMENT_COST_CAP = 20.00

# Token pricing: Sonnet 4.6 rates (per million tokens)
# SDK agents use Sonnet by default, Opus for Strategy/Exploit
PRICING = {
    "sonnet": {"input": 3.0, "output": 15.0},
    "opus":   {"input": 15.0, "output": 75.0},
}
OPUS_AGENTS = {"ST", "EX", "RP"}  # Agents that use Opus

# In-memory budget tracking: agent_code → {tool_calls, estimated_cost, findings}
_agent_budgets: dict[str, dict] = {}
_engagement_cost: float = 0.0
_engagement_cost_eid: str = ""  # Which engagement _engagement_cost belongs to
_engagement_types: list[str] = ["external"]  # BUG-006: Current engagement types for agent gating
_skip_agents: set[str] = set()  # Agents excluded from current engagement (e.g. {"PR"} to skip OSINT)

# BUG-006: Agents allowed per engagement type (server-side enforcement)
_AGENTS_BY_TYPE: dict[str, set[str]] = {
    "external": {"ST", "PR", "AR", "WV", "DA", "PX", "EX", "PE", "VF", "RP"},
    "web_app":  {"ST", "PR", "WV", "DA", "PX", "EX", "PE", "VF", "RP"},
    "internal": {"ST", "PR", "AR", "WV", "DA", "PX", "EX", "PE", "VF", "RP"},
}


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

    BUG-027: No longer increments _engagement_cost with estimates.
    Estimates are still accumulated in budget["estimated_cost"] for
    early-stop detection only (actual cost arrives slower, once per
    query turn via /api/budget/actual-cost). The displayed engagement
    total is derived from actual costs only.
    """
    global _engagement_cost  # read-only here — needed for response/broadcast
    budget = _get_agent_budget(agent)
    budget["tool_calls"] += 1
    cost = _estimate_tool_cost(agent)
    budget["estimated_cost"] += cost
    # NOTE: Do NOT touch _engagement_cost here. Estimates competing with
    # actual costs caused oscillation (BUG-027). _engagement_cost is now
    # the sum of per-agent actual costs only, updated in report_actual_cost.

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
        "engagement_remaining": round(max(ENGAGEMENT_COST_CAP - _engagement_cost, 0), 4),
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

    # Budget exhausted — tool-call count only.
    # BUG-FIX: Previously also checked estimated_cost >= max_cost, which
    # triggered at ~50 calls for Opus agents ($0.12/call × 50 = $6.00)
    # despite a 200-call limit. Actual cost enforcement is handled
    # exclusively by /api/budget/actual-cost endpoint.
    if budget["tool_calls"] >= budget["max_tool_calls"]:
        budget["exhausted"] = True
        response["early_stop"] = True

        if budget["warnings_sent"] < 2:
            budget["warnings_sent"] = 2
            action = "with findings" if budget["findings_count"] > 0 else "WITHOUT findings"
            await _emit("system", agent,
                f"BUDGET EXHAUSTED: {AGENT_NAMES.get(agent, agent)} — "
                f"{budget['tool_calls']}/{budget['max_tool_calls']} calls "
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


# ── BUG-008b: Actual Cost Tracking ────────────────────────

@app.post("/api/budget/actual-cost")
async def report_actual_cost(agent: str, cost_usd: float):
    """Report actual SDK cost from ResultMessage.total_cost_usd.

    BUG-008b: SDK agents accumulate real costs locally but never sent them
    to the server, so engagement cost was ~6x underreported.
    Called by sdk_agent after each ResultMessage with cumulative cost.
    """
    global _engagement_cost, _engagement_cost_eid

    budget = _get_agent_budget(agent)

    # BUG-027: Store actual cost per agent. Do NOT touch estimated_cost —
    # it is used exclusively for early-stop detection in tool-call endpoint.
    # _engagement_cost is now the authoritative sum of all agents' latest
    # actual costs. No delta math — recalculate from scratch to avoid drift.
    prior_actual = budget.get("actual_cost", 0.0)
    budget["actual_cost"] = max(prior_actual, cost_usd)

    # Track which engagement this cost belongs to (BUG-049)
    if state.active_engagement_id:
        _engagement_cost_eid = state.active_engagement_id

    # Recompute engagement total as sum of all per-agent actual costs.
    # Agents that have no actual_cost yet contribute 0 (not their estimate).
    _engagement_cost = sum(
        b.get("actual_cost", 0.0) for b in _agent_budgets.values()
    )

    # Re-check budget thresholds with actual cost
    pct_cost = cost_usd / budget["max_cost"] * 100 if budget["max_cost"] > 0 else 0

    # BUG-016: Include engagement_remaining so agents can show accurate warnings
    engagement_remaining = ENGAGEMENT_COST_CAP - _engagement_cost

    response = {
        "ok": True,
        "agent": agent,
        "actual_cost": round(cost_usd, 4),
        "engagement_cost": round(_engagement_cost, 4),
        "engagement_remaining": round(max(engagement_remaining, 0), 4),
        "early_stop": False,
    }

    if cost_usd >= budget["max_cost"]:
        budget["exhausted"] = True
        response["early_stop"] = True

    if _engagement_cost >= ENGAGEMENT_COST_CAP:
        response["engagement_cap_exceeded"] = True

    # Persist engagement cost to Neo4j so it survives server restarts
    # BUG-049: Target ONLY the specific engagement, not all active ones
    if neo4j_available and neo4j_driver and _engagement_cost > 0 and _engagement_cost_eid:
        try:
            with neo4j_driver.session() as session:
                session.run(
                    "MATCH (e:Engagement {id: $eid}) SET e.engagement_cost = $cost",
                    eid=_engagement_cost_eid,
                    cost=round(_engagement_cost, 4),
                )
        except Exception as e:
            logger.warning("Neo4j cost persistence failed for %s ($%.4f): %s",
                           agent, _engagement_cost, str(e)[:200])

    # Broadcast cost update so dashboard KPI updates in real-time
    await state.broadcast({
        "type": "cost_update",
        "agent": agent,
        "tool_calls": budget["tool_calls"],
        "max_tool_calls": budget["max_tool_calls"],
        "estimated_cost": round(cost_usd, 4),
        "max_cost": budget["max_cost"],
        "engagement_cost": round(_engagement_cost, 4),
        "actual_cost": round(cost_usd, 4),
        "timestamp": time.time(),
    })

    return response


@app.post("/api/budget/session-final-cost")
async def report_session_final_cost(
    total_cost_usd: float,
    total_tool_calls: int,
    engagement_id: str = "",
):
    """Report final aggregated cost from session manager on engagement stop.

    P1-FIX: Session manager aggregates total costs across all agents but
    never synced them back to the server. This endpoint ensures the server's
    _engagement_cost reflects the true total even if individual agent cost
    reports were lost due to network timeouts.
    """
    global _engagement_cost

    # Only update if the session manager total exceeds what we already tracked
    if total_cost_usd > _engagement_cost:
        logger.info(
            "Session final cost sync: server had $%.4f, session manager reports $%.4f (delta +$%.4f)",
            _engagement_cost, total_cost_usd, total_cost_usd - _engagement_cost)
        _engagement_cost = total_cost_usd

    # Persist to Neo4j
    eid = engagement_id or ""
    if neo4j_available and neo4j_driver and _engagement_cost > 0:
        try:
            with neo4j_driver.session() as session:
                if eid:
                    session.run(
                        "MATCH (e:Engagement {id: $eid}) "
                        "SET e.engagement_cost = $cost, e.total_tool_calls = $tools",
                        eid=eid, cost=round(_engagement_cost, 4),
                        tools=total_tool_calls)
                else:
                    session.run(
                        "MATCH (e:Engagement {status: 'active'}) "
                        "SET e.engagement_cost = $cost, e.total_tool_calls = $tools",
                        cost=round(_engagement_cost, 4),
                        tools=total_tool_calls)
        except Exception as e:
            logger.warning("Neo4j final cost write failed: %s", str(e)[:200])

    # Broadcast final cost so dashboard updates
    await state.broadcast({
        "type": "cost_update",
        "agent": "FINAL",
        "engagement_cost": round(_engagement_cost, 4),
        "total_tool_calls": total_tool_calls,
        "timestamp": time.time(),
    })

    return {
        "ok": True,
        "engagement_cost": round(_engagement_cost, 4),
        "total_tool_calls": total_tool_calls,
    }


@app.post("/api/budget/finding")
async def record_budget_finding(agent: str):
    """Record that an agent produced a finding (for cost-per-finding metrics).

    BUG-008b: Previously the finding parameter in tool-call was never set True.
    Separate endpoint avoids double-counting tool calls.
    """
    budget = _get_agent_budget(agent)
    budget["findings_count"] += 1
    return {"ok": True, "agent": agent, "findings_count": budget["findings_count"]}


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
        actual = b.get("actual_cost", 0.0)  # BUG-026 FIX: never fall back to estimated
        agents[code] = {
            "name": AGENT_NAMES[code],
            "tool_calls": b["tool_calls"],
            "max_tool_calls": b["max_tool_calls"],
            "estimated_cost": round(b["estimated_cost"], 4),
            "actual_cost": round(actual, 4),
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


@app.get("/api/budget/engagement")
async def get_engagement_budget(engagement_id: str = ""):
    """Get engagement-level cost summary with efficiency metrics."""
    global _engagement_cost, _engagement_cost_eid
    active = {k: v for k, v in _agent_budgets.items() if v["tool_calls"] > 0}
    # BUG-027: Use actual costs only. _engagement_cost is kept in sync as the
    # sum of per-agent actual costs (updated in report_actual_cost). Agents
    # that haven't reported an actual cost yet contribute 0 — not their
    # estimates — so the total can only monotonically increase.
    #
    # BUG-049: _engagement_cost is a global that belongs to whichever engagement
    # last ran agents. When the frontend queries cost for a DIFFERENT engagement,
    # we must NOT return the in-memory value — go straight to Neo4j instead.
    is_current_engagement = (not engagement_id) or (engagement_id == _engagement_cost_eid)
    if is_current_engagement:
        agent_sum = sum(b.get("actual_cost", 0.0) for b in active.values())
        total_cost = max(_engagement_cost, agent_sum)
    else:
        total_cost = 0.0  # Not the in-memory engagement — must look up in Neo4j
    # Restore from Neo4j if in-memory is zero (server restart scenario or different engagement)
    # BUG-028: Only restore cost for the SPECIFIC engagement requested.
    # Previous fallback query grabbed the highest cost from ANY engagement,
    # causing deleted engagements' costs to "leak" into new sessions.
    if total_cost == 0 and engagement_id and neo4j_available and neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                rec = session.run(
                    "MATCH (e:Engagement {id: $eid}) WHERE e.engagement_cost IS NOT NULL "
                    "RETURN e.engagement_cost AS cost",
                    eid=engagement_id,
                ).single()
                if rec and rec["cost"]:
                    total_cost = float(rec["cost"])
                    # Only update in-memory if this is the current engagement
                    if is_current_engagement:
                        _engagement_cost = total_cost
        except Exception as e:
            logger.warning("Neo4j cost recovery failed: %s", str(e)[:200])
    total_tools = sum(b["tool_calls"] for b in active.values())
    total_findings = sum(b["findings_count"] for b in active.values())

    # Cost efficiency metrics
    cost_per_finding = round(total_cost / total_findings, 4) if total_findings > 0 else 0
    tools_per_finding = round(total_tools / total_findings, 1) if total_findings > 0 else 0

    # Per-agent efficiency
    agent_efficiency = []
    for code, b in active.items():
        actual = b.get("actual_cost", 0.0)  # BUG-026 FIX: never fall back to estimated
        agent_efficiency.append({
            "agent": code,
            "name": AGENT_NAMES.get(code, code),
            "tool_calls": b["tool_calls"],
            "estimated_cost": round(b["estimated_cost"], 4),
            "actual_cost": round(actual, 4),
            "findings": b["findings_count"],
            "cost_per_finding": round(actual / b["findings_count"], 4) if b["findings_count"] > 0 else None,
            "exhausted": b["exhausted"],
            "pct_budget_used": round(actual / b["max_cost"] * 100, 1) if b["max_cost"] > 0 else 0,
        })
    # Sort by cost efficiency (agents with findings first, then by cost)
    agent_efficiency.sort(key=lambda a: (a["findings"] == 0, a["estimated_cost"]))

    return {
        "engagement_cost": round(total_cost, 4),
        "engagement_cap": ENGAGEMENT_COST_CAP,
        "pct_cap_used": round(total_cost / ENGAGEMENT_COST_CAP * 100, 1) if ENGAGEMENT_COST_CAP > 0 else 0,
        "cap_exceeded": total_cost >= ENGAGEMENT_COST_CAP,
        "total_tool_calls": total_tools,
        "total_findings": total_findings,
        "cost_per_finding": cost_per_finding,
        "tools_per_finding": tools_per_finding,
        "active_agents": len(active),
        "exhausted_agents": sum(1 for b in active.values() if b["exhausted"]),
        "agents": agent_efficiency,
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
    if hasattr(state, '_engagement_cap_warned'):
        state._engagement_cap_warned = False
    # Also clear persisted cost in Neo4j so it doesn't restore on reload
    if neo4j_available and neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                session.run(
                    "MATCH (e:Engagement {status: 'active'}) SET e.engagement_cost = 0",
                )
        except Exception as e:
            logger.warning("Neo4j budget reset failed: %s", str(e)[:200])
    return {"ok": True, "message": "All budgets reset"}


# ── F6: Attack Chain Reasoning via Neo4j ──────────────────────

class AttackRelationType(str, Enum):
    ENABLES = "ENABLES"              # Finding A enables exploitation of Finding B
    PIVOTS_TO = "PIVOTS_TO"          # Compromised Host A can reach Host B
    ESCALATES_TO = "ESCALATES_TO"    # Low-priv escalates to higher privilege
    EXPOSES = "EXPOSES"              # Service exposes sensitive data/functionality


_VALID_REL_TYPES = frozenset(e.value for e in AttackRelationType)

def _safe_rel_type(rel: str) -> str:
    """Validate and sanitize relationship type for safe Cypher interpolation.

    Neo4j does not support parameterized relationship types, so we must
    interpolate them. This ensures only known-safe values are used.
    """
    sanitized = re.sub(r'[^A-Z_]', '', rel.upper())
    if sanitized not in _VALID_REL_TYPES:
        raise ValueError(f"Invalid relationship type: {rel}")
    return sanitized


class AttackChainLink(BaseModel):
    """A single link in an attack chain."""
    from_id: str           # Finding or Host ID
    from_label: str        # Human-readable label
    to_id: str
    to_label: str
    relationship: str      # AttackRelationType value
    description: str = ""
    confidence: float = 0.8


class AttackChain(BaseModel):
    """A multi-step attack chain discovered by Strategy Agent."""
    id: str
    engagement_id: str = "eng-001"
    name: str                         # e.g. "SQLi → Admin → RCE"
    links: list[AttackChainLink]
    impact: str = ""                  # What the full chain achieves
    blast_radius: str = ""            # How much damage possible
    priority: int = 1                 # 1=highest
    discovered_by: str = "ST"         # Agent that identified the chain


# ── F6: Attack Chain Auto-Detection Patterns ──────────────
#
# Heuristic rules matching finding category pairs on the SAME target host.
# Each rule: (source_categories, target_categories, relationship, description_template, confidence)

CHAIN_PATTERNS: list[tuple[set[str], set[str], str, str, float]] = [
    # Injection → file/code access enables RCE
    ({"sqli", "A03", "injection"},
     {"lfi", "file_upload", "rce", "command_injection"},
     "ENABLES", "{src} enables {dst} via injection-to-file chain", 0.7),

    # Auth bypass → code execution = privilege escalation
    ({"auth_bypass", "A01", "idor", "broken_access"},
     {"rce", "file_upload", "A05", "command_injection"},
     "ESCALATES_TO", "{src} escalates to {dst} via auth compromise", 0.8),

    # SSRF → internal exploitation
    ({"ssrf", "A10"},
     {"sqli", "rce", "lfi", "A03", "command_injection"},
     "ENABLES", "{src} enables internal {dst} via SSRF", 0.75),

    # XSS → auth bypass = account takeover
    ({"xss", "stored_xss", "reflected_xss"},
     {"auth_bypass", "A01", "idor", "A07", "session_hijack"},
     "ENABLES", "{src} enables {dst} via client-side attack", 0.6),

    # File upload → code execution
    ({"file_upload", "unrestricted_upload"},
     {"rce", "command_injection"},
     "ENABLES", "{src} enables {dst} via malicious upload", 0.85),

    # Weak auth → unauthorized access
    ({"A07", "default_credentials", "weak_password"},
     {"A01", "rce", "sqli", "auth_bypass"},
     "ESCALATES_TO", "{src} escalates to {dst} via weak authentication", 0.7),

    # Information disclosure → targeted exploitation
    ({"A05", "info_disclosure", "directory_listing", "misconfiguration"},
     {"sqli", "xss", "rce", "auth_bypass", "lfi"},
     "EXPOSES", "{src} exposes attack surface for {dst}", 0.5),

    # XXE → file read / SSRF
    ({"xxe", "A03"},
     {"lfi", "ssrf", "rce"},
     "ENABLES", "{src} enables {dst} via XML external entity", 0.7),

    # Credential harvest → lateral access
    ({"credential_exposure", "A02", "sensitive_data"},
     {"auth_bypass", "A01", "rce"},
     "ENABLES", "{src} enables {dst} via harvested credentials", 0.75),
]

# Track last auto-detect run to debounce
_last_chain_detect: float = 0.0
_CHAIN_DETECT_DEBOUNCE = 5.0  # seconds (slightly longer than findings sync)


@app.post("/api/chains/link")
async def create_attack_link(link: AttackChainLink):
    """
    Create a relationship between two findings/hosts in Neo4j.

    Used by agents when they discover that one finding enables another,
    or when a compromised host can pivot to another target.
    """
    if not neo4j_available or not neo4j_driver:
        return JSONResponse(status_code=503, content={
            "error": "Neo4j unavailable — attack chain reasoning requires graph database"
        })

    rel_type = link.relationship.upper()
    if rel_type not in [e.value for e in AttackRelationType]:
        return JSONResponse(status_code=400, content={
            "error": f"Invalid relationship type: {rel_type}. "
                     f"Valid: {[e.value for e in AttackRelationType]}"
        })

    _rel_type = _safe_rel_type(rel_type)
    def _create_link():
        with neo4j_driver.session() as session:
            # Create relationship between existing nodes (Finding or Host)
            # Use MERGE to avoid duplicates
            session.run(f"""
                MATCH (a {{id: $from_id}})
                MATCH (b {{id: $to_id}})
                MERGE (a)-[r:{_rel_type}]->(b)
                SET r.description = $description,
                    r.confidence = $confidence,
                    r.created_at = datetime()
            """, from_id=link.from_id, to_id=link.to_id,
                 description=link.description, confidence=link.confidence)
    try:
        await neo4j_exec(_create_link)
    except Exception as e:
        return JSONResponse(status_code=500, content={
            "error": f"Neo4j error: {str(e)[:300]}"
        })

    await _emit("system", "ST",
        f"Chain link: {link.from_label} —[{rel_type}]→ {link.to_label}",
        {"chain_link": True, "relationship": rel_type,
         "from_id": link.from_id, "to_id": link.to_id})

    return {"ok": True, "relationship": rel_type}


@app.post("/api/chains")
async def create_attack_chain(chain: AttackChain):
    """
    Register a full attack chain discovered by the Strategy Agent.

    Creates the chain node in Neo4j and links it to its constituent findings.
    Also broadcasts to dashboard for visualization.
    """
    if not neo4j_available or not neo4j_driver:
        return JSONResponse(status_code=503, content={
            "error": "Neo4j unavailable"
        })

    def _create_chain():
        with neo4j_driver.session() as session:
            # Create AttackChain node
            session.run("""
                CREATE (ac:AttackChain {
                    id: $id,
                    engagement_id: $eid,
                    name: $name,
                    impact: $impact,
                    blast_radius: $blast_radius,
                    priority: $priority,
                    discovered_by: $discovered_by,
                    links_count: $links_count,
                    created_at: datetime()
                })
            """, id=chain.id, eid=chain.engagement_id,
                 name=chain.name, impact=chain.impact,
                 blast_radius=chain.blast_radius,
                 priority=chain.priority,
                 discovered_by=chain.discovered_by,
                 links_count=len(chain.links))

            # Link to engagement
            session.run("""
                MATCH (e:Engagement {id: $eid})
                MATCH (ac:AttackChain {id: $chain_id})
                MERGE (e)-[:HAS_CHAIN]->(ac)
            """, eid=chain.engagement_id, chain_id=chain.id)

            # Create all chain link relationships
            for link in chain.links:
                try:
                    rel_type = _safe_rel_type(link.relationship)
                except ValueError:
                    continue
                session.run(f"""
                    MATCH (a {{id: $from_id}})
                    MATCH (b {{id: $to_id}})
                    MERGE (a)-[r:{rel_type}]->(b)
                    SET r.description = $desc,
                        r.confidence = $conf,
                        r.chain_id = $chain_id,
                        r.created_at = datetime()
                """, from_id=link.from_id, to_id=link.to_id,
                     desc=link.description, conf=link.confidence,
                     chain_id=chain.id)
    try:
        await neo4j_exec(_create_chain)
    except Exception as e:
        return JSONResponse(status_code=500, content={
            "error": f"Neo4j error: {str(e)[:300]}"
        })

    # Build chain summary for display
    chain_steps = " → ".join(
        [chain.links[0].from_label] +
        [link.to_label for link in chain.links]
    ) if chain.links else chain.name

    await _emit("system", chain.discovered_by,
        f"ATTACK CHAIN [{chain.priority}]: {chain_steps} — {chain.impact}",
        {"attack_chain": True, "chain_id": chain.id,
         "chain_name": chain.name, "steps": len(chain.links)})

    await state.broadcast({
        "type": "attack_chain",
        "chain_id": chain.id,
        "name": chain.name,
        "steps": chain_steps,
        "links_count": len(chain.links),
        "impact": chain.impact,
        "blast_radius": chain.blast_radius,
        "priority": chain.priority,
        "discovered_by": chain.discovered_by,
        "timestamp": time.time(),
    })

    return {"ok": True, "chain_id": chain.id, "links": len(chain.links)}


@app.get("/api/chains")
async def get_attack_chains(engagement_id: str = "eng-001"):
    """Get all attack chains for an engagement from Neo4j."""
    if not neo4j_available or not neo4j_driver:
        return {"chains": [], "message": "Neo4j unavailable"}

    chains = []
    def _get_chains():
        with neo4j_driver.session() as session:
            result = session.run("""
                MATCH (ac:AttackChain {engagement_id: $eid})
                RETURN ac
                ORDER BY ac.priority ASC
            """, eid=engagement_id)
            rows = []
            for record in result:
                node = record["ac"]
                rows.append({
                    "id": node["id"],
                    "name": node["name"],
                    "impact": node.get("impact", ""),
                    "blast_radius": node.get("blast_radius", ""),
                    "priority": node.get("priority", 99),
                    "discovered_by": node.get("discovered_by", "ST"),
                    "links_count": node.get("links_count", 0),
                })
            return rows
    try:
        chains = await neo4j_exec(_get_chains)
    except Exception as e:
        return {"chains": [], "error": str(e)[:200]}

    return {"chains": chains, "count": len(chains)}


@app.get("/api/chains/graph")
async def get_attack_graph(engagement_id: str = "eng-001"):
    """
    Get the full attack graph — all chain relationships for visualization.

    Returns nodes (findings/hosts) and edges (ENABLES/PIVOTS_TO/etc.)
    suitable for rendering as a force-directed graph or Sankey diagram.
    """
    if not neo4j_available or not neo4j_driver:
        return {"nodes": [], "edges": [], "message": "Neo4j unavailable"}

    nodes = {}
    edges = []

    def _get_graph():
        _nodes = {}
        _edges = []
        with neo4j_driver.session() as session:
            # Get all chain relationships for this engagement
            for rel_type in AttackRelationType:
                result = session.run(f"""
                    MATCH (a)-[r:{rel_type.value}]->(b)
                    WHERE (a:Finding AND a.engagement_id = $eid)
                       OR (a:Host AND a.engagement_id = $eid)
                       OR r.chain_id IS NOT NULL
                    RETURN a.id AS from_id,
                           COALESCE(a.title, a.hostname, a.ip, a.id) AS from_label,
                           labels(a)[0] AS from_type,
                           b.id AS to_id,
                           COALESCE(b.title, b.hostname, b.ip, b.id) AS to_label,
                           labels(b)[0] AS to_type,
                           type(r) AS rel_type,
                           r.description AS description,
                           r.confidence AS confidence
                """, eid=engagement_id)

                for record in result:
                    f_id = record["from_id"]
                    t_id = record["to_id"]

                    if f_id not in _nodes:
                        _nodes[f_id] = {
                            "id": f_id,
                            "label": record["from_label"],
                            "type": record["from_type"],
                        }
                    if t_id not in _nodes:
                        _nodes[t_id] = {
                            "id": t_id,
                            "label": record["to_label"],
                            "type": record["to_type"],
                        }

                    _edges.append({
                        "from": f_id,
                        "to": t_id,
                        "relationship": record["rel_type"],
                        "description": record.get("description", ""),
                        "confidence": record.get("confidence", 0.8),
                    })
        return _nodes, _edges

    try:
        nodes, edges = await neo4j_exec(_get_graph)
    except Exception as e:
        return {"nodes": [], "edges": [], "error": str(e)[:200]}

    return {
        "nodes": list(nodes.values()),
        "edges": edges,
        "node_count": len(nodes),
        "edge_count": len(edges),
    }


@app.get("/api/chains/shortest-path")
async def get_shortest_attack_path(
    engagement_id: str = "eng-001",
    from_id: str = "",
    to_id: str = "",
):
    """
    Find shortest attack path between two nodes in the engagement graph.

    If from_id/to_id not specified, finds path from initial access to
    highest-value target (PII/admin/root).
    """
    if not neo4j_available or not neo4j_driver:
        return {"path": [], "message": "Neo4j unavailable"}

    def _get_path():
        with neo4j_driver.session() as session:
            if from_id and to_id:
                # Specific path request
                result = session.run("""
                    MATCH path = shortestPath(
                        (a {id: $from_id})-[*]-(b {id: $to_id})
                    )
                    RETURN [n IN nodes(path) |
                        {id: n.id, label: COALESCE(n.title, n.hostname, n.ip, n.id),
                         type: labels(n)[0]}
                    ] AS nodes,
                    [r IN relationships(path) |
                        {type: type(r), description: r.description}
                    ] AS rels
                """, from_id=from_id, to_id=to_id)
            else:
                # Auto-detect: initial access → sensitive target
                result = session.run("""
                    MATCH (entry:Host {engagement_id: $eid})
                    WHERE entry.access_level = 'initial'
                       OR entry.compromised = true
                    MATCH (target {engagement_id: $eid})
                    WHERE (target:Service AND (target.contains_pii = true OR target.admin = true))
                       OR (target:Host AND target.root_access = true)
                    MATCH path = shortestPath((entry)-[*]-(target))
                    RETURN [n IN nodes(path) |
                        {id: n.id, label: COALESCE(n.title, n.hostname, n.ip, n.id),
                         type: labels(n)[0]}
                    ] AS nodes,
                    [r IN relationships(path) |
                        {type: type(r), description: r.description}
                    ] AS rels
                    LIMIT 1
                """, eid=engagement_id)

            record = result.single()
            return record
    try:
        record = await neo4j_exec(_get_path)
    except Exception as e:
        return {"path": [], "error": str(e)[:200]}

    if not record:
        return {"path": [], "message": "No path found"}

    return {
        "nodes": record["nodes"],
        "relationships": record["rels"],
        "length": len(record["rels"]),
    }


@app.get("/api/chains/blast-radius")
async def get_blast_radius(finding_id: str, engagement_id: str = "eng-001"):
    """
    Calculate the blast radius of a specific finding.

    Traverses the graph outward from the finding to determine what
    an attacker could reach if this finding is exploited.
    """
    if not neo4j_available or not neo4j_driver:
        return {"reachable": [], "message": "Neo4j unavailable"}

    def _get_blast_radius():
        with neo4j_driver.session() as session:
            result = session.run("""
                MATCH (f:Finding {id: $fid})
                OPTIONAL MATCH path = (f)-[:ENABLES|PIVOTS_TO|ESCALATES_TO|EXPOSES*1..4]->(target)
                RETURN COLLECT(DISTINCT {
                    id: target.id,
                    label: COALESCE(target.title, target.hostname, target.ip, target.id),
                    type: labels(target)[0],
                    distance: length(path)
                }) AS reachable
            """, fid=finding_id)
            record = result.single()
            reachable = record["reachable"] if record else []
            return [r for r in reachable if r.get("id")]
    try:
        reachable = await neo4j_exec(_get_blast_radius)
    except Exception as e:
        return {"reachable": [], "error": str(e)[:200]}

    return {
        "finding_id": finding_id,
        "reachable": reachable,
        "blast_radius": len(reachable),
        "max_depth": max((r.get("distance", 0) for r in reachable), default=0),
    }


@app.get("/api/chains/lateral")
async def get_lateral_movement(engagement_id: str = "eng-001"):
    """
    Find lateral movement opportunities — compromised hosts that can
    reach untested hosts/services.
    """
    if not neo4j_available or not neo4j_driver:
        return {"opportunities": [], "message": "Neo4j unavailable"}

    def _get_lateral():
        with neo4j_driver.session() as session:
            result = session.run("""
                MATCH (h1:Host {compromised: true})-[:PIVOTS_TO|NETWORK_ACCESS]->(h2:Host)
                WHERE NOT h2.compromised
                OPTIONAL MATCH (h2)-[:HAS_SERVICE]->(s:Service)
                WHERE NOT s.tested = true
                RETURN h1.id AS from_host,
                       COALESCE(h1.hostname, h1.ip, h1.id) AS from_label,
                       h2.id AS to_host,
                       COALESCE(h2.hostname, h2.ip, h2.id) AS to_label,
                       COLLECT(DISTINCT {
                           id: s.id,
                           name: s.name,
                           port: s.port
                       }) AS untested_services
            """)
            opps = []
            for record in result:
                services = [s for s in record["untested_services"] if s.get("id")]
                opps.append({
                    "from_host": record["from_host"],
                    "from_label": record["from_label"],
                    "to_host": record["to_host"],
                    "to_label": record["to_label"],
                    "untested_services": services,
                    "service_count": len(services),
                })
            return opps
    try:
        opportunities = await neo4j_exec(_get_lateral)
    except Exception as e:
        return {"opportunities": [], "error": str(e)[:200]}

    return {
        "opportunities": opportunities,
        "count": len(opportunities),
    }


# ── F6: Auto-Detection Engine ─────────────────────────────


def _extract_host_from_target(target: str) -> str:
    """Extract hostname/IP from a finding's target field for grouping."""
    return _safe_extract_host(target)


def _normalize_category(cat: str) -> set[str]:
    """Normalize a finding category to a set of matchable labels.

    Handles OWASP codes, specific vuln types, and free-form text.
    Returns lowered set for matching against CHAIN_PATTERNS.
    """
    if not cat:
        return set()
    low = cat.lower().strip()
    labels = {low}
    # Also add without underscores/hyphens for fuzzy matching
    labels.add(low.replace("-", "_"))
    labels.add(low.replace("_", "-"))
    # Common aliases
    aliases = {
        "sql injection": "sqli",
        "sql_injection": "sqli",
        "cross-site scripting": "xss",
        "cross_site_scripting": "xss",
        "remote code execution": "rce",
        "command injection": "command_injection",
        "local file inclusion": "lfi",
        "file inclusion": "lfi",
        "server-side request forgery": "ssrf",
        "insecure direct object reference": "idor",
        "authentication bypass": "auth_bypass",
        "xml external entity": "xxe",
        "directory traversal": "lfi",
        "path traversal": "lfi",
    }
    if low in aliases:
        labels.add(aliases[low])
    return labels


async def _auto_detect_chains(eid: str) -> dict:
    """Analyze findings in an engagement and auto-detect attack chains.

    Groups findings by target host, checks category pairs against
    CHAIN_PATTERNS, creates Neo4j relationships (MERGE = idempotent),
    and optionally creates AttackChain nodes for multi-step paths.

    Returns summary of detected chains and relationships.
    """
    global _last_chain_detect
    now = time.time()
    if now - _last_chain_detect < _CHAIN_DETECT_DEBOUNCE:
        return {"skipped": True, "reason": "debounce"}
    _last_chain_detect = now

    if not neo4j_available or not neo4j_driver:
        return {"chains": 0, "links": 0, "message": "Neo4j unavailable"}

    # 1. Get all findings for this engagement
    findings_by_host: dict[str, list[dict]] = {}
    all_findings: list[dict] = []

    def _fetch_findings():
        with neo4j_driver.session() as sess:
            result = sess.run("""
                MATCH (f:Finding {engagement_id: $eid})
                RETURN f.id AS id, f.title AS title,
                       f.severity AS severity, f.category AS category,
                       f.target AS target, f.agent AS agent
                ORDER BY f.timestamp
            """, eid=eid)
            rows = []
            for record in result:
                rows.append(dict(record))
            return rows
    try:
        _fetched = await neo4j_exec(_fetch_findings)
        for finding in _fetched:
            all_findings.append(finding)
            host = _extract_host_from_target(finding.get("target", ""))
            if host:
                findings_by_host.setdefault(host, []).append(finding)
    except Exception as e:
        return {"chains": 0, "links": 0, "error": str(e)[:200]}

    if len(all_findings) < 2:
        return {"chains": 0, "links": 0, "message": "Need 2+ findings for chain detection"}

    # 2. Same-host pattern matching
    new_links = []

    for host, host_findings in findings_by_host.items():
        if len(host_findings) < 2:
            continue

        for i, f1 in enumerate(host_findings):
            cat1 = _normalize_category(f1.get("category", ""))
            for f2 in host_findings[i + 1:]:
                if f1["id"] == f2["id"]:
                    continue
                cat2 = _normalize_category(f2.get("category", ""))

                for src_cats, dst_cats, rel_type, desc_tpl, confidence in CHAIN_PATTERNS:
                    # Check f1 → f2
                    if cat1 & src_cats and cat2 & dst_cats:
                        desc = desc_tpl.format(
                            src=f1.get("title", "?"),
                            dst=f2.get("title", "?"))
                        new_links.append({
                            "from_id": f1["id"], "from_label": f1.get("title", ""),
                            "to_id": f2["id"], "to_label": f2.get("title", ""),
                            "rel_type": rel_type,
                            "description": desc,
                            "confidence": confidence,
                        })
                    # Check f2 → f1 (reverse direction)
                    if cat2 & src_cats and cat1 & dst_cats:
                        desc = desc_tpl.format(
                            src=f2.get("title", "?"),
                            dst=f1.get("title", "?"))
                        new_links.append({
                            "from_id": f2["id"], "from_label": f2.get("title", ""),
                            "to_id": f1["id"], "to_label": f1.get("title", ""),
                            "rel_type": rel_type,
                            "description": desc,
                            "confidence": confidence,
                        })

    # 3. Cross-host pivot detection
    pivot_links = []
    try:
        with neo4j_driver.session() as sess:
            result = sess.run("""
                MATCH (h1:Host {engagement_id: $eid})
                WHERE h1.compromised = true
                MATCH (h1)-[:NETWORK_ACCESS|CONNECTS_TO]->(h2:Host {engagement_id: $eid})
                WHERE NOT h2.compromised
                RETURN h1.id AS from_id,
                       COALESCE(h1.hostname, h1.ip, h1.id) AS from_label,
                       h2.id AS to_id,
                       COALESCE(h2.hostname, h2.ip, h2.id) AS to_label
            """, eid=eid)

            for record in result:
                pivot_links.append({
                    "from_id": record["from_id"],
                    "from_label": record["from_label"],
                    "to_id": record["to_id"],
                    "to_label": record["to_label"],
                    "rel_type": "PIVOTS_TO",
                    "description": f"{record['from_label']} can pivot to {record['to_label']}",
                    "confidence": 0.8,
                })
    except Exception as e:
        logger.warning("Cross-host pivot detection failed: %s", e)

    all_links = new_links + pivot_links

    if not all_links:
        return {"chains": 0, "links": 0, "message": "No chain patterns detected"}

    # 4. Write relationships to Neo4j (MERGE = idempotent)
    links_created = 0
    try:
        with neo4j_driver.session() as sess:
            for link in all_links:
                try:
                    rel_type = _safe_rel_type(link["rel_type"])
                except ValueError:
                    continue
                result = sess.run(f"""
                    MATCH (a {{id: $from_id}})
                    MATCH (b {{id: $to_id}})
                    MERGE (a)-[r:{rel_type}]->(b)
                    ON CREATE SET r.description = $desc,
                                  r.confidence = $conf,
                                  r.auto_detected = true,
                                  r.created_at = datetime()
                    RETURN type(r) AS rt
                """, from_id=link["from_id"], to_id=link["to_id"],
                     desc=link["description"], conf=link["confidence"])

                if result.single():
                    links_created += 1
    except Exception as e:
        logger.warning("Chain link creation failed: %s", e)

    # 5. Auto-create AttackChain nodes for multi-step paths (2+ links)
    chains_created = 0
    if links_created >= 2:
        # Group links that share nodes into chains
        # Simple approach: find connected components via finding IDs
        node_to_links: dict[str, list[dict]] = {}
        for link in all_links:
            node_to_links.setdefault(link["from_id"], []).append(link)
            node_to_links.setdefault(link["to_id"], []).append(link)

        # Find paths with 2+ links using BFS from each source
        seen_chains: set[str] = set()
        for link in all_links:
            chain_key = f"{link['from_id']}->{link['to_id']}"
            if chain_key in seen_chains:
                continue

            # Follow the chain forward
            chain_links = [link]
            current = link["to_id"]
            visited = {link["from_id"], link["to_id"]}

            for next_link in all_links:
                if next_link["from_id"] == current and next_link["to_id"] not in visited:
                    chain_links.append(next_link)
                    visited.add(next_link["to_id"])
                    current = next_link["to_id"]

            if len(chain_links) >= 2:
                chain_id = f"chain-auto-{uuid.uuid4().hex[:8]}"
                chain_name = " → ".join(
                    [chain_links[0]["from_label"]] +
                    [cl["to_label"] for cl in chain_links])

                # Determine impact from severity of final finding
                final_finding = next(
                    (f for f in all_findings if f["id"] == chain_links[-1]["to_id"]),
                    None)
                impact = (f"Multi-step chain ending at {chain_links[-1]['to_label']} "
                          f"({final_finding.get('severity', '?').upper() if final_finding else '?'})")

                try:
                    with neo4j_driver.session() as sess:
                        sess.run("""
                            CREATE (ac:AttackChain {
                                id: $id,
                                engagement_id: $eid,
                                name: $name,
                                impact: $impact,
                                priority: 1,
                                discovered_by: 'auto-detect',
                                links_count: $lc,
                                auto_detected: true,
                                created_at: datetime()
                            })
                        """, id=chain_id, eid=eid, name=chain_name,
                             impact=impact, lc=len(chain_links))

                        sess.run("""
                            MATCH (e:Engagement {id: $eid})
                            MATCH (ac:AttackChain {id: $cid})
                            MERGE (e)-[:HAS_CHAIN]->(ac)
                        """, eid=eid, cid=chain_id)

                    chains_created += 1
                    for cl in chain_links:
                        seen_chains.add(f"{cl['from_id']}->{cl['to_id']}")

                except Exception as e:
                    logger.warning("AttackChain node creation failed: %s", e)

    # 6. Emit dashboard events
    if links_created > 0:
        await _emit("system", "ST",
            f"Auto-detected {links_created} chain relationships, "
            f"{chains_created} attack chains",
            {"auto_chain_detect": True, "links": links_created,
             "chains": chains_created})

        await state.broadcast({
            "type": "chain_detect",
            "links_detected": links_created,
            "chains_created": chains_created,
            "engagement_id": eid,
            "timestamp": time.time(),
        })

    return {
        "chains": chains_created,
        "links": links_created,
        "same_host_links": len(new_links),
        "pivot_links": len(pivot_links),
        "findings_analyzed": len(all_findings),
        "hosts_analyzed": len(findings_by_host),
    }


@app.post("/api/chains/auto-detect")
async def trigger_chain_detection(engagement_id: str = "eng-001"):
    """Manually trigger attack chain auto-detection for an engagement.

    Analyzes all findings, detects chaining opportunities, and creates
    Neo4j relationships + AttackChain nodes. Idempotent (MERGE).
    """
    global _last_chain_detect
    # Reset debounce for manual trigger
    _last_chain_detect = 0.0
    result = await _auto_detect_chains(engagement_id)
    return {"ok": True, **result}


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
            def _query():
                with neo4j_driver.session() as session:
                    query = """
                        MATCH (e:Engagement)
                        OPTIONAL MATCH (f:Finding {engagement_id: e.id})
                        RETURN e.id AS id, e.name AS name, e.client AS client,
                               e.target AS target, e.scope AS scope, e.types AS type, e.status AS status,
                               e.start_date AS start_date,
                               count(DISTINCT f) AS findings_count
                        ORDER BY e.start_date DESC
                    """
                    result = session.run(query)
                    records = list(result)
                    return records
            records = await neo4j_exec(_query)
            engagements = []
            for record in records:
                status = record.get("status", "active")
                if not include_archived and status == "archived":
                    continue
                # Determine phase: if this is the active AI engagement, show "AI Mode"
                eid = record["id"]
                phase = "Active" if status == "active" else "—"
                if eid == state.active_engagement_id:
                    phase = "AI Mode"
                # Check if this engagement is currently paused
                is_paused = (eid == state.active_engagement_id and
                             not state.engagement_pause_event.is_set() and
                             state.engagement_task and not state.engagement_task.done())
                engagements.append({
                    "id": eid,
                    "name": record["name"],
                    "client": record.get("client", "Unknown"),
                    "scope": record.get("scope", ""),
                    "target": record.get("target") or record.get("scope", ""),
                    "type": record.get("type", "external"),
                    "status": "paused" if is_paused else status,
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
    target: str = ""  # URL/IP/CIDR of the target (e.g., http://example.com:3030)
    types: list[str] = ["external"]
    authorization: str = "manual"  # "documented" (SoW/RoE uploaded) or "manual" (operator assertion)
    evidence_mode: str = "exploitable"  # "exploitable" (only confirmed vulns) or "all" (capture everything)
    scope_doc: str = ""  # Full raw text from uploaded SoW/RoE — injected into agent prompt for scope enforcement
    client_industry: str = "general"  # healthcare, financial, government, saas, critical_infra, ai_ml, eu_regulated, general
    budget: float = 20.0  # BUG-011: Configurable engagement budget in USD (default $20)
    skip_agents: list[str] = []  # Agents to exclude (e.g. ["PR"] to skip OSINT, ["DA","PX"] to skip 0-day)


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
    global ENGAGEMENT_COST_CAP
    engagement_id = f"eng-{str(uuid.uuid4())[:6]}"
    start_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    types_str = ",".join(payload.types)

    # BUG-011: Apply configurable budget from payload
    if payload.budget > 0:
        ENGAGEMENT_COST_CAP = payload.budget

    if neo4j_available and neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                session.run("""
                    CREATE (e:Engagement {
                        id: $id,
                        name: $name,
                        client: $client,
                        target: $target,
                        scope: $scope,
                        scope_doc: $scope_doc,
                        types: $types,
                        authorization: $authorization,
                        evidence_mode: $evidence_mode,
                        client_industry: $client_industry,
                        budget: $budget,
                        skip_agents: $skip_agents,
                        status: 'active',
                        start_date: $start_date
                    })
                """, id=engagement_id, name=payload.name, client=payload.client,
                     target=payload.target, scope=payload.scope,
                     scope_doc=payload.scope_doc, types=types_str,
                     authorization=payload.authorization,
                     evidence_mode=payload.evidence_mode,
                     client_industry=payload.client_industry,
                     budget=payload.budget, skip_agents=",".join(payload.skip_agents),
                     start_date=start_date)

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
        target=payload.target or payload.scope,
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
    status: str | None = None
    name: str | None = None
    target: str | None = None
    scope: str | None = None
    type: str | None = None
    client: str | None = None
    authorization: str | None = None


@app.patch("/api/engagements/{eid}")
async def update_engagement(eid: str, payload: UpdateEngagementPayload):
    """Update engagement fields (status, name, target, scope, type, client, authorization)."""
    # Build dynamic SET clause from non-None fields
    updates = {}
    if payload.status is not None:
        updates["status"] = payload.status
    if payload.name is not None:
        updates["name"] = payload.name
    if payload.target is not None:
        updates["target"] = payload.target
        updates["scope"] = payload.target  # scope mirrors target
    if payload.scope is not None:
        updates["scope"] = payload.scope
    if payload.type is not None:
        updates["type"] = payload.type
    if payload.client is not None:
        updates["client"] = payload.client
    if payload.authorization is not None:
        updates["authorization"] = payload.authorization

    if not updates:
        return JSONResponse(status_code=400, content={"error": "No fields to update"})

    if neo4j_available and neo4j_driver:
        try:
            set_clauses = ", ".join(f"e.{k} = ${k}" for k in updates)
            cypher = f"MATCH (e:Engagement {{id: $id}}) SET {set_clauses}"
            with neo4j_driver.session() as session:
                session.run(cypher, id=eid, **updates)
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
            for k, v in updates.items():
                if hasattr(eng, k):
                    setattr(eng, k, v)
            break
    else:
        return JSONResponse(status_code=404, content={"error": "Engagement not found"})

    await state.broadcast({
        "type": "engagement_changed",
        "engagement_id": eid,
        "timestamp": time.time(),
    })
    return {"ok": True}


@app.get("/api/findings/trends")
async def get_findings_trends(
    scope: str = "engagement",
    engagement_id: str = "",
    client: str = "",
    target: str = "",
):
    """Return findings trend data for area chart.

    Scopes:
    - engagement: findings grouped by date within a single engagement
    - client: findings per engagement start_date, filtered by client name
    - target: findings per engagement start_date, filtered by target
    - all: findings per engagement start_date across all engagements
    """
    labels = []
    datasets = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
    engagements_included = 0

    if neo4j_available and neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                if scope == "engagement" and engagement_id:
                    # Single engagement: first try daily grouping
                    result = session.run("""
                        MATCH (f:Finding {engagement_id: $eid})
                        WITH f,
                             CASE WHEN f.timestamp > 0
                                  THEN date(datetime({epochSeconds: toInteger(f.timestamp)}))
                                  ELSE date()
                             END AS d
                        WITH d, toLower(f.severity) AS sev, count(f) AS cnt
                        RETURN toString(d) AS date, sev, cnt
                        ORDER BY d
                    """, eid=engagement_id)
                    engagements_included = 1

                    date_sev: dict = {}
                    for record in result:
                        d = record["date"]
                        sev = record["sev"] or "info"
                        if d not in date_sev:
                            date_sev[d] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
                        bucket = sev if sev in date_sev[d] else "info"
                        date_sev[d][bucket] = record["cnt"]

                    # Same-day engagement: switch to hourly buckets for meaningful chart
                    if len(date_sev) <= 1:
                        hourly_result = session.run("""
                            MATCH (f:Finding {engagement_id: $eid})
                            WHERE f.timestamp > 0
                            WITH f,
                                 datetime({epochSeconds: toInteger(f.timestamp)}) AS dt
                            WITH toString(dt.hour) + ':00' AS hour_label,
                                 dt.hour AS hour_num,
                                 toLower(f.severity) AS sev,
                                 count(f) AS cnt
                            RETURN hour_label, hour_num, sev, cnt
                            ORDER BY hour_num
                        """, eid=engagement_id)
                        hour_sev: dict = {}
                        for record in hourly_result:
                            h = record["hour_label"]
                            sev = record["sev"] or "info"
                            if h not in hour_sev:
                                hour_sev[h] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
                            bucket = sev if sev in hour_sev[h] else "info"
                            hour_sev[h][bucket] = record["cnt"]
                        if hour_sev:
                            labels = sorted(hour_sev.keys(), key=lambda x: int(x.split(':')[0]))
                            for sev_key in datasets:
                                datasets[sev_key] = [hour_sev[h].get(sev_key, 0) for h in labels]
                        else:
                            labels = sorted(date_sev.keys())
                            for sev_key in datasets:
                                datasets[sev_key] = [date_sev[d].get(sev_key, 0) for d in labels]
                    else:
                        labels = sorted(date_sev.keys())
                        for sev_key in datasets:
                            datasets[sev_key] = [date_sev[d].get(sev_key, 0) for d in labels]

                else:
                    # Cross-engagement: group by engagement start_date
                    where_clause = ""
                    params = {}
                    if scope == "client" and client:
                        where_clause = "WHERE e.client = $client"
                        params["client"] = client
                    elif scope == "target" and target:
                        where_clause = "WHERE e.target CONTAINS $target"
                        params["target"] = target
                    # scope == "all" → no WHERE clause

                    result = session.run(f"""
                        MATCH (e:Engagement)
                        {where_clause}
                        OPTIONAL MATCH (f:Finding {{engagement_id: e.id}})
                        WITH e.start_date AS start_date, e.name AS eng_name, e.id AS eng_id,
                             toLower(f.severity) AS sev, count(f) AS cnt
                        RETURN start_date, eng_name, eng_id, sev, cnt
                        ORDER BY start_date
                    """, **params)

                    # Aggregate by date (multiple engagements on same date get summed)
                    date_sev = {}
                    eng_ids = set()
                    for record in result:
                        sd = record["start_date"] or "Unknown"
                        sev = record["sev"] or "info"
                        if record["eng_id"]:
                            eng_ids.add(record["eng_id"])
                        if sd not in date_sev:
                            date_sev[sd] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
                        bucket = sev if sev in date_sev[sd] else "info"
                        date_sev[sd][bucket] += record["cnt"]

                    engagements_included = len(eng_ids)
                    labels = sorted(date_sev.keys())
                    for sev_key in datasets:
                        datasets[sev_key] = [date_sev[d].get(sev_key, 0) for d in labels]

            return {"labels": labels, "datasets": datasets, "engagements_included": engagements_included}
        except Exception as e:
            print(f"Neo4j trends query error: {e}")

    # Fallback: return empty trend data
    return {"labels": labels, "datasets": datasets, "engagements_included": engagements_included}


@app.get("/api/engagements/filters")
async def get_engagement_filters():
    """Return distinct client names and targets for trend filter dropdowns."""
    clients = set()
    targets = set()

    if neo4j_available and neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                result = session.run("""
                    MATCH (e:Engagement)
                    RETURN collect(DISTINCT e.client) AS clients,
                           collect(DISTINCT e.target) AS targets
                """)
                record = result.single()
                if record:
                    clients = {c for c in (record["clients"] or []) if c}
                    targets = {t for t in (record["targets"] or []) if t}
            return {"clients": sorted(clients), "targets": sorted(targets)}
        except Exception as e:
            print(f"Neo4j filters query error: {e}")

    # Fallback: extract from mock data
    for eng in state.engagements:
        if hasattr(eng, 'client') and eng.client:
            clients.add(eng.client)
        if hasattr(eng, 'target') and eng.target:
            targets.add(eng.target)
    return {"clients": sorted(clients), "targets": sorted(targets)}


@app.post("/api/engagements/{eid}/clear")
async def clear_engagement_data(eid: str, mode: str = "clear"):
    """Clear or reset data for an engagement.

    mode=clear (default): Wipe ALL data (findings, scans, evidence, graph, events, budgets).
    mode=continue: Reset agent states only — keep all findings, scans, evidence, and Neo4j
        data intact so ST can resume from where it left off. Sets status back to 'active'.
    """
    if not re.fullmatch(r'eng-[a-f0-9]{6}', eid):
        return JSONResponse(status_code=400, content={"error": "Invalid engagement ID format"})

    global _agent_budgets, _engagement_cost, _engagement_cost_eid

    if mode == "continue":
        # Reset agent states and budgets so ST can re-spawn, but preserve all finding data
        _agent_budgets = {}
        _engagement_cost = 0.0
        _engagement_cost_eid = ""
        if hasattr(state, '_engagement_cap_warned'):
            state._engagement_cap_warned = False

        for code in state.agent_statuses:
            state.agent_statuses[code] = AgentStatus.IDLE
        state.agent_tasks.clear()

        # Set engagement status back to active
        for eng in state.engagements:
            if eng.id == eid:
                eng.status = "active"
                break

        if neo4j_available and neo4j_driver:
            try:
                with neo4j_driver.session() as session:
                    session.run(
                        "MATCH (e:Engagement {id: $eid}) SET e.status = 'active'",
                        eid=eid,
                    )
            except Exception as e:
                logger.warning("Continue mode Neo4j status update error: %s", str(e)[:200])

        logger.info("[CLEAR/continue] Engagement %s agent states reset — findings preserved", eid)

        await state.broadcast({
            "type": "engagement_cleared",
            "engagement_id": eid,
            "mode": "continue",
            "timestamp": time.time(),
        })

        return {"ok": True, "mode": "continue", "message": "Agent states reset. Findings and scan data preserved."}

    # mode=clear (default): wipe everything
    cleared = {"findings": 0, "events": 0, "graph": 0}

    if neo4j_available and neo4j_driver:
        def _clear_scoped(eid: str) -> dict:
            result = {}
            try:
                with neo4j_driver.session() as session:
                    r = session.run("""
                        MATCH (n)
                        WHERE n.engagement_id = $eid AND NOT n:Engagement
                        DETACH DELETE n
                        RETURN count(*) AS deleted
                    """, eid=eid)
                    result["graph"] = r.single()["deleted"]
                    session.run("""
                        MATCH (e:Engagement {id: $eid})
                        REMOVE e.engagement_cost, e.phase, e.findings_count,
                               e.first_shell_at, e.first_shell_agent,
                               e.first_shell_method, e.first_shell_target,
                               e.first_ex_spawn_at,
                               e.completed_at, e.mtte_seconds
                    """, eid=eid)
                    r2 = session.run("""
                        MATCH (ev:Event)
                        WHERE ev.engagement_id = $eid
                        DETACH DELETE ev
                        RETURN count(*) AS deleted
                    """, eid=eid)
                    result["events"] = r2.single()["deleted"]
            except Exception as e:
                logger.warning("Clear engagement data error: %s", str(e)[:200])
            return result
        cleared = await neo4j_exec(lambda: _clear_scoped(eid))

    _agent_budgets = {}
    _engagement_cost = 0.0
    _engagement_cost_eid = ""
    if hasattr(state, '_engagement_cap_warned'):
        state._engagement_cap_warned = False

    state.findings = [f for f in state.findings if f.engagement != eid]
    state.scans = [s for s in state.scans if s.get("engagement_id") != eid]
    state._reports = [r for r in state._reports if r.get("engagement_id") != eid]
    state.events = [e for e in state.events if (e.metadata or {}).get("engagement_id") != eid]
    state._credentials.pop(eid, None)

    for code in state.agent_statuses:
        state.agent_statuses[code] = AgentStatus.IDLE
    state.agent_tasks.clear()

    try:
        ev_dir = athena_dir / "engagements" / "active" / eid / "08-evidence"
        if ev_dir.exists():
            import shutil
            shutil.rmtree(ev_dir, ignore_errors=True)
            ev_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

    try:
        reports_dir = Path("reports")
        if reports_dir.exists():
            for f in reports_dir.glob(f"*{eid}*"):
                f.unlink(missing_ok=True)
    except Exception:
        pass

    logger.info("[CLEAR] Engagement %s data cleared: %s", eid, cleared)

    await state.broadcast({
        "type": "engagement_cleared",
        "engagement_id": eid,
        "mode": "clear",
        "timestamp": time.time(),
    })

    return {"ok": True, "mode": "clear", "cleared": cleared}


@app.delete("/api/engagements/{eid}")
async def delete_engagement(eid: str, purge_cei: bool = False):
    """Delete an engagement and ALL related data permanently.

    If purge_cei=True, also removes intelligence contributions:
    - TechniqueRecords ONLY linked to this engagement are deleted
    - TechniqueRecords linked to other engagements keep data, just sever the link
    """
    # P2-FIX: Validate eid format to prevent glob metachar injection
    if not re.fullmatch(r'eng-[a-f0-9]{6}', eid):
        return JSONResponse(status_code=400, content={"error": "Invalid engagement ID format"})

    deleted_data = {"engagement": False, "graph": False, "scans": False, "reports": False, "budgets": False, "cei_purged": 0}

    def _neo4j_delete_scoped(eid: str) -> dict:
        """Delete only nodes scoped to this engagement (runs in thread)."""
        result = {}
        try:
            with neo4j_driver.session() as session:
                # Delete all nodes with engagement_id property
                session.run("""
                    MATCH (n)
                    WHERE n.engagement_id = $eid
                    DETACH DELETE n
                """, eid=eid)
                result["graph"] = True
                result["scans"] = True
                # Delete the Engagement node itself (uses 'id', not 'engagement_id')
                session.run(
                    "MATCH (e:Engagement {id: $eid}) DETACH DELETE e",
                    eid=eid,
                )
                result["engagement"] = True
        except Exception as e:
            print(f"Neo4j delete engagement data error: {e}")
        return result

    if neo4j_available and neo4j_driver:
        print(f"[DELETE] Starting Neo4j cleanup for {eid}...")
        neo4j_result = await neo4j_exec(lambda: _neo4j_delete_scoped(eid))
        print(f"[DELETE] Neo4j done: {neo4j_result}")
        deleted_data.update(neo4j_result)
    else:
        print(f"[DELETE] No Neo4j — skipping graph cleanup")

    print("[DELETE] Cleaning in-memory state...")
    # 5. Reset in-memory budgets and cost tracking
    global _agent_budgets, _engagement_cost
    _agent_budgets = {}
    _engagement_cost = 0.0
    if hasattr(state, '_engagement_cap_warned'):
        state._engagement_cap_warned = False
    deleted_data["budgets"] = True

    # 6. Delete reports from disk for this engagement
    try:
        reports_dir = Path("reports")
        if reports_dir.exists():
            for f in reports_dir.glob(f"*{eid}*"):
                f.unlink(missing_ok=True)
        deleted_data["reports"] = True
    except Exception as e:
        print(f"Report cleanup error: {e}")

    # 7. Reset in-memory agent states
    for code in state.agent_statuses:
        state.agent_statuses[code] = AgentStatus.IDLE
    state.agent_tasks.clear()

    # 8. Clear in-memory findings, scans, events, reports for this engagement
    state.findings = [f for f in state.findings if f.engagement != eid]
    state.scans = [s for s in state.scans if s.get("engagement_id") != eid]
    state._reports = [r for r in state._reports if r.get("engagement_id") != eid]
    state.events = [e for e in state.events if (e.metadata or {}).get("engagement_id") != eid]
    state._credentials.pop(eid, None)

    # Remove engagement from in-memory list
    state.engagements = [e for e in state.engagements if e.id != eid]

    # 9. Purge CEI intelligence data if requested
    if purge_cei and neo4j_available and neo4j_driver:
        def _purge_cei(eid: str) -> int:
            purged = 0
            try:
                with neo4j_driver.session() as session:
                    # Count TechniqueRecords ONLY linked to this engagement (before deleting)
                    count_result = session.run("""
                        MATCH (t:TechniqueRecord)-[:USED_IN]->(e:Engagement {id: $eid})
                        WHERE NOT EXISTS {
                            MATCH (t)-[:USED_IN]->(other:Engagement)
                            WHERE other.id <> $eid
                        }
                        RETURN count(t) AS to_delete
                    """, eid=eid)
                    record = count_result.single()
                    purged = record["to_delete"] if record else 0

                    # Now delete those single-engagement TechniqueRecords
                    if purged > 0:
                        session.run("""
                            MATCH (t:TechniqueRecord)-[:USED_IN]->(e:Engagement {id: $eid})
                            WHERE NOT EXISTS {
                                MATCH (t)-[:USED_IN]->(other:Engagement)
                                WHERE other.id <> $eid
                            }
                            DETACH DELETE t
                        """, eid=eid)

                    # For multi-engagement TechniqueRecords, just remove the relationship
                    session.run("""
                        MATCH (t:TechniqueRecord)-[r:USED_IN]->(e:Engagement {id: $eid})
                        DELETE r
                    """, eid=eid)
            except Exception as e:
                logger.warning("CEI purge for engagement %s: %s", eid, e)
            return purged

        cei_purged = await neo4j_exec(lambda: _purge_cei(eid))
        deleted_data["cei_purged"] = cei_purged
        print(f"[DELETE] CEI purge: {cei_purged} technique records deleted")

    print("[DELETE] Broadcasting engagement_changed...")
    await state.broadcast({
        "type": "engagement_changed",
        "engagement_id": eid,
        "timestamp": time.time(),
    })
    print("[DELETE] Done! Returning response.")
    return {"ok": True, "cascade_deleted": deleted_data}


@app.get("/api/engagements/{eid}/summary")
async def get_engagement_summary(eid: str):
    """Get engagement statistics from Neo4j or mock data."""
    if neo4j_available and neo4j_driver:
        try:
            def _query():
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
                               count(DISTINCT CASE WHEN
                                   f.verified = true OR
                                   f.verification_status = 'confirmed' OR
                                   f.verification_status = 'likely'
                               THEN f END) AS exploits,
                               e.started_at AS started_at, e.completed_at AS completed_at,
                               e.first_shell_at AS first_shell_at,
                               e.first_ex_spawn_at AS first_ex_spawn_at,
                               e.evidence_mode AS evidence_mode
                    """, eid=eid)
                    record = result.single()
                    if record is None:
                        return None, None
                    raw_hosts = record["hosts"]
                    ip_list = []
                    if raw_hosts > 0:
                        ip_result = session.run(
                            "MATCH (h:Host {engagement_id: $eid}) RETURN h.ip AS ip",
                            eid=eid,
                        )
                        ip_list = [r["ip"] or "" for r in ip_result]
                    return dict(record), ip_list
            neo4j_record, ip_list = await neo4j_exec(_query)
            if neo4j_record:
                record = neo4j_record
                neo4j_hosts = record["hosts"]
                # BUG-036: Subtract version-string Host nodes (e.g. "3.2.8.1" from UnrealIRCd)
                # that were created directly via MCP tools, bypassing _safe_extract_host.
                # We fetch Host IPs in a lightweight query and filter in Python.
                if neo4j_hosts > 0:
                    version_string_count = sum(
                        1 for ip in ip_list if _is_version_string_ip(ip)
                    )
                    neo4j_hosts = max(0, neo4j_hosts - version_string_count)
                neo4j_services = record["services"]
                neo4j_findings = record["findings"]
                # If Neo4j has real Host/Service data, use it; otherwise supplement from in-memory state
                if neo4j_hosts > 0 or neo4j_findings > 0:
                    # Supplement: if Neo4j has findings but no Host nodes, derive from in-memory findings
                    mem_findings = [f for f in state.findings if f.engagement == eid]
                    mem_hosts = set()
                    for f in mem_findings:
                        if f.target:
                            h = _safe_extract_host(f.target)
                            if h:
                                mem_hosts.add(h)
                    # Count ports from scans first, then fallback to finding targets
                    import re as _re_mp
                    # BUG-027: Use keyword matching — MCP tools have prefix (mcp__kali_external__naabu_scan)
                    _port_kw = ("nmap", "naabu")
                    mem_ports = sum(s.get("findings_count", 0) for s in state.scans
                                    if s.get("engagement_id") == eid
                                    and any(kw in (s.get("tool") or "").lower() for kw in _port_kw))
                    if mem_ports == 0:
                        # Extract unique ports from finding targets
                        port_set = set()
                        for f in mem_findings:
                            target = f.target or ""
                            pm = _re_mp.search(r':(\d+)', target)
                            if pm:
                                pn = int(pm.group(1))
                                if 1 <= pn <= 65535:
                                    port_set.add(pn)
                        mem_ports = len(port_set)
                    # Use max of Neo4j and in-memory severity counts (handles missing BELONGS_TO)
                    mem_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
                    # BUG-022 FIX: Count exploits using VF-confirmed logic ONLY.
                    # Previously used keyword+agent+evidence heuristics which gave a
                    # higher count than exploit-stats, causing KPI mismatch.
                    # Now aligned: both /summary and /exploit-stats count the same way.
                    mem_exploits = 0
                    for f in mem_findings:
                        s = f.severity.value if hasattr(f.severity, 'value') else str(f.severity).lower()
                        if s in mem_sev:
                            mem_sev[s] += 1
                        has_confirmed_ts = bool(getattr(f, 'confirmed_at', None))
                        verification = getattr(f, 'verification_status', '') or ''
                        if has_confirmed_ts or verification in ('confirmed', 'likely'):
                            mem_exploits += 1
                    # BUG-039 FIX: Monotonic increase for services/ports during active engagement.
                    # Use a high-water mark so the KPI never decreases during a pentest.
                    services_now = max(neo4j_services, mem_ports)
                    if not hasattr(state, '_hwm_services'):
                        state._hwm_services = {}
                    state._hwm_services[eid] = max(state._hwm_services.get(eid, 0), services_now)
                    _eng_obj = next((e for e in state.engagements if e.id == eid), None)
                    _started = getattr(_eng_obj, 'started_at', None) if _eng_obj else record.get("started_at")
                    _completed = getattr(_eng_obj, 'completed_at', None) if _eng_obj else record.get("completed_at")
                    _duration = round((_completed or time.time()) - _started, 1) if _started else None
                    return {
                        "hosts": max(neo4j_hosts, len(mem_hosts)),
                        "services": state._hwm_services[eid],
                        "vulnerabilities": record["vulns"],
                        "findings": max(neo4j_findings, len(mem_findings)),
                        "exploits": max(record["exploits"], mem_exploits),
                        "severity": {
                            "critical": max(record["sev_critical"], mem_sev["critical"]),
                            "high": max(record["sev_high"], mem_sev["high"]),
                            "medium": max(record["sev_medium"], mem_sev["medium"]),
                            "low": max(record["sev_low"], mem_sev["low"]),
                        },
                        "duration_seconds": _duration,
                        "started_at": _started,
                        "completed_at": _completed,
                        "first_shell_at": record.get("first_shell_at"),
                        "first_ex_spawn_at": record.get("first_ex_spawn_at"),
                        "evidence_mode": record.get("evidence_mode", "exploitable"),
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
            host = _safe_extract_host(f.target)
            if host:
                hosts.add(host)
    # Count open ports from scan data
    eng_scans = [s for s in state.scans if s.get("engagement_id") == eid]
    # BUG-027: Use keyword matching — MCP tools have prefix (mcp__kali_external__naabu_scan)
    _port_scan_kw = ("nmap", "naabu")
    total_ports = sum(
        s.get("findings_count", 0) for s in eng_scans
        if any(kw in (s.get("tool") or "").lower() for kw in _port_scan_kw)
    )
    # Fallback 1: parse port counts from nmap/naabu output if findings_count was 0
    if total_ports == 0:
        import re
        for s in eng_scans:
            if any(kw in (s.get("tool") or "").lower() for kw in _port_scan_kw) and s.get("output_preview"):
                # Match nmap output format: "22/tcp open ssh" or "PORT  STATE"
                port_matches = re.findall(r'(\d+)/(?:tcp|udp)\s+open', s["output_preview"])
                if not port_matches:
                    port_matches = re.findall(r'PORT\s+\d+', s["output_preview"])
                total_ports += len(port_matches)
    # Fallback 2: extract unique ports from finding targets (e.g., "10.1.1.25:22")
    if total_ports == 0:
        port_set = set()
        for f in eng_findings:
            target = f.target or ""
            port_match = re.search(r':(\d+)', target)
            if port_match:
                port_num = int(port_match.group(1))
                if 1 <= port_num <= 65535:
                    port_set.add(port_num)
        total_ports = len(port_set)
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    # BUG-037 fix: Align exploit counting with exploit-stats endpoint.
    # Only count VF-confirmed findings as exploits (consistent with exploit-stats).
    # Previously used keyword heuristic that inflated the count.
    exploits = 0
    for f in eng_findings:
        s = f.severity.value if hasattr(f.severity, 'value') else str(f.severity).lower()
        if s in sev_counts:
            sev_counts[s] += 1
        has_confirmed_ts = bool(getattr(f, 'confirmed_at', None))
        verification = getattr(f, 'verification_status', '') or ''
        is_confirmed = has_confirmed_ts or verification in ('confirmed', 'likely')
        if is_confirmed:
            exploits += 1

    _eng_fb = next((e for e in state.engagements if e.id == eid), None)
    _started_fb = getattr(_eng_fb, 'started_at', None) if _eng_fb else None
    _completed_fb = getattr(_eng_fb, 'completed_at', None) if _eng_fb else None
    _duration_fb = round((_completed_fb or time.time()) - _started_fb, 1) if _started_fb else None

    # Always fetch engagement-level properties (evidence_mode, shell timestamps)
    # These are on the Engagement node itself, independent of findings count
    _eng_props = {}
    if neo4j_available and neo4j_driver:
        try:
            def _get_eng_props():
                with neo4j_driver.session() as session:
                    r = session.run("""
                        MATCH (e:Engagement {id: $eid})
                        RETURN e.evidence_mode AS evidence_mode,
                               e.first_shell_at AS first_shell_at,
                               e.first_ex_spawn_at AS first_ex_spawn_at
                    """, eid=eid).single()
                    return dict(r) if r else {}
            _eng_props = await neo4j_exec(_get_eng_props)
        except Exception:
            pass

    return {
        "hosts": len(hosts),
        "services": total_ports,
        # BUG-007 fix: vulnerabilities should match findings count (no separate Vulnerability
        # nodes in memory-only mode). Previously had buggy `>= 0` condition that was always True.
        "vulnerabilities": len(eng_findings),
        "findings": len(eng_findings),
        "exploits": exploits,
        "severity": sev_counts,
        "duration_seconds": _duration_fb,
        "started_at": _started_fb,
        "completed_at": _completed_fb,
        "first_shell_at": _eng_props.get("first_shell_at"),
        "first_ex_spawn_at": _eng_props.get("first_ex_spawn_at"),
        "evidence_mode": _eng_props.get("evidence_mode", "exploitable"),
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
                    vuln_id = record.get("id")
                    if not vuln_id:
                        continue
                    findings.append({
                        "id": vuln_id,
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
            def _query():
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

                    result = session.run("""
                        MATCH (f:Finding {engagement_id: $eid})
                        OPTIONAL MATCH (f)-[:FOUND_ON]->(h:Host)
                        WITH f, collect(DISTINCT h.ip) AS affected_hosts
                        OPTIONAL MATCH (f)-[:EVIDENCED_BY]->(ep:EvidencePackage)
                        OPTIONAL MATCH (f)-[:HAS_ARTIFACT]->(art:Artifact)
                        OPTIONAL MATCH (prop_art:Artifact {finding_id: f.id})
                        RETURN f.id AS id, f.title AS title, f.severity AS severity,
                               f.cvss AS cvss, f.status AS status, f.category AS category,
                               f.description AS description, f.target AS target,
                               f.evidence AS evidence, affected_hosts,
                               f.agent AS agent, f.timestamp AS timestamp,
                               count(DISTINCT ep) + count(DISTINCT art) + count(DISTINCT prop_art) AS evidence_count
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
                        # Derive evidence_count from evidence text if no relationships found
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
                            "agent": record.get("agent", ""),
                            "timestamp": _normalize_ts(record.get("timestamp")),
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
                        vuln_id = record.get("id")
                        if not vuln_id:
                            continue
                        host_part = ""
                        t = record.get("target", "")
                        if t:
                            host_part = t.split(":")[0] if ":" in t else t
                        findings.append({
                            "id": vuln_id,
                            "title": record["title"],
                            "severity": record["severity"],
                            "cvss": record.get("cvss"),
                            "status": "discovered",
                            "category": record.get("category", ""),
                            "description": record.get("description", ""),
                            "affected_hosts": [host_part] if host_part else [],
                            "evidence_count": 0,
                        })

                    # BUG-042 fix: Merge in-memory findings not yet persisted to Neo4j
                    neo4j_ids = {f["id"] for f in findings}
                    mem_findings = [f for f in state.findings if f.engagement == eid]
                    for f in mem_findings:
                        if f.id not in neo4j_ids:
                            findings.append({
                                "id": f.id,
                                "title": f.title,
                                "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity).lower(),
                                "cvss": f.cvss,
                                "status": "open",
                                "category": f.category,
                                "description": f.description,
                                "affected_hosts": [f.target],
                                "evidence_count": 1 if f.evidence else 0,
                            })
                    return findings
            findings = await neo4j_exec(_query)
            if findings:
                return findings
        except Exception as e:
            print(f"Neo4j findings query error: {e}")
            # Fall through to in-memory

    # Fallback: filter in-memory findings
    results = [f for f in state.findings if f.engagement == eid]
    return [{
        "id": f.id,
        "title": f.title,
        "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity).lower(),
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
                    MATCH (f:Finding {engagement_id: $eid})
                    RETURN toLower(f.severity) AS severity, count(DISTINCT f) AS cnt
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

    # BUG-042 fix: Take max of Neo4j and in-memory severity counts (same race condition)
    mem_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    mem_total = 0
    mem_findings = [f for f in state.findings if f.engagement == eid]
    # BUG-NEW-005 fix: Deduplicate findings before counting to avoid inflated
    # "Unique Vulnerabilities" numbers when the same vuln appears multiple times.
    seen_fingerprints = set()
    seen_title_keys = set()
    for f in mem_findings:
        # Deduplicate by fingerprint (same vuln on same target)
        fp = getattr(f, 'fingerprint', None)
        if fp:
            if fp in seen_fingerprints:
                continue
            seen_fingerprints.add(fp)
        else:
            # Fallback dedup: normalized title + category
            title_key = f"{getattr(f, 'category', '')}:{getattr(f, 'title', '')[:50].lower().strip()}"
            if title_key in seen_title_keys:
                continue
            seen_title_keys.add(title_key)

        sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity).lower()
        if sev in mem_counts:
            mem_counts[sev] += 1
        else:
            mem_counts["info"] += 1
        mem_total += 1
    # Use whichever source has higher counts
    for sev in counts:
        counts[sev] = max(counts[sev], mem_counts.get(sev, 0))
    total = max(total, mem_total)

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
                # BUG-031 fix: Only count VF-confirmed findings as confirmed exploits.
                # Previous query was too broad (any high severity or EX agent counted).
                # Confirmed = verified by VF agent OR has EXPLOITS edge in graph.
                result = session.run("""
                    MATCH (e:Engagement {id: $eid})
                    OPTIONAL MATCH (f:Finding {engagement_id: $eid})
                    WITH e, collect(f) AS all_findings
                    RETURN size(all_findings) AS total_findings,
                           size([x IN all_findings WHERE
                               x.verified = true OR
                               x.verification_status = 'confirmed' OR
                               x.verification_status = 'likely'
                           ]) AS exploit_count,
                           [x IN all_findings WHERE
                               x.verified = true OR
                               x.verification_status = 'confirmed' OR
                               x.verification_status = 'likely' |
                               {title: x.title, severity: x.severity, timestamp: x.timestamp}] AS exploit_details
                """, eid=eid)
                record = result.single()
                if record and record["total_findings"] > 0:
                    discovered = record["total_findings"]
                    confirmed = record["exploit_count"]
                    # CVE-level dedup: same CVE on same host = 1 confirmed exploit
                    import re as _re_dedup
                    seen_cve_keys = set()
                    deduped_confirmed = 0
                    deduped_details = []
                    for ex in (record["exploit_details"] or []):
                        title = ex.get("title") or ""
                        cve_match = _re_dedup.search(r'CVE-\d{4}-\d+', title, _re_dedup.IGNORECASE)
                        cve = cve_match.group(0).upper() if cve_match else ""
                        # Key: CVE → host:port → title fallback (handles 0-days, default creds)
                        _host = ex.get("host_ip") or ex.get("target") or ""
                        _port_match = _re_dedup.search(r':(\d+)', _host) or _re_dedup.search(r'port\s*(\d+)', title, _re_dedup.IGNORECASE)
                        _port = _port_match.group(1) if _port_match else ""
                        if cve:
                            key = cve
                        elif _host and _port:
                            key = f"{_host}:{_port}"
                        else:
                            key = title[:40].lower().strip()
                        if key and key not in seen_cve_keys:
                            seen_cve_keys.add(key)
                            deduped_confirmed += 1
                            deduped_details.append(ex)
                    confirmed = deduped_confirmed
                    for ex in deduped_details:
                        sev = (ex.get("severity") or "medium").lower()
                        if sev in by_severity:
                            by_severity[sev] += 1
        except Exception as e:
            print(f"Neo4j exploit-stats error: {e}")

    # BUG-042 fix: Take MAX of Neo4j and in-memory counts to prevent race condition.
    # In-memory state is updated immediately when agents report findings, but Neo4j
    # persistence is async. Using either/or caused the Exploit Rate to spike then drop
    # when Neo4j returned partial data (non-zero but lower than in-memory).
    # BUG-S2-004 fix: Exclude port/batch summary findings from discovered count.
    SUMMARY_PATTERNS = ('open tcp port', 'open udp port', 'open ports', 'cves confirmed', 'cves detected')
    mem_findings = [f for f in state.findings if f.engagement == eid]
    mem_findings_clean = [
        f for f in mem_findings
        if not any(pat in (f.title or '').lower() for pat in SUMMARY_PATTERNS)
    ]
    mem_discovered = len(mem_findings_clean)
    mem_confirmed = 0
    mem_by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    import re as _re_dedup_mem
    seen_mem_cve_keys = set()
    for f in mem_findings_clean:
        sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity).lower()
        has_confirmed_ts = bool(getattr(f, 'confirmed_at', None))
        verification = getattr(f, 'verification_status', '') or ''
        is_confirmed = has_confirmed_ts or verification in ('confirmed', 'likely')
        if is_confirmed:
            # CVE-level dedup with host:port fallback for 0-days
            title = f.title or ""
            cve_match = _re_dedup_mem.search(r'CVE-\d{4}-\d+', title, _re_dedup_mem.IGNORECASE)
            cve = cve_match.group(0).upper() if cve_match else ""
            _host = getattr(f, 'target', '') or getattr(f, 'host_ip', '') or ''
            _port_match = _re_dedup_mem.search(r':(\d+)', _host) or _re_dedup_mem.search(r'port\s*(\d+)', title, _re_dedup_mem.IGNORECASE)
            _port = _port_match.group(1) if _port_match else ""
            if cve:
                mem_key = cve
            elif _host and _port:
                mem_key = f"{_host}:{_port}"
            else:
                mem_key = title[:40].lower().strip()
            if mem_key and mem_key in seen_mem_cve_keys:
                continue
            if mem_key:
                seen_mem_cve_keys.add(mem_key)
            mem_confirmed += 1
            if sev in mem_by_severity:
                mem_by_severity[sev] += 1
    # Use whichever source has the higher count (both are authoritative, just async)
    if mem_discovered > discovered:
        discovered = mem_discovered
    if mem_confirmed > confirmed:
        confirmed = mem_confirmed
        for sev in by_severity:
            by_severity[sev] = max(by_severity[sev], mem_by_severity.get(sev, 0))

    # BUG-029: Count exploited-but-unverified findings (EX succeeded, VF didn't confirm)
    # BUG-S2-004 fix: Scope to EX agent only — not all evidenced findings.
    exploited_unverified = 0
    if neo4j_available and neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                result = session.run("""
                    MATCH (f:Finding {engagement_id: $eid})
                    WHERE f.agent = 'EX'
                      AND (
                        (f.evidence IS NOT NULL AND f.evidence <> '')
                        OR EXISTS { (f)-[:HAS_ARTIFACT]->(:Artifact) }
                        OR EXISTS { (f)-[:EVIDENCED_BY]->(:EvidencePackage) }
                      )
                      AND (f.verified IS NULL OR f.verified = false)
                      AND (f.verification_status IS NULL OR (f.verification_status <> 'confirmed' AND f.verification_status <> 'likely'))
                    RETURN count(f) AS cnt
                """, eid=eid)
                rec = result.single()
                if rec:
                    exploited_unverified = rec["cnt"]
        except Exception:
            pass
    # BUG-042 fix: Same max-of-both-sources pattern for exploited_unverified
    # CVE-level dedup applied (same pattern as confirmed)
    import re as _re_unver
    mem_exploited_unverified = 0
    seen_unver_cve_keys = set()
    for f in mem_findings_clean:
        agent_val = getattr(f, 'agent', '') or ''
        is_ex = agent_val == 'EX' or (isinstance(agent_val, list) and 'EX' in agent_val)
        if not is_ex:
            continue
        has_evidence = bool(f.evidence) or getattr(f, 'evidence_count', 0) > 0
        has_confirmed_ts = bool(getattr(f, 'confirmed_at', None))
        verification = getattr(f, 'verification_status', '') or ''
        is_confirmed = has_confirmed_ts or verification in ('confirmed', 'likely')
        if has_evidence and not is_confirmed:
            # CVE dedup with host:port fallback for 0-days
            title = getattr(f, 'title', '') or ''
            cve_match = _re_unver.search(r'CVE-\d{4}-\d+', title, _re_unver.IGNORECASE)
            cve = cve_match.group(0).upper() if cve_match else ""
            _host = getattr(f, 'target', '') or getattr(f, 'host_ip', '') or ''
            _port_match = _re_unver.search(r':(\d+)', _host) or _re_unver.search(r'port\s*(\d+)', title, _re_unver.IGNORECASE)
            _port = _port_match.group(1) if _port_match else ""
            if cve:
                key = cve
            elif _host and _port:
                key = f"{_host}:{_port}"
            else:
                key = title[:40].lower().strip()
            if key and key not in seen_unver_cve_keys:
                seen_unver_cve_keys.add(key)
                mem_exploited_unverified += 1
    if mem_exploited_unverified > exploited_unverified:
        exploited_unverified = mem_exploited_unverified

    total_exploited = confirmed + exploited_unverified
    success_rate = round((confirmed / max(discovered, 1)) * 100, 1)

    # MTTE: estimate from timestamp spread of findings (simplified)
    # BUG-S2-001 fix: Filter to EX-agent findings with actual exploitation evidence only.
    # Previous filter used severity-based matching which pulled in non-exploited findings.
    EXPLOIT_TITLE_KEYWORDS = ('root shell', 'rce confirmed', 'backdoor', 'shell obtained',
                               'command execution', 'remote code execution', 'meterpreter',
                               'exploit confirmed', 'access confirmed')
    timestamps = sorted([f.timestamp for f in mem_findings_clean])
    exploit_findings = [
        f for f in mem_findings_clean
        if (
            # Explicit EX agent
            (getattr(f, 'agent', '') == 'EX' or (isinstance(getattr(f, 'agent', None), list) and 'EX' in f.agent))
            # OR agent is None/empty but title indicates exploitation
            or (not getattr(f, 'agent', None) and any(kw in (f.title or '').lower() for kw in EXPLOIT_TITLE_KEYWORDS))
        )
        and (
            bool(f.evidence)
            or bool(getattr(f, 'confirmed_at', None))
            or any(kw in (f.title or '').lower() for kw in EXPLOIT_TITLE_KEYWORDS)
        )
    ]
    # Use engagement start time for MTTE, not first finding time
    eng_start_ts = None
    for eng in state.engagements:
        if eng.id == eid and hasattr(eng, 'started_at') and eng.started_at:
            eng_start_ts = eng.started_at
            break
    # Fallback: read started_at from Neo4j when in-memory state is cold
    if eng_start_ts is None and neo4j_available and neo4j_driver:
        try:
            def _get_started_at():
                with neo4j_driver.session() as neo_s:
                    r = neo_s.run(
                        "MATCH (e:Engagement {id: $eid}) RETURN e.started_at AS started_at",
                        eid=eid,
                    ).single()
                    return r["started_at"] if r and r["started_at"] else None
            eng_start_ts = await neo4j_exec(_get_started_at)
        except Exception:
            pass
    if eng_start_ts is None and timestamps:
        eng_start_ts = timestamps[0]  # fallback to first finding

    # BUG-S2-001 fix: MTTE = time to FIRST EX exploit, not average across all.
    exploit_findings.sort(key=lambda x: x.timestamp if x.timestamp else float('inf'))
    if eng_start_ts and exploit_findings:
        first = exploit_findings[0]
        delta = max(0, int(first.timestamp - eng_start_ts))
        per_finding_times = [{"title": first.title[:80], "time_s": delta}]
        mtte_seconds = delta

    # MTTE: compute from Neo4j finding timestamps when in-memory is empty
    if not per_finding_times and neo4j_available and neo4j_driver:
        try:
            def _to_epoch(ts):
                """Convert Neo4j DateTime or python value to epoch float."""
                if isinstance(ts, (int, float)):
                    return float(ts)
                # neo4j.time.DateTime has .to_native() → python datetime
                if hasattr(ts, 'to_native'):
                    dt = ts.to_native()
                    return dt.timestamp()
                # python datetime
                if hasattr(ts, 'timestamp'):
                    return ts.timestamp()
                return 0.0

            # BUG-S2-001 fix: Filter to EX agent only; remove severity-based matching.
            def _mtte_query():
                with neo4j_driver.session() as session:
                    result = session.run("""
                        MATCH (f:Finding {engagement_id: $eid})
                        WHERE f.timestamp IS NOT NULL
                          AND (
                            f.agent = 'EX'
                            OR (f.agent IS NULL AND (
                              f.title CONTAINS 'shell' OR f.title CONTAINS 'backdoor' OR
                              f.title CONTAINS 'RCE' OR f.title CONTAINS 'Command Execution' OR
                              f.title CONTAINS 'exploit' OR f.title CONTAINS 'root'
                            ))
                          )
                          AND (f.evidence IS NOT NULL OR f.confirmed_at IS NOT NULL)
                        RETURN f.title AS title, f.timestamp AS ts
                        ORDER BY f.timestamp ASC
                    """, eid=eid)
                    return [dict(record) for record in result]
            records = await neo4j_exec(_mtte_query)
            all_ts = []
            neo4j_exploit_findings = []
            for record in records:
                ts_epoch = _to_epoch(record["ts"])
                if ts_epoch > 0:
                    all_ts.append(ts_epoch)
                    neo4j_exploit_findings.append({"title": record["title"], "ts": ts_epoch})
            # BUG-S2-001 fix: MTTE = time to first EX exploit only.
            if all_ts and neo4j_exploit_findings:
                neo4j_start_ts = eng_start_ts if eng_start_ts is not None else all_ts[0]
                first_neo = neo4j_exploit_findings[0]
                delta = max(0, int(first_neo["ts"] - neo4j_start_ts))
                per_finding_times = [{"title": first_neo["title"], "time_s": delta}]
                mtte_seconds = delta
        except Exception as e:
            print(f"Neo4j MTTE query error: {e}")

    # Format MTTE display
    if mtte_seconds > 0:
        mins, secs = divmod(mtte_seconds, 60)
        mtte_display = f"{mins}m {secs:02d}s" if mins else f"{secs}s"
    else:
        mtte_display = "—"

    # TTFS: Time to First Shell — read from Engagement node
    ttfs_seconds = 0
    ttfs_display = "—"
    if neo4j_available and neo4j_driver:
        try:
            def _get_ttfs():
                with neo4j_driver.session() as session:
                    r = session.run("""
                        MATCH (e:Engagement {id: $eid})
                        RETURN e.first_shell_at AS first_shell, e.started_at AS started,
                               e.first_shell_method AS method, e.first_shell_agent AS agent,
                               e.first_ex_spawn_at AS first_ex_spawn
                    """, eid=eid).single()
                    return dict(r) if r else None
            ttfs_data = await neo4j_exec(_get_ttfs)
            if ttfs_data and ttfs_data.get("first_shell") and ttfs_data.get("started"):
                ttfs_seconds = max(0, int(ttfs_data["first_shell"] - ttfs_data["started"]))
                mins, secs = divmod(ttfs_seconds, 60)
                ttfs_display = f"{mins}m {secs:02d}s" if mins else f"{secs}s"
        except Exception:
            pass

    # TTFS-EX: Time from EX spawn to first shell (exploitation-only speed)
    ttfs_ex_seconds = 0
    ttfs_ex_display = "—"
    if ttfs_data and ttfs_data.get("first_shell") and ttfs_data.get("first_ex_spawn"):
        ttfs_ex_seconds = max(0, int(ttfs_data["first_shell"] - ttfs_data["first_ex_spawn"]))
        ex_mins, ex_secs = divmod(ttfs_ex_seconds, 60)
        ttfs_ex_display = f"{ex_mins}m {ex_secs:02d}s" if ex_mins else f"{ex_secs}s"

    return {
        "discovered_vulns": discovered,
        "confirmed_exploits": confirmed,
        "exploited_unverified": exploited_unverified,  # BUG-029: EX exploited but VF didn't confirm
        "total_exploited": total_exploited,
        "success_rate": success_rate,
        "by_severity": by_severity,
        "mtte_seconds": mtte_seconds,
        "mtte_display": mtte_display,
        "per_finding": per_finding_times[:10],
        "ttfs_seconds": ttfs_seconds,
        "ttfs_display": ttfs_display,
        "ttfs_ex_seconds": ttfs_ex_seconds,
        "ttfs_ex_display": ttfs_ex_display,
    }


@app.get("/api/engagements/{eid}/services-summary")
async def get_services_summary(eid: str):
    """Get services/ports distribution for an engagement."""
    services = []

    if neo4j_available and neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                result = session.run("""
                    MATCH (h:Host {engagement_id: $eid})-[:HAS_SERVICE]->(s:Service)
                    RETURN s.port AS port, s.name AS name,
                           count(DISTINCT h) AS host_count,
                           collect(DISTINCT s.version)[..3] AS versions
                    ORDER BY host_count DESC
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

    # BUG-042 fix: Merge in-memory ports with Neo4j (not either/or).
    # In-memory findings may have ports that haven't been persisted to Neo4j yet.
    import re as _re_svc
    neo4j_ports = {s["port"] for s in services}
    port_counts = {}
    for f in state.findings:
        if f.engagement != eid:
            continue
        target = f.target or ""
        port_match = _re_svc.search(r':(\d+)', target)
        if port_match:
            port = int(port_match.group(1))
            if port in neo4j_ports:
                continue  # Already covered by Neo4j
            name = {80: 'http', 443: 'https', 22: 'ssh', 3306: 'mysql',
                    8080: 'http-proxy', 445: 'smb', 21: 'ftp', 8443: 'https-alt',
                    3632: 'distccd', 8180: 'http-alt', 5432: 'postgresql',
                    1099: 'rmiregistry', 5900: 'vnc'}.get(port, f'port-{port}')
            if port not in port_counts:
                port_counts[port] = {"port": port, "name": name, "count": 0, "versions": []}
            port_counts[port]["count"] += 1
    # Merge: Neo4j services + any extra ports from in-memory
    merged = list(services) + sorted(port_counts.values(), key=lambda x: x["count"], reverse=True)

    return merged


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

    # BUG-036 FIX: Auto-classify default/weak credentials if agents didn't tag them.
    # Common default credentials on Metasploitable, IoT, network devices, etc.
    _DEFAULT_CREDS = {
        "admin", "root", "guest", "test", "user", "administrator", "postgres",
        "mysql", "ftp", "anonymous", "default", "pi", "ubuntu", "vagrant",
        "msfadmin", "service", "tomcat", "manager",
    }
    _WEAK_PASSWORDS = {
        "password", "123456", "admin", "root", "guest", "test", "pass",
        "1234", "12345", "123456789", "qwerty", "letmein", "welcome",
        "monkey", "dragon", "master", "login", "abc123", "password1",
        "msfadmin", "service", "tomcat", "s3cret", "changeme", "default",
    }
    for c in credentials:
        if c.get("type") not in ("default", "weak"):
            uname = (c.get("username") or "").lower()
            pwd = (c.get("password") or c.get("hash") or "").lower()
            if uname in _DEFAULT_CREDS and uname == pwd:
                c["type"] = "default"
            elif uname in _DEFAULT_CREDS:
                c["type"] = "default"
            elif pwd in _WEAK_PASSWORDS:
                c["type"] = "weak"

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

    # Query Neo4j for persisted chains
    if neo4j_available and neo4j_driver:
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

    # Fallback 1: query AttackChain nodes (created by ST agent or auto-detection)
    if not chains and neo4j_available and neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                result = session.run("""
                    MATCH (ac:AttackChain {engagement_id: $eid})
                    RETURN ac.id AS id, ac.name AS name,
                           ac.priority AS priority, ac.impact AS impact,
                           ac.links_count AS links_count,
                           ac.discovered_by AS discovered_by
                    ORDER BY ac.priority ASC
                """, eid=eid)
                for record in result:
                    priority = record.get("priority") or 99
                    severity = ("critical" if priority <= 1
                                else "high" if priority <= 2 else "medium")
                    chains.append({
                        "id": record["id"],
                        "name": record["name"],
                        "severity": severity,
                        "impact": record.get("impact") or "",
                        "steps": [],
                    })
        except Exception as e:
            logger.warning("Neo4j AttackChain query error: %s", e)

    # Fallback 2: query AttackPath nodes
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

    # Fallback 3: Synthesize chains from findings (in-memory + Neo4j)
    # Agents label findings with (CHAIN-N) in titles, and related findings share
    # categories (e.g., multiple SQLi findings form a chain). Parse these.
    if not chains:
        import re
        from types import SimpleNamespace
        mem_findings = [f for f in state.findings if getattr(f, "engagement", "") == eid]

        # Also load from Neo4j if in-memory is empty (e.g., after server restart)
        if not mem_findings and neo4j_available and neo4j_driver:
            try:
                with neo4j_driver.session() as session:
                    result = session.run("""
                        MATCH (f:Finding {engagement_id: $eid})
                        RETURN f.id AS id, f.title AS title, f.severity AS severity,
                               f.category AS category, f.agent AS agent,
                               f.evidence AS evidence, f.timestamp AS timestamp,
                               f.confirmed_at AS confirmed_at
                    """, eid=eid)
                    for record in result:
                        mem_findings.append(SimpleNamespace(
                            id=record["id"],
                            title=record["title"] or "",
                            severity=record["severity"] or "medium",
                            category=record["category"] or "",
                            agent=record["agent"] or "",
                            evidence=record["evidence"],
                            timestamp=record["timestamp"] or 0,
                            confirmed_at=record["confirmed_at"],
                            engagement=eid,
                        ))
            except Exception as e:
                logger.warning("Neo4j chain synthesis query error: %s", e)

        chain_map: dict[str, list] = {}

        # Pass 1: Extract explicit CHAIN-N labels from titles
        for f in mem_findings:
            title = f.title or ""
            match = re.search(r'\(CHAIN-(\d+)\)', title)
            if match:
                cid = f"chain-{match.group(1)}"
                chain_map.setdefault(cid, []).append(f)

        # Pass 2: Group remaining findings by attack category into implicit chains
        # (e.g., multiple SQLi findings = one injection chain)
        category_groups: dict[str, list] = {}
        labeled_ids = {id(f) for fs in chain_map.values() for f in fs}
        for f in mem_findings:
            if id(f) in labeled_ids:
                continue
            cat = (getattr(f, "category", "") or "").lower()
            title = (f.title or "").lower()
            # Map to chain categories
            if "injection" in cat or "sqli" in title or "sql injection" in title:
                category_groups.setdefault("injection", []).append(f)
            elif "path-traversal" in cat or "path traversal" in title or "null byte" in title:
                category_groups.setdefault("path-traversal", []).append(f)
            elif "xss" in cat or "cross-site scripting" in title or "xss" in title:
                category_groups.setdefault("xss", []).append(f)
            elif "access-control" in cat or "authentication" in cat or "admin" in title:
                category_groups.setdefault("access-control", []).append(f)

        # Only create implicit chains with 2+ findings
        implicit_idx = len(chain_map) + 1
        for cat_key, findings_list in category_groups.items():
            if len(findings_list) >= 2:
                cid = f"chain-implicit-{implicit_idx}"
                chain_map.setdefault(cid, []).extend(findings_list)
                implicit_idx += 1

        # Build chain objects
        chain_names = {
            "injection": "SQL Injection → Admin Access",
            "path-traversal": "Path Traversal → File Exfiltration",
            "xss": "XSS → Client-Side Exploitation",
            "access-control": "Auth Bypass → Privilege Escalation",
        }
        sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        for cid, findings_list in chain_map.items():
            severities = []
            for f in findings_list:
                sev = (f.severity.value if hasattr(f.severity, "value")
                       else str(f.severity)).lower()
                severities.append(sev)
            worst = min(severities, key=lambda s: sev_rank.get(s, 5))

            # Determine chain name
            if cid.startswith("chain-implicit-"):
                # Use category-based name
                for cat_key, cat_findings in category_groups.items():
                    if any(id(f) in {id(cf) for cf in cat_findings} for f in findings_list):
                        name = chain_names.get(cat_key, findings_list[0].title)
                        break
                else:
                    name = findings_list[0].title
            else:
                name = findings_list[0].title.split(" (CHAIN-")[0]

            steps = []
            for f in findings_list:
                steps.append({
                    "agent": getattr(f, "agent", "") or "ST",
                    "finding_id": f.id,
                    "description": f.title,
                })
            chains.append({
                "id": cid,
                "name": name,
                "severity": worst,
                "impact": f"{len(findings_list)} linked findings",
                "steps": steps,
            })

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


@app.post("/api/engagements/{eid}/findings")
async def create_engagement_finding(eid: str, payload: FindingPayload):
    """Alias: POST finding scoped to an engagement.

    Delegates to the main create_finding() handler after injecting the
    engagement ID from the URL path (overrides payload.engagement).
    """
    payload.engagement = eid
    return await create_finding(payload)


@app.patch("/api/engagements/{eid}/findings/{fid}")
async def patch_finding(eid: str, fid: str, request: Request):
    """Allow agents to update status and evidence on existing findings."""
    payload = await request.json()
    allowed = {"status", "evidence", "verification_status", "confirmed_at", "exploited_by"}
    updates = {k: v for k, v in payload.items() if k in allowed}
    if not updates:
        return JSONResponse(status_code=400, content={"error": "No valid fields to update"})

    # Update in-memory state
    for f in state.findings:
        if f.id == fid and f.engagement == eid:
            for k, v in updates.items():
                setattr(f, k, v)
            # Set confirmed_at if status becoming confirmed
            if updates.get("status") == "confirmed" and not f.confirmed_at:
                import time as _t
                f.confirmed_at = _t.time()
            break

    # Update Neo4j
    if neo4j_available and neo4j_driver and updates:
        def _patch_neo4j():
            set_clauses = ", ".join(f"f.{k} = ${k}" for k in updates)
            with neo4j_driver.session() as session:
                session.run(
                    f"MATCH (f:Finding {{id: $id, engagement_id: $eid}}) SET {set_clauses}",
                    id=fid, eid=eid, **updates
                )
        try:
            await neo4j_exec(_patch_neo4j)
        except Exception as e:
            logger.warning("Finding PATCH Neo4j error: %s", str(e)[:100])

    return {"ok": True, "updated": fid, "fields": list(updates.keys())}


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
                           ep.notes AS notes,
                           ep.poc_script AS poc_script,
                           ep.poc_output AS poc_output,
                           ep.impact_demonstrated AS impact_demonstrated
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
                        "poc_script": record.get("poc_script"),
                        "poc_output": record.get("poc_output"),
                        "impact_demonstrated": record.get("impact_demonstrated"),
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

                # Fallback: if no EvidencePackages/Artifacts, surface Finding scalar evidence
                if not evidence_packages and not artifacts:
                    fallback_result = session.run("""
                        MATCH (f:Finding {id: $fid})
                        RETURN f.evidence AS evidence, f.poc_script AS poc_script,
                               f.impact_demonstrated AS impact, f.confidence AS confidence,
                               f.verification_status AS vstatus, f.verified_at AS verified_at,
                               f.poc_output AS poc_output
                    """, fid=fid)
                    rec = fallback_result.single()
                    if rec and any(rec.get(k) for k in ("evidence", "poc_script", "poc_output")):
                        evidence_packages.append({
                            "id": f"synthetic-{fid}",
                            "type": "verification_result",
                            "output_evidence": rec.get("evidence") or rec.get("poc_output"),
                            "poc_script": rec.get("poc_script"),
                            "poc_output": rec.get("poc_output"),
                            "impact_demonstrated": rec.get("impact"),
                            "confidence": rec.get("confidence"),
                            "status": rec.get("vstatus"),
                            "verified_by": "VF",
                            "timestamp": rec.get("verified_at"),
                            "http_pairs": None,
                            "response_diff": None,
                            "notes": rec.get("impact"),
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
    finding_id: str = Form(""),
    engagement_id: str = Form(...),
    type: str = Form(...),
    caption: str = Form(""),
    agent: str = Form(""),
    backend: str = Form(""),
    capture_mode: str = Form("manual"),
    evidence_package_id: Optional[str] = Form(None),
    auto_link_latest_finding: bool = Form(False),
    evidence_type: str = Form(""),
):
    """Upload a binary artifact (screenshot, HTTP pair, command output, etc.) for a finding.

    Saves to the engagement's 08-evidence directory, generates thumbnails for
    screenshots, stores metadata in Neo4j, and links to the Finding node.
    """
    # Resolve finding_id via latest finding lookup if not provided
    if auto_link_latest_finding and not finding_id and neo4j_available and neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                result = session.run(
                    "MATCH (f:Finding {engagement_id: $eid}) RETURN f.id AS id "
                    "ORDER BY f.timestamp DESC LIMIT 1",
                    eid=engagement_id,
                )
                record = result.single()
                if record:
                    finding_id = record.get("id") or ""
        except Exception as e:
            print(f"Neo4j latest finding lookup error: {e}")

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
                        evidence_type: $evidence_type,
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
                evidence_type=evidence_type,
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


class TextArtifactRequest(BaseModel):
    engagement_id: str
    type: str
    caption: str = ""
    content: str
    agent: str = ""
    finding_id: str = ""
    auto_link_latest_finding: bool = False
    evidence_type: str = ""


@app.post("/api/artifacts/text")
async def upload_text_artifact(req: TextArtifactRequest):
    """Upload a text artifact (command output, tool log, etc.) as a JSON body.

    Accepts plain-text content, writes it to the appropriate evidence directory,
    creates an Artifact node in Neo4j, and optionally links to the latest finding.
    """
    # Validate artifact type
    if req.type not in ALLOWED_ARTIFACT_TYPES:
        return JSONResponse(
            status_code=400,
            content={"error": f"Invalid artifact type '{req.type}'. Allowed: {sorted(ALLOWED_ARTIFACT_TYPES)}"},
        )

    content_bytes = req.content.encode("utf-8")
    if len(content_bytes) > MAX_ARTIFACT_SIZE:
        return JSONResponse(
            status_code=413,
            content={"error": f"Content too large ({len(content_bytes)} bytes). Max {MAX_ARTIFACT_SIZE} bytes."},
        )

    # Resolve finding_id via latest finding lookup if not provided
    finding_id = req.finding_id
    if req.auto_link_latest_finding and not finding_id and neo4j_available and neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                result = session.run(
                    "MATCH (f:Finding {engagement_id: $eid}) RETURN f.id AS id "
                    "ORDER BY f.timestamp DESC LIMIT 1",
                    eid=req.engagement_id,
                )
                record = result.single()
                if record:
                    finding_id = record.get("id") or ""
        except Exception as e:
            print(f"Neo4j latest finding lookup error (text artifact): {e}")

    # Compute SHA-256 hash
    file_hash = hashlib.sha256(content_bytes).hexdigest()

    # Build safe caption for filename
    safe_caption = re.sub(r"[^a-zA-Z0-9-]", "-", req.caption)[:32].strip("-") or "artifact"

    # Query Finding severity and category for filename context
    finding_severity = "unknown"
    finding_category = "uncategorized"
    if finding_id and neo4j_available and neo4j_driver:
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
            print(f"Neo4j finding lookup error (text artifact): {e}")

    # Generate artifact ID and timestamp
    artifact_id = uuid.uuid4().hex[:8]
    timestamp = time.time()
    ts_str = datetime.utcnow().strftime("%Y%m%d-%H%M%S")

    # Build filename
    type_to_subdir = {
        "screenshot": "screenshots",
        "http_pair": "http-pairs",
        "command_output": "command-output",
        "tool_log": "tool-logs",
        "response_diff": "response-diffs",
    }
    subdir = type_to_subdir.get(req.type, "command-output")
    filename = f"{artifact_id}-{finding_severity}-{finding_category}-{safe_caption}-{ts_str}.txt"

    # Ensure evidence directories exist and write file
    evidence_root = ensure_evidence_dirs(req.engagement_id)
    dest_path = evidence_root / subdir / filename
    dest_path.write_bytes(content_bytes)

    # Compute relative path
    athena_dir = Path(__file__).parent.parent.parent
    try:
        rel_path = str(dest_path.relative_to(athena_dir))
    except ValueError:
        rel_path = str(dest_path)

    # Persist to Neo4j
    if neo4j_available and neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                session.run("""
                    CREATE (a:Artifact {
                        id: $id,
                        engagement_id: $engagement_id,
                        finding_id: $finding_id,
                        type: $type,
                        file_path: $file_path,
                        file_hash: $file_hash,
                        file_size: $file_size,
                        mime_type: $mime_type,
                        caption: $caption,
                        agent: $agent,
                        capture_mode: $capture_mode,
                        evidence_type: $evidence_type,
                        timestamp: $timestamp
                    })
                """,
                id=artifact_id,
                engagement_id=req.engagement_id,
                finding_id=finding_id,
                type=req.type,
                file_path=rel_path,
                file_hash=file_hash,
                file_size=len(content_bytes),
                mime_type="text/plain",
                caption=req.caption,
                agent=req.agent,
                capture_mode="agent",
                evidence_type=req.evidence_type,
                timestamp=timestamp,
                )

                if finding_id:
                    session.run("""
                        MATCH (f:Finding {id: $fid}), (a:Artifact {id: $aid})
                        MERGE (f)-[:HAS_ARTIFACT]->(a)
                    """, fid=finding_id, aid=artifact_id)

        except Exception as e:
            print(f"Neo4j text artifact write error: {e}")

    return {
        "ok": True,
        "artifact_id": artifact_id,
        "file_path": rel_path,
        "file_hash": f"sha256:{file_hash}",
        "file_size": len(content_bytes),
        "mime_type": "text/plain",
        "file_url": f"/api/artifacts/{artifact_id}/file",
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
    linked_only: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
):
    """List artifacts with optional filters. linked_only=true returns only finding-linked artifacts."""
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

                # When linked_only=true, only return artifacts linked to findings
                # via relationships (HAS_ARTIFACT, EVIDENCED_BY, SUPPORTS) or finding_id property
                if linked_only and linked_only.lower() == "true":
                    conditions.append(
                        "(EXISTS { MATCH (f2:Finding)-[:HAS_ARTIFACT]->(a) } "
                        "OR EXISTS { MATCH (f2:Finding)-[:EVIDENCED_BY]->(a) } "
                        "OR EXISTS { MATCH (f2:Finding)-[:SUPPORTS]->(a) } "
                        "OR (a.finding_id IS NOT NULL AND a.finding_id <> ''))"
                    )

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
                           a.evidence_type AS evidence_type,
                           f.severity AS finding_severity
                    ORDER BY a.timestamp DESC
                    SKIP $offset LIMIT $limit
                """
                result = session.run(query, **params)
                athena_dir = Path(__file__).parent.parent.parent
                artifacts = []
                for record in result:
                    art_type = record.get("type")
                    file_path = record.get("file_path")
                    content_text = ""
                    resolved_path = athena_dir / file_path if file_path else None
                    if art_type == "command_output" and file_path and resolved_path.exists():
                        try:
                            content_text = resolved_path.read_text(errors="replace")[:4000]
                        except Exception:
                            pass
                    artifacts.append({
                        "id": record["id"],
                        "type": art_type,
                        "timestamp": record.get("timestamp"),
                        "file_path": file_path,
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
                        "evidence_type": record.get("evidence_type", ""),
                        "finding_severity": record.get("finding_severity"),
                        "file_url": f"/api/artifacts/{record['id']}/file",
                        "thumbnail_url": f"/api/artifacts/{record['id']}/thumbnail" if record.get("thumbnail_path") else None,
                        "content": content_text,
                    })
                # BUG-M2: Get true total count (not just page size)
                count_query = f"MATCH (a:Artifact) {where_clause} RETURN count(a) AS total"
                count_result = session.run(count_query, **params)
                total_count = count_result.single()["total"]
                return {"artifacts": artifacts, "total": total_count, "source": "neo4j"}
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
    except Exception:
        logger.exception("Artifact download failed")
        return JSONResponse(status_code=500, content={"error": "Internal server error"})

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
    except Exception:
        logger.exception("Artifact thumbnail failed")
        return JSONResponse(status_code=500, content={"error": "Internal server error"})

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
        except Exception:
            logger.exception("Artifact deletion failed")
            return JSONResponse(status_code=500, content={"error": "Internal server error"})
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


@app.delete("/api/engagements/{eid}/artifacts")
async def delete_all_artifacts(eid: str):
    """Delete ALL artifacts and evidence packages for an engagement from Neo4j and disk."""
    if not neo4j_available or not neo4j_driver:
        return JSONResponse(status_code=503, content={"error": "Neo4j unavailable"})

    athena_dir = Path(__file__).parent.parent.parent
    deleted_count = 0
    deleted_files = []

    try:
        with neo4j_driver.session() as session:
            # 1. Collect file paths before deletion
            result = session.run(
                "MATCH (a:Artifact {engagement_id: $eid}) "
                "RETURN a.file_path AS file_path, a.thumbnail_path AS thumbnail_path",
                eid=eid,
            )
            file_paths = []
            for record in result:
                fp = record.get("file_path")
                tp = record.get("thumbnail_path")
                if fp:
                    file_paths.append(fp)
                if tp:
                    file_paths.append(tp)

            # 2. Count artifacts
            count_result = session.run(
                "MATCH (a:Artifact {engagement_id: $eid}) RETURN count(a) AS cnt",
                eid=eid,
            )
            count_record = count_result.single()
            deleted_count = count_record["cnt"] if count_record else 0

            # 3. Delete EvidencePackage nodes for this engagement
            session.run(
                "MATCH (ep:EvidencePackage {engagement_id: $eid}) DETACH DELETE ep",
                eid=eid,
            )

            # 4. Delete all Artifact nodes for this engagement
            session.run(
                "MATCH (a:Artifact {engagement_id: $eid}) DETACH DELETE a",
                eid=eid,
            )

        # 5. Delete files + thumbnails from disk
        for rel_path in file_paths:
            fp = athena_dir / rel_path
            if fp.exists():
                fp.unlink()
                deleted_files.append(str(fp))

    except Exception:
        logger.exception("Engagement artifacts deletion failed")
        return JSONResponse(status_code=500, content={"error": "Internal server error"})

    return {"ok": True, "deleted": deleted_count, "deleted_files": len(deleted_files), "engagement": eid}


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

                # Coverage: findings with at least one artifact, evidence package, or evidence property
                cov_result = session.run("""
                    MATCH (f:Finding {engagement_id: $eid})
                    OPTIONAL MATCH (f)-[:HAS_ARTIFACT]->(a:Artifact)
                    OPTIONAL MATCH (f)-[:EVIDENCED_BY|SUPPORTS]->(ep:EvidencePackage)
                    WITH f,
                         count(DISTINCT a) + count(DISTINCT ep) AS rel_ev_count,
                         CASE WHEN f.evidence IS NOT NULL AND f.evidence <> '' THEN 1 ELSE 0 END AS prop_ev
                    WITH f, rel_ev_count + prop_ev AS ev_count
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


# ── Tool Matrix category display names ──
_CATEGORY_DISPLAY = {
    "recon": "Recon",
    "web": "Web Apps",
    "exploit": "Exploitation",
    "enrichment": "Enrichment",
    "post_exploit": "Post-Exploit",
    "cloud": "Cloud",
    "vuln": "Vuln Scan",
    "vuln_scan": "Vuln Scan",  # merged with vuln
    "evidence": "Evidence",
}

# Canonical order for display (vuln and vuln_scan merged as "Vuln Scan")
_CATEGORY_ORDER = ["recon", "web", "exploit", "enrichment", "post_exploit", "cloud", "vuln_scan", "evidence"]


@app.get("/api/tool-matrix")
async def get_tool_matrix(engagement: Optional[str] = None):
    """Return tool registry grouped by category with engagement-aware status.

    Status logic:
        - No engagement param  → all tools 'none'
        - Has engagement       → cross-reference scan history
            covered  = tool has a scan with findings_count > 0
            partial  = tool has a scan but findings_count == 0
            none     = tool has no scan
    """
    tools_list = kali_client.list_tools()

    # Build lookup: tool_name → {findings_count, scan_count, last_scan_status}
    scan_summary: dict[str, dict] = {}
    if engagement:
        scans_raw = await get_scans(engagement=engagement)
        for s in scans_raw:
            tname = s.get("tool", "")
            if not tname:
                continue
            entry = scan_summary.setdefault(tname, {
                "findings_count": 0,
                "scan_count": 0,
                "last_scan_status": s.get("status", ""),
            })
            entry["scan_count"] += 1
            entry["findings_count"] += s.get("findings_count", 0) or 0
            entry["last_scan_status"] = s.get("status", "")

    # Group tools by canonical category key (merge vuln → vuln_scan)
    category_buckets: dict[str, list] = {}
    for t in tools_list:
        raw_cat = t.get("category", "")
        canon_cat = "vuln_scan" if raw_cat == "vuln" else raw_cat
        if canon_cat not in _CATEGORY_DISPLAY:
            canon_cat = "recon"  # fallback for unknown categories
        bucket = category_buckets.setdefault(canon_cat, [])

        # Fuzzy match: scan registers as "nmap" but registry key is "nmap_scan"
        # Try exact match first, then strip _scan/_probe/_discover suffixes, then
        # check if any scan tool name starts with the registry key prefix
        tool_key = t["name"]
        scan_info = scan_summary.get(tool_key, {})
        if not scan_info:
            # Try short name: nmap_scan → nmap
            short = tool_key.rsplit("_", 1)[0] if "_" in tool_key else tool_key
            scan_info = scan_summary.get(short, {})
        if not scan_info:
            # Try MCP prefix: mcp__kali_external__nmap_scan
            for sname, sdata in scan_summary.items():
                if sname.endswith(tool_key) or sname.endswith(short):
                    scan_info = sdata
                    break
        findings_count = scan_info.get("findings_count", 0)
        scan_count = scan_info.get("scan_count", 0)
        last_status = scan_info.get("last_scan_status", "")

        if not engagement:
            status = "none"
        elif scan_count == 0:
            status = "none"
        elif findings_count > 0:
            status = "covered"
        else:
            status = "partial"

        bucket.append({
            "id": t["name"],
            "display_name": t.get("display_name", t["name"]),
            "backends": t.get("backends", []),
            "status": status,
            "findings_count": findings_count,
            "scan_count": scan_count,
            "last_scan_status": last_status,
        })

    # Build ordered category list (skip empty categories)
    categories = []
    for cat_key in _CATEGORY_ORDER:
        tools_in_cat = category_buckets.get(cat_key, [])
        if not tools_in_cat:
            continue
        categories.append({
            "name": _CATEGORY_DISPLAY[cat_key],
            "key": cat_key,
            "tools": tools_in_cat,
        })

    # Append any categories not in the canonical order
    for cat_key, tools_in_cat in category_buckets.items():
        if cat_key not in _CATEGORY_ORDER and tools_in_cat:
            categories.append({
                "name": _CATEGORY_DISPLAY.get(cat_key, cat_key.title()),
                "key": cat_key,
                "tools": tools_in_cat,
            })

    return {"categories": categories}


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

    # BUG-021b + Fix 5a: Normalize "complete" → "completed" for frontend consistency
    # Frontend checks s.status === 'completed'; agents sometimes send "complete" (no "d")
    if scan.get("status") == "complete":
        scan["status"] = "completed"

    # Auto-set completed_at if status changed to completed/error
    # BUG-021b: Agent sends "complete" (no "d") — accept both variants
    if request.get("status") in ("completed", "complete", "error", "aborted", "ABORTED") and not scan.get("completed_at"):
        scan["completed_at"] = datetime.now(timezone.utc).isoformat()

    # BUG-004/BUG-008: Auto-calculate duration if not explicitly provided and scan is done
    # BUG-021b: Accept both "completed" and "complete" status variants
    # BUG-008: Also calculate for "aborted" scans
    if scan.get("status") in ("completed", "complete", "error", "aborted", "ABORTED") and not request.get("duration_s"):
        started = scan.get("started_at")
        completed = scan.get("completed_at")
        if started and completed and scan.get("duration_s", 0) == 0:
            try:
                dt_start = datetime.fromisoformat(started.replace("Z", "+00:00"))
                dt_end = datetime.fromisoformat(completed.replace("Z", "+00:00"))
                calculated = max(0, int((dt_end - dt_start).total_seconds()))
                # BUG-019 FIX: Allow 0s duration (sub-second scans) — use -1 sentinel
                # to distinguish "not calculated" (0) from "instant" (calculated 0).
                scan["duration_s"] = max(calculated, 1)  # Minimum 1s for display
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


def _find_report_dir(athena_dir: Path, report_id: str, engagement_id: str | None = None) -> tuple[Path | None, Path | None]:
    """Find the reporting directory and file for a given report ID.

    Args:
        engagement_id: If provided, only search within this engagement's directory.
    """
    engagements_dir = athena_dir / "engagements" / "active"
    if not engagements_dir.exists():
        return None, None
    for eng_dir in engagements_dir.iterdir():
        if not eng_dir.is_dir():
            continue
        # Filter by engagement ID if provided
        if engagement_id and not eng_dir.name.startswith(engagement_id):
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
    # If no engagement ID is resolved and not requesting all, return empty
    if eid:
        reports = [r for r in state._reports if r.get("engagement_id") == eid]
    elif all_engagements:
        reports = list(state._reports)
    else:
        return []

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
    # BUG-029: Also track file_paths already registered in state._reports to avoid duplicates
    seen_file_paths = {r.get("file_path") for r in reports if r.get("file_path")}

    for scan_root in scan_roots:
        for eng_dir in scan_root.iterdir():
            if not eng_dir.is_dir():
                continue
            # Skip non-engagement directories at engagements/ root
            if scan_root == engagements_base and eng_dir.name in skip_dirs:
                continue
            # Strict match: directory name must start with the engagement ID
            if eid and not eng_dir.name.startswith(eid):
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

            # Fix 6: Deduplicate by absolute path — same file may appear under both
            # scan_roots (active/ and engagements/ root share the same eng_dir via symlink or
            # direct inclusion), causing 2x or 3x duplicates.
            seen_paths: set = set()
            unique_reports = []
            for rf, m in report_files:
                abs_path = rf.resolve()
                if abs_path not in seen_paths:
                    seen_paths.add(abs_path)
                    unique_reports.append((rf, m))
            report_files = unique_reports

            for report_file, meta in report_files:
                file_id = f"file-{report_file.stem}"
                if file_id in seen_file_ids:
                    continue
                # BUG-029: Skip disk report if its file_path is already in state._reports
                rel_path = str(report_file.relative_to(athena_dir))
                if rel_path in seen_file_paths:
                    continue
                seen_file_ids.add(file_id)
                stat = report_file.stat()
                saved = meta.get(file_id, {})
                # Estimate pages and findings count from file content
                est_pages = saved.get("pages")
                est_findings = saved.get("findings_included")
                if est_pages is None or est_findings is None:
                    try:
                        content = report_file.read_text(errors="ignore")
                        if est_pages is None:
                            # ~40 lines per page for markdown reports
                            line_count = content.count("\n")
                            est_pages = max(1, round(line_count / 40))
                        if est_findings is None:
                            # Count finding references (## Finding, ### CVE-, severity markers)
                            import re
                            finding_patterns = re.findall(
                                r"(?:^#{2,3}\s+(?:Finding|CVE-|VULN-))|(?:^\|.*(?:Critical|High|Medium|Low).*\|)",
                                content, re.MULTILINE | re.IGNORECASE)
                            est_findings = len(finding_patterns) if finding_patterns else None
                    except Exception:
                        pass
                reports.append({
                    "id": file_id,
                    "title": saved.get("title") or report_file.stem.replace("-", " ").replace("_", " ").title(),
                    "type": saved.get("type") or (
                        "technical" if "technical" in report_file.stem.lower() else
                        "executive" if "executive" in report_file.stem.lower() else
                        "remediation" if "remediation" in report_file.stem.lower() else "pentest"),
                    "status": saved.get("status", "draft"),
                    "pages": est_pages,
                    "findings_included": est_findings,
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


async def _generate_speed_report_card(eid: str) -> dict:
    """Generate a one-page Speed Report Card after a Sprint engagement completes."""
    try:
        summary = await get_engagement_summary(eid)
        exploit_stats = await get_exploit_stats(eid)

        ttfs = exploit_stats.get("ttfs_display", "—")
        ttfs_s = exploit_stats.get("ttfs_seconds", 0)
        ttfs_ex = exploit_stats.get("ttfs_ex_display", "—")
        ttfs_ex_s = exploit_stats.get("ttfs_ex_seconds", 0)

        # Extract first shell details from Neo4j
        shell_method = "unknown"
        shell_target_ip = ""
        shell_agent = "EX"
        if neo4j_available and neo4j_driver:
            try:
                def _get_shell():
                    with neo4j_driver.session() as session:
                        r = session.run("""
                            MATCH (e:Engagement {id: $eid})
                            RETURN e.first_shell_method AS method, e.first_shell_target AS target,
                                   e.first_shell_agent AS agent, e.target AS eng_target, e.name AS name
                        """, eid=eid).single()
                        return dict(r) if r else {}
                shell_data = await neo4j_exec(_get_shell)
                shell_method = shell_data.get("method") or "unknown"
                shell_target_ip = shell_data.get("target") or shell_data.get("eng_target") or ""
                shell_agent = shell_data.get("agent") or "EX"
            except Exception:
                pass

        # Calculate benchmark comparison
        cs_breakout = 27  # CrowdStrike 2026 GTR fastest breakout
        if ttfs_s > 0 and ttfs_s <= cs_breakout:
            benchmark = f"CrowdStrike fastest: {cs_breakout}s | ATHENA Sprint: {ttfs_s}s  *** MATCH ***"
        elif ttfs_s > 0:
            benchmark = f"CrowdStrike fastest: {cs_breakout}s | ATHENA Sprint: {ttfs_s}s  ({round(ttfs_s/cs_breakout, 1)}x slower)"
        else:
            benchmark = "No shell obtained — benchmark N/A"

        # Agent cost breakdown
        total_cost = summary.get("duration_seconds", 0)
        sev = summary.get("severity", {})

        eng_name = ""
        try:
            eng_obj = next((e for e in state.engagements if e.id == eid), None)
            eng_name = eng_obj.name if eng_obj else eid
        except Exception:
            eng_name = eid

        from datetime import datetime
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M AST")

        report_md = f"""# ATHENA Speed Assessment Report

**Target:** {shell_target_ip}
**Engagement:** {eng_name} ({eid})
**Mode:** Sprint
**Date:** {now_str}

---

## Time to First Shell: {ttfs}

| Phase | Time | Details |
|-------|------|---------|
| End-to-End (TTFS) | **{ttfs}** | Engagement start to confirmed shell |
| Exploitation Only (TTFS-EX) | **{ttfs_ex}** | EX agent spawn to confirmed shell |

## Attack Path

**Method:** {shell_method}
**Agent:** {shell_agent}
**Target:** {shell_target_ip}

## Findings Summary

| Severity | Count |
|----------|-------|
| Critical | {sev.get('critical', 0)} |
| High | {sev.get('high', 0)} |
| Medium | {sev.get('medium', 0)} |
| Low | {sev.get('low', 0)} |
| **Total** | **{summary.get('findings', 0)}** |

## Benchmark Comparison

{benchmark}

> If your team cannot detect and respond in under {ttfs_s}s,
> this attack path succeeds against your infrastructure.

## Recommendations

1. Patch or mitigate the exploited service ({shell_method}) immediately
2. Deploy EDR with sub-{max(10, ttfs_s // 2)}s detection latency for this attack vector
3. Enable automated network containment (isolate on first shell indicator)
4. Schedule a comprehensive penetration test (Standard mode) for full coverage

---

*Generated by ATHENA Sprint Mode | {now_str}*
"""

        # Register the report
        report_id = f"speed-{eid}-{int(time.time())}"
        report_obj = {
            "id": report_id,
            "engagement_id": eid,
            "type": "speed",
            "title": "Speed Assessment Report",
            "status": "final",
            "format": "MD",
            "pages": 1,
            "findings_included": summary.get("findings", 0),
            "exploits_confirmed": exploit_stats.get("confirmed_exploits", 0),
            "severity": sev,
            "summary": f"TTFS: {ttfs} | Method: {shell_method} | {benchmark}",
            "author": "ATHENA Sprint Mode",
            "content": report_md,
            "created_at": time.time(),
            "updated_at": time.time(),
        }
        state._reports.append(report_obj)

        await state.broadcast({
            "type": "report_created",
            "report": {"id": report_id, "type": "speed", "title": "Speed Assessment Report"},
            "timestamp": time.time(),
        })

        logger.info("Speed Report Card generated for engagement %s: TTFS=%s", eid, ttfs)
        return report_obj

    except Exception as e:
        logger.warning("Failed to generate Speed Report Card: %s", str(e)[:200])
        return {}


@app.post("/api/reports")
async def create_report(payload: dict):
    """Register a report from an AI agent or manual creation."""
    report_id = payload.get("id", f"rpt-{str(uuid.uuid4())[:8]}")
    now = time.strftime("%Y-%m-%dT%H:%M:%S")
    eid = payload.get("engagement_id", state.active_engagement_id)
    report_type = payload.get("type", "pentest")

    # BUG-044 FIX: Dedup — normalize report_type before matching.
    # RP sends varying types ("technical", "Technical Report", "TECHNICAL") across chunks.
    _type_normalize = {
        "technical": "technical", "technical report": "technical",
        "executive": "executive", "executive summary": "executive",
        "remediation": "remediation", "remediation roadmap": "remediation",
        "speed": "speed", "speed report": "speed", "speed report card": "speed", "speed assessment": "speed",
    }
    report_type = _type_normalize.get(report_type.lower().strip(), report_type.lower().strip())
    existing_report = None
    for r in state._reports:
        r_type = _type_normalize.get((r.get("type") or "").lower().strip(), (r.get("type") or "").lower())
        if r_type == report_type and r.get("engagement_id") == eid:
            existing_report = r
            break

    # BUG-013 fix: If the RP agent sends zeroed-out findings data, auto-populate
    # from the live engagement summary so reports always reflect actual results.
    findings_count = payload.get("findings_included") or payload.get("findings") or 0
    severity_data = payload.get("severity") or {}
    exploits_count = payload.get("exploits_confirmed") or 0
    if (not findings_count or findings_count == 0) and eid:
        try:
            summary = await get_engagement_summary(eid)
            findings_count = summary.get("findings", 0)
            severity_data = summary.get("severity", {})
            exploits_count = summary.get("exploits", 0)
        except Exception:
            pass  # Use whatever RP agent provided

    # BUG-019: Update existing report instead of creating duplicate
    if existing_report:
        existing_report["title"] = payload.get("title", existing_report.get("title", "Untitled Report"))
        existing_report["status"] = payload.get("status", existing_report.get("status", "draft"))
        existing_report["pages"] = payload.get("pages") or existing_report.get("pages")
        existing_report["findings_included"] = findings_count or existing_report.get("findings_included", 0)
        existing_report["exploits_confirmed"] = exploits_count or existing_report.get("exploits_confirmed", 0)
        existing_report["severity"] = severity_data or existing_report.get("severity", {})
        existing_report["engagement_name"] = payload.get("engagement_name") or existing_report.get("engagement_name", "")
        existing_report["author"] = payload.get("author") or existing_report.get("author", "AI Generated")
        existing_report["format"] = payload.get("format") or existing_report.get("format", "MD")
        existing_report["file_path"] = payload.get("file_path") or existing_report.get("file_path")
        existing_report["summary"] = payload.get("summary") or existing_report.get("summary")
        existing_report["updated_at"] = now

        await state.broadcast({
            "type": "report_created",
            "report": existing_report,
        })

        return {"ok": True, "report_id": existing_report["id"], "updated": True}

    report = {
        "id": report_id,
        "title": payload.get("title", "Untitled Report"),
        "type": report_type,
        "status": payload.get("status", "draft"),
        "pages": payload.get("pages"),
        "findings_included": findings_count,
        "exploits_confirmed": exploits_count,
        "severity": severity_data,
        "engagement_id": eid,
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
async def download_report(report_id: str, engagement: Optional[str] = None):
    """Download a report file by ID, scoped to engagement."""
    athena_dir = Path(__file__).parent.parent.parent
    eid = engagement or state.active_engagement_id
    reports = await get_reports(engagement=eid, include_archived=True)
    for r in reports:
        if r.get("id") == report_id and r.get("file_path"):
            fp = athena_dir / r["file_path"]
            if fp.exists():
                return FileResponse(
                    str(fp),
                    filename=fp.name,
                    media_type="application/octet-stream",
                )
    # BUG-NEW-001 fix: eid may be None for completed engagements (active_engagement_id cleared).
    # Fall back to searching all engagements when scoped search returns nothing.
    if eid is not None:
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
async def delete_report(report_id: str, engagement: Optional[str] = None):
    """Delete a single report by ID (removes file from disk + metadata)."""
    athena_dir = Path(__file__).parent.parent.parent
    eid = engagement or state.active_engagement_id
    # Try filesystem reports (scoped to engagement)
    reporting_dir, report_file = _find_report_dir(athena_dir, report_id, engagement_id=eid)
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
async def update_report(report_id: str, payload: dict, engagement: Optional[str] = None):
    """Update report status (archive, mark final, etc.). Persists to .report-meta.json."""
    athena_dir = Path(__file__).parent.parent.parent
    eid = engagement or state.active_engagement_id
    new_status = payload.get("status")
    if not new_status:
        return JSONResponse({"error": "status required"}, status_code=400)

    # Handle archive — persist status in metadata (don't move files to avoid multi-extension issues)
    if new_status == "archived":
        reporting_dir, report_file = _find_report_dir(athena_dir, report_id, engagement_id=eid)
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
    reporting_dir, _ = _find_report_dir(athena_dir, report_id, engagement_id=eid)
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
        'broken authentication': 'EX', 'authentication': 'EX',
        'information disclosure': 'AR', 'directory listing': 'AR',
        'security misconfiguration': 'WV', 'misconfiguration': 'WV',
        'vulnerable component': 'WV', 'outdated': 'WV',
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
                    id=f"synth-eng-{eid[:8]}", type="system", agent="ST",
                    content=f"Engagement started: {rec.get('name', eid)} — Target: {rec.get('scope', 'N/A')}",
                    timestamp=start_ts,
                    metadata={"engagement": eid, "synthesized": True}
                ))
                # Planning agent event
                events.append(AgentEvent(
                    id=f"synth-st-{eid[:8]}", type="agent_status", agent="ST",
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
                    id=f"synth-da-{rec.get('id', '')[:8]}", type="attack_chain", agent="DA",
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
        def _query_events():
            with neo4j_driver.session() as session:
                query = "MATCH (ev:Event) "
                params: dict = {}
                if eid:
                    query += "WHERE ev.engagement_id = $eid "
                    params["eid"] = eid
                query += "RETURN ev ORDER BY ev.timestamp DESC LIMIT $limit"
                params["limit"] = limit
                result = session.run(query, **params)
                rows = []
                for record in result:
                    ev = record["ev"]
                    if ev["id"] not in seen_ids:
                        rows.append(ev)
                return rows
        try:
            neo4j_rows = await neo4j_exec(_query_events)
            for ev in neo4j_rows:
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


@app.delete("/api/events")
async def delete_events(engagement: Optional[str] = None):
    """Delete all events for an engagement (in-memory + Neo4j)."""
    eid = engagement or state.active_engagement_id
    # Clear in-memory events (also remove orphans with no engagement_id)
    if eid:
        state.events = [e for e in state.events
                        if (e.metadata or {}).get("engagement_id", "") not in ("", eid)]
    else:
        state.events = []
    # Clear Neo4j Event nodes
    deleted_count = 0
    if neo4j_available and neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                if eid:
                    result = session.run(
                        "MATCH (ev:Event {engagement_id: $eid}) DETACH DELETE ev RETURN count(ev) as cnt",
                        eid=eid
                    )
                else:
                    result = session.run("MATCH (ev:Event) DETACH DELETE ev RETURN count(ev) as cnt")
                deleted_count = result.single()["cnt"]
        except Exception as e:
            print(f"Neo4j events delete error: {e}")
    mem_before = len(state.events)
    print(f"[DELETE] Events cleared for engagement={eid}: {deleted_count} Neo4j nodes removed")
    return {"deleted": deleted_count, "engagement": eid}


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
            ip = _safe_extract_host(f.target)
            if ip and ip in existing_ids:
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
            def _query():
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
                            # BUG-036: Filter out version-string IPs (e.g. "3.2.8.1" from UnrealIRCd)
                            # that were created directly as Host nodes by MCP tools, bypassing _safe_extract_host.
                            if ntype == "host" and _is_version_string_ip(node.get("ip", "")):
                                continue
                            node_id = node.get("id", node.get("ip", node.get("name", node.get("username", str(id(node))))))
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
                            coalesce(a.id, a.ip, a.name, a.username) AS from_id,
                            coalesce(b.id, b.ip, b.name, b.username) AS to_id,
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

                    # Compute attack paths from EXPLOITS edges
                    attack_paths_computed = []
                    try:
                        ap_result = session.run("""
                            MATCH (f:Finding)-[:EXPLOITS]->(target)
                            WHERE f.engagement_id = $eid
                            OPTIONAL MATCH (f)-[:FOUND_ON|AFFECTS]->(entry)
                            OPTIONAL MATCH (entry)<-[:HAS_SERVICE]-(entry_host:Host)
                            RETURN f.id AS fid, f.title AS title, f.severity AS severity,
                                   coalesce(entry_host.ip, f.target, '') AS entry,
                                   coalesce(target.ip, target.name, '') AS pivot,
                                   labels(target) AS target_labels
                            LIMIT 50
                        """, eid=eid)
                        for r in ap_result:
                            attack_paths_computed.append({
                                "finding_id": r["fid"],
                                "title": r["title"],
                                "severity": r["severity"],
                                "entry": r["entry"],
                                "pivot": r["pivot"],
                                "target_type": (r["target_labels"] or ["Unknown"])[0],
                            })
                    except Exception as _ap_err:
                        logger.warning("Attack path query error: %s", _ap_err)

                    return nodes, edges, attack_paths_computed
            nodes, edges, attack_paths_computed = await neo4j_exec(_query)

            # If we have findings but no Host/Service nodes (AI mode), synthesize graph from in-memory
            host_count = sum(1 for n in nodes if n["type"] == "host")
            finding_count = sum(1 for n in nodes if n["type"] == "finding")
            if finding_count > 0 and host_count == 0:
                nodes, edges = _synthesize_graph_from_findings(nodes, edges)

            # Post-process: auto-connect orphaned findings/vulns to hosts
            nodes, edges = _connect_orphaned_nodes(nodes, edges)

            return {"nodes": nodes, "edges": edges, "attack_paths": attack_paths_computed, "source": "neo4j"}
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

    # Reset budget trackers (in-memory + Neo4j persisted cost)
    global _engagement_cost
    _agent_budgets.clear()
    _engagement_cost = 0.0
    if neo4j_available and neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                session.run("""
                    MATCH (e:Engagement {id: $eid})
                    SET e.engagement_cost = 0
                    REMOVE e.first_shell_at, e.first_shell_agent, e.first_shell_method,
                           e.first_shell_target, e.first_ex_spawn_at,
                           e.completed_at, e.mtte_seconds, e.findings_count, e.phase
                """, eid=eid)
        except Exception:
            pass

    # Broadcast clear_timeline to all connected clients so their AI drawers reset
    await state.broadcast({
        "type": "clear_timeline",
        "engagement": eid,
        "timestamp": time.time(),
    })

    # Broadcast cost reset so KPI updates to $0.00
    await state.broadcast({
        "type": "cost_update",
        "agent": "ST",
        "engagement_cost": 0.0,
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
    # Re-check Kali health on every status poll so the dashboard reflects reality
    await kali_client.health_check_all()
    kali_status = {}
    for name, backend in kali_client.backends.items():
        kali_status[name] = {
            "available": backend.available,
            "url": backend.base_url,
            "tools": len(backend.tools),
        }
    # Re-check Neo4j connectivity (lightweight ping)
    global neo4j_available
    if neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                session.run("RETURN 1")
            neo4j_available = True
        except Exception:
            neo4j_available = False

    return {
        "neo4j": neo4j_available,
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

    # P0-FIX: Only expose availability — no URIs, usernames, or topology info
    # Browser-side graph rendering uses server-side REST proxy endpoints
    return {
        "available": True,
    }


# ──────────────────────────────────────────────
# H3: Langfuse Observability Status Endpoint
# ──────────────────────────────────────────────

@app.get("/api/observability/status")
async def get_observability_status():
    """H3: Return Langfuse observability status."""
    from langfuse_integration import is_enabled
    return {
        "langfuse_enabled": is_enabled(),
        "langfuse_url": os.environ.get("LANGFUSE_BASE_URL", "http://localhost:3000"),
    }


# ──────────────────────────────────────────────
# Unified Feature Configuration Status
# ──────────────────────────────────────────────

_ENV_FILE = Path(__file__).parent / ".env"

# Keys that are safe to expose in the GET response (no secrets)
_PUBLIC_KEYS = {
    "NEO4J_URI", "NEO4J_USER", "KALI_EXTERNAL_URL", "KALI_INTERNAL_URL",
    "GRAPHITI_LLM_MODEL", "LANGFUSE_BASE_URL",
    "RAG_TYPE", "RAG_MCP_TOOL", "RAG_INDEX_PATH", "VEX_RAG_PATH",
}

# Keys that hold secrets — only show masked hint in GET, full value never returned
_SECRET_KEYS = {
    "NEO4J_PASS", "KALI_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY",
    "LANGFUSE_SECRET_KEY", "LANGFUSE_PUBLIC_KEY",
}

# All keys allowed to be written via the config API
_WRITABLE_KEYS = _PUBLIC_KEYS | _SECRET_KEYS


def _read_env_file() -> dict[str, str]:
    """Parse .env file into a dict. Ignores comments and blank lines."""
    result = {}
    if not _ENV_FILE.exists():
        return result
    for line in _ENV_FILE.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" in stripped:
            key, _, value = stripped.partition("=")
            result[key.strip()] = value.strip()
    return result


def _write_env_file(updates: dict[str, str]):
    """Merge updates into .env file, preserving comments and order.
    New keys are appended. Empty string values remove the key."""
    lines = []
    seen = set()
    if _ENV_FILE.exists():
        for line in _ENV_FILE.read_text().splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and "=" in stripped:
                key = stripped.partition("=")[0].strip()
                if key in updates:
                    seen.add(key)
                    if updates[key]:  # non-empty: update in place
                        lines.append(f"{key}={updates[key]}")
                    # empty string: skip line (remove key)
                    continue
            lines.append(line)
    # Append any new keys not already in the file
    for key, value in updates.items():
        if key not in seen and value:
            lines.append(f"{key}={value}")
    _ENV_FILE.write_text("\n".join(lines) + "\n")
    _ENV_FILE.chmod(0o600)


def _mask_secret(value: str) -> str:
    """Return masked version of a secret for display."""
    if not value:
        return ""
    return "••••••••"


def _save_config():
    """Persist the current _cfg dict back to athena-config.yaml.
    Writes only the athena: top-level key. Preserves the file header comment."""
    config_path = Path(__file__).parent / "athena-config.yaml"
    try:
        header = (
            "# ============================================================\n"
            "# ATHENA Configuration — Portable Pentest Platform\n"
            "# ============================================================\n"
            "# Managed by ATHENA Settings. Manual edits are preserved on next save.\n"
            "# ============================================================\n\n"
        )
        content = header + yaml.dump(
            {"athena": _cfg},
            default_flow_style=False,
            allow_unicode=True,
            sort_keys=False,
        )
        config_path.write_text(content)
        config_path.chmod(0o600)
    except Exception as e:
        logger.error(f"Failed to write athena-config.yaml: {e}")


@app.get("/api/system/resources")
async def get_system_resources():
    """Return detected host resources and performance tier."""
    return _system_resources


@app.post("/api/system/resources")
async def update_system_resources(request: Request):
    """Override the auto-detected performance tier."""
    global _system_resources
    payload = await request.json()
    override_tier = payload.get("tier")
    valid_tiers = {"light": (3, 1), "standard": (5, 1), "performance": (8, 3), "beast": (12, 5)}
    if override_tier == "auto":
        _system_resources = _detect_system_resources()
        return {"ok": True, "message": "Reset to auto-detected tier", **_system_resources}
    if override_tier not in valid_tiers:
        return JSONResponse(status_code=400, content={"error": f"Invalid tier. Valid: auto, {', '.join(valid_tiers)}"})
    max_agents, parallel_ex = valid_tiers[override_tier]
    _system_resources["tier"] = override_tier
    _system_resources["max_concurrent_agents"] = max_agents
    _system_resources["parallel_ex"] = parallel_ex
    _system_resources["override"] = override_tier
    logger.info("System resources overridden: tier=%s, max_agents=%d, parallel_ex=%d", override_tier, max_agents, parallel_ex)
    return {"ok": True, **_system_resources}


@app.get("/api/config/features")
async def get_feature_config():
    """Aggregated feature configuration status for Settings UI."""
    from graphiti_integration import is_enabled as graphiti_enabled
    from langfuse_integration import is_enabled as langfuse_enabled

    # Re-check Kali health so Settings page shows live status
    await kali_client.health_check_all()
    kali_backends = {}
    for name, backend in kali_client.backends.items():
        kali_backends[name] = {"available": backend.available, "url": backend.base_url, "tools": len(backend.tools)}

    # Read .env to show configured (not just active) values
    env_data = _read_env_file()

    # Build editable config map: public values in full, secrets masked
    editable = {}
    for key in _PUBLIC_KEYS:
        editable[key] = os.environ.get(key, env_data.get(key, ""))
    for key in _SECRET_KEYS:
        raw = os.environ.get(key, env_data.get(key, ""))
        editable[key] = _mask_secret(raw)

    return {
        "neo4j": {"enabled": neo4j_available, "uri": os.environ.get("NEO4J_URI", "bolt://localhost:7687")},
        "graphiti": {"enabled": graphiti_enabled(), "model": os.environ.get("GRAPHITI_LLM_MODEL", "claude-haiku-4-5")},
        "langfuse": {"enabled": langfuse_enabled(), "url": os.environ.get("LANGFUSE_BASE_URL", "http://localhost:3000")},
        "rag": {
            "enabled": _cfg.get("rag", {}).get("enabled", True),
            "type": _cfg.get("rag", {}).get("type", "mcp-proxy"),
            "mcp_tool": _cfg.get("rag", {}).get("mcp_tool", "mcp__athena_knowledge_base__search_kb"),
            "index_path": _cfg.get("rag", {}).get("index_path", "./lance_athena_kb"),
            "proxy_port": _cfg.get("rag", {}).get("proxy_port", 8765),
            "proxy_host": _cfg.get("rag", {}).get("proxy_host", "127.0.0.1"),
            "rest_endpoint": "/api/knowledge/search",
            "vex_rag_path": _cfg.get("rag", {}).get("vex_rag_path", ""),
            "vex_rag_module": _cfg.get("rag", {}).get("vex_rag_module", "mcp_server/vex_kb_server.py"),
            "rag_config": _cfg.get("rag", {}).get("rag_config", ""),
            "proxy_status": "checking",
        },
        "kali": {"backends": kali_backends, "tools": len(kali_client.list_tools())},
        "editable": editable,
    }


@app.get("/api/config/athena")
async def get_athena_config():
    """Return loaded ATHENA configuration (secrets masked)."""
    cfg = _cfg
    return {
        "version": cfg.get("version", "unknown"),
        "dashboard": cfg.get("dashboard", {}),
        "backends": {
            name: {"url": b.get("url", ""), "enabled": b.get("enabled", True)}
            for name, b in cfg.get("backends", {}).items()
        },
        "rag": {
            "enabled": cfg.get("rag", {}).get("enabled", False),
            "type": cfg.get("rag", {}).get("type", "mcp"),
        },
        "neo4j": {"uri": cfg.get("neo4j", {}).get("uri", "")},
        "ai": cfg.get("ai", {}),
        "engagement": cfg.get("engagement", {}),
        "config_loaded": bool(_ATHENA_CONFIG),
    }


@app.post("/api/config/update")
async def update_config(body: dict):
    """Update .env configuration. Requires server restart for changes to take effect.
    Accepts a dict of key-value pairs. Only whitelisted keys are accepted.
    Values starting with '••••' are treated as unchanged (masked secrets)."""
    updates = {}
    rejected = []
    for key, value in body.items():
        if key not in _WRITABLE_KEYS:
            rejected.append(key)
            continue
        # Skip masked values (user didn't change the secret)
        if isinstance(value, str) and value.startswith("••••"):
            continue
        updates[key] = str(value).strip()

    if not updates:
        return {"saved": 0, "rejected": rejected, "restart_required": False,
                "message": "No changes to save."}

    _write_env_file(updates)
    logger.info(f"Config updated: {list(updates.keys())} — restart required")

    return {
        "saved": len(updates),
        "keys": list(updates.keys()),
        "rejected": rejected,
        "restart_required": True,
        "message": f"Saved {len(updates)} setting(s) to .env. Restart the server to apply changes.",
    }


@app.post("/api/config/rag")
async def save_rag_config(request: Request):
    """Save RAG configuration fields to athena-config.yaml in memory and on disk."""
    payload = await request.json()
    rag_cfg = _cfg.setdefault("rag", {})
    for key in ("type", "proxy_port", "proxy_host", "mcp_tool", "index_path",
                "vex_rag_path", "vex_rag_module", "rag_config"):
        if key in payload and payload[key] != "":
            rag_cfg[key] = payload[key]
    _save_config()
    logger.info(f"RAG config saved: {list(payload.keys())}")
    return {
        "ok": True,
        "restart_required": True,
        "message": "RAG configuration saved. Restart server to apply changes.",
    }


@app.post("/api/config/toggle")
async def toggle_integration(body: dict):
    """Enable or disable an integration at runtime (no restart required).

    Body: {"integration": "graphiti"|"langfuse", "enabled": true|false}
    """
    integration = body.get("integration", "")
    enabled = body.get("enabled", True)

    if integration == "graphiti":
        from graphiti_integration import (
            init_graphiti, shutdown_graphiti, is_enabled as graphiti_enabled,
        )
        if enabled and not graphiti_enabled():
            ok = await init_graphiti()
            return {"ok": ok, "integration": "graphiti", "enabled": ok,
                    "message": "Graphiti initialized" if ok else "Graphiti init failed (check API keys)"}
        elif not enabled and graphiti_enabled():
            await shutdown_graphiti()
            return {"ok": True, "integration": "graphiti", "enabled": False,
                    "message": "Graphiti disabled"}
        else:
            return {"ok": True, "integration": "graphiti", "enabled": graphiti_enabled(),
                    "message": "No change"}

    elif integration == "langfuse":
        from langfuse_integration import (
            init_langfuse, shutdown_langfuse, is_enabled as langfuse_enabled,
        )
        if enabled and not langfuse_enabled():
            ok = await init_langfuse()
            return {"ok": ok, "integration": "langfuse", "enabled": ok,
                    "message": "Langfuse initialized" if ok else "Langfuse init failed (check URL/keys)"}
        elif not enabled and langfuse_enabled():
            await shutdown_langfuse()
            return {"ok": True, "integration": "langfuse", "enabled": False,
                    "message": "Langfuse disabled"}
        else:
            return {"ok": True, "integration": "langfuse", "enabled": langfuse_enabled(),
                    "message": "No change"}

    elif integration == "rag":
        import subprocess
        rag_cfg = _cfg.setdefault("rag", {})
        if enabled and not rag_cfg.get("enabled"):
            # Verify RAG index is accessible before enabling
            # Read paths from athena-config.yaml first, then env vars, then defaults
            index_path = rag_cfg.get("index_path", "./lance_athena_kb")
            vex_rag_path = (rag_cfg.get("vex_rag_path") or
                            os.environ.get("VEX_RAG_PATH", ""))
            if not vex_rag_path or vex_rag_path == "/path/to/vex-rag":
                return {"ok": False, "integration": "rag", "enabled": False,
                        "message": "Set vex_rag_path in athena-config.yaml or VEX_RAG_PATH env var first"}
            vex_rag_python = (rag_cfg.get("python_path") or
                              os.environ.get("VEX_RAG_PYTHON") or
                              str(Path(vex_rag_path) / ".venv" / "bin" / "python3"))

            # Quick health check: try importing search_kb and checking index
            check_script = (
                "import sys, os; "
                f"sys.path.insert(0, {vex_rag_path!r}); "
                "from mcp_server.vex_kb_server import get_kb_stats; "
                "import json; print(json.dumps(get_kb_stats()))"
            )
            try:
                athena_root = os.environ.get("ATHENA_PROJECT_ROOT",
                                              str(Path(__file__).parent.parent.parent))
                result = await asyncio.to_thread(
                    subprocess.run,
                    [vex_rag_python, "-c", check_script],
                    capture_output=True, text=True, timeout=15,
                    cwd=athena_root,
                    env={**os.environ,
                         "RAG_CONFIG": os.environ.get("ATHENA_RAG_CONFIG",
                                                       str(Path(athena_root) / ".vex-rag.yml")),
                         "PYTHONPATH": vex_rag_path},
                )
                if result.returncode == 0 and result.stdout.strip():
                    stats = json.loads(result.stdout)
                    rag_cfg["enabled"] = True
                    chunk_count = stats.get("total_chunks", "?")
                    healthy = stats.get("search_healthy", False)
                    status = "healthy" if healthy else "index loaded"
                    return {"ok": True, "integration": "rag", "enabled": True,
                            "message": f"RAG enabled — {chunk_count} chunks indexed, search {status}"}
                else:
                    # Index not found or import failed — enable anyway but warn
                    rag_cfg["enabled"] = True
                    stderr_hint = (result.stderr or "")[:150]
                    return {"ok": True, "integration": "rag", "enabled": True,
                            "message": "RAG enabled (index not verified — agents will use MCP tool). "
                                       + stderr_hint}
            except Exception as e:
                # Enable anyway — MCP tool may still work via Claude Code
                rag_cfg["enabled"] = True
                return {"ok": True, "integration": "rag", "enabled": True,
                        "message": f"RAG enabled (health check failed: {str(e)[:100]}). "
                                   "Agents can still use the MCP tool if configured."}
        elif not enabled and rag_cfg.get("enabled"):
            rag_cfg["enabled"] = False
            return {"ok": True, "integration": "rag", "enabled": False,
                    "message": "RAG disabled — agents will skip knowledge base searches"}
        else:
            return {"ok": True, "integration": "rag", "enabled": rag_cfg.get("enabled", False),
                    "message": "No change"}

    else:
        return JSONResponse(status_code=400, content={
            "error": f"Unknown integration: {integration}. Supported: graphiti, langfuse, rag"
        })


# ──────────────────────────────────────────────
# H1: Graphiti Cross-Session Memory Endpoints
# ──────────────────────────────────────────────

@app.get("/api/memory/stats")
async def get_memory_stats():
    """H1: Return Graphiti memory statistics."""
    from graphiti_integration import is_enabled as graphiti_enabled
    if not graphiti_enabled():
        return {"enabled": False, "episodes": 0, "entities": 0}
    try:
        def _count_nodes():
            ep_count = 0
            ent_count = 0
            if neo4j_driver:
                with neo4j_driver.session() as sess:
                    r1 = sess.run("MATCH (n:EpisodicNode) RETURN count(n) as c")
                    ep_count = r1.single()["c"]
                    r2 = sess.run("MATCH (n:EntityNode) RETURN count(n) as c")
                    ent_count = r2.single()["c"]
            return ep_count, ent_count
        episodes, entities = await neo4j_exec(_count_nodes)
        return {"enabled": True, "episodes": episodes, "entities": entities}
    except Exception as e:
        return {"enabled": True, "episodes": -1, "entities": -1, "error": str(e)}


@app.get("/api/memory/search")
async def search_graphiti_memory(
    q: str,
    engagement_id: Optional[str] = None,
    include_global: bool = True,
    limit: int = 10,
):
    """H1: Search Graphiti cross-session memory."""
    from graphiti_integration import search_memory, is_enabled as graphiti_enabled
    if not graphiti_enabled():
        return {"results": [], "enabled": False}
    engagement_ids = [engagement_id] if engagement_id else None
    results = await search_memory(
        query=q, engagement_ids=engagement_ids,
        include_global=include_global, num_results=limit,
    )
    return {"results": results, "enabled": True}


@app.get("/api/memory/similar")
async def find_similar_cases(service: str, version: str = ""):
    """H1: Find similar services from past engagements."""
    from graphiti_integration import get_similar_cases, is_enabled as graphiti_enabled
    if not graphiti_enabled():
        return {"results": [], "enabled": False}
    results = await get_similar_cases(service_name=service, version=version)
    return {"results": results, "enabled": True}


@app.get("/api/knowledge/search")
async def search_knowledge_base(q: str, top_k: int = 5, agent: str = ""):
    """RAG Knowledge Base search via mcp-proxy sidecar (Streamable HTTP).

    Calls the vex-rag MCP server through mcp-proxy HTTP bridge (port 8765).
    Uses MCP Streamable HTTP transport (JSON-RPC over POST /mcp).
    This avoids the Rust tokenizer SIGABRT on fork — mcp-proxy runs vex-rag
    as a separate process, not a forked child of uvicorn.
    """
    import httpx
    import json as _json

    MCP_PROXY_URL = "http://127.0.0.1:8765"
    HEADERS = {"Content-Type": "application/json", "Accept": "application/json"}

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Step 1: Initialize MCP session
            init_resp = await client.post(
                f"{MCP_PROXY_URL}/mcp",
                json={
                    "jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-03-26",
                        "capabilities": {},
                        "clientInfo": {"name": "athena-dashboard", "version": "1.0"}
                    }
                },
                headers=HEADERS,
            )
            if init_resp.status_code != 200:
                raise Exception(f"MCP init failed: {init_resp.status_code}")

            # Extract session ID from response header
            session_id = init_resp.headers.get("mcp-session-id", "")
            if not session_id:
                raise Exception("No Mcp-Session-Id in init response")

            session_headers = {**HEADERS, "Mcp-Session-Id": session_id}

            # Step 2: Send initialized notification
            await client.post(
                f"{MCP_PROXY_URL}/mcp",
                json={"jsonrpc": "2.0", "method": "notifications/initialized"},
                headers=session_headers,
            )

            # Step 3: Call search_kb tool
            resp = await client.post(
                f"{MCP_PROXY_URL}/mcp",
                json={
                    "jsonrpc": "2.0", "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "search_kb",
                        "arguments": {"query": q, "top_k": top_k}
                    }
                },
                headers=session_headers,
            )

            if resp.status_code == 200:
                raw_text = resp.text
                try:
                    data = _json.loads(raw_text)
                except _json.JSONDecodeError:
                    # Handle control characters in response
                    import re
                    cleaned = re.sub(r'[\x00-\x1f\x7f]', ' ', raw_text)
                    data = _json.loads(cleaned)

                result = data.get("result", {})
                content = result.get("content", [])
                if content and isinstance(content, list):
                    text_content = content[0].get("text", "{}") if content else "{}"
                    try:
                        parsed = _json.loads(text_content)
                        documents = parsed.get("documents", [])
                    except _json.JSONDecodeError:
                        documents = [{"content": text_content[:500]}]
                    return {
                        "results": documents,
                        "query": q,
                        "top_k": top_k,
                        "status": "ok",
                        "source": "mcp-proxy",
                    }

            return {
                "results": [],
                "query": q,
                "top_k": top_k,
                "status": "no_results",
                "source": "mcp-proxy",
            }

    except httpx.ConnectError:
        return {
            "results": [],
            "query": q,
            "top_k": top_k,
            "status": "unavailable",
            "reason": "mcp-proxy not running on port 8765 — start ATHENA with ./start.sh",
        }
    except Exception as e:
        return {
            "results": [],
            "query": q,
            "top_k": top_k,
            "status": "error",
            "reason": str(e)[:200],
        }


async def _emit_rag_event(agent: str, query: str, result_count: int, error: str = ""):
    """Emit a RAG search event to the AI drawer timeline."""
    # Only emit during active engagements — skip health checks and manual curl tests
    if not state.active_engagement_id:
        return

    # Sanitize error — strip Python tracebacks, keep only the last meaningful line
    if error:
        lines = error.strip().splitlines()
        # Use last line (the actual error message) if it looks like a traceback
        if len(lines) > 1 and ("Traceback" in lines[0] or "File " in lines[0]):
            error = lines[-1].strip()[:80]
        elif "sys.path.insert" in error or "import sys" in error or "/Users/" in error:
            error = "RAG subprocess error"
        else:
            error = error[:80]

    if result_count > 0:
        content = f'Searched RAG: "{query}" — {result_count} results found'
    elif error:
        content = f'Searched RAG: "{query}" — no results ({error})'
    else:
        content = f'Searched RAG: "{query}" — no results, falling back to searchsploit'

    event = AgentEvent(
        id=f"rag-{int(time.time()*1000)}",
        type="rag_search",
        agent=agent,
        content=content,
        timestamp=time.time(),
        metadata={
            "query": query,
            "result_count": result_count,
            "error": error or None,
            "engagement_id": state.active_engagement_id or "",
        },
    )
    await state.add_event(event)


# ──────────────────────────────────────────────
# Phase C: Real Engagement + Backend API
# ──────────────────────────────────────────────

@app.post("/api/engagement/{eid}/start")
async def start_engagement(eid: str, backend: str = ""):
    """Start a PTES engagement — redirects to multi-agent AI mode.

    Legacy automation endpoint preserved for backwards compatibility.
    All engagements now use the multi-agent architecture.
    """
    return await start_engagement_ai(eid=eid, backend=backend)


# ──────────────────────────────────────────────
# Phase F1a: Multi-Agent AI Mode
# ──────────────────────────────────────────────

_active_session_manager: "AgentSessionManager | None" = None

# ── Internet Connectivity Monitor ──────────────────────────────
_network_down: bool = False
_network_consecutive_failures: int = 0
_network_down_since: float | None = None
_network_paused: bool = False  # True if WE paused due to network (vs user pause)
_network_monitor_task: asyncio.Task | None = None
NETWORK_CHECK_URL = "https://www.google.com/generate_204"
NETWORK_CHECK_INTERVAL = 10  # seconds
NETWORK_FAILURE_THRESHOLD = 2  # consecutive failures to declare outage
NETWORK_CHECK_TIMEOUT = 5  # seconds

# ── Stale Scan Watchdog ──
STALE_SCAN_THRESHOLD = 600  # 10 minutes — mark scan as stalled
STALE_SCAN_CHECK_INTERVAL = 30  # check every 30 seconds
_stale_scan_monitor_task: asyncio.Task | None = None


async def _stale_scan_watchdog():
    """Background task: detect scans stuck in 'running' state and mark as stalled."""
    while True:
        await asyncio.sleep(STALE_SCAN_CHECK_INTERVAL)
        try:
            now = datetime.now(timezone.utc)
            stalled = []
            for scan in list(state.scans):  # snapshot to avoid mutation during iteration
                if scan.get("status") != "running":
                    continue
                started = scan.get("started_at")
                if not started:
                    continue
                if isinstance(started, str):
                    started_dt = datetime.fromisoformat(started)
                    if started_dt.tzinfo is None:
                        started_dt = started_dt.replace(tzinfo=timezone.utc)
                else:
                    started_dt = started
                elapsed = (now - started_dt).total_seconds()
                if elapsed >= STALE_SCAN_THRESHOLD:
                    scan["status"] = "stalled"
                    scan["completed_at"] = now.isoformat()
                    scan["duration_s"] = int(elapsed)
                    logger.warning(
                        f"Stale scan watchdog: {scan.get('tool', '?')} "
                        f"(id={scan.get('id', '?')}) stalled after {int(elapsed)}s"
                    )
                    await state.broadcast({
                        "type": "scan_complete",
                        "scan": scan,
                        "timestamp": time.time(),
                    })
        except Exception as e:
            logger.error(f"Stale scan watchdog error: {e}")


async def _network_connectivity_monitor():
    """Background task: detect internet outages and auto-pause/resume agents."""
    global _network_down, _network_consecutive_failures, _network_down_since, _network_paused

    client = httpx.AsyncClient(timeout=NETWORK_CHECK_TIMEOUT)
    try:
        while True:
            await asyncio.sleep(NETWORK_CHECK_INTERVAL)
            try:
                resp = await client.get(NETWORK_CHECK_URL)
                # Google returns 204, but any 2xx means connectivity works
                is_up = 200 <= resp.status_code < 400
            except Exception:
                is_up = False

            if is_up:
                _network_consecutive_failures = 0
                if _network_down:
                    # Recovery
                    downtime = int(time.time() - (_network_down_since or time.time()))
                    _network_down = False
                    _network_down_since = None
                    logger.info("Internet connectivity restored (was down %ds)", downtime)
                    await state.broadcast({
                        "type": "network_status",
                        "status": "up",
                        "downtime_s": downtime,
                        "timestamp": time.time(),
                    })
                    # Auto-resume only if WE paused (not the user)
                    if _network_paused and _active_session_manager and _active_session_manager._paused:
                        _network_paused = False
                        await _active_session_manager.resume()
                        # Tell agents what happened
                        st = _active_session_manager.agents.get("ST")
                        if st and st.is_running:
                            await st.send_command(
                                f"Internet connectivity restored after {downtime}s outage. "
                                f"Continue your task."
                            )
            else:
                _network_consecutive_failures += 1
                if _network_consecutive_failures >= NETWORK_FAILURE_THRESHOLD and not _network_down:
                    # Declare outage
                    _network_down = True
                    _network_down_since = time.time()
                    logger.warning("Internet connectivity lost (after %d consecutive failures)",
                                   _network_consecutive_failures)
                    await state.broadcast({
                        "type": "network_status",
                        "status": "down",
                        "timestamp": time.time(),
                    })
                    # Auto-pause if engagement is running and not already paused
                    if (_active_session_manager and
                            _active_session_manager.is_running and
                            not _active_session_manager._paused):
                        _network_paused = True
                        await _active_session_manager.pause()
    except asyncio.CancelledError:
        pass
    finally:
        await client.aclose()


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


    # Agent code → PTES phase mapping for Scan Coverage tracking
_AGENT_TO_PHASE = {
    "ST": "PLANNING",
    "PR": "PASSIVE RECON",
    "AR": "INTELLIGENCE GATHERING",
    "WV": "WEB APP TESTING",
    "DA": "VULNERABILITY ANALYSIS",
    "PX": "VULNERABILITY ANALYSIS",
    "EX": "EXPLOITATION",
    "VF": "EXPLOITATION",
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
# BUG-006: Track tool_id → scan_id for auto-update on tool_complete
_active_tool_scans: dict[str, str] = {}


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
                       f.timestamp AS timestamp,
                       f.discovered_at AS discovered_at, f.confirmed_at AS confirmed_at
                ORDER BY f.timestamp DESC
            """, eid=eid)

            new_findings = []
            for record in result:
                fid = record.get("id")
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
                def _neo4j_ts_to_epoch(val):
                    if val is None:
                        return None
                    if hasattr(val, "to_native"):
                        return val.to_native().timestamp()
                    if isinstance(val, (int, float)):
                        return float(val)
                    return None

                ts = rec.get("timestamp")
                if ts is None:
                    ts = time.time()
                elif hasattr(ts, "to_native"):
                    # Neo4j DateTime → Python datetime → epoch float
                    ts = ts.to_native().timestamp()
                elif not isinstance(ts, (int, float)):
                    ts = time.time()
                finding = Finding(
                    id=rec.get("id"),
                    title=rec.get("title") or "Untitled Finding",
                    severity=sev,
                    category=rec.get("category") or "",
                    target=rec.get("target") or "",
                    agent=rec.get("agent") or "ST",
                    description=rec.get("description") or "",
                    cvss=rec.get("cvss") or 0.0,
                    cve=rec.get("cve"),
                    evidence=rec.get("evidence"),
                    timestamp=ts,
                    engagement=eid,
                    discovered_at=_neo4j_ts_to_epoch(rec.get("discovered_at")),
                    confirmed_at=_neo4j_ts_to_epoch(rec.get("confirmed_at")),
                )
                await state.add_finding(finding)

                # Auto-queue HIGH/CRITICAL findings for VF verification
                rec_severity = (rec.get("severity") or "info").lower()
                if rec_severity in ("high", "critical"):
                    await _auto_queue_verification(rec.get("id"), rec_severity, eid)

            # F6: Auto-detect attack chains when new findings arrive
            if new_findings:
                await _auto_detect_chains(eid)

            if new_findings or neo4j_vuln_count > 0:
                # Broadcast updated counts. When no formal Finding nodes exist yet
                # (vuln discovery phase), fall back to Vulnerability node count so
                # the operator sees progress in the Total Findings KPI.
                eng_findings = [f for f in state.findings if f.engagement == eid]
                hosts = set()
                for f in eng_findings:
                    if f.target:
                        host = _safe_extract_host(f.target)
                        if host:
                            hosts.add(host)
                findings_display = len(eng_findings) if eng_findings else neo4j_vuln_count
                # Extract unique ports from finding targets for Open Ports KPI
                import re as _re_ports
                ports = set()
                for f in eng_findings:
                    target = f.target or ""
                    port_match = _re_ports.search(r':(\d+)', target)
                    if port_match:
                        port_num = int(port_match.group(1))
                        if 1 <= port_num <= 65535:
                            ports.add(port_num)
                await state.broadcast({
                    "type": "stat_update",
                    "hosts": len(hosts),
                    "findings": findings_display,
                    "services": len(ports),
                    "vulns": len([f for f in eng_findings if f.severity.value in ("critical", "high")]),
                    "timestamp": time.time(),
                })
    except Exception as e:
        print(f"Findings sync error: {e}")


async def _auto_queue_verification(finding_id: str, finding_severity: str, engagement_id: str):
    """Auto-queue HIGH/CRITICAL findings for VF verification (F3 pipeline).

    Called from create_finding() and _sync_neo4j_findings() to automatically
    queue findings for independent verification through The Moat.
    """
    if finding_severity.lower() not in ("high", "critical"):
        return
    # Skip if already queued
    if finding_id in _finding_verifications:
        return
    # Dedup: skip if any existing verification for this finding is already confirmed
    existing_vids = _finding_verifications.get(finding_id, [])
    if any(
        _verifications[vid]["final_status"] == VerificationStatus.CONFIRMED.value
        for vid in existing_vids
        if vid in _verifications
    ):
        return  # Already confirmed — do not re-queue
    # Find the finding in state
    finding = next((f for f in state.findings if f.id == finding_id), None)
    if not finding:
        return

    verification_id = f"vrf-{str(uuid.uuid4())[:8]}"
    category = finding.category.lower() if finding.category else "default"
    methods = VULN_VERIFICATION_METHODS.get(category, VULN_VERIFICATION_METHODS["default"])
    alt_tools = RETEST_ALTERNATIVES.get(finding.agent, RETEST_ALTERNATIVES["default"])

    verification = {
        "id": verification_id,
        "finding_id": finding_id,
        "engagement_id": engagement_id,
        "finding_title": finding.title,
        "finding_severity": finding.severity.value,
        "finding_category": finding.category,
        "finding_target": finding.target,
        "discovery_agent": finding.agent,
        "status": VerificationStatus.PENDING.value,
        "priority": "high" if finding_severity.lower() == "critical" else "medium",
        "methods": methods,
        "alt_tools": alt_tools,
        "canary_url": None,
        "source_path": None,
        "results": [],
        "final_confidence": 0.0,
        "final_status": VerificationStatus.PENDING.value,
        "created_at": time.time(),
        "updated_at": time.time(),
    }
    _verifications[verification_id] = verification
    _finding_verifications.setdefault(finding_id, []).append(verification_id)

    await _emit("verification_queued", "VF", f"Auto-queued: {finding.title}", {
        "verification_id": verification_id,
        "finding_id": finding_id,
        "auto_triggered": True,
        "methods": methods,
        "priority": verification["priority"],
    })

    # Route verification through ST — all agent coordination flows through ST
    if _active_session_manager and _active_session_manager.is_running:
        st_session = _active_session_manager.agents.get("ST")
        notify_msg = (
            f"New finding requires independent verification: {finding.title} "
            f"({finding_severity.upper()}) on {finding.target}. "
            f"Assign VF to verify using different tools than {finding.agent}. "
            f"Methods: {', '.join(methods)}. "
            f"Verification ID: {verification_id}"
        )
        if st_session and st_session.is_running:
            await st_session.send_command(notify_msg)
        else:
            _active_session_manager.request_agent("ST", notify_msg, priority="high")


async def _scan_for_flags(text: str, eid: str, agent_code: str = ""):
    """Scan text for CTF flags and auto-register captures.

    Called from _sdk_event_to_dashboard() on every agent event so flags
    are captured automatically without agents needing to call the API.
    """
    if not _ctf_session or not _ctf_session["active"] or not text:
        return

    flags = detect_flags(text)
    if not flags:
        return

    for flag_value in flags:
        # Find matching challenge (by URL match or assign to first unsolved)
        matched_challenge_id = None
        for ch_id, ch in _ctf_session["challenges"].items():
            if ch.get("status") == "solved":
                continue
            # Match if this agent is assigned to the challenge
            if ch.get("assigned_agent") == agent_code:
                matched_challenge_id = ch_id
                break

        # Fallback: assign to first unsolved challenge
        if not matched_challenge_id:
            for ch_id, ch in _ctf_session["challenges"].items():
                if ch.get("status") != "solved":
                    matched_challenge_id = ch_id
                    break

        if not matched_challenge_id:
            # No unsolved challenges — log the flag anyway
            await _emit("system", agent_code or "ST",
                f"FLAG DETECTED (no matching challenge): {flag_value}",
                {"ctf_flag_orphan": True, "flag": flag_value})
            continue

        ch = _ctf_session["challenges"][matched_challenge_id]
        if ch.get("status") == "solved":
            continue

        # Register the flag capture
        ch["status"] = "solved"
        ch["flag"] = flag_value
        ch["solved_by"] = agent_code or "unknown"
        ch["solved_at"] = time.time()
        _ctf_session["flags_captured"] += 1
        _ctf_session["captured_points"] += ch.get("points", 0)

        elapsed = time.time() - _ctf_session["started_at"]
        await _emit("system", agent_code or "ST",
            f"FLAG AUTO-CAPTURED: {ch['name']} ({ch.get('points', 0)}pts) — "
            f"{_ctf_session['flags_captured']} flags, "
            f"{_ctf_session['captured_points']}/{_ctf_session['total_points']}pts "
            f"@ {elapsed/60:.1f}m",
            {"ctf_flag": True, "challenge_id": matched_challenge_id,
             "points": ch.get("points", 0), "auto_detected": True})

        await state.broadcast({
            "type": "ctf_flag_captured",
            "challenge_id": matched_challenge_id,
            "challenge_name": ch["name"],
            "category": ch.get("category", "web"),
            "points": ch.get("points", 0),
            "flag": flag_value,
            "agent": agent_code,
            "auto_detected": True,
            "flags_total": _ctf_session["flags_captured"],
            "points_total": _ctf_session["captured_points"],
            "points_max": _ctf_session["total_points"],
            "timestamp": time.time(),
        })


async def _sdk_event_to_dashboard(event: dict, eid: str):
    """Bridge SDK events to the dashboard state + WebSocket broadcast.

    Handles both the event stream (timeline) AND agent status updates
    (LED chips) so the dashboard stays in sync with SDK activity.
    """
    agent_code = event.get("agent", "ST")
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
            # BUG-022 fix: Mark any "running" scans for this agent as completed
            now_iso = datetime.now(timezone.utc).isoformat()
            for scan in state.scans:
                if (scan.get("status") == "running" and
                        scan.get("agent") == agent_code and
                        scan.get("engagement_id") == eid):
                    scan["status"] = "completed"
                    if not scan.get("completed_at"):
                        scan["completed_at"] = now_iso
                    await state.broadcast({
                        "type": "scan_complete",
                        "scan": scan,
                        "timestamp": time.time(),
                    })

        # BUG-005 fix: Inject pending bilateral messages when agent starts running
        if status_str == "running" and agent_code in _pending_bilateral_messages:
            pending = _pending_bilateral_messages.pop(agent_code, [])
            if pending and _active_session_manager:
                session = _active_session_manager.agents.get(agent_code)
                if session and session.is_running:
                    for msg in pending:
                        inject_text = (
                            f"\n{'='*60}\n"
                            f"PENDING MESSAGE from {msg['from']} [{msg['msg_type']}]\n"
                            f"{'='*60}\n"
                            f"{msg['content']}\n"
                            f"{'='*60}\n"
                            f"Incorporate this intelligence into your current task.\n"
                        )
                        await session.send_command(inject_text)

        # Emit phase_update for Scan Coverage when an agent starts running
        if status_str == "running" and agent_code in _AGENT_TO_PHASE:
            await state.broadcast({
                "type": "phase_update",
                "phase": _AGENT_TO_PHASE[agent_code],
                "agent": agent_code,
                "timestamp": time.time(),
            })

    # Handle system events from AgentSessionManager (engagement lifecycle)
    elif event_type == "system":
        control = metadata.get("control")
        if control == "engagement_ended":
            # BUG-014 fix: Reset ALL agent LEDs on engagement end, not just 6.
            # Previously some agents stayed "running" after
            # budget exhaustion or natural completion.
            for ac in AGENT_NAMES:
                await state.update_agent_status(ac, AgentStatus.IDLE)
            await _sync_neo4j_findings(eid)

    # Also update LED on tool_start (agent is actively working)
    elif event_type == "tool_start":
        await state.update_agent_status(agent_code, AgentStatus.RUNNING,
            metadata.get("tool", ""))
        # ENH-001: Extract actual command for execute_command tools
        tool_name = metadata.get("tool", "")
        if "execute_command" in tool_name and not metadata.get("command"):
            tool_input = metadata.get("input", {})
            cmd = tool_input.get("command", "") if isinstance(tool_input, dict) else ""
            if cmd:
                metadata["command"] = cmd.strip()[:200]

        # BUG-006 fix: Auto-create scan record for security tools
        tool_lower = tool_name.lower()
        is_sec_tool = (
            tool_name in _EVIDENCE_TOOLS
            or any(kw in tool_lower for kw in _EVIDENCE_TOOL_KEYWORDS)
        )
        if is_sec_tool:
            tool_id = metadata.get("tool_id", "")
            safe_tool = (
                tool_lower
                .replace("mcp__kali_external__", "")
                .replace("mcp__kali_internal__", "")
                .replace("__", "-")[:30]
            )
            target_str = metadata.get("target", "")
            if not target_str and isinstance(metadata.get("input"), dict):
                target_str = metadata["input"].get("target", "")
            scan_req = {
                "tool": tool_name,
                "tool_display": safe_tool.replace("-", " ").replace("_", " ").title(),
                "target": target_str,
                "agent": agent_code,
                "status": "running",
                "engagement_id": eid,
                "command": metadata.get("command", safe_tool),
            }
            scan_record = await create_scan(scan_req)
            # Track scan ID for update on tool_complete
            if tool_id and isinstance(scan_record, dict):
                _active_tool_scans[tool_id] = scan_record.get("id", "")

        # Also emit phase_update on tool_start for coverage tracking
        if agent_code in _AGENT_TO_PHASE:
            await state.broadcast({
                "type": "phase_update",
                "phase": _AGENT_TO_PHASE[agent_code],
                "agent": agent_code,
                "timestamp": time.time(),
            })

    # On tool_complete: engagement cost cap check + Neo4j stat sync
    # NOTE: Per-agent budget tracking is handled by /api/budget/tool-call endpoint
    # (called by sdk_agent.py). Do NOT duplicate tracking here — that caused BUG-012
    # where costs were double-counted, making agents exhaust at ~50% of expected budget.
    elif event_type == "tool_complete":
        budget = _get_agent_budget(agent_code)
        # BUG-012 FIX: Use authoritative _engagement_cost (actual sum) not estimated_cost sum.
        # Estimated costs diverge wildly from actuals, causing dashboard cost to oscillate.
        _engagement_cost_live = _engagement_cost

        # Check if this tool produced a finding (Neo4j create_finding calls)
        tool_name = metadata.get("tool", "")

        # Engagement-level cost cap check
        if _engagement_cost_live >= ENGAGEMENT_COST_CAP:
            if not getattr(state, '_engagement_cap_warned', False):
                state._engagement_cap_warned = True
                await _emit("system", "ST",
                    f"ENGAGEMENT COST CAP REACHED: ${_engagement_cost_live:.2f} >= "
                    f"${ENGAGEMENT_COST_CAP:.2f}. All agents should wrap up.",
                    {"engagement_cap": True, "cost": round(_engagement_cost_live, 4)})
                await state.broadcast({
                    "type": "engagement_budget_exhausted",
                    "engagement_cost": round(_engagement_cost_live, 4),
                    "cap": ENGAGEMENT_COST_CAP,
                    "timestamp": time.time(),
                })
                # F5: Signal early-stop for all running non-ST agents
                if _active_session_manager and _active_session_manager.is_running:
                    for ac in list(_active_session_manager.agents.keys()):
                        _active_session_manager.signal_early_stop(ac)

        # Broadcast cost_update every 5 tool calls per agent
        if budget["tool_calls"] % 5 == 0:
            await state.broadcast({
                "type": "cost_update",
                "agent": agent_code,
                "tool_calls": budget["tool_calls"],
                "max_tool_calls": budget["max_tool_calls"],
                "estimated_cost": round(budget["estimated_cost"], 4),
                "max_cost": budget["max_cost"],
                "engagement_cost": round(_engagement_cost_live, 4),
                "timestamp": time.time(),
            })
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
        # Normalize tool name for evidence filenames and CEI-2 technique keys
        safe_tool = (
            tool_lower
            .replace("mcp__kali_external__", "")
            .replace("mcp__kali_internal__", "")
            .replace("__", "-")[:30]
        )
        if is_security_tool and event.get("content", "").strip():
            try:
                output_text = event["content"][:50000]  # Cap at 50KB
                # Save to evidence directory
                evidence_root = ensure_evidence_dirs(eid)
                timestamp_str = datetime.now().strftime("%Y%m%d-%H%M%S")
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

                    # Determine best finding to link: VF agent → its active verification target;
                    # other agents → finding whose tool/agent matches, then most recent fallback
                    linked_finding_id = None
                    if agent_code == "VF":
                        # VF agent: link to the finding it's currently verifying
                        for vrf in _verifications.values():
                            if vrf.get("status") == "in_progress" and vrf.get("engagement_id") == eid:
                                linked_finding_id = vrf.get("finding_id")
                                break
                        # Fallback: no in_progress verification — use the most recently updated one
                        if not linked_finding_id:
                            completed_vrfs = [
                                v for v in _verifications.values()
                                if v.get("engagement_id") == eid and v.get("finding_id")
                            ]
                            if completed_vrfs:
                                most_recent = max(completed_vrfs, key=lambda v: v.get("updated_at", 0))
                                linked_finding_id = most_recent.get("finding_id")

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
                            RETURN a
                        """, {
                            "aid": artifact_id, "eid": eid,
                            "path": rel_path, "hash": file_hash,
                            "size": file_size,
                            "caption": f"Auto-captured {safe_tool} output",
                            "agent": agent_code,
                        })

                        # Link artifact to finding — prefer specific ID, then agent match, then most recent
                        if linked_finding_id:
                            sess.run("""
                                MATCH (a:Artifact {id: $aid}), (f:Finding {id: $fid})
                                MERGE (f)-[:HAS_ARTIFACT]->(a)
                            """, {"aid": artifact_id, "fid": linked_finding_id})
                        else:
                            sess.run("""
                                MATCH (a:Artifact {id: $aid})
                                OPTIONAL MATCH (f:Finding {engagement_id: $eid})
                                WITH a, f ORDER BY f.created_at DESC LIMIT 1
                                WHERE f IS NOT NULL
                                MERGE (f)-[:HAS_ARTIFACT]->(a)
                            """, {"aid": artifact_id, "eid": eid})

                    # Broadcast evidence update
                    await state.broadcast({
                        "type": "stat_update",
                        "evidence_count": 1,  # Incremental
                        "timestamp": time.time(),
                    })
            except Exception as e:
                print(f"Evidence auto-capture error: {e}")

        # BUG-006 fix: Auto-update scan record on tool_complete
        tool_id = metadata.get("tool_id", "")
        scan_id = _active_tool_scans.pop(tool_id, None) if tool_id else None
        if scan_id:
            output_preview = (event.get("content", "") or "")[:500]
            try:
                await update_scan(scan_id, {
                    "status": "completed",
                    "output_preview": output_preview,
                    "duration_s": metadata.get("duration_s", 0),
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                })
            except Exception:
                pass

        # BUG-010/004 fix: For exploit/verification agents, bypass debounce to sync
        # findings faster — enables VF to queue earlier while EX is still running
        if agent_code in ("EX", "DA", "VF") and "create_" in tool_name:
            global _last_findings_sync
            _last_findings_sync = 0.0  # Reset debounce for immediate sync

        # Sync new findings from Neo4j on every tool_complete (debounced)
        await _sync_neo4j_findings(eid)

        # CEI-2: Score technique effectiveness across engagements
        if is_security_tool and neo4j_available and neo4j_driver:
            technique_key = f"{safe_tool}:{agent_code}"
            duration_s = metadata.get("duration_s", 0)
            per_call_cost = budget.get("estimated_cost", 0) / max(budget.get("tool_calls", 1), 1)
            content_lower = (event.get("content", "") or "").lower()
            success_hint = any(kw in content_lower for kw in (
                "vulnerability", "cve-", "critical", "high", "medium",
                "exploit", "flag{", "shell", "root", "admin", "found",
            ))
            try:
                with neo4j_driver.session() as sess:
                    sess.run("""
                        MERGE (t:TechniqueRecord {key: $key})
                        ON CREATE SET t.tool=$tool, t.agent=$agent,
                            t.total_attempts=1,
                            t.successes=CASE WHEN $success THEN 1 ELSE 0 END,
                            t.failures=CASE WHEN $success THEN 0 ELSE 1 END,
                            t.success_rate=CASE WHEN $success THEN 1.0 ELSE 0.0 END,
                            t.avg_duration_s=$dur, t.avg_cost_usd=$cost,
                            t.last_used=datetime(), t.last_engagement_id=$eid
                        ON MATCH SET t.total_attempts=t.total_attempts+1,
                            t.successes=t.successes + CASE WHEN $success THEN 1 ELSE 0 END,
                            t.failures=t.failures + CASE WHEN $success THEN 0 ELSE 1 END,
                            t.last_used=datetime(), t.last_engagement_id=$eid
                        WITH t
                        SET t.success_rate = CASE WHEN t.total_attempts > 0
                            THEN toFloat(t.successes) / t.total_attempts ELSE 0.0 END,
                            t.avg_duration_s = CASE WHEN t.total_attempts > 1
                            THEN (t.avg_duration_s * (t.total_attempts - 1) + $dur) / t.total_attempts
                            ELSE $dur END,
                            t.avg_cost_usd = CASE WHEN t.total_attempts > 1
                            THEN (t.avg_cost_usd * (t.total_attempts - 1) + $cost) / t.total_attempts
                            ELSE $cost END
                        WITH t
                        MERGE (e:Engagement {id: $eid})
                        MERGE (t)-[:USED_IN]->(e)
                    """, key=technique_key, tool=safe_tool, agent=agent_code,
                        success=success_hint, dur=duration_s, cost=per_call_cost, eid=eid)
            except Exception as e:
                logger.warning("CEI technique scoring: %s", e)

    # CTF flag auto-detection: scan every event's content for flag patterns
    event_content = event.get("content", "")
    if event_content and _ctf_session and _ctf_session.get("active"):
        await _scan_for_flags(event_content, eid, agent_code)

    # Skip empty control signals from timeline (still broadcast for state changes)
    if event_type == "system" and not event_content and metadata.get("control"):
        await state.broadcast({
            "type": event_type,
            "agent": agent_code,
            "content": "",
            "timestamp": event.get("timestamp", time.time()),
            "metadata": metadata,
        })
        return

    # Add to event timeline
    await state.add_event(AgentEvent(
        id=str(uuid.uuid4())[:8],
        type=event_type,
        agent=agent_code,
        content=event_content,
        timestamp=event.get("timestamp", time.time()),
        metadata=metadata,
    ))


@app.post("/api/engagement/{eid}/start-ai")
async def start_engagement_ai(
    eid: str,
    backend: str = "external",
    target: str = "",
    mode: str = "multi-agent",
):
    """Start an AI-powered PTES engagement.

    Uses multi-agent architecture: Multiple independent Claude SDK sessions — one
    per agent role. ST coordinates, workers execute.

    Works from dashboard GUI and CLI (/athena-engage).
    """
    global _active_session_manager, ENGAGEMENT_COST_CAP

    scope_doc = ""
    client_industry = "general"
    engagement_types = ["external"]  # default
    evidence_mode = "observable"  # default to supervised (HITL gates)
    skip_agents: list[str] = []  # Agents to exclude from this engagement

    # Send early UI feedback before any DB work (perceived speed boost)
    await state.broadcast({
        "type": "engagement_preparing",
        "engagement_id": eid,
        "timestamp": time.time(),
    })

    if not target:
        eng = next((e for e in state.engagements if e.id == eid), None)
        if eng:
            target = eng.target

    # Single Neo4j query for all engagement config (deduplicated from two queries)
    if neo4j_available and neo4j_driver:
        def _load_engagement_config():
            with neo4j_driver.session() as session:
                result = session.run(
                    "MATCH (e:Engagement {id: $eid}) "
                    "RETURN e.target AS target, e.scope AS scope, "
                    "e.scope_doc AS scope_doc, e.client_industry AS client_industry, "
                    "e.types AS types, e.budget AS budget, "
                    "e.evidence_mode AS evidence_mode, e.skip_agents AS skip_agents",
                    eid=eid,
                )
                return result.single()
        try:
            record = await asyncio.to_thread(_load_engagement_config)
            if record:
                if not target and record.get("target"):
                    target = record["target"]
                elif not target and record.get("scope"):
                    target = record["scope"]
                if record.get("scope_doc"):
                    scope_doc = record["scope_doc"]
                if record.get("client_industry"):
                    client_industry = record["client_industry"]
                if record.get("types"):
                    engagement_types = record["types"] if isinstance(record["types"], list) else [record["types"]]
                # P2-FIX: Load per-engagement budget cap from Neo4j
                if record.get("budget") and float(record["budget"]) > 0:
                    ENGAGEMENT_COST_CAP = float(record["budget"])
                if record.get("evidence_mode"):
                    evidence_mode = record["evidence_mode"]
                if record.get("skip_agents"):
                    skip_agents_str = record["skip_agents"]
                    skip_agents = [s.strip() for s in skip_agents_str.split(",") if s.strip()]
        except Exception as e:
            logger.warning("Failed to load engagement config from Neo4j: %s", e)

    if not target:
        return JSONResponse(status_code=400, content={
            "error": "Target scope required. Pass ?target=<ip/cidr/url>"
        })

    # Stop any existing session
    if _active_session_manager and _active_session_manager.is_running:
        await _active_session_manager.stop()
        _active_session_manager = None

    # BUG-021 fix: Auto-detect web_app type for HTTP/HTTPS targets so
    # WV (Web Vuln Scanner) is included in the allowed agent set.
    # This only adds web_app if not already specified and if the target
    # looks like a web URL. Doesn't remove any existing types.
    if target and "web_app" not in engagement_types:
        _target_lower = target.strip().lower()
        if (_target_lower.startswith("http://") or
                _target_lower.startswith("https://") or
                any(_target_lower.endswith(p) for p in
                    [":80", ":443", ":8080", ":8443", ":3000", ":5000"])):
            engagement_types.append("web_app")
            logger.info("Auto-detected web target — added web_app engagement type")

    # Reset budgets for new engagement
    global _engagement_cost, _agent_budgets, _engagement_types
    _agent_budgets = {}
    _engagement_cost = 0.0
    _engagement_types = engagement_types  # BUG-006: Store for agent request gating
    # Apply skip_agents: remove excluded agents from the type-based allowed sets
    global _skip_agents
    _skip_agents = set(skip_agents)
    if _skip_agents:
        logger.info("Skip agents for this engagement: %s", _skip_agents)
    state._engagement_cap_warned = False

    # Reset all agent statuses to IDLE before starting new engagement
    for code in AGENT_NAMES:
        state.agent_statuses[code] = AgentStatus.IDLE
        state.agent_tasks[code] = ""

    # Set engagement active
    state.active_engagement_id = eid
    state.engagement_stopped = False

    # Record started_at timestamp on the in-memory engagement object
    _now_start = time.time()
    for _eng in state.engagements:
        if _eng.id == eid:
            _eng.started_at = _now_start
            _eng.completed_at = None
            break

    # Update Neo4j engagement status to active (non-blocking)
    if neo4j_available and neo4j_driver:
        def _set_active():
            try:
                with neo4j_driver.session() as session:
                    session.run(
                        "MATCH (e:Engagement {id: $eid}) SET e.status = 'active', e.started_at = $started_at",
                        eid=eid,
                        started_at=_now_start,
                    )
            except Exception:
                pass
        asyncio.get_event_loop().run_in_executor(None, _set_active)

    if not MULTI_AGENT_AVAILABLE or not SDK_AVAILABLE:
        return JSONResponse(status_code=500, content={
            "error": "Multi-agent system not available. Check agent_session_manager.py and claude_agent_sdk installation."
        })

    # Map evidence_mode → agent autonomy mode
    # "exploitable" (lab) → full autonomy, no CTF scoring
    # "ctf" → full autonomy + CTF scoring/timer
    # "sprint" → full autonomy, race to first shell, 30-min hard stop
    # "observable" (client/production) → supervised (multi-agent with HITL)
    is_sprint = False
    if mode == "ctf" or evidence_mode == "ctf":
        is_ctf = True
        mode = "ctf"
        logger.info("Engagement mode: CTF — evidence_mode=%s", evidence_mode)
    elif evidence_mode == "sprint":
        is_ctf = False
        is_sprint = True
        mode = "sprint"
        _skip_agents |= {"PE", "RP", "PR"}  # Sprint skips post-exploitation, reporting, passive recon
        logger.info("Engagement mode: Sprint — evidence_mode=%s, forced skip_agents=%s", evidence_mode, _skip_agents)
    elif evidence_mode == "exploitable":
        is_ctf = False
        mode = "autonomous"
        logger.info("Engagement mode: Autonomous (lab) — evidence_mode=%s", evidence_mode)
    else:
        is_ctf = False
        logger.info("Engagement mode: Supervised (client) — evidence_mode=%s", evidence_mode)

    mode_label = "CTF" if is_ctf else ("Sprint" if is_sprint else ("Autonomous" if mode == "autonomous" else "Supervised"))
    is_autonomous = is_ctf or mode == "autonomous" or is_sprint  # Sprint is fully autonomous
    global _is_autonomous
    _is_autonomous = is_autonomous  # BUG-026: expose to scope expansion endpoint

    scope_info = f" Scope document loaded ({len(scope_doc)} chars)." if scope_doc else " No scope document — using target URL constraints only."
    if is_ctf:
        mode_msg = f"CTF MODE activated against {target}. Full AI autonomy — no HITL gates. Flag auto-detection and scoring enabled."
    elif is_sprint:
        mode_msg = f"SPRINT MODE activated against {target}. Racing to first shell — 30-minute hard stop. Full autonomy, no HITL gates. Agents: AR, DA, EX, VF only."
    elif mode == "autonomous":
        mode_msg = f"AUTONOMOUS MODE activated against {target}. Full AI autonomy — no HITL gates.{scope_info}"
    else:
        mode_msg = f"SUPERVISED MODE activated. PTES phases 1-7 against {target}. HITL required for exploitation and novel tools.{scope_info}"
    await state.add_event(AgentEvent(
        id=str(uuid.uuid4())[:8],
        type="system",
        agent="ST",
        content=mode_msg,
        timestamp=time.time(),
    ))

    await state.broadcast({
        "type": "engagement_started",
        "engagement_id": eid,
        "mode": "ai-ctf" if is_ctf else ("ai-autonomous" if mode == "autonomous" else "ai-multi-agent"),
        "engagement_active": True,
        "timestamp": time.time(),
    })

    athena_dir = str(Path(__file__).resolve().parent.parent.parent)

    if is_ctf:
        # ── CTF Mode ──────────────────────────────────────────────
        # Initialize CTF session if not already active
        if not _ctf_session or not _ctf_session["active"]:
            await start_ctf_session(
                engagement_id=eid,
                competition_name=f"CTF-{eid}",
                time_limit_minutes=0,
            )

        # Build challenge list for ST context
        challenge_list = ""
        if _ctf_session and _ctf_session["challenges"]:
            for ch_id, ch in _ctf_session["challenges"].items():
                status = ch.get("status", "unsolved")
                challenge_list += (
                    f"  [{status.upper()}] {ch['name']} (id={ch_id}, "
                    f"cat={ch.get('category','web')}, diff={ch.get('difficulty',1)}, "
                    f"pts={ch.get('points',0)}, url={ch.get('url','')})\n"
                    f"    Description: {ch.get('description','')[:200]}\n"
                )
        else:
            challenge_list = "  No challenges pre-loaded. Discover challenges by exploring the target.\n"

        st_context = f"""CTF ENGAGEMENT: {eid}
Target: {target}
Mode: CTF (Capture The Flag)
Dashboard: http://localhost:8080

CHALLENGE LIST:
{challenge_list}
SCORING: {_ctf_session.get('total_points', 0)} total points available.
Prioritize difficulty 1 challenges first for quick points.

Start by reviewing the challenge list above, then assign agents to solve them.
Request workers via POST http://localhost:8080/api/agents/request
Body: {{"agent":"WV","task":"Solve challenge <name>: <description>. Target: <url>","priority":"high"}}
"""
    elif is_sprint:
        # ── Sprint Mode — Race to First Shell ─────────────────────
        # Resource-aware: spawn parallel EX agents if tier supports it
        _parallel_ex = _system_resources.get("parallel_ex", 1)
        if _parallel_ex >= 3:
            _sprint_ex_context = f"""PARALLEL EXPLOITATION (Performance tier — {_parallel_ex} EX agents available):
Spawn 3 separate EX agents, each targeting ONE specific finding. First shell from any EX wins.
After AR/DA report findings, pick the top 3 highest-severity and assign one per EX agent:

POST http://localhost:8080/api/agents/request
Body: {{"agent":"EX-1","task":"SPRINT EXPLOIT TARGET 1: <highest severity finding>. 60s timeout. Race to shell. POST to /api/engagements/{eid}/first-shell on success.","priority":"critical"}}

POST http://localhost:8080/api/agents/request
Body: {{"agent":"EX-2","task":"SPRINT EXPLOIT TARGET 2: <second highest finding>. 60s timeout. Race to shell. POST to /api/engagements/{eid}/first-shell on success.","priority":"critical"}}

POST http://localhost:8080/api/agents/request
Body: {{"agent":"EX-3","task":"SPRINT EXPLOIT TARGET 3: <third highest finding>. 60s timeout. Race to shell. POST to /api/engagements/{eid}/first-shell on success.","priority":"critical"}}

IMPORTANT: Wait for AR to report at least 3 findings before spawning EX agents. Assign each EX agent a DIFFERENT finding — do not duplicate targets."""
        else:
            _sprint_ex_context = f"""SINGLE EXPLOITATION (resource tier: {_system_resources.get('tier', 'standard')}):
POST http://localhost:8080/api/agents/request
Body: {{"agent":"EX","task":"SPRINT EXPLOIT: Monitor bus for findings from AR/DA. Target top 3 highest-severity only. 60s timeout per attempt, 2 retries max. Race to first shell. When you get a shell, POST to /api/engagements/{eid}/first-shell immediately.","priority":"critical"}}"""
        st_context = f"""ENGAGEMENT: {eid}
Target: {target}
Type: {', '.join(engagement_types)}
Backend: kali_{backend}
Dashboard: http://localhost:8080

MODE: SPRINT — Race to First Shell
OBJECTIVE: Get a confirmed shell/RCE on {target} as FAST as possible.
TIME LIMIT: 30 minutes hard stop. The engagement auto-terminates at 30 minutes.
STRATEGY:
  1. Spawn AR, DA, and EX simultaneously — do NOT wait for phases. Request all three NOW.
  2. AR runs fast scan: naabu top-1000 ports, then nmap top-20 scripts on open ports only. Feed results to DA+EX immediately.
  3. DA researches CVEs as AR discovers services. Feed exploit-ready CVEs to EX via bilateral messaging. Speed over depth.
  4. EX targets ONLY the top 3 highest-severity findings. 60-second timeout per exploit attempt, 2 retries max, then move on.
  5. STOP the engagement the moment EX confirms first shell. Post to /api/engagements/{eid}/first-shell.
  6. Do NOT request PE, RP, or PR — they are DISABLED for sprint mode.

AGENTS AVAILABLE: AR (recon), DA (analysis), EX (exploitation), VF (verification — only if shell needs independent confirmation)
AGENTS DISABLED: PE, RP, PR — do NOT request them.

START NOW — request AR and DA immediately, then EX agent(s):
POST http://localhost:8080/api/agents/request
Body: {{"agent":"AR","task":"SPRINT SCAN: naabu top-1000 ports on {target}, then nmap -sV --top-ports 20 on open ports. 30s timeout per host. Feed results to DA+EX immediately via bilateral messaging.","priority":"critical"}}

POST http://localhost:8080/api/agents/request
Body: {{"agent":"DA","task":"SPRINT ANALYSIS: As AR discovers services, immediately research CVEs and known exploits. Feed exploit-ready CVEs to EX via bilateral messaging. Prioritize by CVSS severity. Speed over depth.","priority":"critical"}}

{_sprint_ex_context}
"""
    else:
        # ── Standard PTES Mode ────────────────────────────────────
        st_context = f"""ENGAGEMENT: {eid}
Target: {target}
Type: {', '.join(engagement_types)}
Backend: kali_{backend}
Dashboard: http://localhost:8080
"""
        if scope_doc:
            st_context += f"\nSCOPE DOCUMENT:\n{scope_doc}\n"
        # BUG-006 fix: Tell ST which agents are appropriate for this engagement type
        _type_agents = {
            "external": "PR (passive recon/OSINT), AR (active recon), EX (exploitation), PE (post-exploitation/lateral movement), VF (verification), RP (reporting). Do NOT request WV — no web app in scope.",
            "web_app":  "PR (passive recon/OSINT), WV (web vuln scan), DA (deep analysis/CVE research), PX (probe executor), EX (exploitation), PE (post-exploitation/lateral movement), VF (verification), RP (reporting). Do NOT request AR — network recon not in scope.",
            "internal": "PR (passive recon/OSINT), AR (active recon), EX (exploitation), PE (post-exploitation/lateral movement), VF (verification), RP (reporting). Do NOT request WV — no web app in scope.",
        }
        _type_str = ', '.join(engagement_types)
        _allowed_agents = _type_agents.get(engagement_types[0], "PR, AR, WV, DA, PX, EX, VF, RP") if len(engagement_types) == 1 else "PR, AR, WV, DA, PX, EX, VF, RP"

        # Filter out skipped agents from the allowed agents text
        if _skip_agents:
            # Parse the allowed agents string to remove skipped ones
            # Format: "PR (passive recon/OSINT), AR (active recon), ..."
            _agent_parts = re.split(r',\s*(?=[A-Z]{2}\s)', _allowed_agents)
            _filtered_parts = [p for p in _agent_parts if not any(p.strip().startswith(sa) for sa in _skip_agents)]
            _allowed_agents = ', '.join(_filtered_parts)

        # Determine starting agent — skip PR if OSINT is skipped
        if "PR" in _skip_agents:
            # Start with AR for external/internal, WV for web_app
            if "web_app" in engagement_types:
                _start_agent = "WV"
                _start_task = f"Web vulnerability scanning against {target} — crawl site, identify technologies, check OWASP Top 10"
            else:
                _start_agent = "AR"
                _start_task = f"Active reconnaissance against {target} — port scanning, service enumeration, OS fingerprinting"
            _skip_note = "\nNOTE: OSINT/Passive Recon (PR) has been SKIPPED for this engagement. Do NOT request PR.\n"
        else:
            _start_agent = "PR"
            _start_task = f"Passive OSINT reconnaissance against {target} — subdomain enumeration, certificate transparency, WHOIS, DNS, Google dorking"
            _skip_note = ""

        if {"DA", "PX"} & _skip_agents:
            _skip_note += "NOTE: 0-Day Hunting (DA/PX) has been SKIPPED for this engagement. Do NOT request DA or PX.\n"

        st_context += f"""
AGENT SELECTION (based on engagement type: {_type_str}):
Allowed agents: {_allowed_agents}
IMPORTANT: Only request agents appropriate for the engagement type. Do NOT request web app agents (WV) for external/network engagements, and do NOT request network recon agents (AR) for web-app-only engagements.
{_skip_note}
Start by querying Neo4j for existing engagement state, then begin with
{_start_agent} — request it via POST http://localhost:8080/api/agents/request
Body: {{"agent":"{_start_agent}","task":"{_start_task}","priority":"high"}}
"""

    # HIGH-2/MED-2: Clear per-engagement state from previous runs
    _pending_bilateral_messages.clear()
    _agent_msg_counts.clear()

    _active_session_manager = AgentSessionManager(
        engagement_id=eid,
        target=target,
        backend=backend,
        dashboard_state=state,
        athena_root=athena_dir,
        mode="sprint" if is_sprint else (mode if is_ctf else ("autonomous" if is_autonomous else "multi-agent")),
        time_limit_minutes=30 if is_sprint else 0,  # Sprint: 30-min hard stop
        neo4j_driver=neo4j_driver,  # MED-3: inject driver, avoid circular import
    )
    _active_session_manager.set_event_callback(
        lambda evt: _sdk_event_to_dashboard(evt, eid)
    )

    try:
        await _active_session_manager.start(initial_st_context=st_context)
    except Exception as e:
        _active_session_manager = None
        return JSONResponse(status_code=500, content={
            "error": f"Multi-agent session failed to start: {str(e)[:300]}"
        })

    if is_ctf:
        started_content = f"CTF session started. ST coordinating flag capture against {target}."
        started_mode = "ai-ctf"
        started_msg = f"CTF engagement started against {target}. ST coordinating flag capture."
    elif is_autonomous:
        started_content = f"Autonomous session started. ST coordinating against {target}. No HITL gates."
        started_mode = "ai-autonomous"
        started_msg = f"Autonomous engagement started against {target}. ST is coordinating."
    else:
        started_content = "Multi-agent session started. ST coordinating, workers on standby."
        started_mode = "ai-multi-agent"
        started_msg = f"Multi-agent engagement started against {target}. ST is coordinating."

    await state.add_event(AgentEvent(
        id=str(uuid.uuid4())[:8],
        type="system",
        agent="ST",
        content=started_content,
        timestamp=time.time(),
    ))

    return {
        "ok": True,
        "engagement_id": eid,
        "mode": started_mode,
        "message": started_msg,
        "skip_agents": list(_skip_agents),
    }


async def _generate_engagement_learnings(eid: str) -> str:
    """CEI-5: Generate structured learnings document from engagement data."""
    if not neo4j_available or not neo4j_driver:
        return ""

    try:
        with neo4j_driver.session() as session:
            # Engagement metadata
            eng_result = session.run("""
                MATCH (e:Engagement {id: $eid})
                RETURN e.target AS target, e.status AS status,
                       e.engagement_cost AS cost, e.types AS types
            """, eid=eid)
            eng = eng_result.single()
            if not eng:
                return ""

            # Techniques used in this engagement
            tech_result = session.run("""
                MATCH (t:TechniqueRecord)-[:USED_IN]->(e:Engagement {id: $eid})
                RETURN t.key AS key, t.tool AS tool, t.agent AS agent,
                       t.success_rate AS rate, t.avg_duration_s AS dur,
                       t.total_attempts AS attempts
                ORDER BY t.success_rate DESC
            """, eid=eid)
            techniques = [dict(r) for r in tech_result]

            # Findings summary
            findings_result = session.run("""
                MATCH (f:Finding {engagement_id: $eid})
                RETURN f.severity AS severity, f.status AS status,
                       f.verified AS verified, count(*) AS cnt
                ORDER BY f.severity
            """, eid=eid)
            findings = [dict(r) for r in findings_result]

        # Build learnings document
        target = eng.get("target", "unknown")
        cost = eng.get("cost") or _engagement_cost or 0
        types_raw = eng.get("types") or []
        types = [types_raw] if isinstance(types_raw, str) else list(types_raw)

        lines = [
            f"# Engagement {eid} — Learnings",
            f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')} | "
            f"**Target:** {target} | **Cost:** ${cost:.2f} | "
            f"**Types:** {', '.join(types) if types else 'general'}",
            "",
        ]

        # Effective techniques
        effective = [t for t in techniques if (t.get("rate") or 0) > 0.3]
        if effective:
            lines.append("## Effective Techniques")
            for t in effective:
                rate_pct = round((t["rate"] or 0) * 100)
                dur = round(t.get("dur") or 0)
                lines.append(f"- **{t['key']}** — {rate_pct}% success, ~{dur}s avg")
            lines.append("")

        # Ineffective techniques
        ineffective = [t for t in techniques if (t.get("rate") or 0) <= 0.3]
        if ineffective:
            lines.append("## Ineffective Techniques")
            for t in ineffective:
                rate_pct = round((t["rate"] or 0) * 100)
                dur = round(t.get("dur") or 0)
                lines.append(f"- {t['key']} — {rate_pct}% success, ~{dur}s avg")
            lines.append("")

        # Findings summary
        total_findings = sum(f.get("cnt", 0) for f in findings)
        if total_findings > 0:
            lines.append("## Findings Summary")
            sev_counts = {}
            for f in findings:
                sev = (f.get("severity") or "unknown").upper()
                sev_counts[sev] = sev_counts.get(sev, 0) + f.get("cnt", 0)
            parts = []
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                if sev in sev_counts:
                    parts.append(f"{sev_counts[sev]} {sev}")
            lines.append(f"**Total:** {total_findings} — {', '.join(parts)}")
            lines.append("")

        return "\n".join(lines)
    except Exception as e:
        logger.warning("CEI learnings generator: %s", e)
        return ""


async def _auto_stop_with_rp_gate(eid: str):
    """BUG-016: When ST declares completion, ensure RP runs before stopping."""
    RP_TIMEOUT_S = 120
    rp_status = state.agent_statuses.get("RP", AgentStatus.IDLE)

    if rp_status != AgentStatus.COMPLETED:
        logger.info(
            "BUG-016: ST complete but RP not done (status=%s). Auto-requesting RP.",
            rp_status.value if hasattr(rp_status, "value") else rp_status,
        )
        if _active_session_manager and _active_session_manager.is_running:
            try:
                _active_session_manager.request_agent(
                    "RP",
                    f"Generate final pentest report for engagement {eid}",
                    priority="high",
                )
            except Exception as e:
                logger.warning("BUG-016: Failed to request RP via session manager: %s", e)
            try:
                await state.broadcast({
                    "type": "agent_request",
                    "agent": "RP",
                    "task": f"Generate final pentest report for engagement {eid}",
                    "priority": "high",
                    "requested_by": "system",
                    "timestamp": time.time(),
                })
            except Exception as e:
                logger.warning("BUG-016: Failed to broadcast RP request: %s", e)

        # Poll until RP completes or timeout
        deadline = time.time() + RP_TIMEOUT_S
        while time.time() < deadline:
            await asyncio.sleep(3)
            rp_now = state.agent_statuses.get("RP", AgentStatus.IDLE)
            if rp_now == AgentStatus.COMPLETED:
                logger.info("BUG-016: RP completed. Proceeding to stop.")
                break
        else:
            logger.warning(
                "BUG-016: RP did not complete within %ds. Stopping anyway.", RP_TIMEOUT_S
            )

    # BUG-025: Before stopping, wait for ALL agents to finish (not just RP)
    ALL_DONE_TIMEOUT_S = 300  # 5 minutes max wait
    deadline_all = time.time() + ALL_DONE_TIMEOUT_S
    while time.time() < deadline_all:
        running_agents = [
            code for code, status in state.agent_statuses.items()
            if status == AgentStatus.RUNNING
        ]
        if not running_agents:
            break
        logger.info("BUG-025: Waiting for running agents: %s", running_agents)
        await asyncio.sleep(5)
    else:
        still_running = [c for c, s in state.agent_statuses.items() if s == AgentStatus.RUNNING]
        logger.warning("BUG-025: Timeout — still running: %s. Stopping anyway.", still_running)

    await stop_engagement(eid)


@app.post("/api/engagement/{eid}/stop")
async def stop_engagement(eid: str):
    """Stop a running engagement and kill all active processes."""
    global _active_session_manager, _is_autonomous
    _is_autonomous = False  # BUG-026: reset autonomous mode on stop
    state.engagement_stopped = True
    state.engagement_pause_event.set()  # Unblock if paused so task can exit

    # 0. Stop manager (instant — sets flags + cancel signals)
    import subprocess as _sp
    eid_for_kill = ""
    if _active_session_manager and _active_session_manager.is_running:
        eid_for_kill = _active_session_manager.engagement_id or ""
        _active_session_manager.is_running = False
        # Cancel all agent tasks directly
        for code, session in _active_session_manager.agents.items():
            if session.is_running:
                session.is_running = False
                if session._query_task and not session._query_task.done():
                    session._query_task.cancel()
        # Cancel manager task
        if _active_session_manager._manager_task and not _active_session_manager._manager_task.done():
            _active_session_manager._manager_task.cancel()
        _active_session_manager = None

    # 1. SIGTERM + immediate SIGKILL — don't wait, kill fast
    if eid_for_kill:
        _sp.run(["pkill", "-15", "-f", f"ATHENA engagement {eid_for_kill}"],
                capture_output=True, timeout=2)
        # Immediate SIGKILL — don't wait 3s, agents have in-flight tool calls
        _sp.run(["pkill", "-9", "-f", f"ATHENA engagement {eid_for_kill}"],
                capture_output=True, timeout=2)

    # 2. Background: Kali kill + final sweep after 1s
    async def _stop_cleanup():
        await asyncio.sleep(1)
        if eid_for_kill:
            # Final sweep for any stragglers
            _sp.run(["pkill", "-9", "-f", f"ATHENA engagement {eid_for_kill}"],
                    capture_output=True, timeout=2)
        if kali_client:
            try:
                await kali_client.kill_all()
            except Exception:
                pass
    asyncio.ensure_future(_stop_cleanup())
    kill_results = {"status": "stop_sent"}

    # 2.5 Broadcast engagement_stopped IMMEDIATELY — don't wait for cleanup
    # This lets the frontend go idle right away while cleanup continues async
    await state.broadcast({
        "type": "system",
        "content": f"Engagement {eid} stopped by operator. Active processes killed.",
        "metadata": {"control": "engagement_stopped"},
        "timestamp": time.time(),
    })

    # 3. Unblock any waiting HITL approvals so the task can exit
    for evt_data in state.approval_events.values():
        evt_data["approved"] = False
        evt_data["event"].set()

    # 4. Cancel the engagement asyncio task (cancels in-flight requests)
    if state.engagement_task and not state.engagement_task.done():
        state.engagement_task.cancel()

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
    _now_stop = time.time()
    for _eng in state.engagements:
        if _eng.id == eid:
            _eng.completed_at = _now_stop
            break
    if neo4j_available and neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                session.run(
                    "MATCH (e:Engagement {id: $eid}) SET e.status = 'completed', e.completed_at = $completed_at",
                    eid=eid,
                    completed_at=_now_stop,
                )
        except Exception:
            pass
    await state.broadcast({
        "type": "engagement_status",
        "engagement_id": eid,
        "status": "completed",
        "timestamp": time.time(),
    })

    # CEI-4: Persist engagement learnings for future engagements
    try:
        learnings = await _generate_engagement_learnings(eid)
        if learnings:
            learnings_dir = Path(__file__).parent.parent.parent / "docs" / "learnings"
            learnings_dir.mkdir(parents=True, exist_ok=True)
            learnings_path = learnings_dir / f"{eid}.md"
            learnings_path.write_text(learnings, encoding="utf-8")
            logger.info("CEI: Saved engagement learnings to %s", learnings_path)
    except Exception as e:
        logger.warning("CEI: Learnings persistence failed: %s", e)

    # Broadcast final cost so the frontend cost display is accurate at session end
    await state.broadcast({
        "type": "cost_update",
        "engagement_cost": round(_engagement_cost, 4),
        "tool_calls": 0,
        "max_tool_calls": 0,
        "final": True,
    })

    # engagement_stopped already broadcast above (step 2.5) — don't duplicate
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
    global _network_paused
    # User-initiated pause clears network_paused flag so auto-resume doesn't
    # override the user's intent.
    _network_paused = False

    # 1. Pause manager (instant — sets flags + cancel signals, no await on tasks)
    if _active_session_manager and _active_session_manager.is_running:
        await _active_session_manager.pause()

    # 2. SIGTERM claude subprocesses (graceful — lets SDK flush session state)
    import subprocess as _sp
    eid = _active_session_manager.engagement_id if _active_session_manager else ""
    if eid:
        _sp.run(["pkill", "-15", "-f", f"ATHENA engagement {eid}"],
                capture_output=True, timeout=2)

    # 3. Background escalation: wait 3s, SIGKILL any survivors
    async def _escalate_kill():
        await asyncio.sleep(3)
        if eid:
            _sp.run(["pkill", "-9", "-f", f"ATHENA engagement {eid}"],
                    capture_output=True, timeout=2)
    asyncio.ensure_future(_escalate_kill())

    # 4. Kill Kali processes (fire-and-forget)
    kill_results = {}
    if kali_client:
        asyncio.ensure_future(kali_client.kill_all())
        kill_results = {"status": "kill_sent"}

    state.engagement_pause_event.clear()

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
    """Resume a paused engagement. Paused scans will be re-run by agents."""
    # Resume multi-agent session manager
    if _active_session_manager and _active_session_manager.is_running:
        await _active_session_manager.resume()

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
    await state.update_agent_status("ST", AgentStatus.RUNNING, "Validating authorization")
    await _emit_thinking("ST",
        thought="Need to validate Rules of Engagement before any scanning begins.",
        reasoning="Authorization is the first step in PTES methodology. Without confirmed scope, all subsequent scanning could be unauthorized.",
        action="validate_roe")
    await asyncio.sleep(2)

    st_tool = str(uuid.uuid4())[:8]
    await _emit_tool_start("ST", "Validating authorization scope...", "roe_validator", st_tool)
    await asyncio.sleep(0.5)
    await _emit_chunk("ST", st_tool, "Loading Rules of Engagement document...\n")
    await asyncio.sleep(0.3)
    await _emit_chunk("ST", st_tool, "Scope: *.acme.com, 10.0.0.0/24\n")
    await asyncio.sleep(0.3)
    await _emit_chunk("ST", st_tool, "Excluded: mail.acme.com, 10.0.0.1 (prod gateway)\n")
    await asyncio.sleep(0.3)
    await _emit_chunk("ST", st_tool, "Authorization: SIGNED — Valid through 2026-03-15\n")
    await _emit_tool_complete("ST", "Authorization validated. Scope: *.acme.com, 10.0.0.0/24", st_tool)
    await asyncio.sleep(1)

    # ── Phase 2: INTELLIGENCE GATHERING ──
    if not await _demo_checkpoint(): return
    await _emit_phase("INTELLIGENCE GATHERING")
    await _emit_thinking("ST",
        thought="Target scope validated. Time to dispatch recon agents in parallel.",
        reasoning="Running Active Recon with broad and deep scanning simultaneously maximizes coverage while minimizing elapsed time.",
        action="dispatch_agents")
    await asyncio.sleep(1.5)

    # Active Recon — historical URL discovery
    await state.update_agent_status("AR", AgentStatus.RUNNING, "Historical URL discovery")
    await _emit_thinking("AR",
        thought="Starting passive reconnaissance against acme.com.",
        reasoning="GAU + Wayback Machine will reveal historical endpoints without touching the target directly.")

    ar_gau_tool = str(uuid.uuid4())[:8]
    await _emit_tool_start("AR", "Running GAU against acme.com...", "gau_discover", ar_gau_tool)
    await asyncio.sleep(0.5)
    await _emit_chunk("AR", ar_gau_tool, "Fetching from Wayback Machine...\n")
    await asyncio.sleep(0.4)
    await _emit_chunk("AR", ar_gau_tool, "  [+] 1,247 URLs from web.archive.org\n")
    await asyncio.sleep(0.3)
    await _emit_chunk("AR", ar_gau_tool, "Fetching from Common Crawl...\n")
    await asyncio.sleep(0.4)
    await _emit_chunk("AR", ar_gau_tool, "  [+] 892 URLs from commoncrawl.org\n")
    await asyncio.sleep(0.3)
    await _emit_chunk("AR", ar_gau_tool, "Fetching from AlienVault OTX...\n")
    await asyncio.sleep(0.3)
    await _emit_chunk("AR", ar_gau_tool, "  [+] 708 URLs from otx.alienvault.com\n")
    await asyncio.sleep(0.3)
    await _emit_chunk("AR", ar_gau_tool, "\nTotal: 2,847 unique URLs\n")
    await asyncio.sleep(0.2)
    await _emit_chunk("AR", ar_gau_tool, "  API endpoints: 23\n  Admin paths: 8\n  Login forms: 3\n")
    await _emit_tool_complete("AR", "GAU found 2,847 historical URLs. 23 API endpoints, 8 admin paths.", ar_gau_tool)
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

    await state.update_agent_status("AR", AgentStatus.COMPLETED)
    await asyncio.sleep(1)

    # ── Phase 3: THREAT MODELING ──
    if not await _demo_checkpoint(): return
    await _emit_phase("THREAT MODELING")
    await state.update_agent_status("DA", AgentStatus.RUNNING, "CVE database queries")
    await _emit_thinking("DA",
        thought="Cross-referencing detected technologies with vulnerability databases.",
        reasoning="Apache Struts 2.5 and WordPress 6.4 are priority targets. Need to check NVD, Exploit-DB, and CISA KEV for known exploits.",
        action="query_nvd")
    await asyncio.sleep(3)

    da_tool = str(uuid.uuid4())[:8]
    await _emit_tool_start("DA", "Querying NVD, Exploit-DB, CISA KEV...", "cve_lookup", da_tool)
    await asyncio.sleep(0.4)
    await _emit_chunk("DA", da_tool, "[NVD] Querying Apache Struts 2.5.x...\n")
    await asyncio.sleep(0.5)
    await _emit_chunk("DA", da_tool, "  CVE-2026-21345 CVSS:10.0 — RCE via OGNL injection [CISA KEV]\n")
    await asyncio.sleep(0.4)
    await _emit_chunk("DA", da_tool, "  CVE-2025-48901 CVSS:9.1 — Auth bypass [CISA KEV]\n")
    await asyncio.sleep(0.4)
    await _emit_chunk("DA", da_tool, "[NVD] Querying WordPress 6.4...\n")
    await asyncio.sleep(0.4)
    await _emit_chunk("DA", da_tool, "  CVE-2026-10234 CVSS:7.5 — SQLi in REST API\n")
    await asyncio.sleep(0.3)
    await _emit_chunk("DA", da_tool, "\n[CISA KEV] 3 actively exploited CVEs found\n")
    await _emit_tool_complete("DA", "Found 8 critical CVEs. 3 in CISA KEV. CVE-2026-21345 (Struts RCE) high priority.", da_tool)
    await state.update_agent_status("DA", AgentStatus.COMPLETED)
    await asyncio.sleep(0.5)

    # Deep Analysis — graph-based kill chain discovery
    await state.update_agent_status("DA", AgentStatus.RUNNING, "Building attack graph")
    await _emit_thinking("DA",
        thought="Constructing multi-step attack paths from CVE data and network topology.",
        reasoning="8 CVEs across 156 hosts create multiple kill chains. Need to identify paths from external-facing services to high-value targets (databases, AD controllers).",
        action="analyze_attack_paths")
    await asyncio.sleep(2)
    await _emit("agent_complete", "DA", "3 critical attack paths identified. Priority: Struts RCE → lateral movement → DB compromise.")
    await state.update_agent_status("DA", AgentStatus.COMPLETED)
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
        discovered_at=time.time(),
        confirmed_at=None,
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
        discovered_at=time.time(),
        confirmed_at=None,
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
        discovered_at=time.time(),
        confirmed_at=None,
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

    # Deep Analysis — custom payload generation for unmatched vulns
    await state.update_agent_status("DA", AgentStatus.RUNNING, "Crafting custom payloads")
    await _emit_thinking("DA",
        thought="Nuclei confirmed standard CVEs. Checking for edge cases where no pre-built exploit exists.",
        reasoning="The CORS misconfiguration + missing CSP combo could allow chained exploitation. Crafting a custom XSS-to-CSRF payload for the admin panel.")
    await asyncio.sleep(2.5)
    await _emit("agent_complete", "DA", "Custom payload crafted: chained XSS→CSRF for admin panel. Ready for exploitation phase.")
    await state.update_agent_status("DA", AgentStatus.COMPLETED)
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
    await state.update_agent_status("EX", AgentStatus.RUNNING, "Simulating attack paths")
    await _emit_thinking("EX",
        thought="SIMULATION MODE: Mapping potential lateral movement from SQL injection compromise.",
        reasoning="Simulated post-exploitation maps the blast radius without actually pivoting. Shows client the real-world impact of the SQLi finding.")
    await asyncio.sleep(3)

    pe_tool = str(uuid.uuid4())[:8]
    await _emit_tool_start("EX", "Simulating lateral movement paths...", "attack_path_sim", pe_tool)
    await asyncio.sleep(0.4)
    await _emit_chunk("EX", pe_tool, "[SIM] Path 1: DB pivot → internal network via MySQL outfile\n")
    await asyncio.sleep(0.5)
    await _emit_chunk("EX", pe_tool, "[SIM] Path 2: Credential reuse across 12 hosts (password hash extraction)\n")
    await asyncio.sleep(0.5)
    await _emit_chunk("EX", pe_tool, "[SIM] Path 3: Privilege escalation via MySQL UDF injection\n")
    await _emit_tool_complete("EX", "3 attack paths simulated: DB pivot, credential reuse (12 hosts), MySQL UDF escalation.", pe_tool)
    await _emit_stats(hosts=156, services=89, vulns=8, findings=7)
    await state.update_agent_status("EX", AgentStatus.COMPLETED)
    await asyncio.sleep(0.5)

    # Verification — purple team detection coverage
    await state.update_agent_status("VF", AgentStatus.RUNNING, "Checking detection coverage")
    await _emit_thinking("VF",
        thought="Querying client SIEM/EDR for detection of exploitation and post-exploitation activity.",
        reasoning="Need to determine if the SQLi exploitation, lateral movement simulation, and UDF escalation attempts triggered any alerts. Undetected activity is often the most critical finding for the client.")
    await asyncio.sleep(2.5)
    await _emit("agent_complete", "VF", "Detection gaps: SQLi exploitation UNDETECTED by WAF. Lateral movement triggered 1 of 3 EDR rules. UDF escalation UNDETECTED.")
    await state.update_agent_status("VF", AgentStatus.COMPLETED)
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
    await state.update_agent_status("ST", AgentStatus.COMPLETED, "Engagement complete")

    await _emit_phase("COMPLETE")
    await _emit("system", "ST", "Acme Corp External engagement completed. All agents finished. Report ready for review.")


async def _handle_multi_agent_operator_command(cmd_text: str):
    """Forward an operator command to ST via the multi-agent session manager.

    BUG-020 FIX: Send immediate acknowledgment BEFORE calling send_command()
    so the operator always sees feedback in the timeline.
    BUG-019 FIX: Classify command and communicate routing to operator.
    """
    # Immediate acknowledgment — operator sees this BEFORE send_command() runs
    is_blocking = _is_blocking_command(cmd_text)
    if is_blocking:
        immediate_ack = "⚡ Blocking command received — interrupting ST now."
    else:
        immediate_ack = "📋 Suggestion queued — ST picks up at next turn boundary (~0.2s-2min)."

    await state.broadcast({
        "type": "operator_response",
        "agent": "ST",
        "agentName": AGENT_NAMES.get("ST", "Strategy"),
        "content": immediate_ack,
        "timestamp": time.time(),
        "metadata": {"command_type": "blocking" if is_blocking else "non_blocking"},
    })

    try:
        result = await _active_session_manager.send_command(cmd_text)
        # Only broadcast final result if it adds info beyond the immediate ack
        if result and "queued" not in result.lower() and "sent" not in result.lower():
            await state.broadcast({
                "type": "operator_response",
                "agent": "ST",
                "agentName": AGENT_NAMES.get("ST", "Strategy"),
                "content": result,
                "timestamp": time.time(),
            })
    except Exception as e:
        err_content = f"Error forwarding command: {str(e)[:200]}"
        await state.add_event(AgentEvent(
            id=str(uuid.uuid4()), type="operator_response", agent="ST",
            content=err_content, timestamp=time.time(),
            metadata={"agent_name": AGENT_NAMES.get("ST", "Strategy"), "engagement": state.active_engagement_id or ""},
        ))
        await state.broadcast({
            "type": "operator_response",
            "agent": "ST",
            "agentName": AGENT_NAMES.get("ST", "Strategy"),
            "content": err_content,
            "timestamp": time.time(),
        })


# ── BUG-037 FIX: Agent Stop API ──────────────

@app.post("/api/agents/stop/{agent_code}")
async def stop_agent(agent_code: str):
    """Force-stop a specific agent. Called by ST to stop VF or other workers.

    This is the server-side force-stop mechanism — it signals early_stop on the
    agent's session, which causes the SDK loop to exit after the current chunk.
    More reliable than prompt-based directives since it doesn't depend on LLM compliance.
    """
    agent_code = agent_code.upper()
    if agent_code == "ST":
        return JSONResponse(status_code=400, content={"error": "Cannot stop ST — use engagement stop instead"})

    if not _active_session_manager or not _active_session_manager.is_running:
        return JSONResponse(status_code=400, content={"error": "No active session manager"})

    _active_session_manager.signal_early_stop(agent_code)
    await state.update_agent_status(agent_code, AgentStatus.IDLE)
    await state.broadcast({
        "type": "agent_status",
        "agent": agent_code,
        "status": "idle",
        "content": f"{agent_code} stopped by directive",
        "timestamp": time.time(),
    })
    return {"ok": True, "agent": agent_code, "message": f"{agent_code} stop signal sent"}


# ── FR-S2-003: ST Override Authority ──────────────

@app.post("/api/agents/stop-all-workers")
async def stop_all_workers():
    """ST override: force-stop all worker agents."""
    worker_codes = ["PR", "AR", "WV", "EX", "PE", "VF", "DA", "PX"]
    stopped = []
    for code in worker_codes:
        try:
            if _active_session_manager and _active_session_manager.is_running:
                _active_session_manager.signal_early_stop(code)
                await state.update_agent_status(code, AgentStatus.IDLE)
                stopped.append(code)
        except Exception:
            pass
    return {"ok": True, "stopped": stopped}


@app.post("/api/agents/force-spawn")
async def force_spawn_agent(request: Request):
    """ST override: spawn agent bypassing workers-still-running gate."""
    payload = await request.json()
    agent_code = payload.get("agent", "")
    task = payload.get("task", "")
    if not agent_code or not _active_session_manager:
        return JSONResponse({"error": "No agent code or session manager"}, status_code=400)
    if hasattr(_active_session_manager, '_pending_rp_request'):
        _active_session_manager._pending_rp_request = None
    await _active_session_manager._spawn_agent(agent_code, task_prompt=task)
    return {"ok": True, "spawned": agent_code}


# ── Phase F1a: Agent Request API ──────────────

@app.post("/api/agents/request")
async def request_agent_spawn(payload: AgentRequestPayload):
    """Request a worker agent to be spawned (called by ST via dashboard API).

    This is how the Strategy Agent requests workers. ST posts JSON body:
        curl -X POST http://localhost:8080/api/agents/request \\
          -H 'Content-Type: application/json' \\
          -d '{"agent":"AR","task":"Port scan target","priority":"high"}'
    """
    if not _active_session_manager or not _active_session_manager.is_running:
        return JSONResponse(status_code=400, content={
            "error": "No active multi-agent session. Start an engagement first."
        })

    if not payload.agent:
        return JSONResponse(status_code=400, content={
            "error": "Agent code required (e.g. AR, WV, EX, VF, RP)"
        })

    # BUG-006 fix: Gate agent requests by engagement type
    # Resolve numbered agents (EX-1 → EX) for permission check
    from agent_configs import resolve_role_code
    _base_agent = resolve_role_code(payload.agent)
    allowed = set()
    for t in _engagement_types:
        allowed |= _AGENTS_BY_TYPE.get(t, {"ST", "PR", "AR", "WV", "DA", "PX", "EX", "PE", "VF", "RP"})
    allowed -= _skip_agents  # Remove skipped agents
    if _base_agent not in allowed:
        return JSONResponse(status_code=400, content={
            "error": f"Agent {payload.agent} (base: {_base_agent}) not allowed for engagement type(s) {_engagement_types}. Allowed: {sorted(allowed)}"
        })

    _active_session_manager.request_agent(payload.agent, payload.task, payload.priority)

    # Sprint mode: record first EX spawn timestamp for TTFS-EX calculation
    if _base_agent == "EX" and _active_session_manager.mode == "sprint" and neo4j_available and neo4j_driver:
        try:
            import time as _time_ex
            def _record_ex_spawn():
                with neo4j_driver.session() as session:
                    session.run("""
                        MATCH (e:Engagement {id: $eid})
                        WHERE e.first_ex_spawn_at IS NULL
                        SET e.first_ex_spawn_at = $now
                    """, eid=_active_session_manager.engagement_id, now=_time_ex.time())
            asyncio.ensure_future(neo4j_exec(_record_ex_spawn))
        except Exception as e:
            logger.warning("Failed to record first_ex_spawn_at: %s", e)

    return {
        "ok": True,
        "agent": payload.agent,
        "task": payload.task[:200],
        "priority": payload.priority,
        "message": f"Agent {payload.agent} spawn requested.",
    }




# ── Real-Time Bus REST API ──────────────────────

@app.post("/api/bus/publish")
async def bus_publish(request: Request):
    """Agent publishes a finding to the message bus.

    Accepts structured Finding schema from agent self-reports.
    Validates via finding_pipeline.validate_finding() and assigns
    confidence HIGH (agent self-reports are trusted).
    """
    global _active_session_manager
    if not _active_session_manager:
        return JSONResponse({"error": "No active engagement"}, 400)

    # BUG-035 fix: Return 422 for malformed JSON instead of 500
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, 422)
    from finding_pipeline import validate_finding, BROADCAST_CONFIDENCES
    from message_bus import BusMessage

    finding = validate_finding(body)
    msg = BusMessage(
        from_agent=body.get("agent", "unknown"),
        to=body.get("to", "ALL"),
        bus_type="finding",
        priority=finding.severity,
        summary=finding.summary,
        target=finding.target,
        data=finding.to_dict(),
        action_needed=finding.action_needed,
    )
    if finding.confidence in BROADCAST_CONFIDENCES:
        if msg.to == "ALL":
            await _active_session_manager.bus.broadcast(msg)
        else:
            await _active_session_manager.bus.send(msg)
    else:
        # LOW confidence: dashboard callbacks only, no agent broadcast
        bus = _active_session_manager.bus
        bus._history.append(msg)
        for cb in bus._callbacks:
            asyncio.create_task(cb(msg))
    return {"ok": True, "message_id": msg.id, "confidence": finding.confidence}


@app.post("/api/bus/directive")
async def bus_directive(request: Request):
    """ST sends a strategic directive via the bus."""
    global _active_session_manager
    if not _active_session_manager:
        return JSONResponse({"error": "No active engagement"}, 400)

    # BUG-035 fix: Return 422 for malformed JSON instead of 500
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, 422)
    from message_bus import BusMessage
    msg = BusMessage(
        from_agent=body.get("agent", "ST"),
        to=body.get("to", "ALL"),
        bus_type="directive",
        priority=body.get("priority", "normal"),
        summary=body.get("directive", ""),
        action_needed=body.get("directive", ""),
    )
    if msg.to == "ALL":
        await _active_session_manager.bus.broadcast(msg)
    else:
        await _active_session_manager.bus.send(msg)

    # BUG-037 FIX: If ST sends an explicit stop directive to a specific agent,
    # also signal early_stop server-side. This is more reliable than waiting
    # for the agent to read and comply with the directive via prompt.
    # BUG-028 FIX: Only match explicit stop commands, not status updates.
    # "COMPLETE" and "FINISH" were false-positiving on "AR has completed recon".
    directive_text = (body.get("directive", "") or "").upper()
    target_agent = (msg.to or "").upper()
    _STOP_DIRECTIVES = ["STOP NOW", "STOP IMMEDIATELY", "TERMINATE", "ABORT",
                        "CEASE OPERATIONS", "HALT OPERATIONS", "SHUT DOWN"]
    if target_agent != "ALL" and target_agent != "ST" and any(
        kw in directive_text for kw in _STOP_DIRECTIVES
    ):
        _active_session_manager.signal_early_stop(target_agent)
        logger.info("BUG-037: Auto-triggered early_stop for %s via ST directive: %s",
            target_agent, directive_text[:80])

    return {"ok": True, "message_id": msg.id}


@app.get("/api/bus/history")
async def bus_history(limit: int = 50):
    """Get recent bus message history."""
    global _active_session_manager
    if not _active_session_manager:
        return {"messages": []}
    msgs = _active_session_manager.bus.get_history(limit=limit)
    return {"messages": [m.to_dict() for m in msgs]}


@app.get("/api/agents/status")
async def get_agent_statuses():
    """Get status of all active agents in the multi-agent session."""
    if not _active_session_manager:
        return {"agents": {}, "mode": "none"}

    return {
        "agents": _active_session_manager.get_agent_statuses(),
        "mode": "multi-agent",
        "is_running": _active_session_manager.is_running,
    }


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
        "agent": "ST",
        "agentName": "Strategy",
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


@app.get("/api/network/status")
async def get_network_status():
    """Get current internet connectivity status."""
    return {
        "status": "down" if _network_down else "up",
        "down_since": _network_down_since,
        "downtime_s": int(time.time() - _network_down_since) if _network_down_since else 0,
        "network_paused": _network_paused,
    }


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


# ============================================================================
# CVE Registry — Shared Confirmed CVE Tracking (Phase 1)
# Eliminates duplicate agent work by tracking CVE verification status.
# Agents check this registry BEFORE working on any CVE.
# ============================================================================

@app.get("/api/engagements/{eid}/confirmed-cves")
async def get_confirmed_cves(eid: str):
    """Return all tracked CVEs for this engagement with their verification status."""
    if not neo4j_available or not neo4j_driver:
        return []
    try:
        def _query():
            with neo4j_driver.session() as session:
                result = session.run("""
                    MATCH (c:ConfirmedCVE {engagement_id: $eid})
                    RETURN c.cve AS cve, c.status AS status, c.host AS host,
                           c.exploited_by AS exploited_by, c.verified_by AS verified_by,
                           c.exploit_method AS exploit_method, c.verification_method AS verification_method,
                           c.exploited_at AS exploited_at, c.verified_at AS verified_at,
                           c.reason AS reason
                    ORDER BY c.exploited_at ASC
                """, eid=eid)
                return [dict(record) for record in result]
        records = await neo4j_exec(_query)
        return records
    except Exception as e:
        print(f"CVE Registry GET error: {e}")
        return []


@app.post("/api/engagements/{eid}/confirmed-cves")
async def update_confirmed_cve(eid: str, request: Request):
    """Update CVE verification status. Agents call this after exploiting/verifying."""
    payload = await request.json()
    cve = payload.get("cve", "").strip()
    status = payload.get("status", "")
    agent = payload.get("agent", "")
    host = payload.get("host", "")
    method = payload.get("method", "")
    reason = payload.get("reason", "")
    evidence = payload.get("evidence", "")

    if not cve or not status:
        return JSONResponse({"error": "cve and status required"}, status_code=400)

    valid_statuses = ("discovered", "exploited", "vf_verifying", "verified",
                      "vf_failed", "escalated", "secondary_confirmed", "confirmed", "unverified")
    if status not in valid_statuses:
        return JSONResponse({"error": f"Invalid status. Valid: {valid_statuses}"}, status_code=400)

    if not neo4j_available or not neo4j_driver:
        return JSONResponse({"error": "Neo4j not available"}, status_code=503)

    try:
        import time as _time
        now = _time.time()

        def _update():
            with neo4j_driver.session() as session:
                # MERGE on cve + engagement_id + host — creates or updates
                session.run("""
                    MERGE (c:ConfirmedCVE {cve: $cve, engagement_id: $eid, host: $host})
                    ON CREATE SET
                        c.status = $status,
                        c.created_at = $now,
                        c.exploited_by = CASE WHEN $status = 'exploited' THEN $agent ELSE null END,
                        c.exploited_at = CASE WHEN $status = 'exploited' THEN $now ELSE null END,
                        c.exploit_method = CASE WHEN $status = 'exploited' THEN $method ELSE null END,
                        c.verified_by = CASE WHEN $status IN ['verified', 'confirmed'] THEN $agent ELSE null END,
                        c.verified_at = CASE WHEN $status IN ['verified', 'confirmed'] THEN $now ELSE null END,
                        c.verification_method = CASE WHEN $status IN ['verified', 'confirmed'] THEN $method ELSE null END,
                        c.reason = $reason,
                        c.evidence = $evidence
                    ON MATCH SET
                        c.status = $status,
                        c.updated_at = $now,
                        c.exploited_by = CASE WHEN $status = 'exploited' THEN $agent ELSE c.exploited_by END,
                        c.exploited_at = CASE WHEN $status = 'exploited' THEN $now ELSE c.exploited_at END,
                        c.exploit_method = CASE WHEN $status = 'exploited' THEN $method ELSE c.exploit_method END,
                        c.verified_by = CASE WHEN $status IN ['verified', 'confirmed'] THEN $agent ELSE c.verified_by END,
                        c.verified_at = CASE WHEN $status IN ['verified', 'confirmed'] THEN $now ELSE c.verified_at END,
                        c.verification_method = CASE WHEN $status IN ['verified', 'confirmed'] THEN $method ELSE c.verification_method END,
                        c.reason = CASE WHEN $reason <> '' THEN $reason ELSE c.reason END,
                        c.evidence = CASE WHEN $evidence <> '' THEN $evidence ELSE c.evidence END
                """, cve=cve, eid=eid, host=host, status=status, agent=agent,
                     method=method, now=now, reason=reason, evidence=evidence)
                return True
        await neo4j_exec(_update)

        # Broadcast status change via WebSocket so dashboard can update
        await state.broadcast({
            "type": "system",
            "agent": agent or "SYSTEM",
            "content": f"CVE Registry: {cve} → {status}" + (f" by {agent}" if agent else ""),
            "timestamp": now,
            "metadata": {"control": "cve_status_update", "cve": cve, "status": status}
        })

        return {"ok": True, "cve": cve, "status": status}
    except Exception as e:
        print(f"CVE Registry POST error: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/api/engagements/{eid}/first-shell")
async def record_first_shell(eid: str, request: Request):
    """Record the timestamp of the first confirmed shell for TTFS calculation.
    Called by EX agent after first successful exploit. Idempotent — only records
    the first call, ignores subsequent calls (one source of truth)."""
    if not neo4j_available or not neo4j_driver:
        return JSONResponse({"error": "Neo4j not available"}, status_code=503)

    payload = await request.json()
    agent = payload.get("agent", "EX")
    method = payload.get("method", "")
    target = payload.get("target", "")

    try:
        import time as _time
        now = _time.time()

        def _record():
            with neo4j_driver.session() as session:
                # Only set first_shell_at if not already set (idempotent)
                result = session.run("""
                    MATCH (e:Engagement {id: $eid})
                    WHERE e.first_shell_at IS NULL
                    SET e.first_shell_at = $now,
                        e.first_shell_agent = $agent,
                        e.first_shell_method = $method,
                        e.first_shell_target = $target
                    RETURN e.first_shell_at AS recorded, e.started_at AS started_at
                """, eid=eid, now=now, agent=agent, method=method, target=target)
                record = result.single()
                if record and record["recorded"]:
                    started = record["started_at"] or now
                    ttfs = max(0, int(now - started))
                    return {"recorded": True, "ttfs_seconds": ttfs}
                return {"recorded": False, "reason": "first_shell_at already set"}
        result = await neo4j_exec(_record)

        # Sprint mode auto-stop: first shell = engagement complete
        if result.get("recorded") and _active_session_manager and _active_session_manager.mode == "sprint":
            logger.info("SPRINT: First shell confirmed on %s via %s — auto-stopping engagement %s", target, method, eid)
            await state.add_event(AgentEvent(
                id=str(uuid.uuid4())[:8],
                type="system",
                agent="ST",
                content=f"SPRINT COMPLETE: First shell obtained via {method or 'exploit'}. TTFS: {result.get('ttfs_seconds', '?')}s. Auto-stopping engagement.",
                timestamp=time.time(),
            ))
            # Broadcast engagement_stopped immediately so the frontend clock freezes NOW,
            # before the session manager's slow cleanup runs.
            await state.broadcast({
                "type": "system",
                "content": f"Engagement {eid} auto-stopped (Sprint: first shell confirmed).",
                "metadata": {"control": "engagement_stopped"},
                "timestamp": time.time(),
            })
            asyncio.ensure_future(_active_session_manager.stop())
            # Auto-generate Speed Report Card after sprint completion
            asyncio.ensure_future(_generate_speed_report_card(eid))

        return {"ok": True, **result}
    except Exception as e:
        return JSONResponse({"error": str(e)[:200]}, status_code=500)
