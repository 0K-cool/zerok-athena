"""Agent Session Manager for ATHENA multi-agent pentesting.

Thin Python layer that spawns and manages independent Claude SDK sessions.
The INTELLIGENCE lives in ST (Strategy Agent) — this module only handles:

1. Spawning SDK sessions per agent role (create_for_role → start)
2. Routing bilateral messages between agents (via Neo4j + WebSocket)
3. Managing HITL approval gates
4. Agent lifecycle (start, stop, status tracking)
5. Listening for ST's agent-request events and spawning workers

Architecture:
    ST is the coordinator. It reads Neo4j, reasons about attack paths,
    and posts agent-request events. This manager listens for those events
    and spawns the requested worker agents. Workers write findings to
    Neo4j. ST reads them and decides what's next.

    ┌─────────┐  request   ┌──────────────────┐  spawn   ┌──────────┐
    │   ST    │──────────→│ SessionManager    │────────→│ AR / WV  │
    │ (Opus)  │           │ (Python asyncio)  │         │ (Sonnet) │
    │         │←──────────│                   │←────────│          │
    └─────────┘  notify   └──────────────────┘  done    └──────────┘
         ↕                        ↕                          ↕
         └────────── Neo4j (shared state) ───────────────────┘

Usage:
    manager = AgentSessionManager(eid, target, backend, state, athena_root)
    manager.set_event_callback(emit_to_dashboard)
    await manager.start()   # Starts ST, then listens for agent requests
    await manager.stop()    # Stops all agents cleanly
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Optional

from agent_configs import AGENT_ROLES, AgentRoleConfig, format_prompt, get_role
from finding_utils import _compute_finding_fingerprint
from langfuse_integration import trace_engagement, is_enabled as langfuse_enabled
from message_bus import MessageBus
from sdk_agent import AthenaAgentSession

logger = logging.getLogger("athena.session_manager")

_DASHBOARD_URL = os.environ.get("ATHENA_DASHBOARD_URL", "http://localhost:8080")

# Derive agent display names from AGENT_ROLES (avoids circular import from server.py)
AGENT_NAMES = {code: role.name for code, role in AGENT_ROLES.items()}


# ── Phase G: Workspace Isolation ──────────────────────────────

class WorkspaceManager:
    """Manages per-agent isolated workspaces for parallel execution.

    Creates lightweight directory scaffolds per agent with symlinks
    to shared resources (CLAUDE.md, .claude/, playbooks/) and
    separate evidence directories to prevent file conflicts.

    ST, RP, and DA run in the main ATHENA root (no isolation needed).
    Worker agents (AR, WV, EX, PE, VF, PX) get isolated workspaces.
    """

    # Agents that stay in the main working directory (no isolation)
    MAIN_DIR_AGENTS = {"ST", "RP", "DA"}

    # Directories/files to symlink from ATHENA root into agent workspaces
    SYMLINK_TARGETS = ["CLAUDE.md", ".claude", "playbooks", "docs", "intel", "mcp-servers"]

    def __init__(self, engagement_id: str, athena_root: Path):
        self.engagement_id = engagement_id
        self.athena_root = athena_root
        self._workspace_root: Path | None = None
        self._agent_dirs: dict[str, Path] = {}
        self._audit_log: list[dict] = []

    @property
    def workspace_root(self) -> Path | None:
        return self._workspace_root

    def setup(self) -> Path:
        """Create the engagement workspace root under /tmp."""
        short_eid = self.engagement_id[:12]
        self._workspace_root = Path(tempfile.mkdtemp(
            prefix=f"athena-{short_eid}-"))
        # M-6: Write lockfile so cleanup_stale_workspaces skips this directory
        (self._workspace_root / ".athena-active").touch()
        self._audit("workspace_created", path=str(self._workspace_root))
        logger.info("Phase G workspace root: %s", self._workspace_root)
        return self._workspace_root

    def create_agent_workspace(self, agent_code: str) -> Path:
        """Create an isolated workspace for a worker agent.

        Returns the ATHENA root for ST/RP (no isolation), or a new
        per-agent directory with symlinks for worker agents.
        """
        if agent_code in self.MAIN_DIR_AGENTS:
            return self.athena_root

        if not self._workspace_root:
            self.setup()

        short_id = str(uuid.uuid4())[:6]
        agent_dir = self._workspace_root / f"{agent_code.lower()}-{short_id}"
        agent_dir.mkdir(parents=True, exist_ok=True)

        # Symlink shared read-only resources from ATHENA root
        for target in self.SYMLINK_TARGETS:
            src = self.athena_root / target
            dst = agent_dir / target
            if src.exists() and not dst.exists():
                try:
                    dst.symlink_to(src)
                except OSError as e:
                    # Fallback: copy if symlink fails
                    logger.warning("Symlink failed for %s, copying: %s", target, e)
                    if src.is_dir():
                        shutil.copytree(src, dst)
                    else:
                        shutil.copy2(src, dst)

        # Copy .mcp.json (not symlink — allows future per-agent customization)
        mcp_src = self.athena_root / ".mcp.json"
        mcp_dst = agent_dir / ".mcp.json"
        if mcp_src.exists() and not mcp_dst.exists():
            shutil.copy2(mcp_src, mcp_dst)

        # Create engagement evidence directories for agent scratch space
        eid = self.engagement_id
        evidence_base = agent_dir / "engagements" / "active" / eid / "08-evidence"
        for subfolder in ["screenshots", "http-pairs", "command-output", "tool-logs"]:
            (evidence_base / subfolder).mkdir(parents=True, exist_ok=True)
        (agent_dir / "engagements" / "active" / eid / "09-reporting").mkdir(
            parents=True, exist_ok=True)

        self._agent_dirs[agent_code] = agent_dir
        self._audit("agent_workspace_created", agent=agent_code,
                     path=str(agent_dir))
        logger.info("Phase G workspace for %s: %s", agent_code, agent_dir)
        return agent_dir

    def get_agent_workspace(self, agent_code: str) -> Path:
        """Get the workspace path for a given agent."""
        if agent_code in self.MAIN_DIR_AGENTS:
            return self.athena_root
        return self._agent_dirs.get(agent_code, self.athena_root)

    def cleanup(self) -> dict:
        """Remove all agent workspaces. Returns audit summary.

        Scans for leaked credentials before removal (G2 audit).
        """
        credential_warnings = []

        # G2: Scan for leaked credentials before cleanup
        for agent_code, agent_dir in self._agent_dirs.items():
            cred_count = self._scan_for_credentials(agent_dir)
            if cred_count > 0:
                credential_warnings.append({
                    "agent": agent_code,
                    "path": str(agent_dir),
                    "credential_hits": cred_count,
                })
                self._audit("credential_warning", agent=agent_code,
                             hits=cred_count, path=str(agent_dir))
                logger.warning("Credential leak in %s workspace: %d hits",
                               agent_code, cred_count)

        # M-6: Remove lockfile before cleanup to signal engagement has stopped
        if self._workspace_root and self._workspace_root.exists():
            lockfile = self._workspace_root / ".athena-active"
            if lockfile.exists():
                lockfile.unlink(missing_ok=True)

        # Remove workspace root (and all agent subdirs)
        if self._workspace_root and self._workspace_root.exists():
            shutil.rmtree(self._workspace_root, ignore_errors=True)
            self._audit("workspace_removed", path=str(self._workspace_root))
            logger.info("Phase G workspaces cleaned up: %s", self._workspace_root)

        return {
            "workspaces_created": len(self._agent_dirs),
            "credential_warnings": credential_warnings,
            "audit_log": self._audit_log,
        }

    def _scan_for_credentials(self, directory: Path) -> int:
        """Scan directory for potential leaked credentials (G2).

        Only scans text files created by the agent, not symlinked
        shared resources.
        """
        cred_pattern = re.compile(
            r'(password|api[_-]?key|secret|token|credential)\s*[:=]',
            re.IGNORECASE)
        count = 0
        for suffix in ("*.md", "*.json", "*.txt", "*.yaml", "*.yml", "*.log",
                        "*.sh", "*.py", "*.xml", "*.env", "*.toml", "*.ini",
                        "*.conf", "*.cfg", "*.properties"):
            for f in directory.rglob(suffix):
                # Skip symlinks (shared resources)
                if f.is_symlink():
                    continue
                try:
                    text = f.read_text(errors="ignore")
                    count += len(cred_pattern.findall(text))
                except Exception:
                    pass
        # Also check files with no extension (loot dumps, credential files)
        for f in directory.rglob("*"):
            if f.is_file() and not f.suffix and not f.is_symlink():
                try:
                    text = f.read_text(errors="ignore")
                    count += len(cred_pattern.findall(text))
                except Exception:
                    pass
        return count

    def _audit(self, event: str, **kwargs):
        """Add entry to the in-memory audit log."""
        self._audit_log.append({
            "event": event,
            "timestamp": time.time(),
            "engagement_id": self.engagement_id,
            **kwargs,
        })

    def touch_lockfile(self):
        """BUG-031: Heartbeat the lockfile so cleanup_stale_workspaces knows we're alive."""
        if self._workspace_root:
            lockfile = self._workspace_root / ".athena-active"
            try:
                lockfile.touch()
            except OSError:
                pass

    @staticmethod
    def cleanup_stale_workspaces(max_age_hours: float = 2.0, active_engagement_ids: set[str] | None = None):
        """Remove stale workspace directories from /tmp.

        Called on server startup to prevent /tmp accumulation from crashes.
        M-6: Skips directories with an active lockfile (.athena-active) whose
        mtime is within the max_age window — prevents deleting live engagements.
        BUG-031: Also skips workspaces whose engagement ID matches an active session.
        """
        tmp = Path(tempfile.gettempdir())
        max_age_seconds = max_age_hours * 3600
        now = time.time()
        active_ids = active_engagement_ids or set()
        cleaned = 0
        for d in tmp.iterdir():
            if d.is_dir() and d.name.startswith("athena-"):
                try:
                    # BUG-031: Extract engagement ID prefix from dir name
                    # Format: athena-{eid[:12]}-{random} e.g. athena-eng-c4e4cc-k5ot5hz9
                    # Strip "athena-" prefix, then match remaining against active eids
                    dir_suffix = d.name[len("athena-"):]  # e.g. "eng-c4e4cc-k5ot5hz9"
                    if active_ids and any(dir_suffix.startswith(eid[:12]) for eid in active_ids):
                        logger.debug("Skipping workspace for active engagement: %s", d.name)
                        continue

                    # M-6: Skip directories with a recently-touched lockfile
                    lockfile = d / ".athena-active"
                    if lockfile.exists():
                        lock_age = now - lockfile.stat().st_mtime
                        if lock_age < max_age_seconds:
                            logger.debug("Skipping active workspace: %s (lockfile age: %.0fs)", d.name, lock_age)
                            continue

                    age = now - d.stat().st_mtime
                    if age > max_age_seconds:
                        shutil.rmtree(d, ignore_errors=True)
                        cleaned += 1
                        logger.info("Cleaned stale workspace: %s (age: %.0fh)",
                                    d, age / 3600)
                except OSError:
                    pass
        if cleaned:
            logger.info("Cleaned %d stale ATHENA workspaces", cleaned)


# ── Operator command classification ───────────────────────────────────
_BLOCKING_COMMAND_KEYWORDS = frozenset([
    "stop", "pause", "cancel", "abort", "halt",
    "approve", "reject", "deny",
    "expand scope", "change scope", "remove scope", "add scope",
    "emergency",
    # BUG-042: Critical operational alerts must interrupt immediately
    "down", "unreachable", "offline", "dead", "crashed",
    "host is down", "target is down", "target down",
    # FLASH priority — only for commands that MUST interrupt immediately
    # Info queries (status, sitrep, report) are non-blocking — queued for next turn
])

def _is_blocking_command(command: str) -> bool:
    """Return True if this command must interrupt ST's active query immediately.

    BLOCKING: stop, pause, cancel, abort, approve, reject, scope changes, emergency.
    NON-BLOCKING: suggestions, questions, status queries — queued for next chunk boundary.
    """
    lower = command.lower()
    return any(kw in lower for kw in _BLOCKING_COMMAND_KEYWORDS)


class AgentSessionManager:
    """Manages multiple concurrent Claude SDK agent sessions.

    ST runs first as the coordinator. When ST requests a worker agent
    (via POST /api/agents/request), this manager spawns it. Workers
    run independently, write to Neo4j, and notify completion.
    """

    def __init__(
        self,
        engagement_id: str,
        target: str,
        backend: str = "external",
        dashboard_state: Any = None,
        athena_root: str | Path = "",
        mode: str = "multi-agent",
        time_limit_minutes: int = 0,
        neo4j_driver: Any = None,  # MED-3: pass driver instead of circular import
        graphiti_client: Any = None,
        langfuse_client: Any = None,
    ):
        self.engagement_id = engagement_id
        self.target = target
        self.backend = backend
        self.dashboard_state = dashboard_state
        self._neo4j_driver = neo4j_driver  # MED-3: stored for context building
        self.mode = mode  # "multi-agent" or "ctf"
        self.time_limit_minutes = time_limit_minutes  # M-3: 0 = unlimited
        self.athena_root = (
            Path(athena_root) if athena_root
            else Path(__file__).resolve().parent.parent.parent
        )

        # Active agent sessions: code → AthenaAgentSession
        self.agents: dict[str, AthenaAgentSession] = {}
        # Agent completion futures for waiting
        self._agent_tasks: dict[str, asyncio.Task] = {}
        # Queue for agent requests from ST
        self._agent_request_queue: asyncio.Queue[dict] = asyncio.Queue()
        # Event callback for dashboard integration
        self._event_callback: Optional[Callable] = None
        # Lifecycle
        self.is_running = False
        self._paused = False  # BUG-029: Manager-level pause flag (survives agent re-spawns)
        self._deferred_spawns: list[dict] = []  # BUG-036: Deferred spawns while paused (no re-queue loop)
        self._manager_task: asyncio.Task | None = None
        # Cost tracking across all agents
        self.total_cost_usd: float = 0.0
        self.total_tool_calls: int = 0
        self._cost_aggregated: set[str] = set()
        self._cost_lock = asyncio.Lock()  # HIGH-3: protect cost mutations from races
        self._pending_rp_request: dict | None = None
        # F5: Budget-exhausted agents pending early-stop
        self._early_stop_queue: set[str] = set()
        # BUG-028: Commands queued while ST is dead (survives re-spawns)
        self._pending_commands: list[str] = []
        # BUG-H3: Guard against concurrent ST re-spawns
        self._st_spawning: bool = False
        # Phase G: Per-agent workspace isolation
        self._workspace_manager = WorkspaceManager(engagement_id, self.athena_root)
        # Real-time message bus for inter-agent communication
        self.bus = MessageBus(engagement_id=engagement_id)
        # External integration clients (passed in for bus callbacks)
        self._graphiti_client = graphiti_client
        self._langfuse_client = langfuse_client
        # H3: Langfuse observability
        self._langfuse_trace_ctx = None
        self._langfuse_trace = None
        # Cache: knowledge briefs don't change between agent spawns
        self._knowledge_brief_cache: dict[str, str] = {}
        # BUG-033: Heartbeat timer — send ST periodic status when workers are active
        self._last_heartbeat: float = 0.0
        self._heartbeat_interval: float = 60.0  # seconds between heartbeats
        # BUG-028b: Track ST tool call start time for auto-cancel on long-running tool calls
        self._st_tool_call_started_at: float | None = None
        # Worker idle watchdog: track last tool_start time per worker code
        self._worker_last_tool_call: dict[str, float] = {}

    def set_event_callback(self, callback: Callable):
        """Set async callback for streaming events to dashboard.

        Also wires bus callbacks for WebSocket forwarding, Graphiti
        ingestion, and Langfuse tracing.
        """
        self._event_callback = callback

        # Wire bus → WebSocket: emit agent_intel events to dashboard
        async def _bus_to_ws(msg):
            await self._emit("agent_intel", msg.from_agent, msg.summary, {
                "type": "agent_intel",
                "agent": msg.from_agent,
                "content": msg.summary,
                "metadata": msg.to_dict(),
            })
        self.bus.on_message(_bus_to_ws)

        # Wire bus → Graphiti: persist findings as episodes
        if self._graphiti_client:
            gc = self._graphiti_client

            async def _bus_to_graphiti(msg):
                try:
                    from graphiti_integration import ingest_episode, is_enabled as graphiti_enabled
                    if graphiti_enabled():
                        await ingest_episode(
                            engagement_id=self.engagement_id,
                            name=f"bus_{msg.from_agent}_{msg.id[:8]}",
                            content=f"[{msg.priority.upper()}] {msg.summary}",
                            source_description=f"Bus message from {msg.from_agent}",
                        )
                except Exception as e:
                    logger.warning("Bus→Graphiti failed: %s", e)
            self.bus.on_message(_bus_to_graphiti)

        # Wire bus → Langfuse: trace bus messages as spans
        if self._langfuse_client:
            lc = self._langfuse_client

            async def _bus_to_langfuse(msg):
                try:
                    if hasattr(lc, 'span'):
                        lc.span(
                            name=f"bus_{msg.bus_type}",
                            input={"from": msg.from_agent, "to": msg.to,
                                   "priority": msg.priority},
                            output={"summary": msg.summary},
                            metadata=msg.to_dict(),
                        )
                except Exception as e:
                    logger.warning("Bus→Langfuse failed: %s", e)
            self.bus.on_message(_bus_to_langfuse)

        # Wire bus → Neo4j: persist findings/escalations as attack graph nodes
        if self._neo4j_driver:
            driver = self._neo4j_driver
            eid = self.engagement_id

            async def _bus_to_neo4j(msg):
                """Auto-persist bus findings into Neo4j attack graph.

                Creates Finding/Host/Service/Credential nodes from bus messages
                so the attack graph stays current in real-time. Uses MERGE for
                idempotency — duplicate bus messages won't create duplicate nodes.
                """
                if msg.bus_type not in ("finding", "escalation"):
                    return  # Only persist actionable intel

                # Structured pipeline: use confidence from Finding data
                data = msg.data or {}
                confidence = data.get("confidence", "")
                if confidence == "low":
                    # LOW confidence: persist but flag as unvalidated
                    pass  # Continue to persist, but mark below
                elif msg.priority not in ("high", "critical") and not confidence:
                    return  # Legacy: skip low/medium noise

                try:
                    from uuid import uuid4 as _uuid4

                    target = msg.target or ""
                    data = msg.data or {}

                    # Extract parameters for vulnerability-identity fingerprint
                    _cve_list = data.get("cve", [])
                    _cve = (_cve_list[0] if isinstance(_cve_list, list) and _cve_list
                            else _cve_list if isinstance(_cve_list, str) and _cve_list
                            else None)
                    _host_ip = None
                    _ip_match = __import__("re").search(
                        r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', target
                    )
                    if _ip_match:
                        _host_ip = _ip_match.group(1)
                    if not _host_ip:
                        _ports = data.get("ports", [])
                        for _p in _ports:
                            if _p.get("host"):
                                _host_ip = _p["host"]
                                break
                    _service_port = data.get("port")
                    if not _service_port:
                        _ports = data.get("ports", [])
                        if _ports:
                            _service_port = _ports[0].get("port")
                    if _service_port is not None:
                        try:
                            _service_port = int(_service_port)
                        except (TypeError, ValueError):
                            _service_port = None

                    fingerprint = _compute_finding_fingerprint(
                        eid, msg.summary[:200], target,
                        _cve, _host_ip, _service_port,
                    )
                    finding_id = f"bus-{fingerprint}"

                    def _persist():
                        with driver.session() as sess:
                            # 1. Create/update Finding node
                            # Use structured Finding fields if available
                            finding_type = data.get("finding_type", msg.bus_type)
                            finding_confidence = data.get("confidence", "high")
                            finding_state = data.get("state", "discovered")
                            finding_severity = data.get("severity", msg.priority)

                            sess.run(
                                "MERGE (f:Finding {fingerprint: $fingerprint, engagement_id: $eid}) "
                                "ON CREATE SET f.id = $id, f.discovered_at = datetime(), f.status = 'open' "
                                "WITH f, "
                                "    {info: 0, low: 1, medium: 2, high: 3, critical: 4} AS ranks "
                                "SET f.title = $title, "
                                "    f.severity = CASE WHEN f.severity IS NULL OR "
                                "        coalesce(ranks[f.severity], 0) < coalesce(ranks[$severity], 0) "
                                "        THEN $severity ELSE f.severity END, "
                                "    f.category = $category, "
                                "    f.finding_type = $finding_type, "
                                "    f.confidence = $confidence, "
                                "    f.state = $state, "
                                "    f.target = $target, "
                                "    f.description = $description, "
                                "    f.fingerprint = $fingerprint, "
                                "    f.discovery_source = 'bus', "
                                "    f.bus_type = $bus_type, "
                                "    f.unvalidated = $unvalidated, "
                                "    f.contributing_agents = "
                                "        CASE WHEN $agent IN coalesce(f.contributing_agents, []) "
                                "        THEN f.contributing_agents "
                                "        ELSE coalesce(f.contributing_agents, []) + [$agent] END, "
                                "    f.timestamp = datetime()",
                                id=finding_id,
                                title=msg.summary[:200],
                                severity=finding_severity,
                                category=finding_type,
                                finding_type=finding_type,
                                confidence=finding_confidence,
                                state=finding_state,
                                target=target,
                                agent=msg.from_agent,
                                description=msg.summary,
                                eid=eid,
                                fingerprint=fingerprint,
                                bus_type=msg.bus_type,
                                unvalidated=(finding_confidence == "low"),
                            )

                            # 2. Auto-create Host node if we have an IP
                            # BUG-030: Also extract IPs from port data when target is empty
                            import re
                            host_ip = None
                            if target:
                                ip_match = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', target)
                                if ip_match:
                                    host_ip = ip_match.group(1)
                            if not host_ip:
                                # Try to extract from port data (naabu format has "host" key)
                                ports = data.get("ports", [])
                                for p in ports:
                                    if p.get("host"):
                                        host_ip = p["host"]
                                        break
                            if not host_ip:
                                # Last resort: extract from summary
                                ip_match = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', msg.summary)
                                if ip_match and ip_match.group(1) != "127.0.0.1":
                                    host_ip = ip_match.group(1)

                            # Fallback: use engagement target IP when host_ip not parseable
                            # from message (e.g. DA credential messages like
                            # "PostgreSQL default credentials postgres/postgres" have no IP).
                            if not host_ip:
                                # 1. Try data["target"] field directly
                                _eng_target = data.get("target", "")
                                if _eng_target:
                                    _ip_match = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', _eng_target)
                                    if _ip_match:
                                        host_ip = _ip_match.group(1)
                            if not host_ip and eid:
                                # 2. Query Neo4j for the engagement's target/scope
                                try:
                                    _eng_result = sess.run(
                                        "MATCH (e:Engagement {id: $eid}) "
                                        "RETURN e.target AS target, e.scope AS scope",
                                        eid=eid,
                                    ).single()
                                    if _eng_result:
                                        _t = _eng_result.get("target") or _eng_result.get("scope") or ""
                                        if _t:
                                            _ip_match = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', _t)
                                            if _ip_match:
                                                host_ip = _ip_match.group(1)
                                except Exception:
                                    pass

                            if host_ip:
                                sess.run(
                                    "MERGE (h:Host {ip: $ip}) "
                                    "ON CREATE SET h.engagement_id = $eid, "
                                    "    h.state = 'open', h.first_seen = datetime() "
                                    "ON MATCH SET h.last_seen = datetime() "
                                    "WITH h "
                                    "MATCH (f:Finding {id: $fid}) "
                                    "MERGE (f)-[:FOUND_ON]->(h)",
                                    ip=host_ip, eid=eid, fid=finding_id,
                                )

                                # 3. Auto-create Service if port data available
                                ports = data.get("ports", [])
                                for p in ports[:5]:
                                    port = p.get("port", "")
                                    svc_name = p.get("service", p.get("name", "unknown"))
                                    if port:
                                            svc_id = f"{host_ip}:{port}"
                                            sess.run(
                                                "MERGE (h:Host {ip: $ip}) "
                                                "MERGE (s:Service {id: $sid, port: $port}) "
                                                "ON CREATE SET s.name = $name, "
                                                "    s.engagement_id = $eid, "
                                                "    s.state = 'open', "
                                                "    s.first_seen = datetime() "
                                                "ON MATCH SET s.last_seen = datetime() "
                                                "MERGE (h)-[:HAS_SERVICE]->(s) "
                                                "WITH s "
                                                "MATCH (f:Finding {id: $fid}) "
                                                "MERGE (f)-[:AFFECTS]->(s)",
                                                ip=host_ip, sid=svc_id,
                                                port=str(port), name=svc_name,
                                                eid=eid, fid=finding_id,
                                            )

                            # 4. Create Credential node if credential finding
                            if any(kw in msg.summary.lower() for kw in (
                                "credential", "password", "login", "creds"
                            )):
                                cred_id = f"cred-{fingerprint}"
                                # Extract username/password from summary
                                _cred_re = re.compile(
                                    r'(?:login|user(?:name)?|user)\s*[:=]\s*["\']?(\S+?)["\']?\s+'
                                    r'(?:password|pass(?:wd)?)\s*[:=]\s*["\']?(\S+?)["\']?(?:\s|$)',
                                    re.IGNORECASE,
                                )
                                cred_match = _cred_re.search(msg.summary)
                                extracted_user = cred_match.group(1) if cred_match else ""
                                extracted_pass = cred_match.group(2) if cred_match else ""
                                if not cred_match:
                                    simple_match = re.search(r'(\w+):(\S+)', msg.summary)
                                    if simple_match and any(kw in msg.summary.lower() for kw in ("default", "weak", "cred")):
                                        extracted_user = simple_match.group(1)
                                        extracted_pass = simple_match.group(2)
                                sess.run(
                                    "MERGE (c:Credential {id: $id}) "
                                    "SET c.engagement_id = $eid, "
                                    "    c.description = $desc, "
                                    "    c.discovered_by = $agent, "
                                    "    c.host = $host, "
                                    "    c.username = $username, "
                                    "    c.password = $password, "
                                    "    c.service = $service, "
                                    "    c.timestamp = datetime() "
                                    "WITH c "
                                    "OPTIONAL MATCH (h:Host {ip: $host}) "
                                    "WHERE $host <> '' "
                                    "FOREACH (_ IN CASE WHEN h IS NOT NULL THEN [1] ELSE [] END | "
                                    "    MERGE (c)-[:HARVESTED_FROM]->(h)"
                                    ")",
                                    id=cred_id, eid=eid,
                                    desc=msg.summary[:500],
                                    agent=msg.from_agent,
                                    host=host_ip or "",
                                    username=extracted_user,
                                    password=extracted_pass,
                                    service=data.get("service", ""),
                                )

                            # 5. Escalation → attack chain progression
                            if msg.bus_type == "escalation":
                                sess.run(
                                    "MATCH (f:Finding {id: $fid}) "
                                    "SET f.is_escalation = true, "
                                    "    f.escalation_type = $etype",
                                    fid=finding_id,
                                    etype=("shell" if "shell" in msg.summary.lower()
                                           else "lateral_movement" if "network" in msg.summary.lower()
                                           else "escalation"),
                                )

                    await asyncio.to_thread(_persist)
                    logger.debug("Bus→Neo4j: persisted %s from %s as %s",
                                 msg.bus_type, msg.from_agent, finding_id)
                except Exception as e:
                    logger.warning("Bus→Neo4j failed: %s", e)

            self.bus.on_message(_bus_to_neo4j)

    # ── Public API ─────────────────────────────

    async def start(self, initial_st_context: str = ""):
        """Start the multi-agent engagement.

        Launches ST (Strategy Agent) first, then listens for agent requests.
        ST will read Neo4j and decide what workers to spawn.
        """
        self.is_running = True

        if not self._event_callback:
            logger.error(
                "AgentSessionManager starting without event callback — "
                "all agent events will be silently dropped"
            )

        # H3: Create root Langfuse trace for this engagement
        if langfuse_enabled():
            self._langfuse_trace_ctx = trace_engagement(
                engagement_id=self.engagement_id,
                target=self.target or "unknown",
                mode="ai-sdk",
            )
            self._langfuse_trace = self._langfuse_trace_ctx.__enter__()

        await self._emit("system", "OR",
            "Multi-agent mode activated. Preparing Strategy Agent (ST)...",
            {"mode": "multi-agent", "engagement_id": self.engagement_id})

        # H1: Query Graphiti for relevant past experience (runs in parallel
        # with early spawn prep inside _spawn_agent via asyncio.gather)
        async def _fetch_graphiti_context() -> str:
            from graphiti_integration import is_enabled as graphiti_enabled
            if not graphiti_enabled():
                return ""
            from graphiti_integration import search_memory
            target = self.target or ""
            if not target:
                return ""
            try:
                past_facts = await search_memory(
                    query=f"penetration test {target} vulnerabilities exploits",
                    include_global=True, num_results=5,
                )
                if past_facts:
                    ctx = "\n\n## Past Engagement Intelligence (from Graphiti memory)\n"
                    ctx += "The following facts were learned from previous engagements:\n"
                    for fact in past_facts:
                        ctx += f"- {fact['fact']} (source: {fact['source_name']} -> {fact['target_name']})\n"
                    ctx += "\nUse these insights to inform your strategy.\n"
                    return ctx
            except Exception as e:
                logger.warning(f"Graphiti context query failed: {e}")
            return ""

        graphiti_context = await _fetch_graphiti_context()
        st_context = initial_st_context + graphiti_context

        # Start ST first — it's the coordinator
        await self._spawn_agent("ST", task_prompt=st_context)

        # CR (Command Router) removed — replaced by deterministic code routing.
        # Operator commands are forwarded to ST via _handle_multi_agent_operator_command()
        # in server.py, which provides instant acknowledgment + direct ST routing.
        # No LLM needed for a relay — faster, free, and reliable.

        # Notify user that ST is planning (takes ~30-60s)
        await self._emit("system", "ST",
            "Strategy Agent is analyzing the target and planning the engagement. "
            "This typically takes 30-60 seconds — sit back while ST builds the attack plan.",
            {"phase": "planning"})

        # Start the manager loop that processes agent requests
        self._manager_task = asyncio.create_task(self._manager_loop())

        logger.info("Multi-agent engagement started: %s (ST + CR + manager loop)",
                     self.engagement_id)

    async def stop(self):
        """Stop all agents and clean up."""
        self.is_running = False

        # Cancel manager loop — fire-and-forget (do NOT block)
        if self._manager_task and not self._manager_task.done():
            self._manager_task.cancel()
            # Do NOT await — manager task cleans up in background

        # Unregister all agents from the bus before stopping sessions
        for code in list(self.agents.keys()):
            self.bus.unregister(code)

        # Pre-gather pkill — catches any processes spawned before is_running=False propagated
        try:
            import subprocess
            eid = getattr(self, 'engagement_id', '')
            if eid:
                subprocess.run(["pkill", "-15", "-f", f"ATHENA engagement {eid}"],
                               capture_output=True, timeout=3)
        except Exception:
            pass

        # Stop all active agent sessions
        stop_tasks = []
        for code, session in self.agents.items():
            if session.is_running:
                stop_tasks.append(self._stop_agent(code))
        if stop_tasks:
            await asyncio.gather(*stop_tasks, return_exceptions=True)

        # BUG-043 + BUG-010 fix: Kill ALL orphaned claude processes for this engagement.
        # pgrep -P (parent-only) is fragile — processes get re-parented on macOS.
        # Use pkill -f to match by the engagement ID in the prompt, which is unique.
        try:
            import subprocess
            # 1. Kill by engagement ID in the command line (most reliable)
            eid = getattr(self, 'engagement_id', '')
            if eid:
                subprocess.run(
                    ["pkill", "-9", "-f", f"ATHENA engagement {eid}"],
                    capture_output=True, text=True, timeout=5
                )
                logger.info("BUG-010: pkill -f 'ATHENA engagement %s' executed", eid)
            # 2. Fallback: kill by server PID tree (catches non-engagement claude processes)
            server_pid = os.getpid()
            result = subprocess.run(
                ["pgrep", "-P", str(server_pid), "-f", "claude"],
                capture_output=True, text=True, timeout=5
            )
            child_pids = [p.strip() for p in result.stdout.strip().split("\n") if p.strip()]
            for pid in child_pids:
                try:
                    os.kill(int(pid), 9)
                    logger.info("BUG-010: Killed child claude process %s", pid)
                except (ProcessLookupError, ValueError):
                    pass
        except Exception as e:
            logger.warning("BUG-010: Failed to kill orphaned processes: %s", str(e)[:200])

        # Aggregate costs (guard against double-counting agents already tallied)
        for code, session in self.agents.items():
            if code not in self._cost_aggregated:
                self.total_cost_usd += session._total_cost_usd
                self.total_tool_calls += session._tool_count

        # P1-FIX: Sync final aggregated cost back to server so dashboard
        # reflects true total even if individual agent cost reports were lost.
        try:
            import httpx
            async with httpx.AsyncClient() as client:
                await client.post(
                    f"{_DASHBOARD_URL}/api/budget/session-final-cost",
                    params={
                        "total_cost_usd": round(self.total_cost_usd, 6),
                        "total_tool_calls": self.total_tool_calls,
                        "engagement_id": self.engagement_id,
                    },
                    timeout=10.0,
                )
        except Exception as e:
            logger.warning("Failed to sync final cost to server: %s", str(e)[:200])

        await self._emit("system", "OR",
            f"Multi-agent engagement stopped. "
            f"{len(self.agents)} agents used, "
            f"{self.total_tool_calls} total tool calls, "
            f"${self.total_cost_usd:.4f} total cost.",
            {"control": "engagement_ended",
             "cost_usd": round(self.total_cost_usd, 4),
             "tool_calls": self.total_tool_calls,
             "agents_used": list(self.agents.keys())})

        # Phase G: Cleanup agent workspaces with G2 credential audit
        try:
            cleanup_result = self._workspace_manager.cleanup()
            if cleanup_result["credential_warnings"]:
                for warn in cleanup_result["credential_warnings"]:
                    await self._emit("system", "OR",
                        f"WARNING: {warn['credential_hits']} potential credential "
                        f"patterns in {warn['agent']} workspace.",
                        {"credential_warning": True, "agent": warn["agent"],
                         "hits": warn["credential_hits"]})
            # Write audit log
            audit_path = self.athena_root / "logs" / "worktree-audit.jsonl"
            audit_path.parent.mkdir(parents=True, exist_ok=True)
            with open(audit_path, "a") as f:
                for entry in cleanup_result["audit_log"]:
                    f.write(json.dumps(entry) + "\n")
            logger.info("Phase G cleanup: %d workspaces, %d credential warnings",
                        cleanup_result["workspaces_created"],
                        len(cleanup_result["credential_warnings"]))
        except Exception as e:
            logger.warning("Phase G workspace cleanup error: %s", e)

        self.agents.clear()
        self._agent_tasks.clear()

        # Final sweep — catch anything that slipped through
        try:
            import subprocess
            eid = getattr(self, 'engagement_id', '')
            if eid:
                subprocess.run(["pkill", "-9", "-f", f"ATHENA engagement {eid}"],
                               capture_output=True, timeout=3)
        except Exception:
            pass

        # H3: Close engagement trace
        if self._langfuse_trace_ctx:
            try:
                self._langfuse_trace_ctx.__exit__(None, None, None)
            except Exception:
                pass
            self._langfuse_trace_ctx = None
            self._langfuse_trace = None
        logger.info("Multi-agent engagement stopped: %s", self.engagement_id)

    async def pause(self):
        """Pause all running agents — instant cancel, no blocking."""
        self._paused = True  # BUG-029: Block re-spawns while paused
        for code, session in self.agents.items():
            if session.is_running and not session.is_paused:
                session.is_paused = True
                if session._query_task and not session._query_task.done():
                    session._query_task.cancel()
        # Fire-and-forget emit — don't block on WebSocket broadcast
        asyncio.ensure_future(self._emit("system", "OR", "All agents paused.",
            {"control": "engagement_paused"}))

    async def resume(self):
        """Resume all paused agents and replay deferred spawn requests."""
        self._paused = False  # BUG-029: Allow re-spawns again
        for code, session in self.agents.items():
            if session.is_paused:
                await session.resume()
        # BUG-036: Replay deferred spawns into the queue now that we're unpaused
        deferred = self._deferred_spawns[:]
        self._deferred_spawns.clear()
        for req in deferred:
            logger.info("Replaying deferred spawn: %s", req["agent"])
            await self._agent_request_queue.put(req)
        await self._emit("system", "OR",
            f"All agents resumed.{f' Replaying {len(deferred)} deferred spawn(s).' if deferred else ''}",
            {"control": "engagement_resumed", "deferred_replayed": len(deferred)})

    async def send_command(self, command: str) -> str:
        """Forward operator command to CR (if running) or ST with two-tier routing.

        CR (Command Router) is the first stop — it handles status/info queries
        instantly via Haiku and routes strategy commands to ST. If CR is not
        running, falls back to routing directly to ST.

        NON-BLOCKING commands (suggestions, questions) are queued into ST's
        _command_queue and picked up at the next chunk boundary (~0.2s if active,
        up to 60s if idle-waiting).

        BLOCKING commands (stop, pause, approve, scope change, emergency) cancel
        the active query and resume immediately with the command prepended.

        BUG-019 FIX: Previously ALL commands used cancel+resume, which killed
        _engagement_loop and caused ST to over-react/end engagements on harmless
        suggestions.
        """
        # Route directly to ST — CR LLM agent removed, code-based routing handles ack.
        st = self.agents.get("ST")
        st_task = self._agent_tasks.get("ST")
        # BUG-H4: Also check task.done() — is_running goes False in finally before task completes
        if st and (st.is_running or (st_task and not st_task.done())):
            # Auto-cancel if ST has a tool call running >30s when operator sends any command
            if st.is_running and st._query_task and not st._query_task.done():
                tool_call_age = (
                    time.time() - self._st_tool_call_started_at
                    if self._st_tool_call_started_at is not None
                    else 0
                )
                if tool_call_age > 30:
                    logger.warning(
                        "Operator command during long tool call (%.1fs) — force-cancelling ST: %s",
                        tool_call_age, command[:80]
                    )
                    st._query_task.cancel()
                    self._st_tool_call_started_at = None
                    # Queue command with high priority marker for re-spawn
                    self._pending_commands.append(
                        f"OPERATOR COMMAND (HIGH PRIORITY — interrupted long-running operation):\n{command}"
                    )
                    return "Interrupted long-running operation — ST will process your command immediately."
            blocking = _is_blocking_command(command)
            if blocking and st.session_id and st._query_task and not st._query_task.done():
                # BLOCKING: Signal _run_query to break at next message chunk boundary.
                # _engagement_loop stays alive — is_running remains True, no agent_complete emitted.
                logger.info("BLOCKING command — interrupting current query via interrupt event: %s",
                    command[:80])
                st._interrupt_event.set()
                await st._command_queue.put(
                    f"OPERATOR COMMAND (respond immediately, then CONTINUE the engagement):\n{command}"
                )
                return "⚡ Blocking command sent — ST responding at next chunk boundary."
            else:
                # NON-BLOCKING: Queue for next chunk boundary (preserves _engagement_loop)
                logger.info("BUG-019: Non-blocking command queued for ST: %s",
                    command[:80])
                return await st.send_command(command)

        # BUG-028: ST is not running — queue command and re-spawn ST immediately
        self._pending_commands.append(command)
        if not self._st_spawning and self.is_running:
            self._st_spawning = True
            try:
                await self._emit("system", "OR",
                    f"ST not running — re-spawning to process operator command.",
                    {"st_respawn": True, "operator_triggered": True})
                await self._spawn_agent(
                    "ST",
                    task_prompt=(
                        f"You are resuming as Strategy Agent. "
                        f"The operator sent a command:\n{command}\n"
                        f"Review the Neo4j graph for all findings so far, "
                        f"process the operator's command, then decide next steps."
                    )
                )
            finally:
                self._st_spawning = False
            return "Re-spawning ST to process your command."
        else:
            await self._emit("system", "OR",
                f"ST not running — command queued for delivery on re-spawn.",
                {"queued_command": True})
            return "Command queued — ST will receive it on re-spawn."

    def signal_early_stop(self, agent_code: str):
        """Signal that an agent should be stopped due to budget exhaustion.

        Called from server.py when _sdk_event_to_dashboard detects budget
        exhaustion. The manager loop picks this up and stops the agent
        gracefully, then notifies ST.
        """
        if agent_code != "ST":  # Never early-stop the coordinator
            self._early_stop_queue.add(agent_code)
            logger.info("Early-stop queued for %s (budget exhausted)", agent_code)

    def request_agent(self, agent_code: str, task: str,
                      priority: str = "medium"):
        """Queue an agent spawn request (called from dashboard API).

        This is how ST requests worker agents — it posts to the dashboard
        API, which calls this method. The manager loop picks it up and
        spawns the agent.
        """
        self._agent_request_queue.put_nowait({
            "agent": agent_code,
            "task": task,
            "priority": priority,
            "timestamp": time.time(),
        })

    def get_agent_statuses(self) -> dict[str, dict]:
        """Get status of all agents for dashboard display."""
        statuses = {}
        for code, session in self.agents.items():
            statuses[code] = {
                "code": code,
                "running": session.is_running,
                "paused": session.is_paused,
                "tool_calls": session._tool_count,
                "cost_usd": round(session._total_cost_usd, 4),
            }
        return statuses

    # ── Manager Loop ───────────────────────────

    async def _manager_loop(self):
        """Main loop: process agent requests from ST and handle lifecycle.

        Runs until the engagement is stopped. Listens for:
        1. Agent spawn requests from ST (via _agent_request_queue)
        2. Agent completion notifications
        """
        # M-3: Engagement-level timeout enforcement
        deadline = None
        if self.time_limit_minutes and self.time_limit_minutes > 0:
            deadline = time.time() + (self.time_limit_minutes * 60)

        try:
            while self.is_running:
                # M-3: Check engagement deadline before processing requests
                if deadline and time.time() > deadline:
                    logger.warning(
                        "Engagement %s exceeded time limit of %d minutes",
                        self.engagement_id, self.time_limit_minutes,
                    )
                    await self._emit("system", "OR",
                        f"Engagement reached time limit "
                        f"({self.time_limit_minutes} min). Stopping.")
                    break

                # BUG-031: Heartbeat lockfile every loop iteration (~5s)
                # so cleanup_stale_workspaces knows this workspace is alive
                self._workspace_manager.touch_lockfile()

                # Wait for agent requests with timeout
                try:
                    request = await asyncio.wait_for(
                        self._agent_request_queue.get(), timeout=5.0)
                except asyncio.TimeoutError:
                    # Check if any agents completed
                    await self._check_agent_completions()
                    continue

                agent_code = request["agent"]
                task = request["task"]
                priority = request.get("priority", "medium")

                logger.info("Agent request: %s (priority=%s) — %s",
                            agent_code, priority, task[:100])

                await self._emit("system", "OR",
                    f"ST requested {agent_code} agent: {task[:200]}",
                    {"agent_request": True, "requested_agent": agent_code,
                     "priority": priority})

                # Gate RP: block until all worker agents are done
                if agent_code == "RP":
                    worker_codes = {"PR", "AR", "WV", "EX", "PE", "VF", "DA", "PX"}
                    still_running = [
                        c for c in worker_codes
                        if c in self.agents and self.agents[c].is_running
                    ]
                    if still_running:
                        await self._emit("system", "OR",
                            f"RP blocked — workers still running: "
                            f"{', '.join(sorted(still_running))}. "
                            f"RP will be queued and retried when all finish.",
                            {"rp_blocked": True,
                             "waiting_on": sorted(still_running)})
                        # Re-queue RP request for retry after completions
                        self._pending_rp_request = request
                        await self._check_agent_completions()
                        continue

                # Spawn the requested agent
                if agent_code in AGENT_ROLES:
                    await self._spawn_agent(agent_code, task_prompt=task)
                else:
                    await self._emit("system", "OR",
                        f"Unknown agent code: {agent_code}. "
                        f"Valid: {', '.join(AGENT_ROLES.keys())}",
                        {"error": True})

                # Also check for completions
                await self._check_agent_completions()

        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.exception("Manager loop error")
            await self._emit("system", "OR",
                f"Session manager error: {str(e)[:500]}")

    async def _check_agent_completions(self):
        """Check if any spawned agents have completed and notify ST.

        Also processes early-stop signals from budget exhaustion (F5).
        """
        # F5: Process early-stop queue first
        for code in list(self._early_stop_queue):
            session = self.agents.get(code)
            if session and session.is_running:
                logger.info("Early-stopping %s due to budget exhaustion", code)
                await session.stop()
                if code not in self._cost_aggregated:
                    self.total_cost_usd += session._total_cost_usd
                    self.total_tool_calls += session._tool_count
                    self._cost_aggregated.add(code)
                await self._emit("agent_status", code, "completed",
                    {"status": "completed", "reason": "budget_exhausted",
                     "cost_usd": round(session._total_cost_usd, 4),
                     "tool_calls": session._tool_count})
                # Notify ST (or re-spawn if ST died)
                early_stop_msg = (
                    f"Agent {code} was EARLY-STOPPED (budget exhausted). "
                    f"({session._tool_count} tool calls, "
                    f"${round(session._total_cost_usd, 4)}). "
                    f"Decide: extend its budget via POST /api/budget/extend, "
                    f"assign a different agent, or mark this path as exhausted."
                )
                st = self.agents.get("ST")
                st_task = self._agent_tasks.get("ST")
                # BUG-H4: Also check task.done() to avoid false "dead ST" detection
                if st and (st.is_running or (st_task and not st_task.done())):
                    await st.send_command(early_stop_msg)
                elif code != "ST" and not self._st_spawning:
                    # BUG-021 fix: Re-spawn ST to handle early-stop decision
                    # BUG-H3: Guard against concurrent ST re-spawns
                    self._st_spawning = True
                    try:
                        logger.info(
                            "ST not running when %s early-stopped — re-spawning ST",
                            code)
                        # BUG-027 fix: Preserve old ST session cost before overwrite.
                        # BUG-H7/M3: Don't add to _cost_aggregated — accumulate into
                        # a running total so subsequent re-spawns can also be captured.
                        old_st = self.agents.get("ST")
                        if old_st:
                            old_st_cost = old_st._total_cost_usd
                            if old_st_cost > 0:
                                async with self._cost_lock:  # HIGH-3: lock cost mutation
                                    self.total_cost_usd += old_st_cost
                                logger.info(
                                    "Preserved old ST cost $%.4f before re-spawn",
                                    old_st_cost)
                        await self._spawn_agent(
                            "ST",
                            task_prompt=(
                                f"You are resuming as Strategy Agent. "
                                f"A worker agent was early-stopped:\n"
                                f"{early_stop_msg}\n"
                                f"Review the Neo4j graph, then decide next steps."
                            )
                        )
                    finally:
                        self._st_spawning = False
            self.bus.unregister(code)
            self._early_stop_queue.discard(code)

        completed = []
        for code, task in list(self._agent_tasks.items()):
            if not isinstance(task, asyncio.Task):  # CRIT-2: guard against None tasks
                completed.append(code)
                continue
            if task.done():
                completed.append(code)
                # Aggregate cost from completed agent (HIGH-3: under lock)
                session = self.agents.get(code)
                if session and code not in self._cost_aggregated:
                    async with self._cost_lock:
                        self.total_cost_usd += session._total_cost_usd
                        self.total_tool_calls += session._tool_count
                        self._cost_aggregated.add(code)

                # Check for errors
                exc = task.exception() if not task.cancelled() else None
                if exc:
                    await self._emit("system", "OR",
                        f"Agent {code} failed: {str(exc)[:300]}",
                        {"agent_error": True, "agent": code})
                else:
                    # BUG-013 fix: Include per-agent cost in completion event.
                    # Previously this had no cost data, so the frontend showed
                    # the manager's accumulated total instead of this agent's cost.
                    agent_cost = round(session._total_cost_usd, 4) if session else 0
                    agent_tools = session._tool_count if session else 0
                    await self._emit("agent_status", code, "completed",
                        {"status": "completed",
                         "cost_usd": agent_cost,
                         "tool_calls": agent_tools})

                # F1: Notify ST with enriched completion summary
                # Include Neo4j stats so ST can reason about next steps
                # without making a separate query.
                if code != "ST":
                    status = "error" if exc else "completed"
                    cost = round(session._total_cost_usd, 4) if session else 0
                    tools = session._tool_count if session else 0
                    # Query Neo4j for a quick summary of what this agent produced
                    neo4j_summary = await self._get_agent_production_summary(
                        code)
                    msg = (
                        f"Agent {code} has {status}. "
                        f"({tools} tool calls, ${cost}).\n"
                    )
                    if neo4j_summary:
                        msg += f"PRODUCTION SUMMARY:\n{neo4j_summary}\n"
                    # Include running agent statuses for situational awareness
                    running = [c for c, t in self._agent_tasks.items()
                               if not t.done() and c != "ST"]
                    if running:
                        msg += f"Still running: {', '.join(running)}. "
                    msg += "Decide next steps: spawn new agents, pivot strategy, or wrap up."

                    st = self.agents.get("ST")
                    st_task = self._agent_tasks.get("ST")
                    # BUG-H4: Also check task.done() to avoid false "dead ST" detection
                    if st and (st.is_running or (st_task and not st_task.done())):
                        await st.send_command(msg)
                    elif not self._st_spawning:
                        # BUG-021 fix: ST died (60s idle timeout) while workers
                        # were running. Re-spawn ST with accumulated context so
                        # it can decide next steps based on worker results.
                        # BUG-H3: Guard against concurrent ST re-spawns
                        self._st_spawning = True
                        try:
                            logger.info(
                                "ST not running when %s completed — re-spawning ST",
                                code)
                            await self._emit("system", "OR",
                                f"Agent {code} completed but ST was idle. "
                                f"Re-spawning Strategy Agent to continue engagement.",
                                {"st_respawn": True})
                            await self._spawn_agent(
                                "ST",
                                task_prompt=(
                                    f"You are resuming as Strategy Agent. "
                                    f"A worker agent just completed:\n{msg}\n"
                                    f"Review the Neo4j graph for all findings so far, "
                                    f"then decide next steps: spawn new agents, "
                                    f"pivot strategy, or generate the final report."
                                )
                            )
                        finally:
                            self._st_spawning = False

        # Clean up completed tasks and unregister from bus
        for code in completed:
            self.bus.unregister(code)
            del self._agent_tasks[code]
            self._worker_last_tool_call.pop(code, None)

        # Auto-spawn RP if it was blocked and all workers are now done
        if self._pending_rp_request:
            worker_codes = {"PR", "AR", "WV", "EX", "PE", "VF", "DA", "PX"}
            still_running = [
                c for c in worker_codes
                if c in self.agents and self.agents[c].is_running
            ]
            if not still_running:
                rp_req = self._pending_rp_request
                self._pending_rp_request = None
                await self._emit("system", "OR",
                    "All workers complete. Spawning RP for final report.",
                    {"rp_unblocked": True})
                await self._spawn_agent(
                    rp_req["agent"], task_prompt=rp_req["task"])

        # Check if ST itself completed (engagement done)
        # BUG-037: Don't declare engagement finished if we're paused — pause cancels
        # SDK queries which looks like "completion" but isn't.
        # BUG-FIX: Previously required `not self._agent_tasks` (all agents done),
        # but when ST budget-exhausts, workers keep running with no coordinator.
        # Now: ST completion = engagement over. Stop any remaining workers.
        if "ST" in completed and not self._paused:
            self._st_tool_call_started_at = None  # Clear on ST session end
            # BUG-038 FIX: ST's idle timeout fires while workers are ACTIVELY running.
            # Previously killed all workers immediately. Now: check if workers are active.
            # If active, re-spawn ST to coordinate. If all done, end engagement.
            active_workers = [
                c for c, t in self._agent_tasks.items()
                if c != "ST" and not t.done()
            ]
            if active_workers:
                # Workers still running — re-spawn ST to coordinate them
                if not self._st_spawning:
                    self._st_spawning = True
                    try:
                        logger.info(
                            "BUG-038: ST timed out but workers still running (%s). "
                            "Re-spawning ST to coordinate.",
                            active_workers
                        )
                        await self._emit("system", "OR",
                            f"ST session ended but workers still active: "
                            f"{', '.join(active_workers)}. Re-spawning ST.",
                            {"st_respawn": True, "bug038": True})
                        await self._spawn_agent(
                            "ST",
                            task_prompt=(
                                f"You are resuming as Strategy Agent. "
                                f"Your previous session ended (idle timeout). "
                                f"Workers still running: {', '.join(active_workers)}. "
                                f"Monitor Neo4j for their results, then decide: "
                                f"wait for completions, request PE if not yet dispatched, "
                                f"or request RP when all workers are done."
                            )
                        )
                    finally:
                        self._st_spawning = False
                return  # Do NOT stop workers, do NOT declare engagement finished
            else:
                # No active workers — engagement is truly done
                remaining = [c for c, t in self._agent_tasks.items() if not t.done()]
                for code in remaining:
                    session = self.agents.get(code)
                    if session and session.is_running:
                        logger.info("Stopping %s — ST completed, no active workers", code)
                        await session.stop()
                        if code not in self._cost_aggregated:
                            self.total_cost_usd += session._total_cost_usd
                            self.total_tool_calls += session._tool_count
                            self._cost_aggregated.add(code)
                        await self._emit("agent_status", code, "completed",
                            {"status": "completed", "reason": "engagement_ended",
                             "cost_usd": round(session._total_cost_usd, 4),
                             "tool_calls": session._tool_count})
                await self._emit("system", "OR",
                    "Strategy Agent completed. Engagement finished.",
                    {"control": "engagement_ended"})
                self.is_running = False
                return

        # BUG-033: Send ST periodic heartbeat when workers are active.
        # Prevents ST from timing out (300s idle) while scans are running.
        if "ST" not in completed:
            await self._maybe_send_heartbeat()

        # Worker idle watchdog — redirect agents stuck with no tool calls for 120s
        _WORKER_IDLE_TIMEOUT = 120.0
        now = time.time()
        for code, session in list(self._agents.items()):
            if code in ("ST", "CR") or not session.is_running:
                continue
            last_call = self._worker_last_tool_call.get(code)
            if last_call is None:
                continue
            idle_secs = now - last_call
            if idle_secs > _WORKER_IDLE_TIMEOUT:
                if code == "EX":
                    redirect = (
                        "REDIRECT: You appear idle. Query Neo4j for remaining HIGH/CRITICAL "
                        "findings and continue exploitation. Do NOT stop after one exploit."
                    )
                else:
                    redirect = (
                        "REDIRECT: You appear idle. Check Neo4j for remaining tasks and continue."
                    )
                logger.warning("IDLE WATCHDOG: %s no tool calls for %.0fs — redirecting", code, idle_secs)
                self._worker_last_tool_call[code] = now  # Reset to avoid repeated redirects
                await session.send_command(redirect)

    async def _maybe_send_heartbeat(self):
        """Fallback keepalive: only fires when no bus traffic for 60s.

        With the real-time MessageBus, agents receive intel updates at
        chunk boundaries. This heartbeat is a safety net — it only sends
        a status pulse to ST if no bus messages were delivered recently,
        preventing ST from timing out (300s idle) during quiet periods.
        """
        now = time.time()

        # Check for recent bus traffic — skip heartbeat if bus is active
        recent_bus = self.bus.get_history(limit=1)
        if recent_bus and (now - recent_bus[-1].timestamp) < self._heartbeat_interval:
            self._last_heartbeat = now  # Reset timer, bus is keeping things alive
            return

        if now - self._last_heartbeat < self._heartbeat_interval:
            return

        # Find active workers (not ST, not completed)
        active_workers = []
        for code, task in self._agent_tasks.items():
            if code == "ST":
                continue
            if isinstance(task, asyncio.Task) and not task.done():
                session = self.agents.get(code)
                tools = session._tool_count if session else 0
                active_workers.append((code, tools))

        if not active_workers:
            return  # No workers running, no heartbeat needed

        st = self.agents.get("ST")
        st_task = self._agent_tasks.get("ST")
        if not st or not (st.is_running or (st_task and not st_task.done())):
            return  # ST isn't running

        # Build heartbeat with worker status + scan health
        msg = self._build_heartbeat_message(active_workers)
        await st.send_command(msg)
        self._last_heartbeat = now

        logger.info("Heartbeat (fallback keepalive) sent to ST: %d active workers, %d scans",
                     len(active_workers),
                     len(self.dashboard_state.scans) if self.dashboard_state else 0)

    def _build_heartbeat_message(self, active_workers: list[tuple[str, int]]) -> str:
        """Build a status heartbeat message for ST with worker + scan health."""
        lines = ["── ENGAGEMENT STATUS UPDATE ──"]

        # Worker status
        worker_parts = []
        for code, tools in active_workers:
            name = AGENT_NAMES.get(code, code)
            worker_parts.append(f"{code} ({name}): running, {tools} tool calls")
        lines.append("ACTIVE WORKERS: " + "; ".join(worker_parts))

        # Scan health from dashboard state
        if self.dashboard_state and hasattr(self.dashboard_state, 'scans'):
            running_scans = []
            completed_scans = 0
            stalled_scans = []
            for scan in self.dashboard_state.scans:
                status = scan.get("status", "")
                tool = scan.get("tool", "unknown")
                # Normalize tool name for display
                short_tool = tool.split("__")[-1] if "__" in tool else tool
                if status == "running":
                    started = scan.get("started_at")
                    elapsed = "?"
                    if started:
                        try:
                            from datetime import datetime, timezone
                            if isinstance(started, str):
                                started_dt = datetime.fromisoformat(started)
                                if started_dt.tzinfo is None:
                                    started_dt = started_dt.replace(tzinfo=timezone.utc)
                            else:
                                started_dt = started
                            elapsed_s = int((datetime.now(timezone.utc) - started_dt).total_seconds())
                            mins, secs = divmod(elapsed_s, 60)
                            elapsed = f"{mins}m{secs:02d}s" if mins else f"{secs}s"
                            if elapsed_s >= 600:
                                stalled_scans.append(f"{short_tool} ({elapsed} — POSSIBLY STALLED)")
                        except Exception:
                            pass
                    running_scans.append(f"{short_tool} ({elapsed})")
                elif status == "completed":
                    completed_scans += 1
                elif status == "stalled":
                    stalled_scans.append(f"{short_tool} (STALLED)")

            if running_scans:
                lines.append(f"RUNNING SCANS: {', '.join(running_scans)}")
            if completed_scans:
                lines.append(f"COMPLETED SCANS: {completed_scans}")
            if stalled_scans:
                lines.append(f"⚠ STALLED SCANS: {', '.join(stalled_scans)}")
                lines.append(
                    "ACTION: Check if stalled scans need cancellation "
                    "(POST /api/scans/{scan_id}/cancel) or re-dispatch."
                )

        # Finding count
        if self.dashboard_state and hasattr(self.dashboard_state, 'findings'):
            finding_count = len(self.dashboard_state.findings)
            lines.append(f"FINDINGS REGISTERED: {finding_count}")

        lines.append(
            "Decide: wait for scans to complete, check scan health, "
            "spawn additional agents, or take corrective action."
        )
        return "\n".join(lines)

    # ── Agent Spawning ─────────────────────────

    async def _spawn_agent(self, code: str, task_prompt: str = ""):
        """Spawn a new agent session for the given role.

        Args:
            code: Agent role code (e.g. "AR", "WV", "EX")
            task_prompt: Optional task-specific instructions from ST.
                If empty, the agent uses its default role prompt.
        """
        # BUG-029: Don't spawn agents while engagement is paused
        # BUG-036: Store in deferred list instead of re-queuing (prevents infinite loop)
        if self._paused:
            logger.info("Engagement paused — deferring spawn of %s", code)
            self._deferred_spawns.append({
                "agent": code, "task": task_prompt or "",
                "priority": "medium", "timestamp": time.time()
            })
            await self._emit("system", "OR",
                f"Spawn of {code} deferred — engagement is paused. Will retry on resume.",
                {"warning": True, "deferred_spawn": code})
            return

        # Resource-aware concurrency limit — check before spawning
        try:
            from server import _system_resources
            max_agents = _system_resources.get("max_concurrent_agents", 12)
            running_count = sum(1 for a in self.agents.values() if a.is_running)
            if running_count >= max_agents:
                logger.warning("Concurrency limit reached (%d/%d) — queueing agent %s", running_count, max_agents, code)
                await self._emit("system", "OR",
                    f"Agent {code} queued — {running_count}/{max_agents} agents running (tier: {_system_resources.get('tier', '?')}). Will spawn when a slot opens.",
                    {"warning": True, "queued": True})
                self._agent_request_queue.put_nowait({"code": code, "task": task_prompt, "priority": "high"})
                return
        except ImportError:
            pass  # Fallback: no limit if import fails

        if code in self.agents and self.agents[code].is_running:
            existing = self.agents[code]
            task = self._agent_tasks.get(code)
            if task and not task.done():
                logger.warning("Agent %s already running (live task), skipping spawn", code)
                await self._emit("system", "OR",
                    f"Agent {code} is already running.",
                    {"warning": True})
                return
            else:
                logger.warning(
                    "Agent %s shows is_running=True but task is done/missing — "
                    "replacing stale session", code
                )

        role = get_role(code)

        # ── Parallel pre-spawn: run all independent setup concurrently ──
        # Neo4j context, pending messages, experience brief, and workspace
        # creation are all independent — run them with asyncio.gather()
        # instead of sequentially (~3-4s savings).
        neo4j_ctx_task = asyncio.ensure_future(self._build_context_from_neo4j(code))
        pending_msgs_task = asyncio.ensure_future(self._get_pending_messages(code))
        experience_task = asyncio.ensure_future(self._fetch_experience_brief(code))
        workspace_task = asyncio.get_running_loop().run_in_executor(  # HIGH-1: fix deprecated get_event_loop()
            None, self._workspace_manager.create_agent_workspace, code)

        # Knowledge brief is sync disk I/O — use cached version or run in executor
        knowledge_brief = self._build_knowledge_brief(role)

        # Await all parallel tasks
        prior_context, pending_msgs, experience_brief, agent_cwd = await asyncio.gather(
            neo4j_ctx_task, pending_msgs_task, experience_task, workspace_task)

        # Assemble context from parallel results
        if pending_msgs:
            prior_context = f"PENDING MESSAGES FOR YOU:\n{pending_msgs}\n\n{prior_context}"

        # If ST provided specific task instructions, prepend them
        if task_prompt:
            prior_context = f"TASK FROM STRATEGY AGENT:\n{task_prompt}\n\n{prior_context}"

        # Create role-configured session with per-agent workspace + bus
        session = AthenaAgentSession.create_for_role(
            role=role,
            engagement_id=self.engagement_id,
            target=self.target,
            backend=self.backend,
            athena_root=str(agent_cwd),
            prior_context=prior_context,
            bus=self.bus,
        )
        self.bus.register(role.code)

        # Wire event callback (same pipeline as single-agent mode)
        if self._event_callback:
            if code == "ST":
                # Wrap ST's callback to track tool call start/end times for auto-cancel
                _outer_cb = self._event_callback
                _manager_ref = self

                async def _st_tracking_callback(event: dict):
                    evt_type = event.get("type")
                    if evt_type == "tool_start":
                        _manager_ref._st_tool_call_started_at = time.time()
                    elif evt_type == "tool_complete":
                        _manager_ref._st_tool_call_started_at = None
                    await _outer_cb(event)

                session.set_event_callback(_st_tracking_callback)
            else:
                _outer_cb_w = self._event_callback
                _mgr = self
                _code = code

                async def _worker_tracking_callback(event: dict):
                    if event.get("type") == "tool_start":
                        _mgr._worker_last_tool_call[_code] = time.time()
                    await _outer_cb_w(event)

                session.set_event_callback(_worker_tracking_callback)
        else:
            logger.error(
                "CRITICAL: Spawning agent %s with no event callback — "
                "events will be silently dropped.", code
            )

        # BUG-013: Suppress per-agent engagement_ended — manager owns that event.
        # Without this, each agent's finally block emits engagement_ended,
        # causing the frontend to reset the cost KPI to that agent's cost
        # instead of the engagement total.
        session._suppress_engagement_ended = True

        # Build the initial prompt for the agent (includes knowledge brief)
        prompt = format_prompt(role, self.engagement_id, self.target,
                               self.backend, prior_context,
                               mode=self.mode,
                               knowledge_brief=knowledge_brief,
                               experience_brief=experience_brief,
                               dashboard_url=_DASHBOARD_URL)
        if task_prompt:
            prompt = f"{task_prompt}\n\n{prompt}"

        try:
            await session.start(prompt)
            # BUG-C7: Only store session after successful start (prevents zombie on failure)
            self.agents[code] = session
            self._agent_tasks[code] = session._query_task
            await self._emit("agent_status", code, "running",
                {"status": "running"})
            logger.info("Spawned agent %s (%s) — model=%s, budget=$%.2f",
                        code, role.name, role.model, role.max_cost_usd)

            # COMMS CHECK: verify agent session is alive and emitting events
            async def _comms_check(agent_code, delay=5):
                await asyncio.sleep(delay)
                s = self.agents.get(agent_code)
                if not s:
                    return  # Agent was removed (stopped/replaced)
                task = self._agent_tasks.get(agent_code)
                if task and task.done():
                    # Agent task died silently — log and notify ST
                    logger.error("COMMS CHECK FAILED: %s task died within %ds of spawn", agent_code, delay)
                    await self._emit("system", "OR",
                        f"⚠ COMMS CHECK FAILED: Agent {agent_code} died after spawn. "
                        f"Check logs for errors. Consider re-spawning.",
                        {"comms_check_failed": True, "agent": agent_code})
                else:
                    logger.info("COMMS CHECK: %s alive (%d tool calls)",
                                agent_code, s._tool_count)
            asyncio.ensure_future(_comms_check(code))

            # BUG-040: Notify ST that the worker agent is now RUNNING.
            # Without this, ST continues its turn, queries Neo4j (empty),
            # and incorrectly concludes the agent didn't spawn.
            if code != "ST":
                st = self.agents.get("ST")
                st_task = self._agent_tasks.get("ST")
                if st and (st.is_running or (st_task and not st_task.done())):
                    await st.send_command(
                        f"Agent {code} ({role.name}) has been SPAWNED and is now RUNNING. "
                        f"It will take time to produce results. Do NOT attempt to do "
                        f"{code}'s work yourself. Wait for its completion notification."
                    )
            # BUG-028: Drain any commands that arrived while ST was dead
            if code == "ST" and self._pending_commands:
                pending_count = len(self._pending_commands)
                failed_cmds = []
                for cmd in self._pending_commands:
                    result = await session.send_command(cmd)
                    if isinstance(result, str) and result.startswith("Error:"):
                        failed_cmds.append(cmd)
                        logger.warning("Failed to deliver pending command to ST: %s", result)
                self._pending_commands.clear()
                if failed_cmds:
                    self._pending_commands.extend(failed_cmds)  # BUG-M4: re-queue failed commands
                else:
                    logger.info("Delivered %d pending command(s) to re-spawned ST", pending_count)
                    await self._emit("system", "OR",
                        f"Delivered {pending_count} queued operator command(s) to ST.",
                        {"pending_commands_delivered": pending_count})
        except Exception as e:
            # BUG-C7: Clean up failed session resources
            if hasattr(session, '_http_client') and session._http_client and not session._http_client.is_closed:
                await session._http_client.aclose()
            logger.exception("Failed to spawn agent %s", code)
            await self._emit("system", "OR",
                f"Failed to spawn {code}: {str(e)[:300]}",
                {"error": True, "agent": code})

    async def _stop_agent(self, code: str):
        """Stop a specific agent session."""
        session = self.agents.get(code)
        if session and session.is_running:
            await session.stop()
        # BUG-018: Always emit idle status, even if session already finished.
        # Previously skipped when is_running was False, leaving VF chip stuck.
        await self._emit("agent_status", code, "idle",
            {"status": "idle"})

        task = self._agent_tasks.pop(code, None)
        if task and not task.done():
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, RuntimeError):
                pass

    # ── Knowledge Brief Builder (CEI Layer 2) ──

    def _build_knowledge_brief(self, role: AgentRoleConfig) -> str:
        """Build a condensed knowledge brief from playbook files on disk.

        Reads the first ~40 lines (overview/summary section) of each
        playbook assigned to this agent role and returns a compact brief.
        This is injected directly into the agent's system prompt —
        the agent literally can't miss it.

        Results are cached per role code since playbooks don't change
        between agent spawns within the same engagement.

        Returns:
            Condensed knowledge brief string, or empty string if no playbooks.
        """
        if role.code in self._knowledge_brief_cache:
            return self._knowledge_brief_cache[role.code]
        if not role.playbooks:
            return ""

        brief_parts = []
        for pb_path in role.playbooks:
            full_path = self.athena_root / pb_path
            if not full_path.exists():
                logger.warning("Playbook not found: %s", full_path)
                continue
            try:
                with open(full_path, "r") as f:
                    lines = []
                    for i, line in enumerate(f):
                        if i >= 40:  # First 40 lines = overview section
                            break
                        lines.append(line)
                content = "".join(lines).strip()
                if content:
                    brief_parts.append(
                        f"### {pb_path}\n{content}\n"
                    )
            except Exception as e:
                logger.warning("Failed to read playbook %s: %s", pb_path, e)

        if not brief_parts:
            self._knowledge_brief_cache[role.code] = ""
            return ""

        result = "\n".join(brief_parts)
        self._knowledge_brief_cache[role.code] = result
        return result

    async def _fetch_experience_brief(self, agent_code: str) -> str:
        """CEI-3: Fetch experience brief from past engagements via API.

        Queries the experience-brief endpoint which returns technique
        effectiveness data from Neo4j. This data-driven brief tells
        agents which tools work best and which to skip.

        Returns:
            Formatted experience brief string, or empty string.
        """
        try:
            import httpx
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get(
                    f"{_DASHBOARD_URL}/api/experience-brief/{agent_code}"
                )
                if resp.status_code == 200:
                    data = resp.json()
                    return data.get("brief", "")
        except Exception as e:
            logger.warning("CEI experience brief fetch failed for %s: %s", agent_code, e)
        return ""

    # ── Neo4j Context Builder ──────────────────

    async def _build_context_from_neo4j(self, agent_code: str) -> str:
        """Query Neo4j for findings from prior phases.

        Each agent gets a relevant summary:
        - AR: Gets nothing (first phase, no prior findings)
        - WV: Gets discovered hosts and services from AR
        - EX: Gets hosts, services, AND vulnerability findings from WV
        - VF: Gets HIGH/CRITICAL findings to verify
        - RP: Gets everything (full engagement data)
        - ST: Gets everything (coordinator needs full picture)
        """
        try:
            from neo4j import GraphDatabase
        except ImportError:
            return "Neo4j not available. Check engagement state via dashboard API."

        # MED-3 fix: Use injected driver instead of circular import
        driver = self._neo4j_driver
        if not driver:
            return "Neo4j driver not initialized."

        eid = self.engagement_id
        code = agent_code

        def _sync_queries():
            parts = []
            try:
                with driver.session() as session:
                    # Hosts
                    if code in ("WV", "EX", "VF", "RP", "ST"):
                        result = session.run(
                            "MATCH (h:Host {engagement_id: $eid}) "
                            "RETURN h.ip AS ip, h.hostname AS hostname, "
                            "h.os AS os LIMIT 50", eid=eid)
                        hosts = [dict(r) for r in result]
                        if hosts:
                            lines = [f"  - {h['ip']}"
                                     + (f" ({h['hostname']})" if h.get('hostname') else "")
                                     + (f" [{h['os']}]" if h.get('os') else "")
                                     for h in hosts]
                            parts.append(f"DISCOVERED HOSTS ({len(hosts)}):\n"
                                         + "\n".join(lines))

                    # Services
                    if code in ("WV", "EX", "VF", "RP", "ST"):
                        result = session.run(
                            "MATCH (s:Service)-[:RUNS_ON]->(h:Host {engagement_id: $eid}) "
                            "RETURN h.ip AS ip, s.port AS port, s.protocol AS protocol, "
                            "s.service AS service, s.version AS version LIMIT 100",
                            eid=eid)
                        services = [dict(r) for r in result]
                        if services:
                            lines = [f"  - {s['ip']}:{s['port']}/{s.get('protocol','tcp')} "
                                     f"— {s.get('service','unknown')}"
                                     + (f" {s['version']}" if s.get('version') else "")
                                     for s in services]
                            parts.append(f"DISCOVERED SERVICES ({len(services)}):\n"
                                         + "\n".join(lines))

                    # Findings (for exploitation, verification, reporting, strategy)
                    if code in ("EX", "VF", "RP", "ST"):
                        # M-1: Parameterized severity filter — no f-string Cypher injection
                        severity_list = None
                        if code == "VF":
                            severity_list = ["critical", "high"]
                        elif code == "EX":
                            severity_list = ["critical", "high", "medium"]

                        if severity_list:
                            result = session.run(
                                "MATCH (f:Finding {engagement_id: $eid}) "
                                "WHERE f.severity IN $severities "
                                "RETURN f.id AS id, f.title AS title, "
                                "f.severity AS severity, f.agent AS agent, "
                                "f.description AS description LIMIT 50",
                                eid=eid, severities=severity_list)
                        else:
                            result = session.run(
                                "MATCH (f:Finding {engagement_id: $eid}) "
                                "RETURN f.id AS id, f.title AS title, "
                                "f.severity AS severity, f.agent AS agent, "
                                "f.description AS description LIMIT 50",
                                eid=eid)
                        findings = [dict(r) for r in result]
                        if findings:
                            lines = [f"  - [{f.get('severity','?').upper()}] {f.get('title','?')} "
                                     f"(by {f.get('agent','?')}) — {f.get('description','')[:100]}"
                                     for f in findings]
                            parts.append(f"FINDINGS ({len(findings)}):\n"
                                         + "\n".join(lines))

                    # Credentials (for exploitation, post-exploitation, reporting)
                    if code in ("EX", "RP", "ST"):
                        result = session.run(
                            "MATCH (c:Credential {engagement_id: $eid}) "
                            "RETURN c.username AS username, c.service AS service, "
                            "c.host AS host LIMIT 20", eid=eid)
                        creds = [dict(r) for r in result]
                        if creds:
                            lines = [f"  - {c.get('username','?')}@{c.get('host','?')} "
                                     f"({c.get('service','?')})" for c in creds]
                            parts.append(f"CREDENTIALS ({len(creds)}):\n"
                                         + "\n".join(lines))

                    # Attack chains (for strategy, reporting)
                    if code in ("ST", "RP"):
                        result = session.run(
                            "MATCH (c:AttackChain {engagement_id: $eid}) "
                            "RETURN c.name AS name, c.impact AS impact, "
                            "c.priority AS priority LIMIT 10", eid=eid)
                        chains = [dict(r) for r in result]
                        if chains:
                            lines = [f"  - [{c.get('priority','-')}] {c.get('name','?')} "
                                     f"— {c.get('impact','?')}" for c in chains]
                            parts.append(f"ATTACK CHAINS ({len(chains)}):\n"
                                         + "\n".join(lines))

                        # Inter-finding chain relationships (ENABLES, PIVOTS_TO, etc.)
                        # BUG-M5: Whitelist — rel_type is f-string interpolated into Cypher
                        _ALLOWED_REL_TYPES = frozenset(("ENABLES", "PIVOTS_TO", "ESCALATES_TO", "EXPOSES"))
                        for rel_type in _ALLOWED_REL_TYPES:
                            result = session.run(f"""
                                MATCH (a)-[r:{rel_type}]->(b)
                                WHERE (a:Finding AND a.engagement_id = $eid)
                                   OR (a:Host AND a.engagement_id = $eid)
                                RETURN COALESCE(a.title, a.hostname, a.ip, a.id) AS src,
                                       COALESCE(b.title, b.hostname, b.ip, b.id) AS dst,
                                       r.confidence AS confidence,
                                       r.description AS description
                                LIMIT 20
                            """, eid=eid)
                            rels = [dict(r) for r in result]
                            if rels:
                                lines = [f"  - {r['src']} —[{rel_type}]→ {r['dst']}"
                                         f" (conf: {r.get('confidence', '?')})"
                                         + (f" — {r['description'][:80]}"
                                            if r.get('description') else "")
                                         for r in rels]
                                parts.append(f"CHAIN RELATIONSHIPS ({rel_type}, "
                                             f"{len(rels)}):\n"
                                             + "\n".join(lines))

            except Exception as e:
                logger.warning("Neo4j context query failed: %s", e)
                parts.append(f"Neo4j query error: {str(e)[:200]}. "
                             "Use Neo4j MCP tools to query engagement state directly.")

            if not parts:
                return "No prior findings yet. This is a fresh engagement."
            return "\n\n".join(parts)

        return await asyncio.to_thread(_sync_queries)

    # ── F2: Pending Message Retrieval ────────

    async def _get_pending_messages(self, agent_code: str) -> str:
        """Fetch bilateral messages addressed to this agent from the server.

        Called when spawning an agent so it starts with awareness of
        messages sent to it before it was running.
        """
        try:
            # BUG-H6: Use httpx (already available) instead of aiohttp (may not be installed)
            import httpx
            async with httpx.AsyncClient(timeout=3.0) as http:
                resp = await http.get(
                    f"{_DASHBOARD_URL}/api/messages",
                    params={"agent": agent_code, "limit": "20"},
                )
                if resp.status_code != 200:
                    return ""
                data = resp.json()
                messages = data.get("messages", [])
                # Filter to messages addressed TO this agent (not FROM)
                incoming = [m for m in messages
                            if m.get("to_agent") == agent_code]
                if not incoming:
                    return ""
                lines = []
                for m in incoming[:10]:  # Cap at 10 most recent
                    lines.append(
                        f"[{m.get('msg_type','msg')}] "
                        f"From {m.get('from_agent','?')} "
                        f"(priority: {m.get('priority','medium')}): "
                        f"{m.get('content','')[:300]}"
                    )
                return "\n".join(lines)
        except Exception:
            return ""

    # ── F1: Agent Production Summary ─────────

    async def _get_agent_production_summary(self, agent_code: str) -> str:
        """Quick Neo4j stats for what an agent produced during this engagement.

        Returns a compact summary like:
            "Hosts: 3, Services: 12, Findings: 5 (2 critical, 2 high, 1 medium)"

        Used in ST completion notifications so the Strategy Agent can
        immediately reason about next steps without querying Neo4j.
        """
        try:
            import server
            driver = getattr(server, "neo4j_driver", None)
            if not driver:
                return ""
        except Exception:
            return ""

        eid = self.engagement_id

        def _sync_summary():
            parts = []
            try:
                with driver.session() as session:
                    # Count hosts
                    result = session.run(
                        "MATCH (h:Host {engagement_id: $eid}) RETURN count(h) AS c",
                        eid=eid)
                    hosts = result.single()["c"]

                    # Count services
                    result = session.run(
                        "MATCH (h:Host {engagement_id: $eid})-[:HAS_SERVICE]->(s:Service) "
                        "RETURN count(s) AS c", eid=eid)
                    services = result.single()["c"]

                    # Findings by severity
                    result = session.run(
                        "MATCH (f:Finding {engagement_id: $eid}) "
                        "RETURN f.severity AS sev, count(f) AS c "
                        "ORDER BY c DESC", eid=eid)
                    findings_by_sev = {r["sev"]: r["c"] for r in result}
                    total_findings = sum(findings_by_sev.values())

                    # Credentials
                    result = session.run(
                        "MATCH (c:Credential {engagement_id: $eid}) "
                        "RETURN count(c) AS c", eid=eid)
                    creds = result.single()["c"]

                    # Attack chains
                    result = session.run(
                        "MATCH (c:AttackChain {engagement_id: $eid}) "
                        "RETURN count(c) AS c", eid=eid)
                    chains = result.single()["c"]

                    parts.append(f"Hosts: {hosts}, Services: {services}")
                    if total_findings:
                        sev_str = ", ".join(
                            f"{c} {s}" for s, c in findings_by_sev.items() if c > 0)
                        parts.append(f"Findings: {total_findings} ({sev_str})")
                    else:
                        parts.append("Findings: 0")
                    if creds:
                        parts.append(f"Credentials: {creds}")
                    if chains:
                        parts.append(f"Attack Chains: {chains}")

            except Exception as e:
                logger.warning("Production summary query failed: %s", e)
                return ""

            return " | ".join(parts)

        return await asyncio.to_thread(_sync_summary)

    # ── Internal Helpers ───────────────────────

    async def _emit(self, event_type: str, agent: str, content: str,
                    metadata: dict | None = None):
        """Emit an event to the dashboard."""
        if self._event_callback:
            await self._event_callback({
                "type": event_type,
                "agent": agent,
                "content": content,
                "metadata": metadata or {},
                "timestamp": time.time(),
            })
