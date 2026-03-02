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
from sdk_agent import AthenaAgentSession

logger = logging.getLogger("athena.session_manager")


# ── Phase G: Workspace Isolation ──────────────────────────────

class WorkspaceManager:
    """Manages per-agent isolated workspaces for parallel execution.

    Creates lightweight directory scaffolds per agent with symlinks
    to shared resources (CLAUDE.md, .claude/, playbooks/) and
    separate evidence directories to prevent file conflicts.

    ST and RP run in the main ATHENA root (no isolation needed).
    Worker agents (AR, WV, EX, VF) get isolated workspaces.
    """

    # Agents that stay in the main working directory (no isolation)
    MAIN_DIR_AGENTS = {"ST", "RP"}

    # Directories/files to symlink from ATHENA root into agent workspaces
    SYMLINK_TARGETS = ["CLAUDE.md", ".claude", "playbooks", "intel", "mcp-servers"]

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
        for suffix in ("*.md", "*.json", "*.txt", "*.yaml", "*.yml", "*.log", "*.sh", "*.py", "*.xml"):
            for f in directory.rglob(suffix):
                # Skip symlinks (shared resources)
                if f.is_symlink():
                    continue
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

    @staticmethod
    def cleanup_stale_workspaces(max_age_hours: float = 2.0):
        """Remove stale workspace directories from /tmp.

        Called on server startup to prevent /tmp accumulation from crashes.
        M-6: Skips directories with an active lockfile (.athena-active) whose
        mtime is within the max_age window — prevents deleting live engagements.
        """
        tmp = Path(tempfile.gettempdir())
        max_age_seconds = max_age_hours * 3600
        now = time.time()
        cleaned = 0
        for d in tmp.iterdir():
            if d.is_dir() and d.name.startswith("athena-"):
                try:
                    # M-6: Skip directories with an active lockfile
                    lockfile = d / ".athena-active"
                    if lockfile.exists():
                        lock_age = now - lockfile.stat().st_mtime
                        if lock_age < max_age_seconds:
                            logger.debug("Skipping active workspace: %s", d.name)
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
    ):
        self.engagement_id = engagement_id
        self.target = target
        self.backend = backend
        self.dashboard_state = dashboard_state
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
        self._manager_task: asyncio.Task | None = None
        # Cost tracking across all agents
        self.total_cost_usd: float = 0.0
        self.total_tool_calls: int = 0
        self._cost_aggregated: set[str] = set()
        self._pending_rp_request: dict | None = None
        # F5: Budget-exhausted agents pending early-stop
        self._early_stop_queue: set[str] = set()
        # Phase G: Per-agent workspace isolation
        self._workspace_manager = WorkspaceManager(engagement_id, self.athena_root)

    def set_event_callback(self, callback: Callable):
        """Set async callback for streaming events to dashboard."""
        self._event_callback = callback

    # ── Public API ─────────────────────────────

    async def start(self, initial_st_context: str = ""):
        """Start the multi-agent engagement.

        Launches ST (Strategy Agent) first, then listens for agent requests.
        ST will read Neo4j and decide what workers to spawn.
        """
        self.is_running = True

        await self._emit("system", "OR",
            "Multi-agent mode activated. Starting Strategy Agent (ST)...",
            {"mode": "multi-agent", "engagement_id": self.engagement_id})

        # Start ST first — it's the coordinator
        await self._spawn_agent("ST", task_prompt=initial_st_context)

        # Start the manager loop that processes agent requests
        self._manager_task = asyncio.create_task(self._manager_loop())

        logger.info("Multi-agent engagement started: %s (ST + manager loop)",
                     self.engagement_id)

    async def stop(self):
        """Stop all agents and clean up."""
        self.is_running = False

        # Cancel manager loop
        if self._manager_task and not self._manager_task.done():
            self._manager_task.cancel()
            try:
                await self._manager_task
            except asyncio.CancelledError:
                pass

        # Stop all active agent sessions
        stop_tasks = []
        for code, session in self.agents.items():
            if session.is_running:
                stop_tasks.append(self._stop_agent(code))
        if stop_tasks:
            await asyncio.gather(*stop_tasks, return_exceptions=True)

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
                    "http://localhost:8080/api/budget/session-final-cost",
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
        logger.info("Multi-agent engagement stopped: %s", self.engagement_id)

    async def pause(self):
        """Pause all running agents."""
        for code, session in self.agents.items():
            if session.is_running and not session.is_paused:
                await session.pause()
        await self._emit("system", "OR", "All agents paused.",
            {"control": "engagement_paused"})

    async def resume(self):
        """Resume all paused agents."""
        for code, session in self.agents.items():
            if session.is_paused:
                await session.resume()
        await self._emit("system", "OR", "All agents resumed.",
            {"control": "engagement_resumed"})

    async def send_command(self, command: str) -> str:
        """Forward operator command to ST (the coordinator)."""
        st = self.agents.get("ST")
        if st and st.is_running:
            return await st.send_command(command)
        return "Error: Strategy Agent (ST) is not running."

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
                    worker_codes = {"AR", "WV", "EX", "VF", "PO", "EC"}
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
                    {"status": "completed", "reason": "budget_exhausted"})
                # Notify ST
                st = self.agents.get("ST")
                if st and st.is_running:
                    cost = round(session._total_cost_usd, 4)
                    tools = session._tool_count
                    await st.send_command(
                        f"Agent {code} was EARLY-STOPPED (budget exhausted). "
                        f"({tools} tool calls, ${cost}). "
                        f"Decide: extend its budget via POST /api/budget/extend, "
                        f"assign a different agent, or mark this path as exhausted."
                    )
            self._early_stop_queue.discard(code)

        completed = []
        for code, task in list(self._agent_tasks.items()):
            if task.done():
                completed.append(code)
                # Aggregate cost from completed agent
                session = self.agents.get(code)
                if session and code not in self._cost_aggregated:
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
                    await self._emit("agent_status", code, "completed",
                        {"status": "completed"})

                # F1: Notify ST with enriched completion summary
                # Include Neo4j stats so ST can reason about next steps
                # without making a separate query.
                st = self.agents.get("ST")
                if st and st.is_running and code != "ST":
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
                    await st.send_command(msg)

        # Clean up completed tasks
        for code in completed:
            del self._agent_tasks[code]

        # Auto-spawn RP if it was blocked and all workers are now done
        if self._pending_rp_request:
            worker_codes = {"AR", "WV", "EX", "VF", "PO", "EC"}
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
        if "ST" in completed and not self._agent_tasks:
            await self._emit("system", "OR",
                "Strategy Agent completed. Engagement finished.",
                {"control": "engagement_ended"})
            self.is_running = False

    # ── Agent Spawning ─────────────────────────

    async def _spawn_agent(self, code: str, task_prompt: str = ""):
        """Spawn a new agent session for the given role.

        Args:
            code: Agent role code (e.g. "AR", "WV", "EX")
            task_prompt: Optional task-specific instructions from ST.
                If empty, the agent uses its default role prompt.
        """
        if code in self.agents and self.agents[code].is_running:
            logger.warning("Agent %s already running, skipping spawn", code)
            await self._emit("system", "OR",
                f"Agent {code} is already running.",
                {"warning": True})
            return

        role = get_role(code)

        # Build context from Neo4j for this agent
        prior_context = await self._build_context_from_neo4j(code)

        # F2: Inject pending bilateral messages addressed to this agent
        pending_msgs = await self._get_pending_messages(code)
        if pending_msgs:
            prior_context = f"PENDING MESSAGES FOR YOU:\n{pending_msgs}\n\n{prior_context}"

        # If ST provided specific task instructions, prepend them
        if task_prompt:
            prior_context = f"TASK FROM STRATEGY AGENT:\n{task_prompt}\n\n{prior_context}"

        # ── Knowledge Brief Injection (CEI Layer 2) ──
        # Read playbook summaries from disk and inject directly into
        # agent context. This GUARANTEES agents have the knowledge —
        # they can't forget to read what's already in their prompt.
        knowledge_brief = self._build_knowledge_brief(role)

        # CEI-3: Fetch experience from past engagements
        experience_brief = await self._fetch_experience_brief(code)

        # Phase G: Create isolated workspace for worker agents
        # ST and RP stay in main ATHENA root, workers get per-agent dirs
        agent_cwd = self._workspace_manager.create_agent_workspace(code)

        # Create role-configured session with per-agent workspace
        session = AthenaAgentSession.create_for_role(
            role=role,
            engagement_id=self.engagement_id,
            target=self.target,
            backend=self.backend,
            athena_root=str(agent_cwd),
            prior_context=prior_context,
        )

        # Wire event callback (same pipeline as single-agent mode)
        if self._event_callback:
            session.set_event_callback(self._event_callback)

        # Store and start
        self.agents[code] = session

        # Build the initial prompt for the agent (includes knowledge brief)
        prompt = format_prompt(role, self.engagement_id, self.target,
                               self.backend, prior_context,
                               mode=self.mode,
                               knowledge_brief=knowledge_brief,
                               experience_brief=experience_brief)
        if task_prompt:
            prompt = f"{task_prompt}\n\n{prompt}"

        try:
            await session.start(prompt)
            self._agent_tasks[code] = session._query_task
            await self._emit("agent_status", code, "running",
                {"status": "running"})
            logger.info("Spawned agent %s (%s) — model=%s, budget=$%.2f",
                        code, role.name, role.model, role.max_cost_usd)
        except Exception as e:
            logger.exception("Failed to spawn agent %s", code)
            await self._emit("system", "OR",
                f"Failed to spawn {code}: {str(e)[:300]}",
                {"error": True, "agent": code})

    async def _stop_agent(self, code: str):
        """Stop a specific agent session."""
        session = self.agents.get(code)
        if session and session.is_running:
            await session.stop()
            await self._emit("agent_status", code, "idle",
                {"status": "idle"})

        task = self._agent_tasks.pop(code, None)
        if task and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    # ── Knowledge Brief Builder (CEI Layer 2) ──

    def _build_knowledge_brief(self, role: AgentRoleConfig) -> str:
        """Build a condensed knowledge brief from playbook files on disk.

        Reads the first ~40 lines (overview/summary section) of each
        playbook assigned to this agent role and returns a compact brief.
        This is injected directly into the agent's system prompt —
        the agent literally can't miss it.

        Returns:
            Condensed knowledge brief string, or empty string if no playbooks.
        """
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
            return ""

        return "\n".join(brief_parts)

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
                    f"http://localhost:8080/api/experience-brief/{agent_code}"
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

        # Import neo4j_driver from server module (it's initialized there)
        try:
            import server
            driver = getattr(server, "neo4j_driver", None)
            if not driver:
                return "Neo4j driver not initialized."
        except Exception:
            return "Could not access Neo4j driver."

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
                    if code in ("EX", "PE", "RP", "ST"):
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
                        for rel_type in ("ENABLES", "PIVOTS_TO", "ESCALATES_TO", "EXPOSES"):
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
            import aiohttp
            async with aiohttp.ClientSession() as http:
                async with http.get(
                    "http://localhost:8080/api/messages",
                    params={"agent": agent_code, "limit": "20"},
                    timeout=aiohttp.ClientTimeout(total=3),
                ) as resp:
                    if resp.status != 200:
                        return ""
                    data = await resp.json()
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
