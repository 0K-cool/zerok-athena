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
import time
from pathlib import Path
from typing import Any, Callable, Optional

from agent_configs import AGENT_ROLES, AgentRoleConfig, format_prompt, get_role
from sdk_agent import AthenaAgentSession

logger = logging.getLogger("athena.session_manager")


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
    ):
        self.engagement_id = engagement_id
        self.target = target
        self.backend = backend
        self.dashboard_state = dashboard_state
        self.mode = mode  # "multi-agent" or "ctf"
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
        # F5: Budget-exhausted agents pending early-stop
        self._early_stop_queue: set[str] = set()

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

        # Aggregate costs
        for session in self.agents.values():
            self.total_cost_usd += session._total_cost_usd
            self.total_tool_calls += session._tool_count

        await self._emit("system", "OR",
            f"Multi-agent engagement stopped. "
            f"{len(self.agents)} agents used, "
            f"{self.total_tool_calls} total tool calls, "
            f"${self.total_cost_usd:.4f} total cost.",
            {"control": "engagement_ended",
             "cost_usd": round(self.total_cost_usd, 4),
             "tool_calls": self.total_tool_calls,
             "agents_used": list(self.agents.keys())})

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
        try:
            while self.is_running:
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
                self.total_cost_usd += session._total_cost_usd
                self.total_tool_calls += session._tool_count
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
                if session:
                    self.total_cost_usd += session._total_cost_usd
                    self.total_tool_calls += session._tool_count

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

        # Create role-configured session
        session = AthenaAgentSession.create_for_role(
            role=role,
            engagement_id=self.engagement_id,
            target=self.target,
            backend=self.backend,
            athena_root=str(self.athena_root),
            prior_context=prior_context,
        )

        # Wire event callback (same pipeline as single-agent mode)
        if self._event_callback:
            session.set_event_callback(self._event_callback)

        # Store and start
        self.agents[code] = session

        # Build the initial prompt for the agent
        prompt = format_prompt(role, self.engagement_id, self.target,
                               self.backend, prior_context,
                               mode=self.mode)
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
        parts = []

        try:
            with driver.session() as session:
                # Hosts
                if agent_code in ("WV", "EX", "VF", "RP", "ST"):
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
                if agent_code in ("WV", "EX", "VF", "RP", "ST"):
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
                if agent_code in ("EX", "VF", "RP", "ST"):
                    severity_filter = ""
                    if agent_code == "VF":
                        severity_filter = "AND f.severity IN ['critical', 'high']"
                    elif agent_code == "EX":
                        severity_filter = "AND f.severity IN ['critical', 'high', 'medium']"

                    result = session.run(
                        f"MATCH (f:Finding {{engagement_id: $eid}}) "
                        f"WHERE true {severity_filter} "
                        f"RETURN f.id AS id, f.title AS title, "
                        f"f.severity AS severity, f.agent AS agent, "
                        f"f.description AS description LIMIT 50",
                        eid=eid)
                    findings = [dict(r) for r in result]
                    if findings:
                        lines = [f"  - [{f.get('severity','?').upper()}] {f.get('title','?')} "
                                 f"(by {f.get('agent','?')}) — {f.get('description','')[:100]}"
                                 for f in findings]
                        parts.append(f"FINDINGS ({len(findings)}):\n"
                                     + "\n".join(lines))

                # Credentials (for exploitation, post-exploitation, reporting)
                if agent_code in ("EX", "PE", "RP", "ST"):
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
                if agent_code in ("ST", "RP"):
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
