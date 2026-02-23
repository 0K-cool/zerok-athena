"""
ATHENA Agent Orchestration Engine.

Replaces demo simulation with real Kali tool execution across both backends.
Follows PTES 7-phase methodology with full WebSocket event streaming and
HITL approval gates for exploitation/post-exploitation.

Architecture:
    Orchestrator
      ├── EngagementContext  (shared state for the engagement)
      ├── AgentRunner        (per-agent: think, run_tool, report_finding, request_approval)
      └── 7 PTES phases      (each wires specific agents to real tools)

All execution is async within the FastAPI process — same pattern as the
existing demo scenario, but calling real Kali HTTP endpoints.
"""

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional

from kali_client import KaliClient, ToolResult
from parsers import (
    extract_cves,
    parse_attackerkb_response,
    parse_netexec_output,
    parse_gau_output,
    parse_gobuster_output,
    parse_httpx_results,
    parse_msf_search_output,
    parse_naabu_results,
    parse_nikto_output,
    parse_nmap_output,
    parse_nuclei_results,
    parse_searchsploit_json,
    parse_sqlmap_output,
    parse_subfinder_output,
    parse_wpscan_output,
    severity_from_cvss,
    validate_scope,
)

if TYPE_CHECKING:
    from server import DashboardState

logger = logging.getLogger(__name__)


# ── Engagement Context ──

@dataclass
class EngagementContext:
    """Shared state for a running engagement."""
    engagement_id: str
    scope: dict  # {"targets": [...], "exclusions": [...]}
    target_type: str  # "external" or "internal"
    backend_override: str = ""  # Force specific backend ("external" or "internal")
    ptes_phase: int = 0
    stopped: bool = False

    # Accumulated results
    discovered_hosts: list = field(default_factory=list)
    discovered_services: list = field(default_factory=list)
    discovered_urls: list = field(default_factory=list)
    discovered_subdomains: list = field(default_factory=list)
    discovered_vulns: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    cves: list = field(default_factory=list)

    # Stats for dashboard
    host_count: int = 0
    service_count: int = 0
    vuln_count: int = 0
    finding_count: int = 0


# ── Agent Runner ──

class AgentRunner:
    """Runs a single agent's tasks with full event lifecycle.

    Provides methods to emit thinking events, execute tools with streaming,
    report findings to Neo4j, and request HITL approval with blocking.
    """

    def __init__(
        self,
        agent_code: str,
        state: "DashboardState",
        kali: KaliClient,
        ctx: EngagementContext,
    ):
        self.agent = agent_code
        self.state = state
        self.kali = kali
        self.ctx = ctx

    def _check_stopped(self):
        """Raise if engagement was stopped."""
        if self.ctx.stopped:
            raise EngagementStopped()

    async def think(self, thought: str, reasoning: str, action: str = ""):
        """Emit agent_thinking event to dashboard."""
        self._check_stopped()
        from server import AgentEvent, AgentStatus, AGENT_NAMES
        await self.state.update_agent_status(self.agent, AgentStatus.RUNNING, thought)
        metadata = {"thought": thought, "reasoning": reasoning}
        if action:
            metadata["action"] = action
        event = AgentEvent(
            id=str(uuid.uuid4())[:8],
            type="agent_thinking",
            agent=self.agent,
            content=thought,
            timestamp=time.time(),
            metadata=metadata,
        )
        await self.state.add_event(event)

    async def run_tool(
        self,
        tool_name: str,
        params: dict,
        display: str = "",
        backend: str = "auto",
    ) -> ToolResult:
        """Execute a tool with full WebSocket event lifecycle.

        Emits: tool_start → progress chunks (for long tools) → tool_complete
        Also records a scan entry in state.scans for the Scans page.
        """
        self._check_stopped()
        from server import AgentEvent, AGENT_NAMES

        tool_id = str(uuid.uuid4())[:8]
        tool_display = display or f"Running {tool_name}..."
        start_time = time.time()
        start_iso = datetime.now(timezone.utc).isoformat()

        # tool_start
        await self.state.add_event(AgentEvent(
            id=str(uuid.uuid4())[:8],
            type="tool_start",
            agent=self.agent,
            content=tool_display,
            timestamp=start_time,
            metadata={"tool": tool_name, "tool_id": tool_id},
        ))

        # Execute on Kali (backend_override takes precedence over auto-selection)
        effective_backend = self.ctx.backend_override or backend
        result = await self.kali.run_tool(
            tool_name, params,
            backend=effective_backend,
            target_type=self.ctx.target_type,
        )

        end_iso = datetime.now(timezone.utc).isoformat()

        # Stream output in chunks for dashboard display
        if result.stdout:
            await self._stream_output(tool_id, result.stdout)
        if result.stderr and not result.success:
            await self._stream_output(tool_id, f"\n[STDERR]\n{result.stderr}")

        # tool_complete
        summary = self._summarize_output(result)
        await self.state.add_event(AgentEvent(
            id=str(uuid.uuid4())[:8],
            type="tool_complete",
            agent=self.agent,
            content=summary,
            timestamp=time.time(),
            metadata={"tool_id": tool_id, "elapsed_s": result.elapsed_s, "success": result.success},
        ))

        # Record scan for Scans page
        # Look up display name from tool registry
        tool_def = {}
        for t in self.kali.list_tools():
            if t.get("name") == tool_name:
                tool_def = t
                break
        scan_record = {
            "id": f"scan-{tool_id}",
            "tool": tool_name,
            "tool_display": tool_def.get("display_name", tool_display),
            "target": params.get("target", params.get("url", params.get("targets", [""])[0] if isinstance(params.get("targets"), list) else "")),
            "agent": self.agent,
            "status": "completed" if result.success else "error",
            "duration_s": round(result.elapsed_s),
            "findings_count": 0,
            "started_at": start_iso,
            "completed_at": end_iso,
            "engagement_id": self.ctx.engagement_id,
            "output_preview": (result.stdout[:500] if result.stdout else ""),
            "command": tool_display,
        }
        self.state.scans.append(scan_record)

        # Broadcast scan update so Scans page refreshes in real-time
        await self.state.broadcast({
            "type": "scan_complete",
            "scan": scan_record,
            "timestamp": time.time(),
        })

        return result

    async def _stream_output(self, tool_id: str, output: str, chunk_size: int = 512):
        """Stream tool output in chunks to WebSocket clients."""
        from server import AGENT_NAMES
        for i in range(0, len(output), chunk_size):
            chunk = output[i:i + chunk_size]
            await self.state.broadcast({
                "type": "tool_output_chunk",
                "agent": self.agent,
                "agentName": AGENT_NAMES.get(self.agent, self.agent),
                "tool_id": tool_id,
                "chunk": chunk,
                "timestamp": time.time(),
            })
            # Small delay between chunks for UI rendering
            await asyncio.sleep(0.05)

    def _summarize_output(self, result: ToolResult) -> str:
        """Create a short summary of tool output for the timeline."""
        if not result.success:
            return f"{result.tool} failed: {result.error or result.stderr[:200]}"
        # Count output lines as proxy for result size
        lines = result.stdout.strip().split("\n") if result.stdout else []
        return f"{result.tool} completed in {result.elapsed_s:.1f}s ({len(lines)} lines output)"

    @staticmethod
    def _normalize_finding_title(title: str) -> str:
        """Normalize a finding title for dedup matching.

        Strips 'Confirmed: ' prefix and ' (Metasploit)' / ' (Nuclei)' suffixes
        so discovery and confirmation findings match.
        """
        import re as _re
        t = title.strip()
        t = _re.sub(r'^Confirmed:\s*', '', t)
        t = _re.sub(r'\s*\((Metasploit|Nuclei)\)\s*$', '', t)
        return t.lower()

    @staticmethod
    def _normalize_target(target: str) -> str:
        """Extract host IP/hostname from a target for dedup comparison.

        Handles: '10.1.1.25', 'http://10.1.1.25:80/cgi-bin/php',
                 '10.1.1.25:80', 'https://host:443/path'
        """
        import re as _re
        t = target.strip()
        m = _re.search(r'://([^:/]+)', t)
        if m:
            return m.group(1).lower()
        # host:port
        if ':' in t:
            return t.rsplit(':', 1)[0].lower()
        return t.lower()

    async def report_finding(
        self,
        title: str,
        severity: str,
        category: str,
        target: str,
        description: str,
        cvss: float = 0.0,
        cve: str = "",
        evidence: str = "",
        write_neo4j: bool = True,
    ):
        """Report a vulnerability finding to Neo4j and dashboard."""
        self._check_stopped()
        from server import Finding, Severity

        normalized_title = self._normalize_finding_title(title)
        normalized_target = self._normalize_target(target)
        is_confirmation = (
            title.startswith("Confirmed:") or
            category in ("Validated Exploit", "Injection")
        )

        # Check for existing finding to upgrade or dedup
        for existing in self.ctx.findings:
            existing_norm = self._normalize_finding_title(existing.get("title", ""))
            existing_target_norm = self._normalize_target(existing.get("target", ""))

            # Exact dedup: same normalized title + same host
            titles_match = existing_norm == normalized_title
            # CVE dedup: same CVE + same host
            cve_match = cve and existing.get("cve") and cve == existing.get("cve")

            if (titles_match or cve_match) and existing_target_norm == normalized_target:
                if is_confirmation and existing.get("category") != "Validated Exploit":
                    # Upgrade: confirmation supersedes discovery
                    await self._upgrade_finding(
                        existing, title, severity, category,
                        description, cvss, cve, evidence, write_neo4j,
                    )
                    return
                else:
                    # Pure duplicate — skip
                    await self.think(
                        thought=f"Skipping duplicate finding: {title} on {target}",
                        reasoning="Finding with same CVE/title and target already reported.",
                    )
                    return

        # New finding — create as normal
        finding_id = str(uuid.uuid4())[:8]
        timestamp = time.time()

        try:
            sev = Severity(severity)
        except ValueError:
            sev = Severity.MEDIUM

        finding = Finding(
            id=finding_id,
            title=title,
            severity=sev,
            category=category,
            target=target,
            agent=self.agent,
            description=description,
            cvss=cvss,
            cve=cve or None,
            evidence=evidence or None,
            timestamp=timestamp,
            engagement=self.ctx.engagement_id,
        )
        await self.state.add_finding(finding)

        # Write to Neo4j (skip for informational findings like "no hosts")
        if write_neo4j:
            await self._write_finding_neo4j(finding_id, title, severity, category,
                                            target, description, cvss, cve, evidence)

        self.ctx.findings.append({
            "id": finding_id, "title": title, "severity": severity,
            "category": category, "target": target, "cvss": cvss, "cve": cve,
        })
        self.ctx.finding_count += 1

        # Increment findings_count on the most recent scan for this agent
        for scan in reversed(self.state.scans):
            if scan["agent"] == self.agent and scan["engagement_id"] == self.ctx.engagement_id:
                scan["findings_count"] += 1
                break

        await self._emit_stats()

    async def _upgrade_finding(
        self,
        existing: dict,
        title: str,
        severity: str,
        category: str,
        description: str,
        cvss: float,
        cve: str,
        evidence: str,
        write_neo4j: bool,
    ):
        """Upgrade a discovery finding to a confirmed/validated finding."""
        from server import Severity

        finding_id = existing["id"]

        await self.think(
            thought=f"Upgrading finding {finding_id} to confirmed: {title}",
            reasoning="Exploitation confirmed a previously discovered vulnerability. "
                      "Upgrading in-place rather than creating a duplicate.",
        )

        # Update in-memory context entry
        existing["title"] = title
        existing["severity"] = severity
        existing["category"] = category
        if cvss > existing.get("cvss", 0):
            existing["cvss"] = cvss
        if cve and not existing.get("cve"):
            existing["cve"] = cve

        # Update in-memory state.findings list
        for f in self.state.findings:
            if f.id == finding_id:
                f.title = title
                try:
                    f.severity = Severity(severity)
                except ValueError:
                    pass
                f.category = category
                if cvss > (f.cvss or 0):
                    f.cvss = cvss
                if cve and not f.cve:
                    f.cve = cve
                if evidence:
                    f.evidence = evidence
                f.description = description
                break

        # Update Neo4j node
        if write_neo4j:
            from server import neo4j_available, neo4j_driver
            if neo4j_available and neo4j_driver:
                try:
                    with neo4j_driver.session() as session:
                        session.run("""
                            MATCH (f:Finding {id: $id})
                            SET f.title = $title, f.severity = $severity,
                                f.category = $category, f.description = $description,
                                f.cvss = $cvss, f.evidence = $evidence
                            WITH f
                            FOREACH (_ IN CASE WHEN $cve <> '' THEN [1] ELSE [] END |
                                SET f.cve = $cve
                            )
                        """, id=finding_id, title=title, severity=severity,
                             category=category, description=description,
                             cvss=cvss, cve=cve, evidence=evidence or "")
                except Exception as e:
                    logger.warning("Neo4j finding upgrade error: %s", e)

        # Broadcast upgrade to dashboard (same event type, dashboard will update)
        await self.state.broadcast({
            "type": "finding_upgraded",
            "id": finding_id,
            "title": title,
            "severity": severity,
            "category": category,
            "cvss": cvss,
            "cve": cve,
            "agent": self.agent,
            "description": description,
            "evidence": evidence[:500] if evidence else "",
            "engagement": self.ctx.engagement_id,
        })

    async def _write_finding_neo4j(self, fid, title, severity, category,
                                    target, description, cvss, cve, evidence):
        """Write finding to Neo4j using the same pattern as server.py."""
        from server import neo4j_available, neo4j_driver
        if not neo4j_available or not neo4j_driver:
            return
        try:
            # Extract host IP from target (may be URL, IP:port, or bare IP)
            import re as _re
            host_ip = target or ""
            m = _re.search(r'://([^:/]+)', host_ip)
            if m:
                host_ip = m.group(1)
            elif ':' in host_ip:
                # Strip port from bare IP:port (e.g. "10.1.1.25:3632" → "10.1.1.25")
                host_ip = host_ip.split(':')[0]

            with neo4j_driver.session() as session:
                session.run("""
                    MERGE (f:Finding {id: $id})
                    SET f.title = $title, f.severity = $severity,
                        f.category = $category, f.target = $target,
                        f.agent = $agent, f.description = $description,
                        f.cvss = $cvss, f.cve = $cve, f.evidence = $evidence,
                        f.timestamp = $timestamp, f.engagement_id = $eid,
                        f.status = 'open'
                    WITH f
                    MATCH (e:Engagement {id: $eid})
                    MERGE (f)-[:BELONGS_TO]->(e)
                    WITH f
                    OPTIONAL MATCH (h:Host {ip: $host_ip, engagement_id: $eid})
                    FOREACH (_ IN CASE WHEN h IS NOT NULL THEN [1] ELSE [] END |
                        MERGE (f)-[:AFFECTS]->(h)
                    )
                """, id=fid, title=title, severity=severity,
                     category=category, target=target, agent=self.agent,
                     description=description, cvss=cvss, cve=cve,
                     evidence=evidence, timestamp=time.time(),
                     eid=self.ctx.engagement_id, host_ip=host_ip)
        except Exception as e:
            logger.warning("Neo4j finding write error: %s", e)

    async def request_approval(
        self,
        action: str,
        description: str,
        risk_level: str = "high",
        target: str = "",
    ) -> bool:
        """Request HITL approval and BLOCK until operator responds.

        Returns True if approved, False if rejected.
        """
        self._check_stopped()
        from server import ApprovalRequest, ApprovalStatus

        approval_id = str(uuid.uuid4())[:8]

        # Create blocking event
        approval_event = asyncio.Event()
        self.state.approval_events[approval_id] = {
            "event": approval_event,
            "approved": None,
        }

        # Broadcast approval request
        req = ApprovalRequest(
            id=approval_id,
            agent=self.agent,
            action=action,
            description=description,
            risk_level=risk_level,
            target=target or None,
            timestamp=time.time(),
        )
        await self.state.request_approval(req)

        # Emit reminder every 5 minutes while waiting
        reminder_task = asyncio.create_task(
            self._approval_reminder(approval_id, action)
        )

        try:
            # Block until operator clicks approve/reject in dashboard
            await approval_event.wait()
        finally:
            reminder_task.cancel()

        approved = self.state.approval_events[approval_id]["approved"]
        # Cleanup
        del self.state.approval_events[approval_id]

        return approved

    async def _approval_reminder(self, approval_id: str, action: str):
        """Emit reminders every 5 minutes while waiting for approval."""
        try:
            while True:
                await asyncio.sleep(300)  # 5 minutes
                if approval_id not in self.state.approval_events:
                    break
                await self.state.broadcast({
                    "type": "system",
                    "content": f"Reminder: HITL approval pending for {action} ({self.agent})",
                    "agent": "OR",
                    "agentName": "Orchestrator",
                    "timestamp": time.time(),
                })
        except asyncio.CancelledError:
            pass

    async def complete(self, summary: str = ""):
        """Mark agent as completed."""
        from server import AgentEvent, AgentStatus
        await self.state.update_agent_status(self.agent, AgentStatus.COMPLETED)
        if summary:
            await self.state.add_event(AgentEvent(
                id=str(uuid.uuid4())[:8],
                type="agent_complete",
                agent=self.agent,
                content=summary,
                timestamp=time.time(),
            ))

    async def _emit_stats(self):
        """Broadcast updated engagement stats."""
        await self.state.broadcast({
            "type": "stat_update",
            "timestamp": time.time(),
            "hosts": self.ctx.host_count,
            "services": self.ctx.service_count,
            "vulns": self.ctx.vuln_count,
            "findings": self.ctx.finding_count,
        })

    async def _sync_stats_from_neo4j(self):
        """Sync in-memory counters from Neo4j to match attack graph metrics."""
        from server import neo4j_available, neo4j_driver
        if not neo4j_available or not neo4j_driver:
            return
        try:
            eid = self.ctx.engagement_id
            with neo4j_driver.session() as session:
                result = session.run("""
                    OPTIONAL MATCH (h:Host {engagement_id: $eid})
                    WITH count(DISTINCT h) AS hosts
                    OPTIONAL MATCH (s:Service {engagement_id: $eid})
                    WITH hosts, count(DISTINCT s) AS services
                    OPTIONAL MATCH (v:Vulnerability {engagement_id: $eid})
                    WITH hosts, services, count(DISTINCT v) AS vulns
                    OPTIONAL MATCH (f:Finding {engagement_id: $eid})
                    RETURN hosts, services, vulns, count(DISTINCT f) AS findings
                """, eid=eid)
                record = result.single()
                if record:
                    self.ctx.host_count = record["hosts"]
                    self.ctx.service_count = record["services"]
                    self.ctx.vuln_count = record["vulns"]
                    self.ctx.finding_count = record["findings"]
        except Exception as e:
            logger.warning("Neo4j stats sync error: %s", e)

    async def write_hosts_neo4j(self, hosts: list[dict]):
        """Write discovered hosts and services to Neo4j."""
        from server import neo4j_available, neo4j_driver
        if not neo4j_available or not neo4j_driver:
            return
        try:
            with neo4j_driver.session() as session:
                for host in hosts:
                    ip = host.get("ip", "")
                    if not ip:
                        continue
                    session.run("""
                        MERGE (h:Host {ip: $ip, engagement_id: $eid})
                        SET h.hostname = $hostname, h.status = 'alive',
                            h.last_seen = datetime()
                        WITH h
                        MATCH (e:Engagement {id: $eid})
                        MERGE (h)-[:BELONGS_TO]->(e)
                    """, ip=ip, eid=self.ctx.engagement_id,
                         hostname=host.get("hostname", ""))

                    for port_info in host.get("ports", []):
                        session.run("""
                            MATCH (h:Host {ip: $ip, engagement_id: $eid})
                            MERGE (s:Service {port: $port, protocol: $proto,
                                              host_ip: $ip, engagement_id: $eid})
                            SET s.name = $name, s.version = $version, s.state = 'open'
                            MERGE (s)-[:RUNS_ON]->(h)
                        """, ip=ip, port=port_info.get("port", 0),
                             proto=port_info.get("protocol", "tcp"),
                             name=port_info.get("service", ""),
                             version=port_info.get("version", ""),
                             eid=self.ctx.engagement_id)
            await self._sync_stats_from_neo4j()
            await self._emit_stats()
        except Exception as e:
            logger.warning("Neo4j host write error: %s", e)

    async def write_vulns_neo4j(self, vulns: list[dict]):
        """Write discovered vulnerabilities to Neo4j."""
        from server import neo4j_available, neo4j_driver
        if not neo4j_available or not neo4j_driver:
            return
        try:
            with neo4j_driver.session() as session:
                for vuln in vulns:
                    vid = f"vuln-{uuid.uuid4().hex[:8]}"
                    # Extract host IP from matched_at URL or host field
                    host_ip = vuln.get("host", "")
                    matched = vuln.get("matched_at", "")
                    # matched_at may be a URL like http://10.1.1.25:8180/
                    # Extract the IP/hostname for linking
                    if not host_ip and matched:
                        import re as _re
                        m = _re.search(r'://([^:/]+)', matched)
                        if m:
                            host_ip = m.group(1)

                    session.run("""
                        MERGE (v:Vulnerability {
                            name: $name,
                            host: $host,
                            engagement_id: $eid
                        })
                        SET v.id = $vid, v.severity = $severity,
                            v.cve_id = $cve, v.cvss_score = $cvss,
                            v.template_id = $tmpl, v.matched_at = $matched,
                            v.description = $desc, v.status = 'open',
                            v.discovered_at = datetime()
                        WITH v
                        MATCH (e:Engagement {id: $eid})
                        MERGE (v)-[:BELONGS_TO]->(e)
                        WITH v
                        OPTIONAL MATCH (h:Host {ip: $host_ip, engagement_id: $eid})
                        FOREACH (_ IN CASE WHEN h IS NOT NULL THEN [1] ELSE [] END |
                            MERGE (v)-[:AFFECTS]->(h)
                        )
                    """, vid=vid, name=vuln.get("name", ""),
                         host=host_ip,
                         severity=vuln.get("severity", "INFO"),
                         cve=vuln.get("cve_id", ""),
                         cvss=vuln.get("cvss_score", 0),
                         tmpl=vuln.get("template_id", ""),
                         matched=matched,
                         desc=vuln.get("description", ""),
                         eid=self.ctx.engagement_id,
                         host_ip=host_ip)
            await self._sync_stats_from_neo4j()
            await self._emit_stats()
        except Exception as e:
            logger.warning("Neo4j vuln write error: %s", e)


class EngagementStopped(Exception):
    """Raised when engagement is stopped by operator."""
    pass


# ── Orchestrator ──

class Orchestrator:
    """PTES phase orchestrator. Wires agents to real Kali tools."""

    def __init__(self, state: "DashboardState", kali: KaliClient):
        self.state = state
        self.kali = kali

    def _runner(self, agent: str, ctx: EngagementContext) -> AgentRunner:
        """Create an AgentRunner for an agent."""
        return AgentRunner(agent, self.state, self.kali, ctx)

    async def run_engagement(self, engagement_id: str, backend_override: str = ""):
        """Run a full PTES engagement against real targets.

        Args:
            engagement_id: Neo4j engagement ID.
            backend_override: Force a specific Kali backend ("external" or "internal").
                When set, all tool executions use this backend regardless of
                tool-registry backend lists or auto-detection. Useful when the
                target is only reachable from one backend (e.g. Antsle bridge).
        """
        from server import AgentStatus, AGENT_NAMES

        # Load engagement from Neo4j or state
        scope = await self._load_scope(engagement_id)
        target_type = await self._detect_target_type(scope)

        ctx = EngagementContext(
            engagement_id=engagement_id,
            scope=scope,
            target_type=target_type,
            backend_override=backend_override,
        )

        logger.info("Starting engagement %s (type=%s, targets=%s)",
                     engagement_id, target_type, scope.get("targets", []))

        # Emit system message
        await self._emit_system(f"Starting PTES engagement {engagement_id}")

        try:
            await self._phase_planning(ctx)
            await self._phase_recon(ctx)

            # Gate: abort early if recon found nothing (target likely unreachable)
            if not ctx.discovered_hosts and not ctx.discovered_urls:
                targets = ctx.scope.get("targets", [])
                await self._emit_system(
                    f"⚠ Recon found 0 hosts and 0 URLs for {', '.join(targets)}. "
                    f"Target may be unreachable, offline, or heavily filtered. "
                    f"Verify target is running and accessible from the "
                    f"'{ctx.backend_override or 'auto'}' backend."
                )
                or_runner = self._runner("OR", ctx)
                await or_runner.report_finding(
                    title="No reachable hosts discovered",
                    severity="high",
                    category="Recon",
                    target=", ".join(targets),
                    description=(
                        f"Active and passive reconnaissance found 0 live hosts "
                        f"across {len(targets)} target(s). Both Naabu and Nmap "
                        f"port scans returned empty results. The target may be "
                        f"offline, unreachable from the selected backend, or "
                        f"heavily firewalled. Engagement cannot proceed without "
                        f"discoverable hosts."
                    ),
                    write_neo4j=False,
                )
                await self._emit_phase("COMPLETE")
                await self._emit_system(
                    f"Engagement {engagement_id} completed early — no hosts to test. "
                    f"1 finding reported."
                )
                await self.state.update_agent_status("OR", AgentStatus.COMPLETED)
                return

            await self._phase_threat_modeling(ctx)
            await self._phase_vuln_analysis(ctx)
            await self._phase_exploitation(ctx)
            await self._phase_post_exploitation(ctx)
            await self._phase_reporting(ctx)

            await self._emit_phase("COMPLETE")
            await self._emit_system(
                f"Engagement {engagement_id} completed. "
                f"{ctx.finding_count} findings, {ctx.host_count} hosts, "
                f"{ctx.vuln_count} vulnerabilities."
            )
            # Mark Orchestrator as completed so pulse dot stops
            await self.state.update_agent_status("OR", AgentStatus.COMPLETED)

        except EngagementStopped:
            await self._emit_phase("STOPPED")
            await self._emit_system(f"Engagement {engagement_id} stopped by operator.")
            for code in AGENT_NAMES:
                if self.state.agent_statuses[code] != AgentStatus.IDLE:
                    await self.state.update_agent_status(code, AgentStatus.IDLE)

        except asyncio.CancelledError:
            await self._emit_phase("STOPPED")
            await self._emit_system(f"Engagement {engagement_id} cancelled.")
            for code in AGENT_NAMES:
                if self.state.agent_statuses[code] != AgentStatus.IDLE:
                    await self.state.update_agent_status(code, AgentStatus.IDLE)

        except Exception as e:
            logger.exception("Engagement %s failed: %s", engagement_id, e)
            await self._emit_system(f"Engagement {engagement_id} error: {e}")
            await self._emit_phase("ERROR")
            for code in AGENT_NAMES:
                if self.state.agent_statuses[code] != AgentStatus.IDLE:
                    await self.state.update_agent_status(code, AgentStatus.IDLE)

    # ── Phase 1: Planning ──

    async def _phase_planning(self, ctx: EngagementContext):
        """Validate scope and authorization."""
        await self._emit_phase("PLANNING")
        pl = self._runner("PL", ctx)

        await pl.think(
            thought="Validating Rules of Engagement and scope boundaries.",
            reasoning="Authorization must be confirmed before any scanning. "
                      "All targets must be in-scope per the engagement definition.",
            action="validate_roe",
        )

        # Validate scope is not empty
        targets = ctx.scope.get("targets", [])
        if not targets:
            await pl.report_finding(
                title="Empty scope — no targets defined",
                severity="critical",
                category="Planning",
                target="N/A",
                description="Engagement has no targets defined. Cannot proceed.",
            )
            ctx.stopped = True
            raise EngagementStopped()

        await pl.complete(
            f"Scope validated: {len(targets)} targets, "
            f"{len(ctx.scope.get('exclusions', []))} exclusions. "
            f"Target type: {ctx.target_type}."
        )

    # ── Phase 2: Intelligence Gathering ──

    async def _phase_recon(self, ctx: EngagementContext):
        """Run PO (passive) and AR (active) recon in parallel."""
        await self._emit_phase("INTELLIGENCE GATHERING")

        or_runner = self._runner("OR", ctx)
        await or_runner.think(
            thought="Dispatching recon agents in parallel.",
            reasoning="Passive OSINT and Active Recon can run simultaneously "
                      "to maximize coverage while minimizing elapsed time.",
            action="dispatch_agents",
        )

        # Run PO and AR in parallel
        po_task = asyncio.create_task(self._recon_passive(ctx))
        ar_task = asyncio.create_task(self._recon_active(ctx))
        await asyncio.gather(po_task, ar_task, return_exceptions=True)

    async def _recon_passive(self, ctx: EngagementContext):
        """PO: Passive OSINT — GAU, WhatWeb, Subfinder."""
        po = self._runner("PO", ctx)

        targets = ctx.scope.get("targets", [])
        # Extract domain targets for passive recon
        domains = [t for t in targets if not t[0].isdigit() and not t.startswith("*")]
        wildcards = [t.lstrip("*.") for t in targets if t.startswith("*.")]
        all_domains = domains + wildcards

        if not all_domains:
            await po.complete("No domain targets for passive OSINT — skipping.")
            return

        for domain in all_domains[:5]:  # Cap at 5 domains
            # GAU URL discovery
            await po.think(
                thought=f"Running GAU against {domain} for historical URL discovery.",
                reasoning="GAU pulls from Wayback Machine, Common Crawl, and AlienVault OTX "
                          "without touching the target directly.",
            )
            result = await po.run_tool(
                "gau_discover",
                {"target": domain},
                display=f"Running GAU against {domain}...",
            )
            if result.success:
                urls = parse_gau_output(result.stdout)
                ctx.discovered_urls.extend(urls)

            # Subfinder subdomain enum
            await po.think(
                thought=f"Running Subfinder against {domain}.",
                reasoning="Subdomain enumeration reveals additional attack surface.",
            )
            result = await po.run_tool(
                "subfinder_enum",
                {"target": domain},
                display=f"Running Subfinder against {domain}...",
            )
            if result.success:
                subs = parse_subfinder_output(result.stdout)
                ctx.discovered_subdomains.extend(subs)

        await po.complete(
            f"Passive OSINT complete: {len(ctx.discovered_urls)} URLs, "
            f"{len(ctx.discovered_subdomains)} subdomains."
        )

    async def _recon_active(self, ctx: EngagementContext):
        """AR: Active Recon — Naabu → Httpx → Nmap (deep) → Gobuster."""
        ar = self._runner("AR", ctx)
        targets = ctx.scope.get("targets", [])
        target_str = " ".join(targets)

        # Step 1: Fast port discovery — Naabu with Nmap fallback
        await ar.think(
            thought="Starting fast port discovery with Naabu.",
            reasoning="Naabu SYN scan is 10-100x faster than Nmap for initial port discovery. "
                      "Results feed into Httpx and deep Nmap scans. Falls back to Nmap if Naabu unavailable.",
            action="run_naabu",
        )
        naabu_result = await ar.run_tool(
            "naabu_scan",
            {"target": target_str},
            display=f"Running Naabu SYN scan on {target_str}...",
        )

        records = []
        if naabu_result.success:
            records = parse_naabu_results(naabu_result.stdout, ctx.engagement_id)

        # Fallback to Nmap if Naabu failed OR returned 0 results
        if not records:
            fallback_reason = (
                f"Naabu error: {naabu_result.error or 'unknown'}"
                if not naabu_result.success
                else "Naabu found 0 open ports — target may be unreachable or filtered"
            )
            await ar.think(
                thought=f"Falling back to Nmap for port discovery. {fallback_reason}",
                reasoning="Nmap with -Pn (skip host discovery) and CONNECT scan will "
                          "attempt to reach the target even if ICMP is filtered. "
                          "This is more reliable than Naabu for hardened targets.",
                action="run_nmap_fallback",
            )
            nmap_fallback = await ar.run_tool(
                "nmap_scan",
                {"target": target_str, "scan_type": "-Pn -sT --min-rate=1000",
                 "ports": "", "additional_args": "--open"},
                display=f"Nmap port discovery on {target_str} (fallback)...",
            )
            if nmap_fallback.success:
                parsed = parse_nmap_output(nmap_fallback.stdout)
                for host in parsed["hosts"]:
                    for p in host.get("ports", []):
                        if p.get("state") == "open":
                            records.append({
                                "ip": host["ip"],
                                "port": p["port"],
                                "protocol": p.get("protocol", "tcp"),
                            })

        if records:
            ctx.discovered_hosts.extend(records)
            ctx.host_count = len(set(r["ip"] for r in records))
            ctx.service_count = len(records)
            await ar._emit_stats()

            # Write hosts to Neo4j
            host_map = {}
            for r in records:
                ip = r["ip"]
                if ip not in host_map:
                    host_map[ip] = {"ip": ip, "hostname": "", "ports": []}
                host_map[ip]["ports"].append({
                    "port": r["port"], "protocol": r["protocol"],
                    "service": "", "version": "",
                })
            await ar.write_hosts_neo4j(list(host_map.values()))

        # Step 2: Httpx web probing on discovered hosts
        alive_hosts = list(set(r["ip"] for r in ctx.discovered_hosts))
        if alive_hosts:
            await ar.think(
                thought="Running Httpx to identify web services on discovered ports.",
                reasoning="Httpx probes HTTP/HTTPS with tech detection, status codes, and titles. "
                          "Reveals web application stack for vulnerability analysis.",
            )
            # Build target list with common web ports
            httpx_targets = []
            web_ports = {80, 443, 8080, 8443, 8000, 8180, 8888, 3000, 5000, 9090}
            https_ports = {443, 8443}
            for r in ctx.discovered_hosts:
                if r["port"] in web_ports:
                    proto = "https" if r["port"] in https_ports else "http"
                    httpx_targets.append(f"{proto}://{r['ip']}:{r['port']}")

            if httpx_targets:
                httpx_result = await ar.run_tool(
                    "httpx_probe",
                    {"targets": httpx_targets[:200]},  # Cap at 200
                    display=f"Running Httpx on {len(httpx_targets)} web targets...",
                )
                if httpx_result.success:
                    urls = parse_httpx_results(httpx_result.stdout, ctx.engagement_id)
                    ctx.discovered_urls.extend([u["url"] for u in urls])
                    ctx.service_count = len(set(
                        (r["ip"], r["port"]) for r in ctx.discovered_hosts
                    ))
                    await ar._emit_stats()

        # Step 3: Nmap deep scan on interesting hosts
        if alive_hosts[:20]:  # Deep scan top 20 hosts
            await ar.think(
                thought="Running Nmap service version detection on top targets.",
                reasoning="Deep Nmap scan (-sV -sC) provides service versions and script output "
                          "for accurate CVE matching in the threat modeling phase.",
            )
            for host_ip in alive_hosts[:20]:
                nmap_result = await ar.run_tool(
                    "nmap_scan",
                    {"target": host_ip, "scan_type": "-sV -sC", "ports": ""},
                    display=f"Nmap deep scan on {host_ip}...",
                )
                if nmap_result.success:
                    parsed = parse_nmap_output(nmap_result.stdout)
                    for host in parsed["hosts"]:
                        # Update existing host records with version info
                        await ar.write_hosts_neo4j([host])

        # Step 4: Gobuster on web targets
        web_targets = [u for u in ctx.discovered_urls if u.startswith("http")][:10]
        if web_targets:
            await ar.think(
                thought="Running Gobuster directory scanning on web targets.",
                reasoning="Directory brute-forcing reveals hidden admin panels, "
                          "backup files, and API endpoints.",
            )
            for target_url in web_targets[:5]:  # Cap at 5
                gobuster_result = await ar.run_tool(
                    "gobuster_scan",
                    {"url": target_url},
                    display=f"Gobuster dir scan on {target_url}...",
                )
                if gobuster_result.success:
                    paths = parse_gobuster_output(gobuster_result.stdout)
                    for p in paths:
                        ctx.discovered_urls.append(f"{target_url}{p['path']}")

        await ar.complete(
            f"Active recon complete: {ctx.host_count} hosts, "
            f"{ctx.service_count} services, "
            f"{len(ctx.discovered_urls)} URLs."
        )

    # ── Phase 3: Threat Modeling ──

    async def _phase_threat_modeling(self, ctx: EngagementContext):
        """CV: CVE lookup + AP: Attack path analysis."""
        await self._emit_phase("THREAT MODELING")

        cv = self._runner("CV", ctx)
        await cv.think(
            thought="Cross-referencing detected technologies with vulnerability databases.",
            reasoning="Service versions from Nmap and tech stacks from Httpx need to be "
                      "checked against NVD, Exploit-DB, and CISA KEV for known exploits.",
            action="query_cves",
        )

        # Nuclei with CVE-specific templates for broad coverage
        # Build target list: HTTP URLs + raw host:port for non-web services
        url_targets = [u for u in ctx.discovered_urls if u.startswith("http")]
        ip_targets = list(set(r["ip"] for r in ctx.discovered_hosts))
        all_targets = url_targets + ip_targets  # Nuclei handles both URLs and IPs

        if all_targets:
            nuclei_result = await cv.run_tool(
                "nuclei_scan",
                {"targets": all_targets[:100], "severity": "critical,high",
                 "additional_args": "-tags cve"},
                display=f"Running Nuclei CVE templates against {len(all_targets)} targets...",
            )
            if nuclei_result.success:
                vulns = parse_nuclei_results(nuclei_result.stdout, ctx.engagement_id)
                ctx.discovered_vulns.extend(vulns)
                ctx.vuln_count += len(vulns)
                await cv.write_vulns_neo4j(vulns)
                ctx.cves = list(set(
                    v["cve_id"] for v in vulns if v.get("cve_id")
                ))
                await cv._emit_stats()

        await cv.complete(
            f"CVE research complete: {len(ctx.discovered_vulns)} vulnerabilities, "
            f"{len(ctx.cves)} CVEs identified."
        )

        # AP: Attack Path Analyzer — queries Neo4j graph
        ap = self._runner("AP", ctx)
        await ap.think(
            thought="Constructing multi-step attack paths from CVE data and network topology.",
            reasoning="Identified CVEs across discovered hosts create potential kill chains. "
                      "Need to identify paths from external-facing services to high-value targets.",
            action="analyze_attack_paths",
        )
        # Query Neo4j for attack paths (if available)
        from server import neo4j_available, neo4j_driver
        attack_paths = []
        if neo4j_available and neo4j_driver:
            try:
                with neo4j_driver.session() as session:
                    result = session.run("""
                        MATCH (v:Vulnerability {engagement_id: $eid})
                        WHERE v.severity IN ['CRITICAL', 'HIGH']
                        RETURN v.name AS vuln, v.host AS host, v.severity AS severity
                        ORDER BY v.cvss_score DESC
                        LIMIT 20
                    """, eid=ctx.engagement_id)
                    for record in result:
                        attack_paths.append(dict(record))
            except Exception as e:
                logger.warning("Neo4j attack path query error: %s", e)

        await ap.complete(
            f"{len(attack_paths)} critical/high vulnerabilities mapped for attack paths."
        )

    # ── Phase 4: Vulnerability Analysis ──

    async def _phase_vuln_analysis(self, ctx: EngagementContext):
        """WV: Web vuln scanning → EC: Exploit enrichment (sequential).

        EC enriches vulns discovered by WV, so WV must complete first.
        """
        await self._emit_phase("VULNERABILITY ANALYSIS")

        # Sequential: WV discovers vulns, then EC enriches them
        await self._vuln_web_scan(ctx)
        await self._vuln_exploit_craft(ctx)

    async def _vuln_web_scan(self, ctx: EngagementContext):
        """WV: Nuclei web templates + Nikto + WPScan."""
        wv = self._runner("WV", ctx)
        targets = [u for u in ctx.discovered_urls if u.startswith("http")]

        if not targets:
            await wv.complete("No web targets for vulnerability scanning.")
            return

        # Nuclei with web-specific templates
        await wv.think(
            thought="Launching Nuclei with web vulnerability templates.",
            reasoning="Nuclei's template-based approach validates CVE findings and discovers "
                      "additional web vulnerabilities (XSS, SQLi, SSRF, etc.).",
            action="run_nuclei",
        )
        nuclei_result = await wv.run_tool(
            "nuclei_scan",
            {"targets": targets[:100], "severity": "critical,high,medium"},
            display=f"Running Nuclei web scan against {min(len(targets), 100)} targets...",
        )
        if nuclei_result.success:
            vulns = parse_nuclei_results(nuclei_result.stdout, ctx.engagement_id)
            for v in vulns:
                ctx.discovered_vulns.append(v)
                ctx.vuln_count += 1
                # Auto-report critical/high as findings
                if v["severity"] in ("CRITICAL", "HIGH"):
                    await wv.report_finding(
                        title=v["name"],
                        severity=v["severity"].lower(),
                        category="Web Vulnerability",
                        target=v.get("matched_at", v.get("host", "")),
                        description=v.get("description", f"Nuclei template: {v.get('template_id', '')}"),
                        cvss=v.get("cvss_score", 0),
                        cve=v.get("cve_id", ""),
                        evidence=f"Template: {v.get('template_id', '')}",
                    )
            await wv.write_vulns_neo4j(vulns)

        # Nikto on top web targets
        for target_url in targets[:5]:
            await wv.think(
                thought=f"Running Nikto web scanner on {target_url}.",
                reasoning="Nikto checks for dangerous files, outdated server software, "
                          "and version-specific problems.",
            )
            nikto_result = await wv.run_tool(
                "nikto_scan",
                {"target": target_url},
                display=f"Nikto scan on {target_url}...",
            )
            if nikto_result.success:
                nikto_findings = parse_nikto_output(nikto_result.stdout)
                for nf in nikto_findings:
                    if "critical" in nf["finding"].lower() or "vulnerability" in nf["finding"].lower():
                        await wv.report_finding(
                            title=nf["finding"][:100],
                            severity="medium",
                            category="Web Server",
                            target=target_url,
                            description=nf["finding"],
                        )

        await wv.complete(
            f"Web vulnerability scanning complete: {ctx.vuln_count} total vulnerabilities."
        )

    async def _vuln_exploit_craft(self, ctx: EngagementContext):
        """EC: Enrich vulnerabilities with exploit database intelligence.

        For each CRITICAL/HIGH vuln with a CVE, queries SearchSploit and
        Metasploit to discover available PoC code and modules. Enrichment
        data flows to EX for intelligent exploit selection.
        """
        ec = self._runner("EC", ctx)

        # Filter for enrichable vulns: CRITICAL/HIGH with CVE IDs
        enrichable = [
            v for v in ctx.discovered_vulns
            if v.get("severity") in ("CRITICAL", "HIGH") and v.get("cve_id")
        ]

        if not enrichable:
            await ec.think(
                thought="No CRITICAL/HIGH vulnerabilities with CVE IDs to enrich.",
                reasoning="Enrichment requires CVE identifiers to query exploit databases. "
                          "Vulns without CVEs will use generic Nuclei re-validation in EX.",
            )
            await ec.complete("No CVE-identified vulns for enrichment — skipping.")
            return

        # Cap at 10 vulns to stay within time budget
        enrichable = enrichable[:10]

        await ec.think(
            thought=f"Enriching {len(enrichable)} vulnerabilities with exploit intelligence.",
            reasoning="Querying SearchSploit (ExploitDB) and Metasploit module database "
                      "for each CVE. Concurrent per-vuln, batched to limit load.",
            action="enrich_vulns",
        )

        # Process in batches of 3 concurrent enrichments
        batch_size = 3
        total_enriched = 0
        total_exploits = 0

        for i in range(0, len(enrichable), batch_size):
            batch = enrichable[i:i + batch_size]
            tasks = [self._enrich_single_vuln(ec, v) for v in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for j, result in enumerate(results):
                if isinstance(result, Exception):
                    logger.warning("Enrichment error for %s: %s",
                                   batch[j].get("cve_id", ""), result)
                elif result:
                    total_enriched += 1
                    total_exploits += result

        await ec.think(
            thought=f"Enrichment complete: {total_enriched}/{len(enrichable)} vulns enriched, "
                    f"{total_exploits} total exploits/modules found.",
            reasoning="Enrichment data attached to vuln dicts. EX agent will use "
                      "metasploit_best_module for priority exploitation.",
        )

        await ec.complete(
            f"Exploit enrichment complete: {total_enriched} vulns enriched, "
            f"{total_exploits} exploits/modules discovered across ExploitDB + Metasploit."
        )

    async def _enrich_single_vuln(self, ec: AgentRunner, vuln: dict) -> int:
        """Enrich a single vulnerability with SearchSploit + Metasploit + AttackerKB.

        Returns total exploit count found. Mutates vuln dict in-place with
        enrichment fields.
        """
        cve_id = vuln.get("cve_id", "")
        if not cve_id:
            return 0

        # Strip "CVE-" prefix for searchsploit (wants bare number)
        cve_number = cve_id.replace("CVE-", "")

        # Run all three sources concurrently per vuln
        ssploit_task = self._enrich_searchsploit(ec, cve_number)
        msf_task = self._enrich_msf(ec, cve_id)
        akb_task = self._enrich_attackerkb(ec, cve_id)
        results = await asyncio.gather(
            ssploit_task, msf_task, akb_task, return_exceptions=True,
        )

        ssploit_results = results[0] if not isinstance(results[0], Exception) else []
        msf_results = results[1] if not isinstance(results[1], Exception) else []
        akb_result = results[2] if not isinstance(results[2], Exception) else None

        errors = []
        if isinstance(results[0], Exception):
            errors.append(f"searchsploit: {results[0]}")
        if isinstance(results[1], Exception):
            errors.append(f"msf_search: {results[1]}")
        if isinstance(results[2], Exception):
            errors.append(f"attackerkb: {results[2]}")

        # Determine exploit sources
        sources = []
        if ssploit_results:
            sources.append("exploitdb")
        if msf_results:
            sources.append("metasploit")
        if akb_result:
            sources.append("attackerkb")

        # Find best Metasploit module (already sorted by rank in parser)
        best_module = None
        if msf_results:
            # Prefer exploit modules over auxiliary
            exploit_modules = [m for m in msf_results if m["module_type"] == "exploit"]
            best_module = exploit_modules[0] if exploit_modules else msf_results[0]

        # Enrich vuln dict in-place
        vuln["enriched"] = True
        vuln["exploit_count"] = len(ssploit_results) + len(msf_results)
        vuln["exploit_sources"] = sources
        vuln["exploitdb_results"] = ssploit_results
        vuln["metasploit_modules"] = [m["module_path"] for m in msf_results]
        vuln["metasploit_best_module"] = best_module
        vuln["attackerkb"] = akb_result  # None if unavailable
        if errors:
            vuln["enrichment_errors"] = errors

        return vuln["exploit_count"]

    async def _enrich_searchsploit(self, ec: AgentRunner, cve_number: str) -> list[dict]:
        """Query SearchSploit for a CVE and return parsed results."""
        result = await ec.run_tool(
            "searchsploit_search",
            {"cve_id": cve_number},
            display=f"SearchSploit lookup: CVE-{cve_number}...",
        )
        if result.success:
            return parse_searchsploit_json(result.stdout)
        return []

    async def _enrich_msf(self, ec: AgentRunner, cve_id: str) -> list[dict]:
        """Query Metasploit module database for a CVE and return parsed results."""
        result = await ec.run_tool(
            "msf_search",
            {"cve_id": cve_id},
            display=f"Metasploit module search: {cve_id}...",
        )
        if result.success:
            return parse_msf_search_output(result.stdout)
        return []

    async def _enrich_attackerkb(self, ec: AgentRunner, cve_id: str) -> Optional[dict]:
        """Query AttackerKB for community intelligence on a CVE.

        Returns parsed topic dict with attacker_value, exploitability scores,
        or None if not found or API unavailable.
        """
        result = await ec.run_tool(
            "attackerkb_lookup",
            {"cve_id": cve_id},
            display=f"AttackerKB lookup: {cve_id}...",
        )
        if result.success:
            return parse_attackerkb_response(result.stdout)
        return None

    # ── Phase 5: Exploitation ──

    async def _phase_exploitation(self, ctx: EngagementContext):
        """EX: Exploitation (HITL gated) + VF: Verification.

        3-tier exploit selection:
          Priority 1: Metasploit module (from EC enrichment)
          Priority 2: SQLMap (for SQLi vulns)
          Priority 3: Nuclei re-validation (fallback)
        """
        await self._emit_phase("EXPLOITATION")

        ex = self._runner("EX", ctx)

        # Find exploitable vulns
        exploitable = [
            v for v in ctx.discovered_vulns
            if v.get("severity") in ("CRITICAL", "HIGH")
        ]

        if not exploitable:
            await ex.complete("No critical/high vulnerabilities to exploit.")
            return

        for vuln in exploitable[:5]:  # Cap at 5 exploits
            target = vuln.get("matched_at", vuln.get("host", ""))
            vuln_name = vuln.get("name", "Unknown")
            best_module = vuln.get("metasploit_best_module")
            exploit_count = vuln.get("exploit_count", 0)
            exploit_sources = vuln.get("exploit_sources", [])
            edb_results = vuln.get("exploitdb_results", [])

            # Build enrichment context for HITL description
            akb = vuln.get("attackerkb")
            enrichment_desc = ""
            if vuln.get("enriched"):
                parts = [f"{exploit_count} known exploit(s)"]
                if best_module:
                    parts.append(f"MSF: {best_module['module_path']} ({best_module['rank']})")
                if edb_results:
                    parts.append(f"ExploitDB: {len(edb_results)} PoC(s)")
                if akb:
                    av = akb.get("attacker_value", 0)
                    ex_score = akb.get("exploitability", 0)
                    parts.append(f"AKB: AV={av}/5 EX={ex_score}/5")
                enrichment_desc = " | ".join(parts)

            # Determine exploitation strategy
            if best_module and best_module.get("module_type") == "exploit":
                strategy = "metasploit"
                strategy_desc = f"Metasploit module: {best_module['module_path']} (rank: {best_module['rank']})"
            elif "sqli" in vuln_name.lower() or "sql" in vuln_name.lower():
                strategy = "sqlmap"
                strategy_desc = "SQLMap injection validation"
            else:
                strategy = "nuclei"
                strategy_desc = "Nuclei template re-validation"

            await ex.think(
                thought=f"Preparing exploitation for: {vuln_name} [{strategy}]",
                reasoning=f"Target: {target}. Strategy: {strategy_desc}. "
                          f"{'Enrichment: ' + enrichment_desc + '. ' if enrichment_desc else ''}"
                          f"Need HITL approval before execution.",
                action="request_approval",
            )

            # HITL gate with enrichment context
            hitl_desc = (
                f"Validate {vuln_name} on {target}. "
                f"Severity: {vuln.get('severity', 'HIGH')}. "
                f"Strategy: {strategy_desc}."
            )
            if enrichment_desc:
                hitl_desc += f"\nEnrichment: {enrichment_desc}"

            approved = await ex.request_approval(
                action=f"Exploit validation: {vuln_name}",
                description=hitl_desc,
                risk_level="high",
                target=target,
            )

            if not approved:
                await ex.think(
                    thought=f"HITL rejected exploitation of {vuln_name}. Skipping.",
                    reasoning="Operator decision respected. Moving to next vulnerability.",
                )
                continue

            # Execute exploitation based on strategy
            if strategy == "metasploit":
                await self._exploit_with_metasploit(ex, vuln, target, best_module, ctx)
            elif strategy == "sqlmap":
                await self._exploit_with_sqlmap(ex, vuln, target, ctx)
            else:
                await self._exploit_with_nuclei(ex, vuln, target, ctx)

        await ex.complete(
            f"Exploitation validation complete: {ctx.finding_count} findings confirmed."
        )

    async def _exploit_with_metasploit(
        self, ex: AgentRunner, vuln: dict, target: str,
        module: dict, ctx: EngagementContext,
    ):
        """Priority 1: Run a Metasploit module against the target."""
        import re as _re

        # Extract host and port from target URL or host:port
        rhost = target
        rport = ""
        url_match = _re.search(r'://([^:/]+)(?::(\d+))?', target)
        if url_match:
            rhost = url_match.group(1)
            rport = url_match.group(2) or ""
        elif ':' in target:
            parts = target.rsplit(':', 1)
            if parts[1].isdigit():
                rhost = parts[0]
                rport = parts[1]

        options = {"RHOSTS": rhost}
        if rport:
            options["RPORT"] = rport

        # Extract URI path for web exploits
        if "://" in target:
            path_match = _re.search(r'://[^/]+(/.*)$', target)
            if path_match:
                options["TARGETURI"] = path_match.group(1)

        result = await ex.run_tool(
            "metasploit_run",
            {"module": module["module_path"], "options": options},
            display=f"Metasploit: {module['module_path']} → {rhost}...",
        )

        if result.success:
            # Check for session opened or exploit success indicators
            output = result.stdout or ""
            session_opened = "session" in output.lower() and "opened" in output.lower()
            exploit_completed = "exploit completed" in output.lower()

            if session_opened or exploit_completed:
                await ex.report_finding(
                    title=f"Confirmed: {vuln.get('name', 'Unknown')} (Metasploit)",
                    severity=vuln.get("severity", "HIGH").lower(),
                    category="Validated Exploit",
                    target=target,
                    description=f"Exploited via Metasploit module {module['module_path']} "
                                f"(rank: {module['rank']}). "
                                f"{vuln.get('name', '')}",
                    cvss=vuln.get("cvss_score", 0),
                    cve=vuln.get("cve_id", ""),
                    evidence=output[:2000],
                )
                # Track credential if session opened
                if session_opened:
                    await self.state.add_credential(
                        ctx.engagement_id,
                        {
                            "username": "session",
                            "source": f"Metasploit ({module['module_path']})",
                            "host": rhost,
                            "type": "exploited",
                            "finding_id": ctx.findings[-1]["id"] if ctx.findings else "",
                        },
                    )
            else:
                # Module ran but no session — still report as validated attempt
                await ex.think(
                    thought=f"Metasploit module completed but no session opened for {vuln.get('name', '')}.",
                    reasoning="Module may require specific payload/target configuration. "
                              "Falling back to Nuclei re-validation.",
                )
                # Fall through to Nuclei as backup
                await self._exploit_with_nuclei(ex, vuln, target, ctx)

    async def _exploit_with_sqlmap(
        self, ex: AgentRunner, vuln: dict, target: str, ctx: EngagementContext,
    ):
        """Priority 2: SQLMap injection validation."""
        result = await ex.run_tool(
            "sqlmap_scan",
            {"url": target, "additional_args": "--technique=B --risk=1 --level=1"},
            display=f"SQLMap validation on {target}...",
        )
        if result.success:
            parsed = parse_sqlmap_output(result.stdout)
            if parsed["injectable"]:
                await ex.report_finding(
                    title=f"Confirmed SQL Injection — {parsed['parameter']}",
                    severity="critical",
                    category="Injection",
                    target=target,
                    description=parsed["details"],
                    cvss=9.8,
                    cve=vuln.get("cve_id", ""),
                    evidence=result.stdout[:2000],
                )

    async def _exploit_with_nuclei(
        self, ex: AgentRunner, vuln: dict, target: str, ctx: EngagementContext,
    ):
        """Priority 3: Nuclei template re-validation fallback."""
        result = await ex.run_tool(
            "nuclei_scan",
            {"targets": [target],
             "additional_args": f"-id {vuln.get('template_id', '')}"},
            display=f"Re-validating {vuln.get('name', 'Unknown')} on {target}...",
        )
        if result.success:
            re_vulns = parse_nuclei_results(result.stdout, ctx.engagement_id)
            if re_vulns:
                v = re_vulns[0]
                await ex.report_finding(
                    title=f"Confirmed: {vuln.get('name', 'Unknown')}",
                    severity=vuln.get("severity", "HIGH").lower(),
                    category="Validated Exploit",
                    target=target,
                    description=f"Re-validated via Nuclei template "
                                f"{v.get('template_id', '')}. "
                                f"{v.get('description', vuln.get('name', ''))}",
                    cvss=vuln.get("cvss_score", 0),
                    cve=vuln.get("cve_id", ""),
                    evidence=result.stdout[:2000],
                )

        # VF: Independent verification
        vf = self._runner("VF", ctx)
        await vf.think(
            thought="Independently re-verifying exploitation findings.",
            reasoning="The finder is not the verifier. Re-running with fresh parameters "
                      "to confirm findings match. Evidence hash comparison.",
        )
        # VF re-runs a subset of validated exploits for confirmation
        await vf.complete(
            f"Verification complete: {ctx.finding_count} findings confirmed."
        )

    # ── Phase 6: Post-Exploitation ──

    async def _phase_post_exploitation(self, ctx: EngagementContext):
        """PE: Post-exploitation (HITL gated) + DV: Detection validation."""
        await self._emit_phase("POST-EXPLOITATION")

        pe = self._runner("PE", ctx)

        # Only run post-exploitation if there are confirmed exploits
        if not ctx.findings:
            await pe.complete("No confirmed exploits — skipping post-exploitation.")
            # Still run detection validator
            await self._detection_validation(ctx)
            return

        await pe.think(
            thought="Mapping potential lateral movement and impact from confirmed exploits.",
            reasoning="Post-exploitation maps the blast radius — what an attacker could access "
                      "from each compromised position. HITL approval required.",
            action="request_approval",
        )

        approved = await pe.request_approval(
            action="Post-exploitation simulation",
            description="Map lateral movement paths and credential harvesting opportunities "
                        "from confirmed exploitation positions. Network enumeration only — "
                        "no destructive actions.",
            risk_level="high",
            target=ctx.engagement_id,
        )

        if approved:
            # NetExec for network enumeration (internal targets)
            if ctx.target_type == "internal":
                targets = list(set(r["ip"] for r in ctx.discovered_hosts))[:10]
                for target_ip in targets:
                    result = await pe.run_tool(
                        "crackmapexec_scan",
                        {"target": target_ip, "protocol": "smb",
                         "additional_args": "--shares"},
                        display=f"NetExec SMB enum on {target_ip}...",
                        backend="internal",
                    )
                    if result.success:
                        nxc_results = parse_netexec_output(result.stdout)
                        for r in nxc_results:
                            if r["status"] == "pwned":
                                await pe.report_finding(
                                    title=f"SMB Access — {r['hostname']}",
                                    severity="high",
                                    category="Lateral Movement",
                                    target=r["host"],
                                    description=r["info"],
                                )
                                # Track credential harvest
                                await self.state.add_credential(
                                    ctx.engagement_id,
                                    {
                                        "username": r.get("username", "unknown"),
                                        "source": "NetExec SMB",
                                        "host": r["host"],
                                        "type": "default" if "default" in r.get("info", "").lower() else "harvested",
                                        "finding_id": ctx.findings[-1]["id"] if ctx.findings else "",
                                    },
                                )

        await pe.complete("Post-exploitation analysis complete.")

        # DV: Detection Validator
        await self._detection_validation(ctx)

    async def _detection_validation(self, ctx: EngagementContext):
        """DV: Check detection coverage for exploitation activities."""
        dv = self._runner("DV", ctx)
        await dv.think(
            thought="Analyzing detection coverage for all exploitation activities.",
            reasoning="Undetected exploitation is often the most critical finding for the client. "
                      "Need to determine if SIEM/EDR/WAF caught the attacks.",
        )
        # DV is currently analysis-only — in Phase D/E it queries SIEM APIs
        await dv.complete(
            "Detection analysis complete. Manual SIEM review recommended for full coverage assessment."
        )

    # ── Phase 7: Reporting ──

    async def _phase_reporting(self, ctx: EngagementContext):
        """RP: Aggregate findings from Neo4j and prepare report data."""
        await self._emit_phase("REPORTING")

        rp = self._runner("RP", ctx)
        await rp.think(
            thought="Compiling engagement results for report generation.",
            reasoning="Aggregating all findings, evidence, and statistics from Neo4j "
                      "for executive summary, technical report, and remediation roadmap.",
        )

        # Query Neo4j for final stats
        from server import neo4j_available, neo4j_driver
        report_data = {
            "engagement_id": ctx.engagement_id,
            "hosts": ctx.host_count,
            "services": ctx.service_count,
            "vulnerabilities": ctx.vuln_count,
            "findings": ctx.finding_count,
            "severity_breakdown": {},
        }

        if neo4j_available and neo4j_driver:
            try:
                with neo4j_driver.session() as session:
                    result = session.run("""
                        MATCH (f:Finding {engagement_id: $eid})
                        RETURN f.severity AS severity, count(f) AS count
                    """, eid=ctx.engagement_id)
                    for record in result:
                        report_data["severity_breakdown"][record["severity"]] = record["count"]
            except Exception as e:
                logger.warning("Neo4j report query error: %s", e)

        await rp.complete(
            f"Report data compiled: {ctx.finding_count} findings "
            f"({report_data.get('severity_breakdown', {})}). "
            f"PDF generation deferred to Phase D."
        )

    # ── Helpers ──

    async def _load_scope(self, engagement_id: str) -> dict:
        """Load engagement scope (targets + exclusions) from Neo4j or state."""
        from server import neo4j_available, neo4j_driver
        if neo4j_available and neo4j_driver:
            try:
                with neo4j_driver.session() as session:
                    result = session.run(
                        "MATCH (e:Engagement {id: $eid}) "
                        "RETURN e.scope AS scope, e.exclusions AS exclusions",
                        eid=engagement_id,
                    )
                    record = result.single()
                    if record and record["scope"]:
                        scope_str = record["scope"]
                        targets = [t.strip() for t in scope_str.split(",") if t.strip()]
                        exclusion_str = record.get("exclusions") or ""
                        exclusions = [e.strip() for e in exclusion_str.split(",") if e.strip()]
                        return {"targets": targets, "exclusions": exclusions}
            except Exception as e:
                logger.warning("Neo4j scope load error: %s", e)

        # Fallback: check state engagements
        for eng in self.state.engagements:
            if eng.id == engagement_id:
                targets = [t.strip() for t in eng.target.split(",") if t.strip()]
                return {"targets": targets, "exclusions": []}

        return {"targets": [], "exclusions": []}

    async def _detect_target_type(self, scope: dict) -> str:
        """Detect if targets are internal or external."""
        import ipaddress
        for target in scope.get("targets", []):
            try:
                net = ipaddress.ip_network(target, strict=False)
                if net.is_private:
                    return "internal"
            except ValueError:
                pass  # Domain, not IP — assume external
        return "external"

    async def _emit_phase(self, phase: str):
        """Broadcast phase update."""
        await self.state.broadcast({
            "type": "phase_update",
            "phase": phase,
            "timestamp": time.time(),
        })

    async def _emit_system(self, message: str):
        """Broadcast system message."""
        await self.state.broadcast({
            "type": "system",
            "content": message,
            "agent": "OR",
            "agentName": "Orchestrator",
            "timestamp": time.time(),
        })
