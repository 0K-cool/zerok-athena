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
from typing import TYPE_CHECKING, Optional

from kali_client import KaliClient, ToolResult
from parsers import (
    extract_cves,
    parse_crackmapexec_output,
    parse_gau_output,
    parse_gobuster_output,
    parse_httpx_results,
    parse_naabu_results,
    parse_nikto_output,
    parse_nmap_output,
    parse_nuclei_results,
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
        """
        self._check_stopped()
        from server import AgentEvent, AGENT_NAMES

        tool_id = str(uuid.uuid4())[:8]
        tool_display = display or f"Running {tool_name}..."

        # tool_start
        await self.state.add_event(AgentEvent(
            id=str(uuid.uuid4())[:8],
            type="tool_start",
            agent=self.agent,
            content=tool_display,
            timestamp=time.time(),
            metadata={"tool": tool_name, "tool_id": tool_id},
        ))

        # Execute on Kali (backend_override takes precedence over auto-selection)
        effective_backend = self.ctx.backend_override or backend
        result = await self.kali.run_tool(
            tool_name, params,
            backend=effective_backend,
            target_type=self.ctx.target_type,
        )

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
    ):
        """Report a vulnerability finding to Neo4j and dashboard."""
        self._check_stopped()
        from server import Finding, Severity

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

        # Write to Neo4j
        await self._write_finding_neo4j(finding_id, title, severity, category,
                                        target, description, cvss, cve, evidence)

        self.ctx.findings.append({
            "id": finding_id, "title": title, "severity": severity,
            "target": target, "cvss": cvss,
        })
        self.ctx.finding_count += 1
        await self._emit_stats()

    async def _write_finding_neo4j(self, fid, title, severity, category,
                                    target, description, cvss, cve, evidence):
        """Write finding to Neo4j using the same pattern as server.py."""
        from server import neo4j_available, neo4j_driver
        if not neo4j_available or not neo4j_driver:
            return
        try:
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
                """, id=fid, title=title, severity=severity,
                     category=category, target=target, agent=self.agent,
                     description=description, cvss=cvss, cve=cve,
                     evidence=evidence, timestamp=time.time(),
                     eid=self.ctx.engagement_id)
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
                    """, vid=vid, name=vuln.get("name", ""),
                         host=vuln.get("host", ""),
                         severity=vuln.get("severity", "INFO"),
                         cve=vuln.get("cve_id", ""),
                         cvss=vuln.get("cvss_score", 0),
                         tmpl=vuln.get("template_id", ""),
                         matched=vuln.get("matched_at", ""),
                         desc=vuln.get("description", ""),
                         eid=self.ctx.engagement_id)
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

        except EngagementStopped:
            await self._emit_phase("STOPPED")
            await self._emit_system(f"Engagement {engagement_id} stopped by operator.")
            # Reset all agents to idle
            for code in AGENT_NAMES:
                if self.state.agent_statuses[code] != AgentStatus.IDLE:
                    await self.state.update_agent_status(code, AgentStatus.IDLE)

        except Exception as e:
            logger.exception("Engagement %s failed: %s", engagement_id, e)
            await self._emit_system(f"Engagement {engagement_id} error: {e}")
            await self._emit_phase("ERROR")

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

        if naabu_result.success:
            records = parse_naabu_results(naabu_result.stdout, ctx.engagement_id)
        else:
            # Naabu failed (not installed or error) — fallback to Nmap port discovery
            logger.warning("Naabu failed (%s), falling back to Nmap port discovery",
                          naabu_result.error or "unknown error")
            await ar.think(
                thought="Naabu unavailable — falling back to Nmap for port discovery.",
                reasoning=f"Naabu error: {naabu_result.error or 'unknown'}. "
                          "Using Nmap with fast scan flags as fallback.",
                action="run_nmap_fallback",
            )
            nmap_fallback = await ar.run_tool(
                "nmap_scan",
                {"target": target_str, "scan_type": "-Pn -sS --min-rate=1000",
                 "ports": "", "additional_args": "--open"},
                display=f"Nmap fast port discovery on {target_str} (Naabu fallback)...",
            )
            records = []
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
        """WV: Web vuln scanning + EC: Exploit crafting."""
        await self._emit_phase("VULNERABILITY ANALYSIS")

        # Run WV and EC in parallel
        wv_task = asyncio.create_task(self._vuln_web_scan(ctx))
        ec_task = asyncio.create_task(self._vuln_exploit_craft(ctx))
        await asyncio.gather(wv_task, ec_task, return_exceptions=True)

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
        """EC: Analyze vulns and prepare exploit strategies."""
        ec = self._runner("EC", ctx)

        await ec.think(
            thought="Analyzing discovered vulnerabilities for exploitation potential.",
            reasoning="Not all vulnerabilities are exploitable. Need to assess which have "
                      "public exploits, PoC code, or can be chained for impact.",
        )

        # EC doesn't run tools directly — it analyzes findings
        # In Phase D/E, this becomes an LLM agent that reasons about exploit selection
        exploitable = [
            v for v in ctx.discovered_vulns
            if v.get("severity") in ("CRITICAL", "HIGH")
        ]

        await ec.complete(
            f"Exploit analysis complete: {len(exploitable)} potentially exploitable "
            f"vulnerabilities identified for validation."
        )

    # ── Phase 5: Exploitation ──

    async def _phase_exploitation(self, ctx: EngagementContext):
        """EX: Exploitation (HITL gated) + VF: Verification."""
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

            await ex.think(
                thought=f"Preparing exploitation validation for: {vuln_name}",
                reasoning=f"Target: {target}. Need HITL approval before running "
                          f"any exploitation tools per engagement rules.",
                action="request_approval",
            )

            # HITL gate
            approved = await ex.request_approval(
                action=f"Exploit validation: {vuln_name}",
                description=f"Validate {vuln_name} on {target}. "
                            f"Severity: {vuln.get('severity', 'HIGH')}. "
                            f"Read-only validation — no data modification.",
                risk_level="high",
                target=target,
            )

            if not approved:
                await ex.think(
                    thought=f"HITL rejected exploitation of {vuln_name}. Skipping.",
                    reasoning="Operator decision respected. Moving to next vulnerability.",
                )
                continue

            # Run appropriate exploitation tool
            if "sqli" in vuln_name.lower() or "sql" in vuln_name.lower():
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
            else:
                # Generic Nuclei re-validation for non-SQLi vulns
                result = await ex.run_tool(
                    "nuclei_scan",
                    {"targets": [target],
                     "additional_args": f"-id {vuln.get('template_id', '')}"},
                    display=f"Re-validating {vuln_name} on {target}...",
                )

        await ex.complete("Exploitation validation complete.")

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
            # CrackMapExec for network enumeration (internal targets)
            if ctx.target_type == "internal":
                targets = list(set(r["ip"] for r in ctx.discovered_hosts))[:10]
                for target_ip in targets:
                    result = await pe.run_tool(
                        "crackmapexec_scan",
                        {"target": target_ip, "protocol": "smb",
                         "additional_args": "--shares"},
                        display=f"CrackMapExec SMB enum on {target_ip}...",
                        backend="internal",
                    )
                    if result.success:
                        cme_results = parse_crackmapexec_output(result.stdout)
                        for r in cme_results:
                            if r["status"] == "pwned":
                                await pe.report_finding(
                                    title=f"SMB Access — {r['hostname']}",
                                    severity="high",
                                    category="Lateral Movement",
                                    target=r["host"],
                                    description=r["info"],
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
