"""ATHENA Real-Time Multi-Agent Message Bus.

In-memory pub/sub with per-agent asyncio queues for real-time
inter-agent intelligence sharing during penetration test engagements.
"""

from __future__ import annotations

import asyncio
import collections
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine
from uuid import uuid4

logger = logging.getLogger(__name__)


@dataclass
class BusMessage:
    """A message on the agent communication bus."""
    from_agent: str
    to: str                    # "ALL" for broadcast, or agent code for direct
    bus_type: str              # finding | request | directive | status | escalation
    priority: str              # low | medium | high | critical
    summary: str
    target: str | None = None
    data: dict = field(default_factory=dict)
    action_needed: str | None = None
    id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "from_agent": self.from_agent,
            "to": self.to,
            "bus_type": self.bus_type,
            "priority": self.priority,
            "summary": self.summary,
            "target": self.target,
            "data": self.data,
            "action_needed": self.action_needed,
            "timestamp": self.timestamp,
        }


# Priority ordering for sorting (higher = more important)
_PRIORITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


class MessageBus:
    """In-memory message bus for real-time agent coordination.

    Each registered agent gets an asyncio.Queue. broadcast() enqueues
    to all agents except the sender. send() enqueues to a specific agent.
    drain() non-blockingly empties an agent's queue.
    """

    def __init__(self, engagement_id: str):
        self.engagement_id = engagement_id
        self._queues: dict[str, asyncio.Queue] = {}
        self._history: collections.deque[BusMessage] = collections.deque(maxlen=1000)
        self._callbacks: list[Callable[[BusMessage], Coroutine]] = []

    def register(self, agent_code: str) -> None:
        """Create a message queue for an agent."""
        if agent_code not in self._queues:
            self._queues[agent_code] = asyncio.Queue()
            logger.info("Bus: registered agent %s (engagement %s)",
                        agent_code, self.engagement_id)

    def unregister(self, agent_code: str) -> None:
        """Remove an agent's queue."""
        self._queues.pop(agent_code, None)
        logger.info("Bus: unregistered agent %s", agent_code)

    async def broadcast(self, msg: BusMessage) -> None:
        """Send message to all registered agents except the sender."""
        self._history.append(msg)
        for code, q in self._queues.items():
            if code != msg.from_agent:
                await q.put(msg)
        # Fire callbacks via create_task (fire-and-forget)
        for cb in self._callbacks:
            asyncio.create_task(cb(msg))
        logger.debug("Bus: broadcast from %s -> %d agents: %s",
                      msg.from_agent, len(self._queues) - 1, msg.summary[:80])

    async def send(self, msg: BusMessage) -> None:
        """Send message to a specific agent."""
        self._history.append(msg)
        q = self._queues.get(msg.to)
        if q:
            await q.put(msg)
        for cb in self._callbacks:
            asyncio.create_task(cb(msg))
        logger.debug("Bus: direct %s -> %s: %s",
                      msg.from_agent, msg.to, msg.summary[:80])

    async def drain(self, agent_code: str) -> list[BusMessage]:
        """Non-blocking drain of all pending messages for an agent.

        Fully empties the queue. Messages not included in the injection
        (due to cap) are discarded -- by the next turn, they are stale.
        """
        q = self._queues.get(agent_code)
        if not q:
            return []
        msgs = []
        while not q.empty():
            try:
                msgs.append(q.get_nowait())
            except asyncio.QueueEmpty:
                break
        return msgs

    def get_history(self, limit: int = 50) -> list[BusMessage]:
        """Get recent bus history (most recent last)."""
        items = list(self._history)
        return items[-limit:] if len(items) > limit else items

    def on_message(self, callback: Callable[[BusMessage], Coroutine]) -> None:
        """Register an async callback fired on every message.

        Deduplicates by identity -- calling on_message(same_fn) twice is a no-op.
        """
        if callback not in self._callbacks:
            self._callbacks.append(callback)


# ── Finding Extraction Patterns ──────────────────────────────

# Port patterns (nmap, naabu, etc.)
_PORT_RE = re.compile(
    r'(\d{1,5})/(?:tcp|udp)\s+open\s+(\S+)', re.IGNORECASE)
_NAABU_PORT_RE = re.compile(
    r'(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})')

# CVE pattern
_CVE_RE = re.compile(r'(CVE-\d{4}-\d{4,7})', re.IGNORECASE)

# IP/subnet patterns
_SUBNET_RE = re.compile(
    r'(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})')
_IP_RE = re.compile(
    r'(\d{1,3}(?:\.\d{1,3}){3})')

# Service/version patterns
_SERVICE_RE = re.compile(
    r'(Apache|Nginx|Tomcat|IIS|OpenSSH|MySQL|PostgreSQL|Redis|MongoDB'
    r'|Elasticsearch|Jenkins|GitLab|WordPress|Drupal|Joomla'
    r'|vsftpd|ProFTPD|Exim|Postfix|Dovecot|Samba)'
    r'[/\s]*([\d.]+)?',
    re.IGNORECASE)

# Credential indicators
_CRED_KEYWORDS = (
    "valid credentials", "password found", "login successful",
    "authenticated successfully", "creds found", "default credentials",
    "admin:admin", "root:root", "credential",
)

# Shell/exploitation indicators
_SHELL_KEYWORDS = (
    "shell access", "reverse shell", "gained shell", "command execution",
    "remote code execution", "rce confirmed", "meterpreter",
    "shell obtained", "got shell",
)

# Vulnerability indicators
_VULN_KEYWORDS = (
    "sql injection", "sqli confirmed", "xss confirmed",
    "ssrf confirmed", "lfi confirmed", "rfi confirmed",
    "command injection", "path traversal", "file inclusion",
    "[critical]", "[high]", "vulnerability confirmed",
    "exploitable", "vuln found",
)

# Scan completion indicators
_SCAN_DONE_KEYWORDS = (
    "scan complete", "nmap done", "scanning complete",
    "finished scanning", "scan finished",
)

# Noise -- don't extract from these
_NOISE_KEYWORDS = (
    "starting scan", "initializing", "loading",
    "connecting to", "establishing",
)


def extract_findings(
    agent_code: str, tool_name: str, tool_result: str
) -> list[BusMessage]:
    """Parse tool output for actionable intel. Returns 0+ messages.

    Best-effort extraction -- missing something is acceptable.
    False positives are preferable to false negatives.
    """
    if not tool_result or len(tool_result) < 20:
        return []

    output = tool_result[:8000]  # Cap to prevent regex on huge outputs
    output_lower = output.lower()
    findings: list[BusMessage] = []

    # Check for noise-only output
    if all(kw in output_lower for kw in ("starting", "done")) and len(output) < 100:
        return []

    # 1. Shell/exploitation (highest priority)
    if any(kw in output_lower for kw in _SHELL_KEYWORDS):
        target = None
        ip_match = _IP_RE.search(output)
        if ip_match:
            target = ip_match.group(1)
        findings.append(BusMessage(
            from_agent=agent_code, to="ALL",
            bus_type="escalation", priority="critical",
            summary=f"Shell/RCE obtained: {output[:200]}",
            target=target,
            data={"tool": tool_name, "raw_output": output[:2000]},
            action_needed="Verify persistence, check for lateral movement paths",
        ))

    # 2. Credentials (critical)
    if any(kw in output_lower for kw in _CRED_KEYWORDS):
        findings.append(BusMessage(
            from_agent=agent_code, to="ALL",
            bus_type="finding", priority="critical",
            summary=f"Credentials discovered: {output[:200]}",
            target=None,
            data={"tool": tool_name, "raw_output": output[:2000]},
            action_needed="Try credentials against all discovered services",
        ))

    # 3. CVEs (high)
    cve_matches = _CVE_RE.findall(output)
    if cve_matches:
        cves = list(set(cve_matches))[:5]  # Dedupe, cap at 5
        findings.append(BusMessage(
            from_agent=agent_code, to="ALL",
            bus_type="finding", priority="high",
            summary=f"CVE(s) identified: {', '.join(cves)}",
            data={"cves": cves, "tool": tool_name, "raw_output": output[:2000]},
            action_needed=f"Research and attempt exploitation of {', '.join(cves)}",
        ))

    # 4. Open ports (high)
    ports = _PORT_RE.findall(output)
    naabu_ports = _NAABU_PORT_RE.findall(output)
    if ports:
        port_list = [(p, s) for p, s in ports][:10]
        port_str = ", ".join(f"{p}/{s}" for p, s in port_list)
        findings.append(BusMessage(
            from_agent=agent_code, to="ALL",
            bus_type="finding", priority="high",
            summary=f"Open ports: {port_str}",
            data={"ports": [{"port": p, "service": s} for p, s in port_list],
                  "tool": tool_name},
            action_needed="Fingerprint services and check for known vulnerabilities",
        ))
    elif naabu_ports and not ports:
        port_str = ", ".join(f"{ip}:{p}" for ip, p in naabu_ports[:10])
        findings.append(BusMessage(
            from_agent=agent_code, to="ALL",
            bus_type="finding", priority="high",
            summary=f"Open ports: {port_str}",
            data={"ports": [{"host": ip, "port": p} for ip, p in naabu_ports[:10]],
                  "tool": tool_name},
        ))

    # 5. Vulnerabilities (high)
    if any(kw in output_lower for kw in _VULN_KEYWORDS) and not any(
        f.bus_type in ("escalation",) or "CVE" in f.summary for f in findings
    ):
        # Don't double-report if already captured as CVE or shell, but DO report alongside ports
        findings.append(BusMessage(
            from_agent=agent_code, to="ALL",
            bus_type="finding", priority="high",
            summary=f"Vulnerability confirmed: {output[:200]}",
            data={"tool": tool_name, "raw_output": output[:2000]},
        ))

    # 6. Service/version identification (medium)
    svc_matches = _SERVICE_RE.findall(output)
    if svc_matches and not any(f.priority in ("critical", "high") and "port" not in f.summary.lower() for f in findings):
        services = [f"{s} {v}".strip() for s, v in svc_matches[:5]]
        ip_match = _IP_RE.search(output)
        target = ip_match.group(1) if ip_match else None
        findings.append(BusMessage(
            from_agent=agent_code, to="ALL",
            bus_type="finding", priority="medium",
            summary=f"Service identified: {', '.join(services)}",
            target=target,
            data={"services": services, "tool": tool_name},
            action_needed="Check for known CVEs and misconfigurations",
        ))

    # 7. New subnet/network (escalation)
    subnets = _SUBNET_RE.findall(output)
    if subnets and any(kw in output_lower for kw in ("internal", "discovered", "subnet", "network")):
        findings.append(BusMessage(
            from_agent=agent_code, to="ALL",
            bus_type="escalation", priority="high",
            summary=f"New network discovered: {', '.join(subnets[:3])}",
            data={"subnets": subnets[:3], "tool": tool_name},
            action_needed="Enumerate internal hosts, escalate to ST for pivot decision",
        ))

    # 8. Scan completion (low -- status only)
    if any(kw in output_lower for kw in _SCAN_DONE_KEYWORDS) and not findings:
        findings.append(BusMessage(
            from_agent=agent_code, to="ALL",
            bus_type="status", priority="low",
            summary=f"Scan complete: {tool_name.split('__')[-1] if '__' in tool_name else tool_name}",
            data={"tool": tool_name},
        ))

    return findings


# ── Context Injection Formatting ──────────────────────────────

_MAX_INJECTION_MESSAGES = 20


def format_intel_update(
    messages: list[BusMessage], agent_code: str
) -> str:
    """Format drained bus messages into a prompt injection block.

    Returns empty string if no messages. Sorts by priority (critical
    first), caps at 20 messages, formats directives separately.
    """
    if not messages:
        return ""

    # Separate directives from findings
    directives = [m for m in messages if m.bus_type == "directive"]
    others = [m for m in messages if m.bus_type != "directive"]

    # Sort non-directives by priority (critical first), then recency
    others.sort(
        key=lambda m: (-_PRIORITY_ORDER.get(m.priority, 0), -m.timestamp))

    # Cap at max messages (always keep critical/high, drop low first)
    if len(others) > _MAX_INJECTION_MESSAGES:
        others = others[:_MAX_INJECTION_MESSAGES]

    parts = []

    # Format directives first (highest priority)
    for d in directives:
        parts.append(
            f"═══ STRATEGIC DIRECTIVE from {d.from_agent} ═══\n"
            f"Priority: {d.priority.upper()}\n"
            f"\"{d.summary}\"\n"
            f"═══ END DIRECTIVE ═══"
        )

    # Format findings/status/requests/escalations
    if others:
        parts.append(
            f"═══ INTELLIGENCE UPDATE ({len(others)} new message"
            f"{'s' if len(others) != 1 else ''}) ═══\n")
        now = time.time()
        for m in others:
            age = int(now - m.timestamp)
            age_str = f"{age}s ago" if age < 60 else f"{age // 60}m ago"
            target_str = f" on {m.target}" if m.target else ""
            dest = f" -> {m.to}" if m.to != "ALL" else " -> ALL"

            line = f"[{m.priority.upper()}] from {m.from_agent}{dest} ({age_str})\n"
            line += f"  {m.summary}{target_str}\n"
            if m.action_needed:
                line += f"  Action needed: {m.action_needed}\n"
            parts.append(line)

        parts.append("═══ END INTELLIGENCE UPDATE ═══")

    return "\n".join(parts)
