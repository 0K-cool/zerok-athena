# Real-Time Multi-Agent Communication Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add real-time inter-agent intelligence sharing to ATHENA so agents coordinate like a pentest team — sharing findings, acting on each other's intel, and receiving strategic directives from ST.

**Architecture:** In-memory MessageBus with per-agent asyncio queues, auto-extraction of findings from tool results, injection of intel updates at chunk boundaries in the engagement loop, and SDK-native `publish_finding`/`send_directive` tools for explicit agent communication.

**Tech Stack:** Python 3.11+, asyncio, Claude Agent SDK, FastAPI WebSocket, Neo4j/Graphiti, Langfuse

**Spec:** `docs/plans/2026-03-11-real-time-agent-communication-design.md`

**Deadline:** Weekend (March 15-16, 2026)

---

## File Structure

| File | Action | Responsibility |
|------|--------|----------------|
| `tools/athena-dashboard/message_bus.py` | **CREATE** | MessageBus, BusMessage, Finding Extractor, Context Injector |
| `tools/athena-dashboard/sdk_agent.py` | MODIFY | Bus integration: extraction after tool results, injection at chunk boundary, tool handlers |
| `tools/athena-dashboard/agent_session_manager.py` | MODIFY | Bus lifecycle (register/unregister), simplified heartbeat fallback, pass bus to sessions |
| `tools/athena-dashboard/agent_configs.py` | MODIFY | Add real-time intel prompt sections to all agent prompts |
| `tools/athena-dashboard/server.py` | MODIFY | WebSocket callback wiring for `agent_intel` events |
| `tools/athena-dashboard/tests/test_message_bus.py` | **CREATE** | Unit tests for MessageBus, Finding Extractor, Context Injector |
| `tools/athena-dashboard/tests/test_bus_integration.py` | **CREATE** | Integration tests for bus + session manager + SDK agent |

---

## Chunk 1: MessageBus Core + Tests

### Task 1: BusMessage dataclass and MessageBus class

**Files:**
- Create: `tools/athena-dashboard/message_bus.py`
- Create: `tools/athena-dashboard/tests/test_message_bus.py`

- [ ] **Step 1: Write failing tests for BusMessage and MessageBus**

```python
# tests/test_message_bus.py
import asyncio
import pytest
from message_bus import BusMessage, MessageBus


def _make_msg(from_agent="AR", to="ALL", bus_type="finding",
              priority="high", summary="test finding"):
    return BusMessage(
        from_agent=from_agent, to=to, bus_type=bus_type,
        priority=priority, summary=summary, target="10.0.0.1:80",
        data={}, action_needed=None,
    )


class TestBusMessage:
    def test_create_message(self):
        msg = _make_msg()
        assert msg.from_agent == "AR"
        assert msg.to == "ALL"
        assert msg.bus_type == "finding"
        assert msg.id  # auto-generated uuid
        assert msg.timestamp > 0  # auto-generated

    def test_to_dict(self):
        msg = _make_msg()
        d = msg.to_dict()
        assert d["from_agent"] == "AR"
        assert d["bus_type"] == "finding"
        assert isinstance(d["timestamp"], float)


class TestMessageBus:
    @pytest.fixture
    def bus(self):
        return MessageBus(engagement_id="test-eid-001")

    @pytest.mark.asyncio
    async def test_register_and_unregister(self, bus):
        bus.register("AR")
        assert "AR" in bus._queues
        bus.unregister("AR")
        assert "AR" not in bus._queues

    @pytest.mark.asyncio
    async def test_broadcast_excludes_sender(self, bus):
        bus.register("AR")
        bus.register("WV")
        bus.register("EX")
        msg = _make_msg(from_agent="AR")
        await bus.broadcast(msg)
        # AR should NOT receive its own message
        ar_msgs = await bus.drain("AR")
        assert len(ar_msgs) == 0
        # WV and EX should receive it
        wv_msgs = await bus.drain("WV")
        assert len(wv_msgs) == 1
        assert wv_msgs[0].from_agent == "AR"
        ex_msgs = await bus.drain("EX")
        assert len(ex_msgs) == 1

    @pytest.mark.asyncio
    async def test_send_direct(self, bus):
        bus.register("AR")
        bus.register("WV")
        bus.register("EX")
        msg = _make_msg(from_agent="AR", to="WV")
        await bus.send(msg)
        # Only WV gets it
        wv_msgs = await bus.drain("WV")
        assert len(wv_msgs) == 1
        ex_msgs = await bus.drain("EX")
        assert len(ex_msgs) == 0

    @pytest.mark.asyncio
    async def test_drain_empties_queue(self, bus):
        bus.register("WV")
        msg = _make_msg(from_agent="AR")
        # Manually put in WV's queue (simulating broadcast)
        await bus._queues["WV"].put(msg)
        msgs = await bus.drain("WV")
        assert len(msgs) == 1
        # Second drain should be empty
        msgs2 = await bus.drain("WV")
        assert len(msgs2) == 0

    @pytest.mark.asyncio
    async def test_history_bounded(self, bus):
        bus.register("WV")
        # Broadcast more than maxlen messages
        for i in range(1100):
            msg = _make_msg(summary=f"finding {i}")
            bus._history.append(msg)
        assert len(bus._history) == 1000  # deque maxlen

    @pytest.mark.asyncio
    async def test_get_history(self, bus):
        bus.register("WV")
        for i in range(5):
            msg = _make_msg(summary=f"finding {i}")
            bus._history.append(msg)
        hist = bus.get_history(limit=3)
        assert len(hist) == 3

    @pytest.mark.asyncio
    async def test_on_message_callback(self, bus):
        bus.register("WV")
        received = []

        async def callback(msg):
            received.append(msg)

        bus.on_message(callback)
        msg = _make_msg(from_agent="AR")
        await bus.broadcast(msg)
        # Let event loop process the create_task
        await asyncio.sleep(0.05)
        assert len(received) == 1
        assert received[0].from_agent == "AR"

    @pytest.mark.asyncio
    async def test_broadcast_to_unregistered_agent_no_error(self, bus):
        """Sending to no registered agents should not raise."""
        msg = _make_msg()
        await bus.broadcast(msg)  # No agents registered, should be fine

    @pytest.mark.asyncio
    async def test_engagement_id_stored(self, bus):
        assert bus.engagement_id == "test-eid-001"
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-dashboard
.venv/bin/python -m pytest tests/test_message_bus.py -v
```

Expected: FAIL with `ModuleNotFoundError: No module named 'message_bus'`

- [ ] **Step 3: Implement MessageBus and BusMessage**

```python
# message_bus.py
"""ATHENA Real-Time Multi-Agent Message Bus.

In-memory pub/sub with per-agent asyncio queues for real-time
inter-agent intelligence sharing during penetration test engagements.
"""

from __future__ import annotations

import asyncio
import collections
import logging
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
        logger.debug("Bus: broadcast from %s → %d agents: %s",
                      msg.from_agent, len(self._queues) - 1, msg.summary[:80])

    async def send(self, msg: BusMessage) -> None:
        """Send message to a specific agent."""
        self._history.append(msg)
        q = self._queues.get(msg.to)
        if q:
            await q.put(msg)
        for cb in self._callbacks:
            asyncio.create_task(cb(msg))
        logger.debug("Bus: direct %s → %s: %s",
                      msg.from_agent, msg.to, msg.summary[:80])

    async def drain(self, agent_code: str) -> list[BusMessage]:
        """Non-blocking drain of all pending messages for an agent.

        Fully empties the queue. Messages not included in the injection
        (due to cap) are discarded — by the next turn, they are stale.
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

        Deduplicates by identity — calling on_message(same_fn) twice is a no-op.
        """
        if callback not in self._callbacks:
            self._callbacks.append(callback)
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-dashboard
.venv/bin/python -m pytest tests/test_message_bus.py -v
```

Expected: All 11 tests PASS

- [ ] **Step 5: Commit**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-dashboard
git add message_bus.py tests/test_message_bus.py
git commit -m "feat: add MessageBus core with per-agent queues and broadcast/direct messaging"
```

---

### Task 2: Finding Extractor

**Files:**
- Modify: `tools/athena-dashboard/message_bus.py`
- Modify: `tools/athena-dashboard/tests/test_message_bus.py`

- [ ] **Step 1: Write failing tests for extract_findings**

Add to `tests/test_message_bus.py`:

```python
from message_bus import extract_findings


class TestFindingExtractor:
    def test_extract_open_ports_nmap(self):
        output = """Starting Nmap 7.94
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8443/tcp open  https-alt
Nmap done: 1 IP address (1 host up)"""
        msgs = extract_findings("AR", "mcp__kali_external__nmap_scan", output)
        assert len(msgs) >= 1
        assert any("open" in m.summary.lower() or "port" in m.summary.lower() for m in msgs)
        assert msgs[0].from_agent == "AR"
        assert msgs[0].bus_type == "finding"
        assert msgs[0].priority in ("high", "medium")

    def test_extract_service_version(self):
        output = "Apache/2.4.52 (Ubuntu) running on 10.0.0.5:80"
        msgs = extract_findings("WV", "mcp__kali_external__httpx_scan", output)
        assert len(msgs) >= 1
        assert any("apache" in m.summary.lower() or "service" in m.summary.lower() for m in msgs)

    def test_extract_cve(self):
        output = "CVE-2024-50623 affects Cleo Harmony versions before 5.8.0.21"
        msgs = extract_findings("WV", "Bash", output)
        assert len(msgs) >= 1
        assert msgs[0].priority == "high"
        assert "CVE-2024-50623" in msgs[0].summary

    def test_extract_credential(self):
        output = "Valid credentials found: admin:password123 on SSH port 22"
        msgs = extract_findings("EX", "Bash", output)
        assert len(msgs) >= 1
        assert msgs[0].priority == "critical"
        assert msgs[0].bus_type == "finding"

    def test_extract_shell(self):
        output = "Gained shell access on 10.0.0.5 via reverse shell on port 4444"
        msgs = extract_findings("EX", "Bash", output)
        assert len(msgs) >= 1
        assert msgs[0].bus_type == "escalation"
        assert msgs[0].priority == "critical"

    def test_extract_sql_injection(self):
        output = "[CRITICAL] SQL Injection confirmed at /api/login parameter 'username'"
        msgs = extract_findings("WV", "mcp__kali_external__nuclei_scan", output)
        assert len(msgs) >= 1
        assert msgs[0].priority in ("high", "critical")

    def test_no_findings_in_noise(self):
        output = "Starting scan...\nInitializing...\nDone."
        msgs = extract_findings("AR", "Bash", output)
        assert len(msgs) == 0

    def test_extract_new_subnet(self):
        output = "Discovered internal network 192.168.1.0/24 via ARP scan"
        msgs = extract_findings("AR", "Bash", output)
        assert len(msgs) >= 1
        assert msgs[0].bus_type == "escalation"
        assert msgs[0].priority == "high"
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-dashboard
.venv/bin/python -m pytest tests/test_message_bus.py::TestFindingExtractor -v
```

Expected: FAIL with `ImportError: cannot import name 'extract_findings'`

- [ ] **Step 3: Implement extract_findings in message_bus.py**

Add to `message_bus.py`:

```python
import re

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

# Noise — don't extract from these
_NOISE_KEYWORDS = (
    "starting scan", "initializing", "loading",
    "connecting to", "establishing",
)


def extract_findings(
    agent_code: str, tool_name: str, tool_result: str
) -> list[BusMessage]:
    """Parse tool output for actionable intel. Returns 0+ messages.

    Best-effort extraction — missing something is acceptable.
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
    if svc_matches and not any(f.priority in ("critical", "high") for f in findings):
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

    # 8. Scan completion (low — status only)
    if any(kw in output_lower for kw in _SCAN_DONE_KEYWORDS) and not findings:
        findings.append(BusMessage(
            from_agent=agent_code, to="ALL",
            bus_type="status", priority="low",
            summary=f"Scan complete: {tool_name.split('__')[-1] if '__' in tool_name else tool_name}",
            data={"tool": tool_name},
        ))

    return findings
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-dashboard
.venv/bin/python -m pytest tests/test_message_bus.py::TestFindingExtractor -v
```

Expected: All 8 tests PASS

- [ ] **Step 5: Commit**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-dashboard
git add message_bus.py tests/test_message_bus.py
git commit -m "feat: add Finding Extractor with regex-based intel extraction from tool outputs"
```

---

### Task 3: Context Injector (format_intel_update)

**Files:**
- Modify: `tools/athena-dashboard/message_bus.py`
- Modify: `tools/athena-dashboard/tests/test_message_bus.py`

- [ ] **Step 1: Write failing tests for format_intel_update**

Add to `tests/test_message_bus.py`:

```python
from message_bus import format_intel_update


class TestContextInjector:
    def test_format_empty_inbox(self):
        result = format_intel_update([], "WV")
        assert result == ""

    def test_format_single_finding(self):
        msgs = [_make_msg(from_agent="AR", summary="Open port 22/ssh on 10.0.0.5")]
        result = format_intel_update(msgs, "WV")
        assert "INTELLIGENCE UPDATE" in result
        assert "AR" in result
        assert "Open port 22/ssh" in result
        assert "END INTELLIGENCE UPDATE" in result

    def test_format_sorts_by_priority(self):
        msgs = [
            _make_msg(priority="low", summary="scan done"),
            _make_msg(priority="critical", summary="shell obtained"),
            _make_msg(priority="medium", summary="service found"),
        ]
        result = format_intel_update(msgs, "WV")
        # Critical should appear before low
        crit_pos = result.index("CRITICAL")
        low_pos = result.index("LOW")
        assert crit_pos < low_pos

    def test_format_caps_at_20(self):
        msgs = [_make_msg(summary=f"finding {i}") for i in range(25)]
        result = format_intel_update(msgs, "WV")
        # Should only contain 20 entries
        assert result.count("[HIGH]") <= 20

    def test_st_gets_strategic_overview(self):
        msgs = [_make_msg(summary="port found")]
        result = format_intel_update(msgs, "ST")
        assert "INTELLIGENCE UPDATE" in result
        # ST format includes the message

    def test_directive_format(self):
        msgs = [BusMessage(
            from_agent="ST", to="ALL", bus_type="directive",
            priority="urgent",
            summary="Pivot to internal network immediately",
            action_needed="Pivot to internal network immediately",
        )]
        result = format_intel_update(msgs, "WV")
        assert "STRATEGIC DIRECTIVE" in result
        assert "URGENT" in result
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-dashboard
.venv/bin/python -m pytest tests/test_message_bus.py::TestContextInjector -v
```

Expected: FAIL with `ImportError: cannot import name 'format_intel_update'`

- [ ] **Step 3: Implement format_intel_update**

Add to `message_bus.py`:

```python
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
            dest = f" → {m.to}" if m.to != "ALL" else " → ALL"

            line = f"[{m.priority.upper()}] from {m.from_agent}{dest} ({age_str})\n"
            line += f"  {m.summary}{target_str}\n"
            if m.action_needed:
                line += f"  Action needed: {m.action_needed}\n"
            parts.append(line)

        parts.append("═══ END INTELLIGENCE UPDATE ═══")

    return "\n".join(parts)
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-dashboard
.venv/bin/python -m pytest tests/test_message_bus.py::TestContextInjector -v
```

Expected: All 6 tests PASS

- [ ] **Step 5: Run ALL message_bus tests**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-dashboard
.venv/bin/python -m pytest tests/test_message_bus.py -v
```

Expected: All 25 tests PASS (11 + 8 + 6)

- [ ] **Step 6: Commit**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-dashboard
git add message_bus.py tests/test_message_bus.py
git commit -m "feat: add Context Injector for formatting bus messages as prompt injection blocks"
```

---

## Chunk 2: SDK Agent Integration

### Task 4: Integrate bus into AthenaAgentSession

**Files:**
- Modify: `tools/athena-dashboard/sdk_agent.py`
  - `__init__()` (line 346–395): Add `_bus` field and `_pending_injection` buffer
  - `create_for_role()` (line 417–443): Accept bus parameter
  - `_handle_user_message()` (line 1472–1517): Add finding extraction after tool results
  - `_engagement_loop()` (line 1101–1166): Inject bus intel into prompt at chunk boundary

- [ ] **Step 1: Add bus field to AthenaAgentSession.__init__**

In `sdk_agent.py`, after line 395 (end of `__init__`), add:

```python
        # Real-time message bus for inter-agent communication
        self._bus: Any = None  # Set via create_for_role() or set_bus()
        self._pending_injection: str = ""  # Accumulated intel for next prompt
```

- [ ] **Step 2: Update create_for_role() to accept bus**

In `sdk_agent.py`, modify `create_for_role()` at line 417. Add `bus` parameter:

Change the method signature from:
```python
    @classmethod
    def create_for_role(
        cls,
        role: AgentRoleConfig,
        engagement_id: str,
        target: str,
        backend: str = "external",
        athena_root: str | Path = "",
        prior_context: str = "",
    ) -> "AthenaAgentSession":
```

To:
```python
    @classmethod
    def create_for_role(
        cls,
        role: AgentRoleConfig,
        engagement_id: str,
        target: str,
        backend: str = "external",
        athena_root: str | Path = "",
        prior_context: str = "",
        bus: Any = None,
    ) -> "AthenaAgentSession":
```

And after `session._current_agent = role.code` (line 440), add:

```python
        session._bus = bus
```

- [ ] **Step 3: Add finding extraction to _handle_user_message**

In `sdk_agent.py`, add import at top (after existing imports):

```python
from message_bus import extract_findings
```

In `_handle_user_message()`, after the Graphiti ingestion block (after line 1504), add:

```python
                    # Bus: Extract findings from tool output and broadcast
                    if self._bus and self._role_config:
                        bus_msgs = extract_findings(
                            self._role_config.code, tool_name, output)
                        for bm in bus_msgs:
                            if bm.to == "ALL":
                                await self._bus.broadcast(bm)
                            else:
                                await self._bus.send(bm)
```

Also add the same block after the second tool result path (after line 1516), inside the `elif msg.tool_use_result:` branch, after the `_emit("tool_complete"...)` call:

```python
            # Bus: Extract findings from tool output and broadcast
            if self._bus and self._role_config and not _is_tool_output_noise(output):
                bus_msgs = extract_findings(
                    self._role_config.code, tool_name, output)
                for bm in bus_msgs:
                    if bm.to == "ALL":
                        await self._bus.broadcast(bm)
                    else:
                        await self._bus.send(bm)
```

- [ ] **Step 4: Add bus drain + injection at chunk boundary in BOTH engagement loops**

**CRITICAL: ATHENA has TWO engagement loops that must both get bus injection:**
1. `_engagement_loop()` (line 1101) — initial engagement
2. `_resume_engagement_loop()` (line 1287) — after pause/resume

Create a helper method to keep it DRY:

```python
    def _build_next_prompt(self, base_prompt: str) -> str:
        """Prepend any pending bus intel to the next prompt.

        Called at chunk boundaries in both engagement loops.
        Ensures operator commands, auto-continue, and resume
        all get intel context without duplicating logic.
        """
        if self._pending_injection:
            combined = self._pending_injection + "\n\n" + base_prompt
            self._pending_injection = ""
            return combined
        return base_prompt
```

**In BOTH `_engagement_loop()` (line 1121) and `_resume_engagement_loop()` (line 1299):**

After `await self._run_query(prompt, resume_id)`, add the drain:

```python
                # Bus: Drain inbox and prepare injection for next chunk
                if self._bus and self._role_config:
                    from message_bus import format_intel_update
                    inbox = await self._bus.drain(self._role_config.code)
                    if inbox:
                        self._pending_injection = format_intel_update(
                            inbox, self._role_config.code)
```

**In BOTH loops, at ALL prompt assignment points, wrap with `_build_next_prompt()`:**

1. **Operator command (idle wait)** — lines 1146/1319: After `prompt = cmd`:
```python
                        prompt = self._build_next_prompt(cmd)
```

2. **Operator command (active)** — lines 1158/1330: After `prompt = cmd`:
```python
                        prompt = self._build_next_prompt(cmd)
```

3. **Auto-continue** — lines 1163/1333: Replace `prompt = "Continue..."`:
```python
                            prompt = self._build_next_prompt(
                                "Continue with the next step of the penetration test.")
```

This ensures:
- **Operator commands** (Kelvin types in dashboard) get intel context prepended — agent sees both the intel AND Kelvin's instruction
- **Auto-continue** gets intel context — agent sees what happened since last chunk
- **Resume after pause** gets accumulated intel — agent catches up on what happened during pause
- **Operator command always takes priority** — it's the base prompt, intel is context above it

**Note on tool approach:** The Claude Agent SDK's `ClaudeAgentOptions` does not expose a `tools` parameter for registering Python-handled tools. Instead, agents call `publish_finding` and `send_directive` via Bash curl commands that hit the server's REST API (see Task 6). The agent prompts (Task 7) include the curl templates. No Python-side tool handler is needed in `sdk_agent.py`.

- [ ] **Step 5b: Bridge bus messages to bilateral message events (dashboard timeline)**

The existing `send_bilateral_message()` (line 447) emits `agent_message` events that the dashboard renders as from→to arrows in the timeline. Bus messages should also appear as arrows.

Add to `_handle_user_message()`, right after the bus extraction block:

```python
                    # Bridge bus findings to dashboard timeline as bilateral messages
                    if self._bus and self._role_config:
                        for bm in bus_msgs:
                            if bm.priority in ("high", "critical"):
                                await self.send_bilateral_message(
                                    from_agent=bm.from_agent,
                                    to_agent=bm.to if bm.to != "ALL" else "ALL",
                                    msg_type=bm.bus_type,
                                    content=bm.summary[:500],
                                    priority=bm.priority,
                                )
```

This means: when AR discovers a port and broadcasts to the bus, the dashboard timeline shows an "AR → ALL" arrow with the finding summary. Only high/critical findings get arrows to avoid timeline noise.

- [ ] **Step 6: Verify syntax**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-dashboard
.venv/bin/python -c "import ast; ast.parse(open('sdk_agent.py').read()); print('OK')"
```

Expected: `OK`

- [ ] **Step 7: Commit**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-dashboard
git add sdk_agent.py
git commit -m "feat: integrate message bus into SDK agent — extraction, injection, tool handlers"
```

---

### Task 5: Integrate bus into AgentSessionManager

**Files:**
- Modify: `tools/athena-dashboard/agent_session_manager.py`
  - `__init__()` (line 278–335): Add bus initialization
  - `_spawn_agent()` (line 987–1115): Pass bus to session, register agent
  - `_check_agent_completions()` (line 679–881): Unregister completed agents
  - `_maybe_send_heartbeat()` (line 884–915): Simplify to fallback keepalive
  - `stop_engagement()`: Cleanup bus

- [ ] **Step 1: Add bus to __init__**

In `agent_session_manager.py`, add import at top:

```python
from message_bus import MessageBus
```

After line 327 (`self._workspace_manager = WorkspaceManager(...)`), add:

```python
        # Real-time message bus for inter-agent communication
        self.bus = MessageBus(engagement_id=engagement_id)
```

- [ ] **Step 2: Pass bus to sessions in _spawn_agent**

In `_spawn_agent()`, at the `AthenaAgentSession.create_for_role()` call (around line 1043), add the `bus` parameter:

Change:
```python
        session = AthenaAgentSession.create_for_role(
            role=role,
            engagement_id=self.engagement_id,
            target=self.target,
            backend=self.backend,
            athena_root=str(agent_cwd),
            prior_context=prior_context,
        )
```

To:
```python
        session = AthenaAgentSession.create_for_role(
            role=role,
            engagement_id=self.engagement_id,
            target=self.target,
            backend=self.backend,
            athena_root=str(agent_cwd),
            prior_context=prior_context,
            bus=self.bus,
        )
```

Right after this line, register the agent on the bus:

```python
        self.bus.register(role.code)
```

- [ ] **Step 3: Unregister agents on completion and early-stop**

In `_check_agent_completions()`, where completed agents are processed, add bus unregistration. Find where `completed` agents are iterated (look for the block that removes from `self.agents`), and add:

```python
            self.bus.unregister(code)
```

Also in `_check_agent_completions()`, where early-stopped agents are processed (the `_early_stop_queue` handling), add the same:

```python
            self.bus.unregister(code)
```

- [ ] **Step 3b: Bus cleanup on stop**

In `stop()` (line 408), after stopping all agents but before `self.agents.clear()` (line 483), add:

```python
        # Cleanup bus — unregister all agents, log final history
        for code in list(self.bus._queues.keys()):
            self.bus.unregister(code)
        bus_history = self.bus.get_history()
        if bus_history:
            logger.info("Bus: %d total messages during engagement %s",
                        len(bus_history), self.engagement_id)
```

- [ ] **Step 3c: Bus behavior during pause/resume**

**Pause (line 496):** No bus changes needed. Agent sessions pause (cancel current `_run_query`), but their bus queues **remain active**. If a tool result was in-flight when pause hit, its extracted findings still get broadcast. Messages accumulate in queues during pause.

**Resume (line 505):** No bus changes needed. When agents resume, their next `_engagement_loop` iteration drains the bus inbox (which may have accumulated messages during pause) and injects them into the prompt. Deferred spawns replay via `_spawn_agent()` which already calls `self.bus.register(role.code)`.

**Evidence collection:** No changes needed. `_capture_exploitation_evidence()` (line 840) runs independently inside `_handle_user_message`. Bus extraction also runs there. Both read the same `output` string — no conflict, no ordering dependency. Evidence goes to the artifact API; bus findings go to the message bus. They complement each other.

**Early-stop:** Handled in Step 3 above — early-stopped agents get unregistered from the bus so they stop receiving messages.

- [ ] **Step 4: Simplify heartbeat to fallback**

Replace `_maybe_send_heartbeat()` (lines 884–915) with a version that only fires when no bus traffic has reached ST:

```python
    async def _maybe_send_heartbeat(self):
        """Fallback keepalive: send ST a status if no bus messages for 60s.

        The message bus handles real-time intel sharing. This heartbeat
        is retained only to prevent ST's 300s idle timeout during long
        tool calls when no bus messages flow.
        """
        now = time.time()
        if now - self._last_heartbeat < self._heartbeat_interval:
            return

        # Find active workers
        active_workers = []
        for code, task in self._agent_tasks.items():
            if code == "ST":
                continue
            if isinstance(task, asyncio.Task) and not task.done():
                session = self.agents.get(code)
                tools = session._tool_count if session else 0
                active_workers.append((code, tools))

        if not active_workers:
            return

        st = self.agents.get("ST")
        st_task = self._agent_tasks.get("ST")
        if not st or not (st.is_running or (st_task and not st_task.done())):
            return

        # Simplified keepalive message (bus provides detailed intel)
        worker_parts = []
        for code, tools in active_workers:
            name = AGENT_NAMES.get(code, code)
            worker_parts.append(f"{code} ({name}): {tools} calls")
        msg = (
            f"── KEEPALIVE: {len(active_workers)} workers active: "
            f"{', '.join(worker_parts)} ──"
        )
        await st.send_command(msg)
        self._last_heartbeat = now
        logger.info("Heartbeat keepalive sent to ST: %d active workers",
                     len(active_workers))
```

- [ ] **Step 5: Register WebSocket callback**

Add a method to register the dashboard callback on the bus. In `set_event_callback()` (line 337–339), add bus callback wiring:

```python
    def set_event_callback(self, callback: Callable):
        """Set async callback for streaming events to dashboard."""
        self._event_callback = callback
        # Wire bus messages to dashboard WebSocket
        # NOTE: _event_callback takes a SINGLE dict argument (same as _emit pattern)
        async def _bus_to_ws(msg):
            if self._event_callback:
                await self._event_callback({
                    "type": "agent_intel",
                    "agent": msg.from_agent,
                    "content": msg.summary,
                    "metadata": msg.to_dict(),
                })
        self.bus.on_message(_bus_to_ws)
```

- [ ] **Step 5b: Register Graphiti persistence callback**

ATHENA already has Graphiti (Neo4j knowledge graph) integration. Bus messages with high/critical findings should be persisted for cross-engagement intelligence.

**IMPORTANT:** Graphiti and Langfuse instances live on `server.py` module globals (created in `start_engagement_ai()`), NOT on `AgentSessionManager`. The callbacks must access them via the server module or be passed in as constructor args.

In `AgentSessionManager.__init__()`, add optional parameters:

```python
        # Optional observability hooks (injected from server.py)
        self._graphiti_client = kwargs.get("graphiti_client")  # graphiti_core.Graphiti instance
        self._langfuse_client = kwargs.get("langfuse_client")  # langfuse.Langfuse instance
```

In `set_event_callback()`, after the `_bus_to_ws` registration, add a Graphiti callback:

```python
        # Wire bus findings to Graphiti for cross-engagement intelligence
        graphiti = self._graphiti_client
        eid = self.engagement_id
        async def _bus_to_graphiti(msg):
            if msg.priority in ("high", "critical") and graphiti:
                try:
                    await graphiti.add_episode(
                        name=f"bus_{msg.bus_type}_{msg.id[:8]}",
                        episode_body=(
                            f"Agent {msg.from_agent} reported {msg.bus_type}: "
                            f"{msg.summary}"
                        ),
                        source_description=f"ATHENA bus {eid}",
                    )
                except Exception as e:
                    logger.warning("Bus→Graphiti failed: %s", e)
        self.bus.on_message(_bus_to_graphiti)
```

In `server.py`'s `start_engagement_ai()`, pass the instances when constructing the manager:

```python
    _active_session_manager = AgentSessionManager(
        ...,
        graphiti_client=graphiti_instance,  # may be None if not configured
        langfuse_client=langfuse_instance,  # may be None if not configured
    )
```

- [ ] **Step 5c: Register Langfuse tracing callback**

ATHENA already has Langfuse integration for observability. Bus messages should appear in traces.

```python
        # Wire bus messages to Langfuse for tracing
        langfuse = self._langfuse_client
        async def _bus_to_langfuse(msg):
            try:
                if langfuse:
                    langfuse.event(
                        name=f"bus_{msg.bus_type}",
                        metadata={
                            "from_agent": msg.from_agent,
                            "to": msg.to,
                            "priority": msg.priority,
                            "bus_type": msg.bus_type,
                            "engagement_id": self.engagement_id,
                        },
                        input=msg.summary,
                    )
            except Exception as e:
                logger.warning("Bus→Langfuse failed: %s", e)
        self.bus.on_message(_bus_to_langfuse)
```

**Note:** Both Graphiti and Langfuse callbacks use closure variables captured from `self._graphiti_client` / `self._langfuse_client` which are set at construction time. If either is `None` (service not configured), the callback is a no-op. Fire-and-forget with try/except — failures are logged but don't block the bus. The `on_message` dedup guard (HIGH-2 fix) prevents double-registration.

- [ ] **Step 6: Verify syntax**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-dashboard
.venv/bin/python -c "import ast; ast.parse(open('agent_session_manager.py').read()); print('OK')"
```

Expected: `OK`

- [ ] **Step 7: Commit**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-dashboard
git add agent_session_manager.py
git commit -m "feat: integrate message bus into AgentSessionManager — lifecycle, heartbeat fallback, WebSocket/Graphiti/Langfuse wiring"
```

---

## Chunk 3: Agent Prompts + Server API + Validation

### Task 6: Add bus communication REST endpoints to server

**Files:**
- Modify: `tools/athena-dashboard/server.py`

The Claude Agent SDK doesn't support registering custom Python-handled tools directly. Instead, agents call bus tools via Bash hitting the server's REST API. This is consistent with how agents already interact with the server (budget, findings, scans).

- [ ] **Step 1: Add /api/bus/publish endpoint**

In `server.py`, add after the existing `/api/agents/request` endpoint:

```python
@app.post("/api/bus/publish")
async def bus_publish(request: Request):
    """Agent publishes a finding to the message bus."""
    global _active_session_manager
    if not _active_session_manager:
        return JSONResponse({"error": "No active engagement"}, 400)

    body = await request.json()
    from message_bus import BusMessage
    msg = BusMessage(
        from_agent=body.get("agent", "unknown"),
        to=body.get("to", "ALL"),
        bus_type=body.get("type", "finding"),
        priority=body.get("priority", "medium"),
        summary=body.get("summary", ""),
        target=body.get("target"),
        data=body.get("data", {}),
        action_needed=body.get("action_needed"),
    )
    if msg.to == "ALL":
        await _active_session_manager.bus.broadcast(msg)
    else:
        await _active_session_manager.bus.send(msg)
    return {"ok": True, "message_id": msg.id}


@app.post("/api/bus/directive")
async def bus_directive(request: Request):
    """ST sends a strategic directive via the bus."""
    global _active_session_manager
    if not _active_session_manager:
        return JSONResponse({"error": "No active engagement"}, 400)

    body = await request.json()
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
    return {"ok": True, "message_id": msg.id}


@app.get("/api/bus/history")
async def bus_history(limit: int = 50):
    """Get recent bus message history."""
    global _active_session_manager
    if not _active_session_manager:
        return {"messages": []}
    msgs = _active_session_manager.bus.get_history(limit=limit)
    return {"messages": [m.to_dict() for m in msgs]}
```

- [ ] **Step 2: Verify syntax**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-dashboard
.venv/bin/python -c "import ast; ast.parse(open('server.py').read()); print('OK')"
```

Expected: `OK`

- [ ] **Step 3: Commit**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-dashboard
git add server.py
git commit -m "feat: add bus REST API endpoints — /api/bus/publish, /api/bus/directive, /api/bus/history"
```

---

### Task 7: Update agent system prompts

**Files:**
- Modify: `tools/athena-dashboard/agent_configs.py`

- [ ] **Step 1: Add real-time intel section to all worker prompts**

Create a shared prompt block. Add after the existing tool set definitions (around line 130):

```python
# ── Real-Time Intelligence Prompt Block ──────────────────────
_REALTIME_INTEL_WORKER = """
## Real-Time Intelligence

You are part of a coordinated multi-agent team. Share discoveries IMMEDIATELY:

**To publish a finding to ALL agents:**
```bash
curl -s -X POST http://localhost:8080/api/bus/publish \\
  -H "Content-Type: application/json" \\
  -d '{"agent": "{AGENT_CODE}", "summary": "WHAT YOU FOUND", "priority": "high", "target": "IP:PORT", "type": "finding"}'
```

Priority levels: low, medium, high, critical
Types: finding, request, escalation

**Publish IMMEDIATELY when you find:**
- Open ports, services, or version info
- Vulnerabilities or CVE matches
- Valid credentials
- Successful exploits
- New networks or hosts

**Intel from other agents is injected between your work cycles. Read it. Act on it.**

### How to use incoming intel:
- Service version found by another agent → check for known CVEs before scanning
- Credentials shared → try them on your target services
- Directive from ST → reprioritize immediately
- Exploit succeeded → note for reports, avoid redundant work

### When to escalate to ST:
- Scope boundary reached (new subnet, out-of-scope host)
- Critical finding (shell, domain admin, data breach)
- Stuck or blocked (need different approach)
"""

_REALTIME_INTEL_ST = """
## Real-Time Command

You command a team of agents who share intel in real-time.

**To send a strategic directive to ALL agents:**
```bash
curl -s -X POST http://localhost:8080/api/bus/directive \\
  -H "Content-Type: application/json" \\
  -d '{"agent": "ST", "directive": "YOUR ORDER HERE", "priority": "urgent"}'
```

**To send to a specific agent:**
```bash
curl -s -X POST http://localhost:8080/api/bus/directive \\
  -H "Content-Type: application/json" \\
  -d '{"agent": "ST", "directive": "YOUR ORDER", "priority": "urgent", "to": "EX"}'
```

Priority: normal (when convenient), urgent (pivot now), critical (stop everything)

### Your role:
- Monitor incoming intel for strategic opportunities (pivots, credential reuse, lateral movement)
- Issue directives when the situation changes
- Don't micromanage — workers handle tactics autonomously
- Escalations from workers require your decision

**Intel from agents is injected between your work cycles. Act on it.**
"""
```

- [ ] **Step 2: Append real-time intel to each agent's prompt template**

For each agent prompt, append the appropriate block. Modify the template strings:

For ST (`_ST_PROMPT`, around line 212–288): Append `_REALTIME_INTEL_ST` at the end.
For AR (`_AR_PROMPT`, around line 340–361): Append `_REALTIME_INTEL_WORKER`.
For WV (`_WV_PROMPT`, around line 384–428): Append `_REALTIME_INTEL_WORKER`.
For EX (`_EX_PROMPT`, around line 429–476): Append `_REALTIME_INTEL_WORKER`.
For PR, PE, VF, DA, PX, RP: Append `_REALTIME_INTEL_WORKER`.

Implementation: In each prompt string, add `{realtime_intel}` placeholder at the end. Then in `format_prompt()`, replace it with the appropriate block based on role code:

```python
# In format_prompt() or wherever prompts are assembled:
realtime = _REALTIME_INTEL_ST if role.code == "ST" else _REALTIME_INTEL_WORKER
# Replace {AGENT_CODE} placeholder
realtime = realtime.replace("{AGENT_CODE}", role.code)
```

**Alternative (simpler):** Just concatenate the block directly in each prompt constant. Since the prompts are already long strings, appending is the least-risk approach:

```python
_ST_PROMPT = _ST_PROMPT + _REALTIME_INTEL_ST
_AR_PROMPT = _AR_PROMPT + _REALTIME_INTEL_WORKER
_WV_PROMPT = _WV_PROMPT + _REALTIME_INTEL_WORKER
_EX_PROMPT = _EX_PROMPT + _REALTIME_INTEL_WORKER
_PR_PROMPT = _PR_PROMPT + _REALTIME_INTEL_WORKER
_PE_PROMPT = _PE_PROMPT + _REALTIME_INTEL_WORKER
_VF_PROMPT = _VF_PROMPT + _REALTIME_INTEL_WORKER
_DA_PROMPT = _DA_PROMPT + _REALTIME_INTEL_WORKER
_PX_PROMPT = _PX_PROMPT + _REALTIME_INTEL_WORKER
_RP_PROMPT = _RP_PROMPT + _REALTIME_INTEL_WORKER
```

Add these lines after all prompt definitions but before `AGENT_CONFIGS` dict.

- [ ] **Step 2b: CRITICAL — Add `{AGENT_CODE}` replacement to `format_prompt()`**

The curl commands in `_REALTIME_INTEL_WORKER` and `_REALTIME_INTEL_ST` contain `{AGENT_CODE}` placeholders. Without this step, agents will publish findings with literal `{AGENT_CODE}` as their identifier.

Find `format_prompt()` function (around line ~1198 in agent_configs.py) and add this line at the end, before the return:

```python
    # Replace {AGENT_CODE} with actual agent code for bus curl commands
    prompt = prompt.replace("{AGENT_CODE}", role.code)
```

If `format_prompt()` doesn't exist as a standalone function (prompts may be passed directly from `AGENT_CONFIGS[code].prompt`), then do the replacement in `_spawn_agent()` inside `agent_session_manager.py`, right after retrieving the prompt:

```python
        # Replace {AGENT_CODE} placeholder in bus curl commands
        prompt = prompt.replace("{AGENT_CODE}", role.code)
```

Verify by searching for `{AGENT_CODE}` in the assembled prompt — it should NOT appear after replacement.

- [ ] **Step 3: Verify syntax**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-dashboard
.venv/bin/python -c "import ast; ast.parse(open('agent_configs.py').read()); print('OK')"
```

Expected: `OK`

- [ ] **Step 4: Commit**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-dashboard
git add agent_configs.py
git commit -m "feat: add real-time intel communication prompts to all agent roles"
```

---

### Task 8: Integration smoke test

**Files:**
- Create: `tools/athena-dashboard/tests/test_bus_integration.py`

- [ ] **Step 1: Write integration test**

```python
# tests/test_bus_integration.py
"""Integration tests for message bus with agent session manager."""
import asyncio
import pytest
from message_bus import MessageBus, BusMessage, extract_findings, format_intel_update


class TestBusIntegration:
    """End-to-end tests simulating multi-agent bus flow."""

    @pytest.mark.asyncio
    async def test_full_flow_ar_discovers_wv_receives(self):
        """AR finds ports → bus → WV receives intel in injection."""
        bus = MessageBus(engagement_id="test-integration-001")
        bus.register("ST")
        bus.register("AR")
        bus.register("WV")
        bus.register("EX")

        # AR runs nmap, finds ports
        nmap_output = """PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
443/tcp  open  https"""
        findings = extract_findings("AR", "mcp__kali_external__nmap_scan", nmap_output)
        assert len(findings) >= 1

        # Broadcast findings
        for f in findings:
            await bus.broadcast(f)

        # WV drains and formats
        wv_inbox = await bus.drain("WV")
        assert len(wv_inbox) >= 1
        injection = format_intel_update(wv_inbox, "WV")
        assert "INTELLIGENCE UPDATE" in injection
        assert "AR" in injection

        # ST also received
        st_inbox = await bus.drain("ST")
        assert len(st_inbox) >= 1

        # AR did NOT receive its own message
        ar_inbox = await bus.drain("AR")
        assert len(ar_inbox) == 0

    @pytest.mark.asyncio
    async def test_st_directive_reaches_workers(self):
        """ST sends directive → all workers receive it."""
        bus = MessageBus(engagement_id="test-integration-002")
        bus.register("ST")
        bus.register("AR")
        bus.register("WV")
        bus.register("EX")

        directive = BusMessage(
            from_agent="ST", to="ALL",
            bus_type="directive", priority="urgent",
            summary="Pivot to internal network 192.168.1.0/24",
            action_needed="Pivot to internal network 192.168.1.0/24",
        )
        await bus.broadcast(directive)

        # All workers receive
        for code in ("AR", "WV", "EX"):
            inbox = await bus.drain(code)
            assert len(inbox) == 1
            assert inbox[0].bus_type == "directive"

        # ST doesn't receive own directive
        st_inbox = await bus.drain("ST")
        assert len(st_inbox) == 0

    @pytest.mark.asyncio
    async def test_direct_message_ex_to_vf(self):
        """EX sends direct request to VF only."""
        bus = MessageBus(engagement_id="test-integration-003")
        bus.register("EX")
        bus.register("VF")
        bus.register("AR")

        msg = BusMessage(
            from_agent="EX", to="VF",
            bus_type="request", priority="high",
            summary="Verify exploit on 10.0.0.5:8443",
            action_needed="Run verification scan",
        )
        await bus.send(msg)

        vf_inbox = await bus.drain("VF")
        assert len(vf_inbox) == 1

        ar_inbox = await bus.drain("AR")
        assert len(ar_inbox) == 0

    @pytest.mark.asyncio
    async def test_ws_callback_fires(self):
        """WebSocket callback fires on broadcast."""
        bus = MessageBus(engagement_id="test-integration-004")
        bus.register("AR")
        bus.register("WV")

        ws_events = []
        async def mock_ws_callback(msg):
            ws_events.append(msg.to_dict())

        bus.on_message(mock_ws_callback)

        finding = BusMessage(
            from_agent="AR", to="ALL",
            bus_type="finding", priority="high",
            summary="Port 22 open",
        )
        await bus.broadcast(finding)
        await asyncio.sleep(0.05)

        assert len(ws_events) == 1
        assert ws_events[0]["from_agent"] == "AR"

    @pytest.mark.asyncio
    async def test_history_persists_across_drains(self):
        """Messages stay in history even after agents drain."""
        bus = MessageBus(engagement_id="test-integration-005")
        bus.register("AR")
        bus.register("WV")

        msg = BusMessage(
            from_agent="AR", to="ALL",
            bus_type="finding", priority="high",
            summary="Test finding",
        )
        await bus.broadcast(msg)

        # WV drains
        await bus.drain("WV")

        # History still has the message
        hist = bus.get_history()
        assert len(hist) == 1
        assert hist[0].summary == "Test finding"

    @pytest.mark.asyncio
    async def test_pause_accumulates_resume_drains(self):
        """Messages accumulate during pause and are available on resume."""
        bus = MessageBus(engagement_id="test-pause-001")
        bus.register("ST")
        bus.register("AR")
        bus.register("WV")

        # Simulate pause — bus queues stay active
        # AR broadcasts a finding (could happen from in-flight tool result)
        msg = BusMessage(
            from_agent="AR", to="ALL",
            bus_type="finding", priority="high",
            summary="Port 443 open on 10.0.0.5",
        )
        await bus.broadcast(msg)

        # WV hasn't drained yet (paused). Message sits in queue.
        assert not bus._queues["WV"].empty()

        # Simulate resume — WV drains accumulated messages
        wv_inbox = await bus.drain("WV")
        assert len(wv_inbox) == 1
        assert wv_inbox[0].summary == "Port 443 open on 10.0.0.5"

    @pytest.mark.asyncio
    async def test_stop_cleans_up_bus(self):
        """Stop unregisters all agents from bus."""
        bus = MessageBus(engagement_id="test-stop-001")
        bus.register("ST")
        bus.register("AR")
        bus.register("WV")
        assert len(bus._queues) == 3

        # Simulate stop cleanup
        for code in list(bus._queues.keys()):
            bus.unregister(code)
        assert len(bus._queues) == 0

        # History still accessible after stop
        bus._history.append(BusMessage(
            from_agent="AR", to="ALL",
            bus_type="finding", priority="high",
            summary="test",
        ))
        assert len(bus.get_history()) == 1

    @pytest.mark.asyncio
    async def test_early_stop_unregisters_agent(self):
        """Early-stopped agent is unregistered, stops receiving messages."""
        bus = MessageBus(engagement_id="test-earlystop-001")
        bus.register("ST")
        bus.register("AR")
        bus.register("EX")

        # EX gets early-stopped (budget exhausted)
        bus.unregister("EX")

        # Subsequent broadcast doesn't go to EX
        msg = BusMessage(
            from_agent="AR", to="ALL",
            bus_type="finding", priority="high",
            summary="New port found",
        )
        await bus.broadcast(msg)

        assert "EX" not in bus._queues
        # ST still gets it
        st_inbox = await bus.drain("ST")
        assert len(st_inbox) == 1

    @pytest.mark.asyncio
    async def test_evidence_and_bus_independent(self):
        """Bus extraction and evidence capture both work on same tool output."""
        # Simulates _handle_user_message processing both paths
        output = "Gained shell access on 10.0.0.5 via CVE-2024-50623"

        # Bus extraction
        findings = extract_findings("EX", "Bash", output)
        assert len(findings) >= 1
        assert any(f.bus_type == "escalation" for f in findings)

        # Evidence capture would also fire on this output
        # (tested separately — here we just verify no interference)
        assert "shell" in output.lower()  # _is_exploitation_result would match

    @pytest.mark.asyncio
    async def test_on_message_dedup_guard(self):
        """Registering the same callback twice only fires it once."""
        bus = MessageBus(engagement_id="test-dedup-001")
        bus.register("AR")
        bus.register("WV")

        received = []
        async def my_callback(msg):
            received.append(msg)

        bus.on_message(my_callback)
        bus.on_message(my_callback)  # duplicate — should be ignored
        assert len(bus._callbacks) == 1

        msg = BusMessage(
            from_agent="AR", to="ALL",
            bus_type="finding", priority="high",
            summary="Test dedup",
        )
        await bus.broadcast(msg)
        await asyncio.sleep(0.05)
        assert len(received) == 1  # not 2

    @pytest.mark.asyncio
    async def test_credential_extraction_broadcasts_critical(self):
        """Credential finding is broadcast as critical to all agents."""
        bus = MessageBus(engagement_id="test-integration-006")
        bus.register("EX")
        bus.register("AR")
        bus.register("WV")
        bus.register("ST")

        output = "Hydra found valid credentials: admin:P@ssw0rd on SSH port 22"
        findings = extract_findings("EX", "Bash", output)
        assert any(f.priority == "critical" for f in findings)

        for f in findings:
            await bus.broadcast(f)

        # All other agents should have critical intel
        for code in ("AR", "WV", "ST"):
            inbox = await bus.drain(code)
            assert len(inbox) >= 1
            assert any(m.priority == "critical" for m in inbox)
```

- [ ] **Step 2: Run integration tests**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-dashboard
.venv/bin/python -m pytest tests/test_bus_integration.py -v
```

Expected: All 11 tests PASS (6 original + 4 stop/pause/resume/evidence + 1 dedup guard)

- [ ] **Step 3: Run ALL tests**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-dashboard
.venv/bin/python -m pytest tests/ -v
```

Expected: All tests PASS (message_bus + integration + existing tests)

- [ ] **Step 4: Commit**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-dashboard
git add tests/test_bus_integration.py
git commit -m "test: add integration tests for multi-agent message bus flow"
```

---

### Task 9: Manual validation — run a pentest

- [ ] **Step 1: Restart the server**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-dashboard
./start.sh
```

- [ ] **Step 2: Start a Lab pentest from the dashboard**

Open `http://localhost:8080`, select a target, start a Lab engagement.

- [ ] **Step 3: Verify bus operation**

Monitor the terminal for `Bus:` log lines:
- `Bus: registered agent AR` — agents registering
- `Bus: broadcast from AR → 3 agents:` — findings broadcasting
- `Bus: direct EX → VF:` — direct messages

Check the bus history endpoint:
```bash
curl -s http://localhost:8080/api/bus/history | python3 -m json.tool
```

- [ ] **Step 4: Verify agents act on intel**

In the dashboard timeline, look for agents referencing information from other agents' findings. Check Langfuse traces for inter-agent context in prompts.

- [ ] **Step 5: Commit final state**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-dashboard
git add -A
git commit -m "feat: ATHENA real-time multi-agent communication — message bus, finding extraction, context injection, agent prompts"
```

- [ ] **Step 6: Push**

```bash
git push origin main
```

---

## Summary

| Task | Est. Time | Dependencies |
|------|-----------|-------------|
| Task 1: MessageBus core | 15 min | None |
| Task 2: Finding Extractor | 20 min | Task 1 |
| Task 3: Context Injector | 15 min | Task 1 |
| Task 4: SDK Agent integration | 25 min | Tasks 1-3 |
| Task 5: Session Manager integration | 20 min | Tasks 1, 4 |
| Task 6: Server REST endpoints | 15 min | Task 1 |
| Task 7: Agent prompts | 15 min | Task 6 |
| Task 8: Integration tests | 15 min | Tasks 1-7 |
| Task 9: Manual validation | 30 min | Tasks 1-8 |
| **Total** | **~3 hours** | |

**Critical path:** Tasks 1→2→3→4→5→9 (bus core → extraction → injection → SDK → manager → validate)

**Parallel work:** Tasks 6+7 can run in parallel with Tasks 4+5 (independent files)
