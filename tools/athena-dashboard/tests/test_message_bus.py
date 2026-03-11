"""Tests for ATHENA Real-Time Multi-Agent Message Bus.

Covers: BusMessage, MessageBus, Finding Extractor, Context Injector.
"""

import asyncio
import pytest
from message_bus import BusMessage, MessageBus, extract_findings, format_intel_update


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
