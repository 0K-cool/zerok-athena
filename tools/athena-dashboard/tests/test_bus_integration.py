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
        output = "Gained shell access on 10.0.0.5 via CVE-2024-50623"

        # Bus extraction
        findings = extract_findings("EX", "Bash", output)
        assert len(findings) >= 1
        assert any(f.bus_type == "escalation" for f in findings)

        # Evidence capture would also fire on this output
        assert "shell" in output.lower()

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
