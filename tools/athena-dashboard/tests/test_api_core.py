"""API tests for ATHENA core endpoints.

Tests health, engagements CRUD, and basic server functionality.
Uses in-process AsyncClient (no real server needed).
"""
import pytest
# Fixtures auto-loaded from conftest.py

pytestmark = pytest.mark.asyncio


async def test_health_endpoint(client):
    """GET /health returns healthy status."""
    resp = await client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"


async def test_root_serves_html(client):
    """GET / serves the dashboard HTML."""
    resp = await client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers.get("content-type", "")


async def test_list_engagements(client):
    """GET /api/engagements returns a list."""
    resp = await client.get("/api/engagements")
    assert resp.status_code == 200
    data = resp.json()
    # Response is either {"engagements": [...]} or [...]
    engagements = data.get("engagements", data) if isinstance(data, dict) else data
    assert isinstance(engagements, list)


async def test_get_agents(client):
    """GET /api/agents returns agent status list."""
    resp = await client.get("/api/agents")
    assert resp.status_code == 200


async def test_get_status(client):
    """GET /api/status returns server status."""
    resp = await client.get("/api/status")
    assert resp.status_code == 200


async def test_get_system_resources(client):
    """GET /api/system/resources returns CPU/RAM info."""
    resp = await client.get("/api/system/resources")
    assert resp.status_code == 200
    data = resp.json()
    assert "cores" in data or "cpu" in data or "tier" in data


async def test_post_finding(client, sample_finding):
    """POST /api/findings creates a finding and returns 200/201."""
    resp = await client.post("/api/findings", json=sample_finding)
    assert resp.status_code in (200, 201)
    data = resp.json()
    assert "id" in data or "finding_id" in data or "ok" in data


async def test_get_findings_for_engagement(client, sample_finding):
    """GET /api/engagements/{eid}/findings returns findings list."""
    # Create a finding first
    await client.post("/api/findings", json=sample_finding)

    resp = await client.get(f"/api/engagements/{sample_finding['engagement']}/findings")
    assert resp.status_code == 200
    data = resp.json()
    findings = data if isinstance(data, list) else data.get("findings", [])
    assert isinstance(findings, list)
    assert len(findings) >= 1


async def test_get_exploit_stats(client, sample_finding):
    """GET /api/engagements/{eid}/exploit-stats returns stats."""
    await client.post("/api/findings", json=sample_finding)

    resp = await client.get(f"/api/engagements/{sample_finding['engagement']}/exploit-stats")
    assert resp.status_code == 200
    data = resp.json()
    assert "discovered_vulns" in data or "confirmed_exploits" in data


async def test_get_vuln_severity(client, sample_finding):
    """GET /api/engagements/{eid}/vuln-severity returns severity counts."""
    await client.post("/api/findings", json=sample_finding)

    resp = await client.get(f"/api/engagements/{sample_finding['engagement']}/vuln-severity")
    assert resp.status_code == 200
    data = resp.json()
    assert "severity" in data or "critical" in data or "high" in data


async def test_get_services_summary(client, sample_finding):
    """GET /api/engagements/{eid}/services-summary returns services."""
    await client.post("/api/findings", json=sample_finding)

    resp = await client.get(f"/api/engagements/{sample_finding['engagement']}/services-summary")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)


async def test_get_credentials(client, sample_finding):
    """GET /api/engagements/{eid}/credentials returns credential data."""
    await client.post("/api/findings", json=sample_finding)

    resp = await client.get(f"/api/engagements/{sample_finding['engagement']}/credentials")
    assert resp.status_code == 200
    data = resp.json()
    assert "total" in data or "credentials" in data
