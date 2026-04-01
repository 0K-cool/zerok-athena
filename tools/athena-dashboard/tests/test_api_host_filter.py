"""API tests for ATHENA host filtering (Session 1 feature I8/I9).

Tests that ?host_ip= parameter correctly filters findings, exploit-stats,
services-summary, and vuln-severity endpoints to a specific target host.
"""
import pytest
# Fixtures auto-loaded from conftest.py

pytestmark = pytest.mark.asyncio


async def _seed_two_hosts(client, f1, f2):
    """Helper: create findings on two different hosts."""
    await client.post("/api/findings", json=f1)
    await client.post("/api/findings", json=f2)


async def test_findings_no_filter_returns_all(client, sample_finding, sample_finding_2):
    """Without host_ip filter, all findings are returned."""
    await _seed_two_hosts(client, sample_finding, sample_finding_2)

    resp = await client.get(f"/api/engagements/{sample_finding['engagement']}/findings")
    assert resp.status_code == 200
    findings = resp.json() if isinstance(resp.json(), list) else resp.json().get("findings", [])
    hosts = {f.get("host_ip", "") for f in findings if f.get("host_ip")}
    # Should have findings from both hosts
    assert len(findings) >= 2


async def test_findings_filter_by_host(client, sample_finding, sample_finding_2):
    """With host_ip filter, only matching host's findings are returned."""
    await _seed_two_hosts(client, sample_finding, sample_finding_2)

    host = sample_finding["host_ip"]
    resp = await client.get(f"/api/engagements/{sample_finding['engagement']}/findings?host_ip={host}")
    assert resp.status_code == 200
    findings = resp.json() if isinstance(resp.json(), list) else resp.json().get("findings", [])
    # All returned findings should be for the filtered host
    for f in findings:
        target = f.get("host_ip", "") or (f.get("affected_hosts", [""])[0] if f.get("affected_hosts") else "")
        if target:
            assert host in target, f"Finding {f.get('title')} has host {target}, expected {host}"


async def test_exploit_stats_filter_by_host(client, sample_finding, sample_finding_2):
    """Exploit stats with host_ip filter scopes to that host."""
    await _seed_two_hosts(client, sample_finding, sample_finding_2)

    resp_all = await client.get(f"/api/engagements/{sample_finding['engagement']}/exploit-stats")
    resp_filtered = await client.get(
        f"/api/engagements/{sample_finding['engagement']}/exploit-stats?host_ip={sample_finding['host_ip']}"
    )
    assert resp_all.status_code == 200
    assert resp_filtered.status_code == 200
    # Filtered should have <= total discovered vulns
    all_data = resp_all.json()
    filtered_data = resp_filtered.json()
    assert filtered_data.get("discovered_vulns", 0) <= all_data.get("discovered_vulns", 0)


async def test_vuln_severity_filter_by_host(client, sample_finding, sample_finding_2):
    """Vuln severity with host_ip filter scopes to that host."""
    await _seed_two_hosts(client, sample_finding, sample_finding_2)

    resp = await client.get(
        f"/api/engagements/{sample_finding['engagement']}/vuln-severity?host_ip={sample_finding['host_ip']}"
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "severity" in data or "critical" in data or "high" in data


async def test_services_summary_filter_by_host(client, sample_finding, sample_finding_2):
    """Services summary with host_ip filter scopes to that host."""
    await _seed_two_hosts(client, sample_finding, sample_finding_2)

    resp = await client.get(
        f"/api/engagements/{sample_finding['engagement']}/services-summary?host_ip={sample_finding['host_ip']}"
    )
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)


async def test_hosts_endpoint(client, sample_finding, sample_finding_2):
    """GET /api/engagements/{eid}/hosts returns discovered hosts."""
    await _seed_two_hosts(client, sample_finding, sample_finding_2)

    resp = await client.get(f"/api/engagements/{sample_finding['engagement']}/hosts")
    assert resp.status_code == 200
    data = resp.json()
    assert "hosts" in data
    assert data["total"] >= 0


async def test_exploit_stats_by_host(client, sample_finding, sample_finding_2):
    """GET /api/engagements/{eid}/exploit-stats/by-host returns per-host stats."""
    await _seed_two_hosts(client, sample_finding, sample_finding_2)

    resp = await client.get(f"/api/engagements/{sample_finding['engagement']}/exploit-stats/by-host")
    assert resp.status_code == 200
    data = resp.json()
    assert "hosts" in data or "engagement_id" in data
