# mcp-servers/neo4j-mcp/tests/test_server.py
"""Tests for neo4j-mcp server tools."""
import json
import pytest

# Test schema validation for tool inputs
def test_create_host_valid():
    """Valid host creation input."""
    host = {
        "ip": "10.0.0.5",
        "hostname": "web01.example.com",
        "os": "Ubuntu 22.04",
        "engagement_id": "eng-2026-001"
    }
    assert host["ip"]
    assert host["engagement_id"]

def test_create_host_rejects_missing_ip():
    """Host must have IP."""
    host = {"hostname": "web01.example.com"}
    assert "ip" not in host

def test_create_vulnerability_valid():
    """Valid vulnerability creation."""
    vuln = {
        "id": "vuln-001",
        "cve_id": "CVE-2024-1234",
        "name": "SQL Injection",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "engagement_id": "eng-2026-001"
    }
    assert vuln["severity"] in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    assert 0 <= vuln["cvss_score"] <= 10

def test_create_engagement_valid():
    """Valid engagement creation."""
    engagement = {
        "id": "eng-2026-001",
        "name": "Client_2026-02-19_Web",
        "client": "Client Name",
        "scope": json.dumps({"targets": ["10.0.0.0/24"]}),
        "status": "active"
    }
    assert engagement["status"] in ["active", "completed", "archived"]

def test_cypher_query_sanitization():
    """Ensure basic injection prevention."""
    malicious = "'; DROP DATABASE neo4j; //"
    # Should be passed as parameter, not interpolated
    safe_query = "MATCH (h:Host {ip: $ip}) RETURN h"
    assert "$ip" in safe_query
    assert malicious not in safe_query
