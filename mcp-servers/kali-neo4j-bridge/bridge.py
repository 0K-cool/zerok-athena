# mcp-servers/kali-neo4j-bridge/bridge.py
"""Bridge to write Kali MCP tool results into Neo4j.

Usage by agents:
  After calling kali_internal MCP tools (naabu_scan, nuclei_scan, etc.),
  pass the JSON result to the appropriate bridge function to persist
  results in the knowledge graph.
"""
import json
import re
from typing import Any

def parse_naabu_results(raw_output: str, engagement_id: str) -> list[dict]:
    """Parse naabu scan output into host/service records for Neo4j.

    Expected format from naabu: IP:PORT lines or JSON output.
    Returns list of {ip, port, protocol} dicts.
    """
    records = []
    for line in raw_output.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        # JSON mode: {"ip":"x","port":80}
        if line.startswith("{"):
            try:
                obj = json.loads(line)
                records.append({
                    "ip": obj.get("ip", obj.get("host", "")),
                    "port": int(obj.get("port", 0)),
                    "protocol": "tcp"
                })
            except json.JSONDecodeError:
                continue
        # Text mode: 10.0.0.5:80
        elif ":" in line:
            parts = line.rsplit(":", 1)
            if len(parts) == 2 and parts[1].isdigit():
                records.append({"ip": parts[0], "port": int(parts[1]), "protocol": "tcp"})
    return records

def parse_nuclei_results(raw_output: str, engagement_id: str) -> list[dict]:
    """Parse nuclei scan JSON output into vulnerability records.

    Nuclei JSON output includes: template-id, severity, host, matched-at, etc.
    """
    vulns = []
    for line in raw_output.strip().split("\n"):
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
            vulns.append({
                "name": obj.get("info", {}).get("name", obj.get("template-id", "")),
                "severity": obj.get("info", {}).get("severity", "info").upper(),
                "host": obj.get("host", ""),
                "matched_at": obj.get("matched-at", ""),
                "template_id": obj.get("template-id", ""),
                "cve_id": ",".join(obj.get("info", {}).get("classification", {}).get("cve-id", [])),
                "cvss_score": obj.get("info", {}).get("classification", {}).get("cvss-score", 0),
                "description": obj.get("info", {}).get("description", ""),
            })
        except json.JSONDecodeError:
            continue
    return vulns

def parse_httpx_results(raw_output: str, engagement_id: str) -> list[dict]:
    """Parse httpx probe JSON output into URL/service records."""
    urls = []
    for line in raw_output.strip().split("\n"):
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
            urls.append({
                "url": obj.get("url", ""),
                "status_code": obj.get("status_code", 0),
                "title": obj.get("title", ""),
                "tech": obj.get("tech", []),
                "content_type": obj.get("content_type", ""),
                "host": obj.get("host", ""),
                "port": obj.get("port", 0),
            })
        except json.JSONDecodeError:
            continue
    return urls

def validate_scope(target: str, scope: dict) -> bool:
    """Check if a target IP/domain is within engagement scope.

    Args:
        target: IP address or domain to check
        scope: {"targets": ["10.0.0.0/24", "*.example.com"], "exclusions": ["10.0.0.1"]}
    """
    import ipaddress

    exclusions = scope.get("exclusions", [])
    for excl in exclusions:
        if target == excl:
            return False

    targets = scope.get("targets", [])
    for allowed in targets:
        if target == allowed:
            return True
        # CIDR check
        try:
            if ipaddress.ip_address(target) in ipaddress.ip_network(allowed, strict=False):
                return True
        except ValueError:
            pass
        # Wildcard domain check
        if allowed.startswith("*.") and target.endswith(allowed[1:]):
            return True
    return False
