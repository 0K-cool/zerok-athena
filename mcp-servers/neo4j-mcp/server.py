# mcp-servers/neo4j-mcp/server.py
"""Neo4j MCP Server for ATHENA v2.0 Knowledge Graph operations."""
import os
import sys
import json
import logging
import uuid
from datetime import datetime
from typing import Any, Optional

from mcp.server.fastmcp import FastMCP
from neo4j import GraphDatabase

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
                    handlers=[logging.StreamHandler(sys.stderr)])
logger = logging.getLogger(__name__)

NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://your-kali-host:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASS = os.environ.get("NEO4J_PASS", "$NEO4J_PASS")

mcp = FastMCP("athena-neo4j")

driver = None

def get_driver():
    global driver
    if driver is None:
        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
        driver.verify_connectivity()
        logger.info(f"Connected to Neo4j at {NEO4J_URI}")
    return driver

def run_query(query: str, params: dict = None) -> list[dict]:
    """Execute Cypher query with parameters. NEVER interpolate user input."""
    d = get_driver()
    with d.session() as session:
        result = session.run(query, params or {})
        return [dict(record) for record in result]

@mcp.tool()
def create_engagement(name: str, client: str, scope: str,
                      methodology: str = "PTES",
                      engagement_type: str = "external") -> str:
    """Create a new engagement in the knowledge graph."""
    eid = f"eng-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    run_query("""
        CREATE (e:Engagement {
            id: $id, name: $name, client: $client, scope: $scope,
            methodology: $methodology, type: $type,
            start_date: datetime(), status: 'active'
        }) RETURN e
    """, {"id": eid, "name": name, "client": client, "scope": scope,
          "methodology": methodology, "type": engagement_type})
    return json.dumps({"engagement_id": eid, "status": "created"})

@mcp.tool()
def list_engagements() -> str:
    """List all engagements with their status."""
    results = run_query("""
        MATCH (e:Engagement)
        RETURN e.id AS id, e.name AS name, e.client AS client,
               e.status AS status, e.start_date AS start_date
        ORDER BY e.start_date DESC
    """)
    return json.dumps(results, default=str)

@mcp.tool()
def create_host(ip: str, engagement_id: str, hostname: str = "",
                os_name: str = "", os_version: str = "") -> str:
    """Add a discovered host to the knowledge graph."""
    run_query("""
        MERGE (h:Host {ip: $ip, engagement_id: $eid})
        SET h.hostname = $hostname, h.os = $os, h.os_version = $osv,
            h.status = 'alive', h.last_seen = datetime()
        WITH h
        MATCH (e:Engagement {id: $eid})
        MERGE (e)-[:TARGETS]->(h)
        RETURN h
    """, {"ip": ip, "eid": engagement_id, "hostname": hostname,
          "os": os_name, "osv": os_version})
    return json.dumps({"host": ip, "status": "created"})

@mcp.tool()
def create_service(host_ip: str, port: int, protocol: str,
                   engagement_id: str, name: str = "", version: str = "",
                   banner: str = "") -> str:
    """Add a discovered service to a host."""
    run_query("""
        MATCH (h:Host {ip: $ip, engagement_id: $eid})
        MERGE (s:Service {port: $port, protocol: $proto, host_ip: $ip, engagement_id: $eid})
        SET s.name = $name, s.version = $version, s.banner = $banner, s.state = 'open'
        MERGE (h)-[:HAS_SERVICE]->(s)
        RETURN s
    """, {"ip": host_ip, "port": port, "proto": protocol, "eid": engagement_id,
          "name": name, "version": version, "banner": banner})
    return json.dumps({"host": host_ip, "port": port, "status": "created"})

@mcp.tool()
def create_url(url: str, engagement_id: str, status_code: int = 0,
               content_type: str = "", tech_stack: str = "") -> str:
    """Add a discovered URL to the knowledge graph."""
    run_query("""
        MERGE (u:URL {url: $url, engagement_id: $eid})
        SET u.status_code = $status, u.content_type = $ct,
            u.tech_stack = $tech, u.discovered_at = datetime()
        WITH u
        MATCH (e:Engagement {id: $eid})
        MERGE (e)-[:DISCOVERED]->(u)
        RETURN u
    """, {"url": url, "eid": engagement_id, "status": status_code,
          "ct": content_type, "tech": tech_stack})
    return json.dumps({"url": url, "status": "created"})

@mcp.tool()
def create_subdomain(name: str, engagement_id: str,
                     resolved_ips: str = "", source: str = "") -> str:
    """Add a discovered subdomain to the knowledge graph."""
    run_query("""
        MERGE (s:Subdomain {name: $name, engagement_id: $eid})
        SET s.resolved_ips = $ips, s.source = $src, s.discovered_at = datetime()
        WITH s
        MATCH (e:Engagement {id: $eid})
        MERGE (e)-[:DISCOVERED]->(s)
        RETURN s
    """, {"name": name, "eid": engagement_id, "ips": resolved_ips, "src": source})
    return json.dumps({"subdomain": name, "status": "created"})

@mcp.tool()
def create_vulnerability(host_ip: str, port: int, name: str, severity: str,
                         engagement_id: str, cve_id: str = "",
                         cvss_score: float = 0.0, description: str = "",
                         nuclei_template: str = "") -> str:
    """Record a discovered vulnerability."""
    vid = f"vuln-{uuid.uuid4().hex[:8]}"
    run_query("""
        MATCH (s:Service {host_ip: $ip, port: $port, engagement_id: $eid})
        CREATE (v:Vulnerability {
            id: $vid, cve_id: $cve, name: $name, description: $desc,
            cvss_score: $cvss, severity: $sev, nuclei_template: $tmpl,
            status: 'open', engagement_id: $eid, discovered_at: datetime()
        })
        MERGE (s)-[:HAS_VULNERABILITY]->(v)
        RETURN v
    """, {"ip": host_ip, "port": port, "vid": vid, "cve": cve_id,
          "name": name, "desc": description, "cvss": cvss_score,
          "sev": severity, "tmpl": nuclei_template, "eid": engagement_id})
    return json.dumps({"vulnerability_id": vid, "severity": severity})

@mcp.tool()
def create_credential(username: str, engagement_id: str,
                      hash_type: str = "", hash_value: str = "",
                      plaintext: str = "", source: str = "",
                      domain: str = "") -> str:
    """Record a discovered credential."""
    cid = f"cred-{uuid.uuid4().hex[:8]}"
    run_query("""
        CREATE (c:Credential {
            id: $cid, username: $user, hash_type: $ht, hash_value: $hv,
            plaintext: $pt, source: $src, domain: $dom,
            engagement_id: $eid, discovered_at: datetime()
        }) RETURN c
    """, {"cid": cid, "user": username, "ht": hash_type, "hv": hash_value,
          "pt": plaintext, "src": source, "dom": domain, "eid": engagement_id})
    return json.dumps({"credential_id": cid, "username": username})

@mcp.tool()
def create_finding(title: str, severity: str, engagement_id: str,
                   agent: str = "", category: str = "",
                   description: str = "", cvss: float = 0.0,
                   remediation: str = "", references: str = "",
                   affected_hosts: str = "", evidence: str = "") -> str:
    """Create a confirmed finding for the report. Always pass agent (e.g. 'EX', 'DA', 'VF') and category."""
    fid = f"find-{uuid.uuid4().hex[:8]}"
    if not agent:
        _tl = title.lower()
        if any(kw in _tl for kw in ('exploit', 'shell', 'rce', 'backdoor', 'root', 'command execution')):
            agent = "EX"
        elif any(kw in _tl for kw in ('open port', 'scan', 'discovered', 'fingerprint')):
            agent = "AR"
        elif any(kw in _tl for kw in ('cve', 'cvss', 'debrief', 'hypothesis', 'analysis')):
            agent = "DA"
        else:
            agent = "EX"
    import time as _time
    run_query("""
        CREATE (f:Finding {
            id: $fid, title: $title, severity: $sev, description: $desc,
            cvss: $cvss, remediation: $rem, references: $refs,
            agent: $agent, category: $cat, evidence: $evidence,
            discovery_source: 'mcp', timestamp: $ts,
            status: 'confirmed', engagement_id: $eid, created_at: datetime()
        })
        WITH f
        MATCH (e:Engagement {id: $eid})
        MERGE (e)-[:CONTAINS]->(f)
        RETURN f
    """, {"fid": fid, "title": title, "sev": severity, "desc": description,
          "cvss": cvss, "rem": remediation, "refs": references,
          "agent": agent, "cat": category or "uncategorized",
          "evidence": evidence, "ts": _time.time(), "eid": engagement_id})
    if affected_hosts:
        for hip in affected_hosts.split(","):
            run_query("""
                MATCH (f:Finding {id: $fid}), (h:Host {ip: $ip, engagement_id: $eid})
                MERGE (f)-[:AFFECTS]->(h)
            """, {"fid": fid, "ip": hip.strip(), "eid": engagement_id})
    return json.dumps({"finding_id": fid, "severity": severity})

@mcp.tool()
def create_artifact(engagement_id: str, finding_id: str, artifact_type: str,
                    file_path: str, file_hash: str, caption: str = "",
                    agent: str = "unknown", backend: str = "external",
                    capture_mode: str = "exploitable", file_size: int = 0,
                    mime_type: str = "text/plain") -> str:
    """Create an evidence artifact linked to a finding. Types: screenshot, http_pair, command_output, tool_log, response_diff."""
    aid = f"art-{uuid.uuid4().hex[:8]}"
    run_query("""
        CREATE (a:Artifact {
            id: $aid, engagement_id: $eid, finding_id: $fid,
            type: $type, file_path: $path, file_hash: $hash,
            file_size: $size, mime_type: $mime, caption: $caption,
            agent: $agent, backend: $backend, capture_mode: $mode,
            timestamp: datetime()
        })
        WITH a
        MATCH (f:Finding {id: $fid})
        MERGE (f)-[:HAS_ARTIFACT]->(a)
        WITH a
        MATCH (e:Engagement {id: $eid})
        MERGE (e)-[:HAS_EVIDENCE]->(a)
        RETURN a
    """, {"aid": aid, "eid": engagement_id, "fid": finding_id,
          "type": artifact_type, "path": file_path, "hash": file_hash,
          "size": file_size, "mime": mime_type, "caption": caption,
          "agent": agent, "backend": backend, "mode": capture_mode})
    return json.dumps({"artifact_id": aid, "type": artifact_type, "finding_id": finding_id})

@mcp.tool()
def query_graph(cypher: str, params: str = "{}") -> str:
    """Run a read-only Cypher query against the knowledge graph."""
    upper = cypher.upper()
    for keyword in ["CREATE", "DELETE", "SET", "REMOVE", "MERGE", "DROP", "DETACH"]:
        if keyword in upper:
            return json.dumps({"error": f"Write operation '{keyword}' not allowed. Use specific create_* tools."})
    p = json.loads(params)
    results = run_query(cypher, p)
    return json.dumps(results, default=str)

@mcp.tool()
def get_engagement_summary(engagement_id: str) -> str:
    """Get summary statistics for an engagement."""
    stats = {}
    for label, key in [("Host", "hosts"), ("Service", "services"),
                       ("Vulnerability", "vulnerabilities"), ("Finding", "findings"),
                       ("Credential", "credentials"), ("AttackPath", "attack_paths")]:
        r = run_query(f"MATCH (n:{label} {{engagement_id: $eid}}) RETURN count(n) AS c",
                      {"eid": engagement_id})
        stats[key] = r[0]["c"] if r else 0
    sevs = run_query("""
        MATCH (v:Vulnerability {engagement_id: $eid})
        RETURN v.severity AS severity, count(v) AS count
    """, {"eid": engagement_id})
    stats["severity_breakdown"] = {s["severity"]: s["count"] for s in sevs}
    return json.dumps(stats)

@mcp.tool()
def get_attack_surface(engagement_id: str) -> str:
    """Get all hosts and their services for an engagement."""
    results = run_query("""
        MATCH (h:Host {engagement_id: $eid})-[:HAS_SERVICE]->(s:Service)
        RETURN h.ip AS ip, h.hostname AS hostname, h.os AS os,
               collect({port: s.port, protocol: s.protocol,
                       name: s.name, version: s.version}) AS services
        ORDER BY h.ip
    """, {"eid": engagement_id})
    return json.dumps(results, default=str)

if __name__ == "__main__":
    mcp.run()
