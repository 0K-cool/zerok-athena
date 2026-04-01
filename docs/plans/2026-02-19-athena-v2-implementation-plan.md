# ATHENA v2.0 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement ATHENA v2.0 multi-agent AI pentesting platform with Neo4j knowledge graph, enhanced MCP tool servers, 4 new agents, and evolved dashboard — Stage 1 (own engagements).

**Architecture:** Claude Code Agent Teams orchestrate 13 specialist agents. Existing kali MCP bridge (FastMCP → Flask API on mini-PC) is enhanced with Neo4j result writing and scope enforcement. A new neo4j-mcp server provides graph operations. The single-file HTML dashboard evolves with engagement management, findings table, and attack graph visualization.

**Tech Stack:** Python 3.11+ (FastMCP, neo4j driver, Flask), Neo4j 5.x, Neovis.js 2.x, Claude Code Agent Teams (Opus 4.6 / Sonnet 4.5 / Haiku 4.5)

**Design Doc:** `docs/plans/2026-02-19-athena-v2-architecture-design.md`

**Mini-PC Required:** Tasks 1-3 and Task 12+ require ATHENA mini-PC to be powered on.

---

## Phase A: Foundation — Neo4j + neo4j-mcp (Week 1)

### Task 1: Install and Configure Neo4j on Mini-PC

**Files:**
- Create: `neo4j/install.sh`
- Create: `neo4j/schema.cypher`
- Create: `neo4j/neo4j.conf.patch`

**Prereqs:** Mini-PC powered on, SSH access via ZeroTier (`your-internal-kali`)

**Step 1: Write the Neo4j install script**

```bash
#!/usr/bin/env bash
# neo4j/install.sh — Install Neo4j Community 5.x on Kali (Debian-based)
set -euo pipefail

echo "[*] Adding Neo4j repository..."
wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo gpg --dearmor -o /usr/share/keyrings/neo4j.gpg
echo 'deb [signed-by=/usr/share/keyrings/neo4j.gpg] https://debian.neo4j.com stable latest' | \
  sudo tee /etc/apt/sources.list.d/neo4j.list

echo "[*] Installing Neo4j..."
sudo apt-get update
sudo apt-get install -y neo4j

echo "[*] Configuring Neo4j for LAN access..."
sudo sed -i 's/#server.default_listen_address=0.0.0.0/server.default_listen_address=0.0.0.0/' /etc/neo4j/neo4j.conf

echo "[*] Setting initial password..."
sudo neo4j-admin dbms set-initial-password $NEO4J_PASS

echo "[*] Starting Neo4j..."
sudo systemctl enable neo4j
sudo systemctl start neo4j

echo "[+] Neo4j installed. Bolt: bolt://your-internal-kali:7687  Browser: http://your-internal-kali:7474"
```

**Step 2: Write the schema creation script**

```cypher
// neo4j/schema.cypher — ATHENA v2.0 Knowledge Graph Schema

// Constraints (unique identifiers)
CREATE CONSTRAINT host_ip IF NOT EXISTS FOR (h:Host) REQUIRE h.ip IS UNIQUE;
CREATE CONSTRAINT domain_name IF NOT EXISTS FOR (d:Domain) REQUIRE d.name IS UNIQUE;
CREATE CONSTRAINT subdomain_name IF NOT EXISTS FOR (s:Subdomain) REQUIRE s.name IS UNIQUE;
CREATE CONSTRAINT vuln_id IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.id IS UNIQUE;
CREATE CONSTRAINT finding_id IF NOT EXISTS FOR (f:Finding) REQUIRE f.id IS UNIQUE;
CREATE CONSTRAINT engagement_id IF NOT EXISTS FOR (e:Engagement) REQUIRE e.id IS UNIQUE;
CREATE CONSTRAINT credential_id IF NOT EXISTS FOR (c:Credential) REQUIRE c.id IS UNIQUE;
CREATE CONSTRAINT exploit_result_id IF NOT EXISTS FOR (er:ExploitResult) REQUIRE er.id IS UNIQUE;
CREATE CONSTRAINT evidence_id IF NOT EXISTS FOR (ep:EvidencePackage) REQUIRE ep.id IS UNIQUE;

// Indexes (query performance)
CREATE INDEX host_engagement IF NOT EXISTS FOR (h:Host) ON (h.engagement_id);
CREATE INDEX service_port IF NOT EXISTS FOR (s:Service) ON (s.port);
CREATE INDEX vuln_severity IF NOT EXISTS FOR (v:Vulnerability) ON (v.severity);
CREATE INDEX finding_severity IF NOT EXISTS FOR (f:Finding) ON (f.severity);
CREATE INDEX engagement_status IF NOT EXISTS FOR (e:Engagement) ON (e.status);

// Node property type hints (documentation only — Neo4j 5.x)
// :Host {ip, hostname, os, os_version, status, first_seen, last_seen, engagement_id}
// :Service {port, protocol, name, version, banner, state, host_ip, engagement_id}
// :Domain {name, registrar, nameservers, whois_data, engagement_id}
// :Subdomain {name, resolved_ips, source, engagement_id}
// :URL {url, status_code, content_type, tech_stack, engagement_id}
// :Vulnerability {id, cve_id, name, description, cvss_score, severity, nuclei_template, status, engagement_id}
// :Credential {id, username, hash_type, hash_value, plaintext, source, domain, engagement_id}
// :AttackPath {id, name, steps, complexity, impact, probability, engagement_id}
// :ExploitResult {id, technique, target, success, output_hash, timestamp, agent_id, engagement_id}
// :EvidencePackage {id, type, data_hash, screenshots, http_pairs, timing_data, verified_by, engagement_id}
// :Finding {id, title, description, severity, cvss, remediation, references, status, engagement_id}
// :Engagement {id, name, client, scope, start_date, end_date, status, methodology}
// :Person {name, role, email, phone, social_profiles, source, engagement_id}
// :Organization {name, industry, size, technologies, engagement_id}
// :LeakedCredential {id, email, source_breach, password_hash, date_leaked, engagement_id}
```

**Step 3: SSH into mini-PC and run install**

```bash
scp neo4j/install.sh kali@your-internal-kali:~/athena-neo4j-install.sh
ssh kali@your-internal-kali "chmod +x ~/athena-neo4j-install.sh && sudo ~/athena-neo4j-install.sh"
```

Expected: Neo4j running on mini-PC, Bolt accessible at `bolt://your-internal-kali:7687`

**Step 4: Apply schema**

```bash
cat neo4j/schema.cypher | cypher-shell -u neo4j -p $NEO4J_PASS -a bolt://your-internal-kali:7687
```

Expected: All constraints and indexes created

**Step 5: Verify connectivity from MacBook**

```bash
pip install neo4j
python3 -c "
from neo4j import GraphDatabase
d = GraphDatabase.driver('bolt://your-internal-kali:7687', auth=('neo4j', '$NEO4J_PASS'))
with d.session() as s:
    r = s.run('RETURN 1 AS test')
    print('Neo4j OK:', r.single()['test'])
d.close()
"
```

Expected: `Neo4j OK: 1`

**Step 6: Commit**

```bash
git add neo4j/
git commit -m "feat: Add Neo4j install script and schema for ATHENA v2.0"
```

---

### Task 2: Build neo4j-mcp Server

**Files:**
- Create: `mcp-servers/neo4j-mcp/server.py`
- Create: `mcp-servers/neo4j-mcp/requirements.txt`
- Create: `mcp-servers/neo4j-mcp/tests/test_server.py`

**Step 1: Write the test file**

```python
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
```

**Step 2: Run tests to verify they pass (schema validation only)**

```bash
cd mcp-servers/neo4j-mcp && python -m pytest tests/test_server.py -v
```

Expected: All 5 tests PASS

**Step 3: Write the neo4j-mcp server**

```python
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

NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://your-internal-kali:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASS = os.environ.get("NEO4J_PASS", "$NEO4J_PASS")

mcp = FastMCP("athena-neo4j", description="ATHENA Knowledge Graph — Neo4j CRUD and Cypher queries")

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

# --- Engagement Management ---

@mcp.tool()
def create_engagement(name: str, client: str, scope: str,
                      methodology: str = "PTES",
                      engagement_type: str = "external") -> str:
    """Create a new engagement in the knowledge graph.

    Args:
        name: Engagement name (e.g. Client_2026-02-19_Web)
        client: Client name
        scope: JSON string of scope definition (targets, exclusions)
        methodology: Testing methodology (default: PTES)
        engagement_type: external, internal, web, or hybrid
    """
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

# --- Host/Service Management ---

@mcp.tool()
def create_host(ip: str, engagement_id: str, hostname: str = "",
                os_name: str = "", os_version: str = "") -> str:
    """Add a discovered host to the knowledge graph.

    Args:
        ip: IP address of the host
        engagement_id: Engagement this host belongs to
        hostname: Hostname if resolved
        os_name: Operating system name
        os_version: OS version
    """
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
    """Add a discovered service to a host.

    Args:
        host_ip: IP of the host running this service
        port: Port number
        protocol: tcp or udp
        engagement_id: Engagement ID
        name: Service name (e.g. http, ssh)
        version: Service version string
        banner: Service banner text
    """
    run_query("""
        MATCH (h:Host {ip: $ip, engagement_id: $eid})
        MERGE (s:Service {port: $port, protocol: $proto, host_ip: $ip, engagement_id: $eid})
        SET s.name = $name, s.version = $version, s.banner = $banner, s.state = 'open'
        MERGE (h)-[:HAS_SERVICE]->(s)
        RETURN s
    """, {"ip": host_ip, "port": port, "proto": protocol, "eid": engagement_id,
          "name": name, "version": version, "banner": banner})
    return json.dumps({"host": host_ip, "port": port, "status": "created"})

# --- Vulnerability Management ---

@mcp.tool()
def create_vulnerability(host_ip: str, port: int, name: str, severity: str,
                         engagement_id: str, cve_id: str = "",
                         cvss_score: float = 0.0, description: str = "",
                         nuclei_template: str = "") -> str:
    """Record a discovered vulnerability.

    Args:
        host_ip: Affected host IP
        port: Affected port
        name: Vulnerability name
        severity: CRITICAL, HIGH, MEDIUM, LOW, or INFO
        engagement_id: Engagement ID
        cve_id: CVE identifier if known
        cvss_score: CVSS v3.1 score (0-10)
        description: Vulnerability description
        nuclei_template: Nuclei template ID that found this
    """
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

# --- Credential Management ---

@mcp.tool()
def create_credential(username: str, engagement_id: str,
                      hash_type: str = "", hash_value: str = "",
                      plaintext: str = "", source: str = "",
                      domain: str = "") -> str:
    """Record a discovered credential.

    Args:
        username: Username
        engagement_id: Engagement ID
        hash_type: Hash type (NTLM, NTLMv2, SHA1, bcrypt, etc.)
        hash_value: Hash value
        plaintext: Plaintext password (if cracked)
        source: Where this credential was found
        domain: AD domain if applicable
    """
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

# --- Finding Management ---

@mcp.tool()
def create_finding(title: str, severity: str, engagement_id: str,
                   description: str = "", cvss: float = 0.0,
                   remediation: str = "", references: str = "",
                   affected_hosts: str = "") -> str:
    """Create a confirmed finding for the report.

    Args:
        title: Finding title
        severity: CRITICAL, HIGH, MEDIUM, LOW, INFO
        engagement_id: Engagement ID
        description: Detailed finding description
        cvss: CVSS v3.1 score
        remediation: Remediation recommendation
        references: JSON array of reference URLs
        affected_hosts: Comma-separated list of affected host IPs
    """
    fid = f"find-{uuid.uuid4().hex[:8]}"
    run_query("""
        CREATE (f:Finding {
            id: $fid, title: $title, severity: $sev, description: $desc,
            cvss: $cvss, remediation: $rem, references: $refs,
            status: 'confirmed', engagement_id: $eid, created_at: datetime()
        })
        WITH f
        MATCH (e:Engagement {id: $eid})
        MERGE (e)-[:CONTAINS]->(f)
        RETURN f
    """, {"fid": fid, "title": title, "sev": severity, "desc": description,
          "cvss": cvss, "rem": remediation, "refs": references, "eid": engagement_id})
    # Link to affected hosts
    if affected_hosts:
        for hip in affected_hosts.split(","):
            run_query("""
                MATCH (f:Finding {id: $fid}), (h:Host {ip: $ip, engagement_id: $eid})
                MERGE (f)-[:AFFECTS]->(h)
            """, {"fid": fid, "ip": hip.strip(), "eid": engagement_id})
    return json.dumps({"finding_id": fid, "severity": severity})

# --- Query Tools ---

@mcp.tool()
def query_graph(cypher: str, params: str = "{}") -> str:
    """Run a read-only Cypher query against the knowledge graph.

    Args:
        cypher: Cypher query (READ ONLY — no CREATE/DELETE/SET)
        params: JSON string of query parameters
    """
    # Safety: block write operations
    upper = cypher.upper()
    for keyword in ["CREATE", "DELETE", "SET", "REMOVE", "MERGE", "DROP", "DETACH"]:
        if keyword in upper:
            return json.dumps({"error": f"Write operation '{keyword}' not allowed. Use specific create_* tools."})
    p = json.loads(params)
    results = run_query(cypher, p)
    return json.dumps(results, default=str)

@mcp.tool()
def get_engagement_summary(engagement_id: str) -> str:
    """Get summary statistics for an engagement.

    Args:
        engagement_id: Engagement ID
    """
    stats = {}
    for label, key in [("Host", "hosts"), ("Service", "services"),
                       ("Vulnerability", "vulnerabilities"), ("Finding", "findings"),
                       ("Credential", "credentials"), ("AttackPath", "attack_paths")]:
        r = run_query(f"MATCH (n:{label} {{engagement_id: $eid}}) RETURN count(n) AS c",
                      {"eid": engagement_id})
        stats[key] = r[0]["c"] if r else 0
    # Severity breakdown
    sevs = run_query("""
        MATCH (v:Vulnerability {engagement_id: $eid})
        RETURN v.severity AS severity, count(v) AS count
    """, {"eid": engagement_id})
    stats["severity_breakdown"] = {s["severity"]: s["count"] for s in sevs}
    return json.dumps(stats)

@mcp.tool()
def get_attack_surface(engagement_id: str) -> str:
    """Get all hosts and their services for an engagement.

    Args:
        engagement_id: Engagement ID
    """
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
```

**Step 4: Write requirements.txt**

```
mcp[cli]>=1.0.0
neo4j>=5.0.0
```

**Step 5: Test server starts without errors**

```bash
cd mcp-servers/neo4j-mcp
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -c "from server import mcp; print('Server module loads OK')"
```

Expected: `Server module loads OK`

**Step 6: Add neo4j-mcp to `.mcp.json`**

Add to the existing `.mcp.json`:
```json
{
  "athena-neo4j": {
    "command": "/Users/kelvinlomboy/VERSANT/Projects/ATHENA/mcp-servers/neo4j-mcp/.venv/bin/python",
    "args": ["/Users/kelvinlomboy/VERSANT/Projects/ATHENA/mcp-servers/neo4j-mcp/server.py"],
    "env": {
      "NEO4J_URI": "bolt://your-internal-kali:7687",
      "NEO4J_USER": "neo4j",
      "NEO4J_PASS": "$NEO4J_PASS"
    },
    "description": "ATHENA Knowledge Graph — Neo4j CRUD and Cypher queries"
  }
}
```

**Step 7: Verify MCP connection**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA && claude mcp list
```

Expected: `athena-neo4j` appears in the MCP server list

**Step 8: Commit**

```bash
git add mcp-servers/neo4j-mcp/ .mcp.json
git commit -m "feat: Add neo4j-mcp server for knowledge graph operations"
```

---

### Task 3: Enhance Kali MCP with Scope Enforcement and Neo4j Integration

**Files:**
- Modify: `/Users/kelvinlomboy/VERSANT/MCPs/mcp-kali-linux-main/mcp_server.py`
- Create: `mcp-servers/kali-neo4j-bridge/bridge.py`

**Context:** The existing kali MCP (FastMCP) proxies to a Flask API on the mini-PC. Rather than modifying the third-party MCP, we create a middleware bridge that intercepts tool results and writes them to Neo4j.

**Step 1: Create the Kali-Neo4j bridge module**

This is a helper module that agents import to post-process kali MCP results into Neo4j.

```python
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
```

**Step 2: Write tests for the bridge**

```python
# mcp-servers/kali-neo4j-bridge/tests/test_bridge.py
from bridge import parse_naabu_results, parse_nuclei_results, parse_httpx_results, validate_scope

def test_parse_naabu_text():
    raw = "10.0.0.5:80\n10.0.0.5:443\n10.0.0.6:22"
    results = parse_naabu_results(raw, "eng-001")
    assert len(results) == 3
    assert results[0] == {"ip": "10.0.0.5", "port": 80, "protocol": "tcp"}

def test_parse_naabu_json():
    raw = '{"ip":"10.0.0.5","port":80}\n{"ip":"10.0.0.5","port":443}'
    results = parse_naabu_results(raw, "eng-001")
    assert len(results) == 2

def test_validate_scope_cidr():
    scope = {"targets": ["10.0.0.0/24"], "exclusions": ["10.0.0.1"]}
    assert validate_scope("10.0.0.5", scope) == True
    assert validate_scope("10.0.0.1", scope) == False  # excluded
    assert validate_scope("192.168.1.1", scope) == False  # out of range

def test_validate_scope_wildcard():
    scope = {"targets": ["*.example.com"], "exclusions": []}
    assert validate_scope("web.example.com", scope) == True
    assert validate_scope("other.com", scope) == False
```

**Step 3: Run tests**

```bash
cd mcp-servers/kali-neo4j-bridge && python -m pytest tests/ -v
```

Expected: All tests PASS

**Step 4: Commit**

```bash
git add mcp-servers/kali-neo4j-bridge/
git commit -m "feat: Add Kali-Neo4j bridge for result parsing and scope enforcement"
```

---

## Phase B: Agent Modernization (Week 2)

### Task 4: Update Passive Recon (PR) Agent

**Files:**
- Modify: `.claude/agents/passive-osint-agent.md`

**Changes:**
1. Add Neo4j output — all OSINT results write to knowledge graph via neo4j-mcp
2. Expand OSINT categories — infrastructure, people/org, credential, technology
3. Add new MCP tool references — subfinder (via kali_internal), gau_discover, shodan (if key available)
4. Add engagement_id parameter threading

**Step 1: Rewrite agent with Neo4j integration and expanded OSINT**

Update the agent markdown to include:
- Mission section: Add "Write all discoveries to Neo4j knowledge graph"
- Input Parameters: Add `engagement_id` as required field
- New OSINT sections:
  - Infrastructure OSINT: CT logs, subfinder, GAU, DNS records, WHOIS
  - People/Organization OSINT: Public records, org charts, job postings
  - Credential OSINT: HaveIBeenPwned, breach databases, GitHub dorking
  - Technology OSINT: Wappalyzer, BuiltWith, httpx tech detection
- Each tool section: Add "Neo4j Write" step using `create_host`, `create_subdomain`, `create_person`, etc.
- Post-flight: Summary of all nodes created in Neo4j

**Step 2: Commit**

```bash
git add .claude/agents/passive-osint-agent.md
git commit -m "feat: Update PR agent with Neo4j integration and expanded OSINT"
```

---

### Task 5: Update Active Recon (AR) Agent

**Files:**
- Modify: `.claude/agents/active-recon-agent.md`

**Changes:**
1. Replace legacy tool references (DNSRecon, Nmap-only) with ProjectDiscovery pipeline
2. Add Neo4j output for all scan results
3. Reference Kali-Neo4j bridge parsers for structured output
4. Add scope validation step using bridge.validate_scope()
5. Update scanning pipeline: `naabu_scan → httpx_probe → service fingerprinting`

**Step 1: Rewrite agent scanning pipeline**

Update the agent to use:
- `naabu_scan` (kali_internal MCP) for port discovery → parse with bridge → write hosts/services to Neo4j
- `httpx_probe` (kali_internal MCP) for HTTP probing → parse → write URLs to Neo4j
- `nmap_scan` (kali_internal MCP) for deep service fingerprinting on discovered ports → write to Neo4j
- Pre-flight: Validate all targets against scope using Neo4j engagement scope
- Post-flight: `get_engagement_summary` to report discovery statistics

**Step 2: Commit**

```bash
git add .claude/agents/active-recon-agent.md
git commit -m "feat: Update AR agent with ProjectDiscovery pipeline and Neo4j"
```

---

### Task 6: Update Vulnerability Scanner (VS) and Web Vuln Scanner (WV) Agents

**Files:**
- Modify: `.claude/agents/cve-researcher.md` (VS)
- Modify: `.claude/agents/web-vuln-scanner-agent.md` (WV)

**Changes to VS (cve-researcher.md):**
1. Use `nuclei_scan` with network templates for infrastructure vuln scanning
2. Parse nuclei JSON output → write Vulnerability nodes to Neo4j
3. Add CVE correlation (query Neo4j for known CVEs matching services)
4. Reference engagement_id throughout

**Changes to WV (web-vuln-scanner-agent.md):**
1. Use `katana_crawl` for endpoint discovery → write URLs to Neo4j
2. Use `nuclei_scan` with web + DAST templates
3. Add authenticated scanning workflow (inject session cookies)
4. Parse results → write Vulnerability nodes to Neo4j

**Step 1: Update both agents with Neo4j-integrated scanning workflows**

**Step 2: Commit**

```bash
git add .claude/agents/cve-researcher.md .claude/agents/web-vuln-scanner-agent.md
git commit -m "feat: Update VS/WV agents with Nuclei pipeline and Neo4j"
```

---

### Task 7: Update Exploitation (EX) and Post-Exploitation (PE) Agents

**Files:**
- Modify: `.claude/agents/exploitation-agent.md`
- Modify: `.claude/agents/post-exploitation-agent.md`

**Changes to EX:**
1. Read attack paths from Neo4j (query_graph) instead of flat files
2. Produce ExploitResult JSON schema (technique, target, predicted_impact, payload)
3. Write ExploitResult to Neo4j via neo4j-mcp
4. HITL gate enforcement — emit `approval_request` to dashboard before execution
5. After execution, create EvidencePackage stub for Verification Agent

**Changes to PE:**
1. Use crackmapexec_scan (existing kali MCP tool) for AD enumeration
2. Write Credential nodes to Neo4j after each discovery
3. Each lateral movement → create new Host relationships in Neo4j
4. Pivot loop: after gaining new access, trigger AR → VS re-scan on new scope

**Step 1: Update both agents**

**Step 2: Commit**

```bash
git add .claude/agents/exploitation-agent.md .claude/agents/post-exploitation-agent.md
git commit -m "feat: Update EX/PE agents with Neo4j state and HITL gates"
```

---

### Task 8: Update Orchestrator (EO), Report Generator (RG), and Cleanup (CV) Agents

**Files:**
- Modify: `.claude/agents/orchestrator-agent.md`
- Modify: `.claude/agents/reporting-agent.md`
- Modify: `.claude/agents/planning-agent.md` (rename role to CV/Cleanup)

**Changes to EO:**
1. Use Agent Teams dispatch pattern (spawn specialist agents via Task tool)
2. Phase management via Neo4j (track current PTES phase per engagement)
3. Engagement initialization: create Engagement node, validate scope
4. Phase transitions: emit `phase_update` to dashboard WebSocket
5. Cross-agent coordination: pass engagement_id to all agents

**Changes to RG:**
1. Query Neo4j for all findings, evidence, attack paths
2. Use `get_engagement_summary` for executive summary statistics
3. Generate white-label reports via `branding.yml` or `/versant-docs`
4. CVSS auto-scoring from Vulnerability nodes

**Changes to CV (planning-agent.md → cleanup-agent.md):**
1. Query Neo4j for all artifacts created during engagement
2. Verify artifact removal
3. Archive engagement in Neo4j (set status = 'completed')

**Step 1: Update all three agents**

**Step 2: Commit**

```bash
git add .claude/agents/orchestrator-agent.md .claude/agents/reporting-agent.md .claude/agents/planning-agent.md
git commit -m "feat: Update EO/RG/CV agents with Agent Teams and Neo4j"
```

---

## Phase C: New Agents (Week 3)

### Task 9: Create Verification Agent (VA)

**Files:**
- Create: `.claude/agents/verification-agent.md`

**Agent Definition:**

```markdown
# Verification Agent

**Role**: Independent Exploit Verification
**Specialization**: Re-execute exploits independently, capture structured evidence
**Model**: Sonnet 4.5 (never the same model instance as the finding agent)

## Mission

Independently verify exploit results produced by the Exploitation Agent.
You are the "second pair of eyes" — your job is to confirm or deny findings
with deterministic evidence, not LLM judgment.

**CRITICAL**: You must NEVER trust the Exploitation Agent's output at face value.
Re-execute the exploit independently and capture your own evidence.

## Input: ExploitResult (from Neo4j)

Query: MATCH (er:ExploitResult {status: 'pending_verification', engagement_id: $eid})

## Output: EvidencePackage

Write to Neo4j via create_evidence_package() with:
- HTTP request/response pairs (raw)
- Timing data (baseline vs exploit execution)
- Screenshots (if web-based)
- Response diffs (baseline vs exploit response)
- Confidence: HIGH/MEDIUM/LOW

## Verification Methods by Vulnerability Type

[Table from design doc Section 5]

## Workflow

1. Query Neo4j for pending ExploitResults
2. For each ExploitResult:
   a. Read technique, target, payload
   b. Execute baseline request (no payload) → capture response
   c. Execute exploit request (with payload) → capture response
   d. Compare: timing delta, response length delta, unique strings
   e. If web: take screenshot via Playwright MCP
   f. Package evidence → write EvidencePackage to Neo4j
   g. Update ExploitResult status: 'verified' or 'unconfirmed'
3. Report summary to Orchestrator
```

**Step 1: Write the full agent markdown file**

**Step 2: Commit**

```bash
git add .claude/agents/verification-agent.md
git commit -m "feat: Add Verification Agent for independent exploit confirmation"
```

---

### Task 10: Create Attack Path Analyzer (APA) Agent

**Files:**
- Create: `.claude/agents/attack-path-analyzer-agent.md`

**Agent Definition:**

```markdown
# Attack Path Analyzer Agent

**Role**: Kill Chain Discovery via Graph Traversal
**Specialization**: Neo4j graph queries to find multi-step attack paths
**Model**: Opus 4.6 (requires strategic reasoning about attack chains)

## Mission

Analyze the knowledge graph to discover multi-step attack paths from
external entry points to high-value targets (domain controllers, databases,
critical infrastructure). Prioritize paths by complexity and impact.

## Workflow

1. Query Neo4j for all hosts, services, vulnerabilities in engagement
2. Identify entry points (internet-facing hosts with vulns)
3. Identify high-value targets (DCs, databases, key servers)
4. Run shortest-path and all-paths queries
5. Score paths: complexity * probability * impact
6. Create AttackPath nodes in Neo4j
7. If BloodHound data available: query AD paths
8. Report prioritized attack paths to Orchestrator

## Key Cypher Queries

[Include attack path queries from design doc Section 4]
```

**Step 1: Write the full agent markdown file**

**Step 2: Commit**

```bash
git add .claude/agents/attack-path-analyzer-agent.md
git commit -m "feat: Add Attack Path Analyzer agent for kill chain discovery"
```

---

### Task 11: Create Exploit Crafter (EC) and Detection Validator (DV) Agents

**Files:**
- Create: `.claude/agents/exploit-crafter-agent.md`
- Create: `.claude/agents/detection-validator-agent.md`

**EC Agent:** Generates novel payloads when existing exploits don't match. Self-verification loop: generate → test in sandbox → iterate (max 3) → submit ExploitResult.
- Model: Opus 4.6
- References: Big Sleep pattern, XBOW self-verification

**DV Agent:** Purple team capability. After exploitation, checks if defensive controls detected the activity.
- Model: Sonnet 4.5
- Workflow: Query SIEM/EDR (if available) → check for alerts matching exploit timestamp → create Detection Coverage report
- Outputs: Detection coverage matrix (found/missed by technique)

**Step 1: Write both agent markdown files**

**Step 2: Commit**

```bash
git add .claude/agents/exploit-crafter-agent.md .claude/agents/detection-validator-agent.md
git commit -m "feat: Add Exploit Crafter and Detection Validator agents"
```

---

## Phase D: Dashboard Evolution (Week 4)

### Task 12: Add Engagement Management to Dashboard

**Files:**
- Modify: `tools/athena-dashboard/server.py`
- Modify: `tools/athena-dashboard/index.html`

**Server Changes (server.py):**

Add REST API endpoints:
```python
@app.get("/api/engagements")
# Query Neo4j for all engagements via neo4j driver

@app.post("/api/engagements")
# Create new engagement in Neo4j

@app.get("/api/engagements/{eid}/summary")
# Get engagement stats from Neo4j
```

Add WebSocket message:
```python
# engagement_changed — broadcast when active engagement switches
```

**Dashboard Changes (index.html):**

1. **AI Drawer Header:** Add engagement selector dropdown above agent chips
   - `<select id="engagement-select">` populated from `/api/engagements`
   - Changing selection reloads timeline and stats

2. **Sidebar:** Add engagement list section
   - Green dot = active, gray = completed
   - Click to switch engagement
   - "+ New Engagement" button opens creation form

3. **CSS:** Engagement selector styling, sidebar engagement list

**Step 1: Add server API endpoints for engagements**

**Step 2: Add engagement selector to AI drawer header**

**Step 3: Add engagement list to sidebar**

**Step 4: Test in browser — launch dashboard, verify engagement switching**

```bash
cd tools/athena-dashboard && ./start.sh
# Open http://localhost:8080
# Verify: engagement dropdown visible, sidebar shows engagement list
```

**Step 5: Commit**

```bash
git add tools/athena-dashboard/
git commit -m "feat: Add engagement management to dashboard"
```

---

### Task 13: Add Findings Table to Dashboard

**Files:**
- Modify: `tools/athena-dashboard/server.py`
- Modify: `tools/athena-dashboard/index.html`

**Server Changes:**

```python
@app.get("/api/engagements/{eid}/findings")
# Query Neo4j: MATCH (f:Finding {engagement_id: $eid}) RETURN f ORDER BY f.cvss DESC

@app.get("/api/engagements/{eid}/findings/{fid}/evidence")
# Query Neo4j: MATCH (f:Finding {id: $fid})-[:EVIDENCED_BY]->(ep:EvidencePackage) RETURN ep
```

**Dashboard Changes:**

1. Add "Findings" tab to main content area
2. Sortable/filterable table: ID, Title, Severity (color badge), CVSS, Status, Evidence count
3. Click row → expand to show evidence (HTTP pairs, screenshots, timing data)
4. Severity filter chips: CRITICAL | HIGH | MEDIUM | LOW

**Step 1: Add server endpoints**

**Step 2: Add findings tab HTML/CSS/JS**

**Step 3: Test — create test findings via neo4j-mcp, verify they appear in table**

**Step 4: Commit**

```bash
git add tools/athena-dashboard/
git commit -m "feat: Add findings table with evidence gallery to dashboard"
```

---

### Task 14: Add Attack Graph Visualization (Neovis.js)

**Files:**
- Modify: `tools/athena-dashboard/index.html`
- Modify: `tools/athena-dashboard/server.py`

**Dashboard Changes:**

1. Add Neovis.js CDN link: `<script src="https://unpkg.com/neovis.js@2.1.0"></script>`
2. Add "Attack Graph" tab with `<div id="attack-graph">` container
3. Configure Neovis with node colors by type (Host=green, Vulnerability=red, etc.)
4. Connect to Neo4j via Bolt (browser → Neo4j directly, not through server)
5. Add graph interaction: click node → show details panel, hover → highlight connections

**Server Changes:**

```python
@app.get("/api/neo4j-config")
# Return Neo4j connection details for browser-side Neovis.js
# (URI, user, read-only credentials)
```

**Step 1: Add Neovis.js CDN and attack graph tab**

**Step 2: Configure graph visualization with node/relationship styling**

**Step 3: Add interaction handlers (click, hover)**

**Step 4: Test with sample data in Neo4j**

**Step 5: Commit**

```bash
git add tools/athena-dashboard/
git commit -m "feat: Add attack graph visualization with Neovis.js"
```

---

## Phase E: Integration Testing (Week 4)

### Task 15: End-to-End Dry Run

**Files:**
- Create: `engagements/DryRun_v2_YYYY-MM-DD/scope.yml`

**Prereqs:** Mini-PC powered on, Neo4j running, all MCP servers connected

**Step 1: Create dry run scope**

```yaml
# engagements/DryRun_v2_YYYY-MM-DD/scope.yml
engagement:
  name: "DryRun_v2_2026-XX-XX"
  client: "ATHENA Test Lab"
  type: "external"
  scope:
    targets:
      - 172.26.80.0/24  # Mini-PC network
    exclusions:
      - 172.26.80.1    # Gateway
    allowed_ports: [1-65535]
    testing_window: "24/7"
    rules_of_engagement: "Test lab — no restrictions"
```

**Step 2: Test neo4j-mcp — create engagement**

Use Claude Code in ATHENA directory:
```
Create an engagement named DryRun_v2 for ATHENA Test Lab targeting 172.26.80.0/24
```

Verify: Engagement node appears in Neo4j

**Step 3: Test PR agent — run OSINT**

```
Run passive reconnaissance on DryRun_v2 engagement
```

Verify: Subdomain, Domain, URL nodes appear in Neo4j

**Step 4: Test AR agent — run active recon**

```
Run active reconnaissance for DryRun_v2 — scan your-internal-kali with naabu and httpx
```

Verify: Host and Service nodes appear in Neo4j

**Step 5: Test VS/WV agents — run vulnerability scanning**

```
Run vulnerability scanning for DryRun_v2 with nuclei
```

Verify: Vulnerability nodes appear in Neo4j

**Step 6: Test APA agent — analyze attack paths**

```
Analyze attack paths for DryRun_v2 engagement
```

Verify: AttackPath nodes appear in Neo4j

**Step 7: Test dashboard — verify all views**

Open http://localhost:8080:
- [ ] Engagement selector shows DryRun_v2
- [ ] Agent timeline shows real scanning activity
- [ ] Findings table shows discovered vulnerabilities
- [ ] Attack graph renders hosts and connections
- [ ] Phase badge progresses through PTES phases

**Step 8: Commit dry run results**

```bash
git add engagements/DryRun_v2_*/
git commit -m "test: Complete ATHENA v2.0 end-to-end dry run"
```

---

## Phase F: Internal Pentest Tools (Stage 2 Preview — Optional Week 4)

### Task 16: Add BloodHound MCP Server

**Files:**
- Create: `mcp-servers/bloodhound-mcp/server.py`
- Create: `mcp-servers/bloodhound-mcp/requirements.txt`

**Prereqs:** BloodHound CE installed on mini-PC with API enabled

This is a stretch goal for Stage 1. The MCP server wraps BloodHound CE REST API for:
- Importing SharpHound/BloodHound-python collection data
- Querying AD attack paths (shortest path to DA, Kerberoastable users, etc.)
- Exporting path data to Neo4j engagement graph

**Step 1: Write BloodHound API wrapper**

**Step 2: Add to `.mcp.json`**

**Step 3: Test AD path queries**

**Step 4: Commit**

```bash
git add mcp-servers/bloodhound-mcp/
git commit -m "feat: Add BloodHound MCP server for AD attack path analysis"
```

---

## Dependency Graph

```
Task 1 (Neo4j Setup)
  └──▶ Task 2 (neo4j-mcp)
        ├──▶ Task 3 (Kali-Neo4j Bridge)
        │     ├──▶ Task 4 (PR Agent)
        │     ├──▶ Task 5 (AR Agent)
        │     ├──▶ Task 6 (VS/WV Agents)
        │     ├──▶ Task 7 (EX/PE Agents)
        │     └──▶ Task 8 (EO/RG/CV Agents)
        ├──▶ Task 9 (Verification Agent)
        ├──▶ Task 10 (Attack Path Analyzer)
        ├──▶ Task 11 (Exploit Crafter / Detection Validator)
        ├──▶ Task 12 (Dashboard: Engagements)
        ├──▶ Task 13 (Dashboard: Findings)
        └──▶ Task 14 (Dashboard: Attack Graph)

Tasks 4-11 can be parallelized (independent agent files)
Tasks 12-14 can be parallelized (independent dashboard features)
Task 15 (Dry Run) depends on ALL above
Task 16 (BloodHound) is independent stretch goal
```

---

## Risk Notes

1. **Mini-PC availability:** Tasks 1, 3, 15 need it running. Kelvin must power on before starting.
2. **Neo4j password:** `$NEO4J_PASS` is a placeholder — move to 1Password before any client work.
3. **Kali MCP API key:** Currently hardcoded in `.mcp.json` — move to env var.
4. **Neovis.js browser-to-Neo4j:** Requires Neo4j to be accessible from browser (CORS config needed).
5. **Agent testing:** No unit tests for markdown agents — validation is via dry run (Task 15).

---

**Estimated Effort:** 4 weeks (solo + AI), ~80-120 hours total
**Stage 2 (Productize) plan:** Created separately after Stage 1 dry run validates architecture

---

## Phase G: Parallel Agent Isolation (Worktrees)

**Added:** February 27, 2026
**Prerequisite:** Phase F bilateral messaging (F2)
**Effort:** 1-2 weeks | **Impact:** 3-5x engagement speed

Uses Claude Code `isolation: "worktree"` (v2.1.49+) to give each agent its own git worktree — true parallel execution with zero file conflicts.

**Components:**
- **G1:** WorktreeCreate security hook — propagates CLAUDE.md, .mcp.json, security constraints to isolated agents (BLOCKING)
- **G2:** WorktreeRemove audit hook — scans for credential leakage before cleanup
- **G3:** Agent definition updates — add `isolation: "worktree"` to agent configs
- **G4:** Evidence merge pipeline — Neo4j as primary store, worktree filesystem is scratch only

**Target:** 4-5 concurrent agents, <15 min engagement duration (vs ~30-45 min sequential)

**Full plan:** `docs/PHASE-F-PLAN.md` (Phase G section)
