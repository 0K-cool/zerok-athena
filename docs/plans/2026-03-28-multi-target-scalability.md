# Multi-Target Scalability Architecture — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable ATHENA to pentest networks with 10-1000+ hosts, thousands of findings, proper per-host dedup, and scalable report generation.

**Architecture:** Phased approach — P1 (scope parsing + host-aware data model), P2 (per-host agent routing + indexed queries), P3 (paginated reporting + pre-aggregated data), P4 (dashboard scaling + virtual scrolling). Each phase delivers a working, testable improvement.

**Tech Stack:** Python/FastAPI (server.py), Neo4j (graph model), JavaScript (index.html dashboard), Claude Agent SDK (agent orchestration)

**Current state:** All code validated against 1 Metasploitable host. 42-73 findings per engagement. 7 concurrent agents max.

**Target state:** 10-1000+ hosts. 200-50,000 findings. Subnet-based agent teams. Per-host reports. <3s dashboard load at any scale.

---

## Phase 1: Scope Parsing + Host-Aware Data Model

**Goal:** ATHENA understands multi-host scope and every finding links to a specific host.

---

### Task 1: Scope Parser — Parse CIDR, Comma-Separated, Hostname Lists

**Files:**
- Create: `tools/athena-dashboard/scope_parser.py`
- Modify: `tools/athena-dashboard/server.py` (engagement creation endpoint)
- Test: `tools/athena-dashboard/tests/test_scope_parser.py`

- [ ] **Step 1: Write failing tests for scope parsing**

```python
# tests/test_scope_parser.py
from scope_parser import parse_scope, ScopeTarget

def test_single_ip():
    targets = parse_scope("10.1.1.25")
    assert len(targets) == 1
    assert targets[0].ip == "10.1.1.25"
    assert targets[0].cidr is None

def test_cidr_32():
    targets = parse_scope("10.1.1.25/32")
    assert len(targets) == 1
    assert targets[0].ip == "10.1.1.25"

def test_cidr_24():
    targets = parse_scope("10.1.1.0/24")
    assert len(targets) == 1
    assert targets[0].ip is None
    assert targets[0].cidr == "10.1.1.0/24"
    assert targets[0].host_count == 254

def test_comma_separated():
    targets = parse_scope("10.1.1.25, 10.1.1.26, 10.1.1.30")
    assert len(targets) == 3

def test_mixed_scope():
    targets = parse_scope("10.1.1.0/24, 192.168.1.100, web.target.com")
    assert len(targets) == 3
    assert targets[2].hostname == "web.target.com"

def test_hostname():
    targets = parse_scope("metasploitable.local")
    assert len(targets) == 1
    assert targets[0].hostname == "metasploitable.local"

def test_empty_scope():
    targets = parse_scope("")
    assert len(targets) == 0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd tools/athena-dashboard && python3 -m pytest tests/test_scope_parser.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'scope_parser'`

- [ ] **Step 3: Implement scope parser**

```python
# scope_parser.py
"""Parse engagement scope into structured target list.

Supports: single IP, CIDR ranges, comma-separated lists, hostnames,
and mixed formats. Returns structured ScopeTarget objects.
"""
import ipaddress
import re
from dataclasses import dataclass, field


@dataclass
class ScopeTarget:
    """A single target in the engagement scope."""
    ip: str | None = None           # Single IP (e.g., "10.1.1.25")
    cidr: str | None = None         # CIDR range (e.g., "10.1.1.0/24")
    hostname: str | None = None     # Hostname (e.g., "web.target.com")
    host_count: int = 1             # Number of hosts in this target
    ports: list[int] = field(default_factory=list)  # Specific ports if provided

    @property
    def display_name(self) -> str:
        return self.ip or self.cidr or self.hostname or "unknown"

    @property
    def is_single_host(self) -> bool:
        return self.host_count == 1


def parse_scope(scope_string: str) -> list[ScopeTarget]:
    """Parse a scope string into a list of ScopeTarget objects.

    Formats supported:
    - Single IP: "10.1.1.25"
    - CIDR: "10.1.1.0/24"
    - Comma-separated: "10.1.1.25, 10.1.1.26"
    - Hostname: "web.target.com"
    - Mixed: "10.1.1.0/24, 192.168.1.100, web.target.com"
    - With ports: "10.1.1.25:8080" (port extracted, stored separately)
    """
    if not scope_string or not scope_string.strip():
        return []

    targets = []
    # Split on comma, semicolon, or newline
    parts = re.split(r'[,;\n]+', scope_string)

    for part in parts:
        part = part.strip()
        if not part:
            continue

        # Extract port if present (ip:port format)
        port = None
        port_match = re.match(r'^(.+):(\d{1,5})$', part)
        if port_match and not part.startswith('http'):
            part = port_match.group(1)
            port = int(port_match.group(2))

        target = _parse_single_target(part)
        if port and target:
            target.ports = [port]
        if target:
            targets.append(target)

    return targets


def _parse_single_target(s: str) -> ScopeTarget | None:
    """Parse a single scope entry."""
    s = s.strip()
    if not s:
        return None

    # CIDR notation
    if '/' in s:
        try:
            network = ipaddress.ip_network(s, strict=False)
            if network.prefixlen == 32:
                return ScopeTarget(ip=str(network.network_address), host_count=1)
            return ScopeTarget(
                cidr=str(network),
                host_count=max(1, network.num_addresses - 2),  # Exclude network + broadcast
            )
        except ValueError:
            pass

    # Single IP
    try:
        addr = ipaddress.ip_address(s)
        return ScopeTarget(ip=str(addr), host_count=1)
    except ValueError:
        pass

    # Hostname
    if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$', s):
        return ScopeTarget(hostname=s, host_count=1)

    return None


def expand_scope_to_hosts(targets: list[ScopeTarget]) -> list[str]:
    """Expand scope targets to individual host IPs/hostnames for agent dispatch.

    For CIDRs, returns individual IPs (up to a limit to prevent /16 explosion).
    For hostnames, returns hostname as-is (DNS resolution happens at scan time).
    """
    MAX_EXPAND = 1024  # Safety limit — don't expand /16 into 65K hosts
    hosts = []
    for t in targets:
        if t.ip:
            hosts.append(t.ip)
        elif t.cidr:
            try:
                network = ipaddress.ip_network(t.cidr, strict=False)
                expanded = [str(ip) for ip in network.hosts()]
                if len(expanded) > MAX_EXPAND:
                    # Too large to expand — return CIDR as-is for subnet-level scanning
                    hosts.append(t.cidr)
                else:
                    hosts.extend(expanded)
            except ValueError:
                hosts.append(t.cidr)
        elif t.hostname:
            hosts.append(t.hostname)
    return hosts


def estimate_engagement_scale(targets: list[ScopeTarget]) -> dict:
    """Estimate engagement scale for resource planning."""
    total_hosts = sum(t.host_count for t in targets)
    return {
        "total_targets": len(targets),
        "total_hosts": total_hosts,
        "has_cidr": any(t.cidr for t in targets),
        "has_hostnames": any(t.hostname for t in targets),
        "scale": (
            "small" if total_hosts <= 10
            else "medium" if total_hosts <= 100
            else "large" if total_hosts <= 1000
            else "enterprise"
        ),
        "recommended_agent_teams": max(1, total_hosts // 50),  # 1 team per 50 hosts
        "estimated_findings": total_hosts * 5,  # ~5 findings per host average
        "estimated_cost_usd": total_hosts * 0.50,  # ~$0.50 per host average
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd tools/athena-dashboard && python3 -m pytest tests/test_scope_parser.py -v`
Expected: All 7 tests PASS

- [ ] **Step 5: Commit**

```bash
git add tools/athena-dashboard/scope_parser.py tools/athena-dashboard/tests/test_scope_parser.py
git commit -m "feat: scope parser — CIDR, comma-separated, hostname support"
```

---

### Task 2: Host-Aware Finding Model — Add host_ip to Finding Neo4j Node

**Files:**
- Modify: `tools/athena-dashboard/agent_session_manager.py` (bus MERGE adds host_ip)
- Modify: `tools/athena-dashboard/server.py` (POST /api/findings adds host_ip, indexes)
- Modify: `tools/athena-dashboard/finding_utils.py` (fingerprint uses host_ip consistently)

- [ ] **Step 1: Add Neo4j index on Finding.host_ip**

In `server.py`, find the Neo4j index creation block (around line 685). Add:

```python
session.run("CREATE INDEX finding_host_ip IF NOT EXISTS FOR (f:Finding) ON (f.host_ip)")
session.run("CREATE INDEX finding_engagement_host IF NOT EXISTS FOR (f:Finding) ON (f.engagement_id, f.host_ip)")
```

- [ ] **Step 2: Ensure bus path always writes host_ip to Finding node**

In `agent_session_manager.py`, `_bus_to_neo4j`, the MERGE SET clause: verify `f.host_ip` is being set from `_host_ip` (the extracted IP from target/title/summary). If not, add:

```cypher
f.host_ip = CASE WHEN $host_ip <> '' THEN $host_ip ELSE f.host_ip END,
```

And add `host_ip=_host_ip or "",` to the params dict.

- [ ] **Step 3: Ensure POST path writes host_ip**

In `server.py`, `create_finding`, the `_write_finding` MERGE: verify `f.host_ip` is being set from `host_ip`. If not, add it.

- [ ] **Step 4: Add per-host exploit-stats query**

In `server.py`, add a new endpoint:

```python
@app.get("/api/engagements/{eid}/exploit-stats/by-host")
async def get_exploit_stats_by_host(eid: str):
    """Get exploit stats grouped by host IP."""
    # Neo4j query with GROUP BY host_ip
    result = session.run("""
        MATCH (f:Finding {engagement_id: $eid})
        WHERE f.host_ip IS NOT NULL AND f.host_ip <> ''
        WITH f.host_ip AS host,
             count(f) AS total,
             size([x IN collect(f) WHERE x.status = 'confirmed']) AS confirmed
        RETURN host, total, confirmed
        ORDER BY confirmed DESC
    """, eid=eid)
```

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: host-aware finding model — host_ip on Finding nodes + per-host stats"
```

---

### Task 3: Scope Integration — Wire Parser into Engagement Creation

**Files:**
- Modify: `tools/athena-dashboard/server.py` (engagement creation + scope endpoint)

- [ ] **Step 1: Import scope_parser in server.py**

```python
from scope_parser import parse_scope, estimate_engagement_scale, ScopeTarget
```

- [ ] **Step 2: Parse scope on engagement creation**

In the `create_engagement` endpoint, after the engagement is created, parse the scope and store the structured targets:

```python
# Parse scope into structured targets
scope_targets = parse_scope(payload.scope or payload.target or "")
scale = estimate_engagement_scale(scope_targets)

# Store on engagement
eng.scope_targets = scope_targets
eng.scale = scale
```

- [ ] **Step 3: Update /api/scope endpoint to return structured data**

```python
@app.get("/api/scope")
async def get_engagement_scope():
    eid = state.active_engagement_id
    eng = next((e for e in state.engagements if e.id == eid), None)
    targets = parse_scope(getattr(eng, 'target', '') or getattr(eng, 'scope', '') or '')
    scale = estimate_engagement_scale(targets)
    return {
        "engagement_id": eid,
        "raw_scope": getattr(eng, 'target', ''),
        "targets": [{"ip": t.ip, "cidr": t.cidr, "hostname": t.hostname, "host_count": t.host_count} for t in targets],
        "scale": scale,
    }
```

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "feat: scope parser integrated into engagement creation + /api/scope"
```

---

## Phase 2: Per-Host Agent Routing + Indexed Queries

**Goal:** Agents work on specific hosts. Queries scale with indexes. EX doesn't get overwhelmed by 5000 findings.

---

### Task 4: Per-Host Finding Queries — Replace Full-Scan with Indexed

**Files:**
- Modify: `tools/athena-dashboard/server.py` (exploit-stats, GET /api/findings)

- [ ] **Step 1: Add host_ip filter to GET /api/findings**

```python
@app.get("/api/engagements/{eid}/findings")
async def get_engagement_findings(eid: str, host_ip: str = None, severity: str = None, status: str = None, limit: int = 100, offset: int = 0):
    # Add WHERE clauses for host_ip, severity, status
    where_clauses = ["f.engagement_id = $eid"]
    params = {"eid": eid}
    if host_ip:
        where_clauses.append("f.host_ip = $host_ip")
        params["host_ip"] = host_ip
    if severity:
        where_clauses.append("f.severity = $severity")
        params["severity"] = severity
    if status:
        where_clauses.append("f.status = $status")
        params["status"] = status
    # Add LIMIT and SKIP for pagination
```

- [ ] **Step 2: Add host_ip filter to exploit-stats**

In the exploit-stats Neo4j query, add optional host_ip parameter:

```python
@app.get("/api/engagements/{eid}/exploit-stats")
async def get_exploit_stats(eid: str, host_ip: str = None):
    # If host_ip provided, scope all queries to that host
```

- [ ] **Step 3: Commit**

```bash
git add -A
git commit -m "feat: per-host filtering on findings + exploit-stats endpoints"
```

---

### Task 5: ST Host-Aware Agent Dispatch

**Files:**
- Modify: `tools/athena-dashboard/agent_configs.py` (_ST_PROMPT)

- [ ] **Step 1: Add multi-host dispatch instructions to ST prompt**

After the existing dispatch rules, add:

```
MULTI-HOST ENGAGEMENT:
When the engagement scope contains multiple hosts (check /api/scope):
1. Query /api/scope to get the target list and scale estimate
2. For SMALL scale (≤10 hosts): dispatch one agent team (AR+DA+EX+VF) that cycles through all hosts
3. For MEDIUM scale (10-100 hosts): dispatch agents with specific host assignments:
   - AR: scan all hosts first (naabu + nmap across the range)
   - DA: research CVEs for discovered services (no host limit)
   - EX: exploit one host at a time, moving to next when done
   - VF: verify findings as they come in
4. For LARGE scale (100+ hosts): request parallel agent teams via POST /api/agents/request-team
   - Each team handles a subnet or host group
   - Coordinate via bilateral messaging
5. ALWAYS include the specific host IP in finding titles and tool commands
6. NEVER run nmap or naabu against a /16 without rate limiting (-rate 500)
```

- [ ] **Step 2: Commit**

```bash
git add tools/athena-dashboard/agent_configs.py
git commit -m "feat: ST multi-host dispatch instructions for scaled engagements"
```

---

### Task 6: EX Per-Host Exploitation Queue

**Files:**
- Modify: `tools/athena-dashboard/agent_configs.py` (_EX_PROMPT)

- [ ] **Step 1: Add per-host exploitation instructions to EX prompt**

In the EX EXPLOITATION LOOP section, modify step 2:

```
2. Query Neo4j for HIGH/CRITICAL findings:
   - If multi-host engagement: GET /api/engagements/{eid}/findings?severity=critical&host_ip=<current_host>&status=open
   - Work on ONE HOST at a time. Complete all exploits for host A before moving to host B.
   - After completing a host, report to ST: "Host <IP> exploitation complete. N exploits confirmed. Moving to next host."
   - Query /api/scope for the next unfinished host
```

- [ ] **Step 2: Commit**

```bash
git add tools/athena-dashboard/agent_configs.py
git commit -m "feat: EX per-host exploitation queue for multi-target engagements"
```

---

## Phase 3: Paginated Report Generation

**Goal:** RP generates reports for 100+ findings without stalling. Pre-aggregated data endpoint reduces N+1 queries.

---

### Task 7: Pre-Aggregated Report Data Endpoint

**Files:**
- Modify: `tools/athena-dashboard/server.py`

- [ ] **Step 1: Create /api/report-data endpoint**

```python
@app.get("/api/engagements/{eid}/report-data")
async def get_report_data(eid: str):
    """Pre-aggregated data for report generation.

    Returns ALL data RP needs in a single response — no N+1 queries.
    Structured by host, then by severity, then by finding.
    """
    # Single Neo4j query with COLLECT + grouping
    result = session.run("""
        MATCH (f:Finding {engagement_id: $eid})
        OPTIONAL MATCH (f)-[:EVIDENCED_BY]->(a:Artifact)
        WITH f.host_ip AS host,
             f.severity AS severity,
             collect(DISTINCT {
                 id: f.id, title: f.title, severity: f.severity,
                 status: f.status, cve: f.cve, agent: f.agent,
                 description: f.description, target: f.target,
                 evidence_count: count(a)
             }) AS findings
        RETURN host, severity, findings
        ORDER BY host, severity
    """, eid=eid)

    # Also get engagement summary stats
    # Also get credentials, attack chains, hosts/services
    # Return everything in one JSON blob
```

- [ ] **Step 2: Commit**

```bash
git add tools/athena-dashboard/server.py
git commit -m "feat: /api/report-data — single-query pre-aggregated data for RP"
```

---

### Task 8: RP Chunked Report Generation

**Files:**
- Modify: `tools/athena-dashboard/agent_configs.py` (_RP_PROMPT)

- [ ] **Step 1: Update RP prompt for chunked generation**

Replace RP's report generation workflow with:

```
REPORT GENERATION WORKFLOW:

1. FIRST: Query /api/engagements/{eid}/report-data — this returns ALL data in one call.
   DO NOT query individual findings. Use this pre-aggregated data for all reports.

2. EXECUTIVE SUMMARY (always generate first — smallest, most important):
   - 1-2 pages
   - Overall risk rating, key findings count, critical vulns
   - Write to engagements/active/{eid}/09-reporting/executive-summary.md
   - POST /api/reports with type="executive-summary"

3. TECHNICAL REPORT (generate per-host if >50 findings):
   - If total findings ≤50: one report, all findings in severity order
   - If total findings >50: generate per-host sections
     - For each host in report-data: write a section with that host's findings
     - Combine into one report or generate separate per-host reports
   - Write to engagements/active/{eid}/09-reporting/technical-report.md
   - POST /api/reports with type="technical"

4. REMEDIATION ROADMAP (generate last):
   - Group remediations by priority (Critical → High → Medium → Low)
   - De-duplicate: same CVE on multiple hosts = one remediation, list affected hosts
   - Write to engagements/active/{eid}/09-reporting/remediation-roadmap.md
   - POST /api/reports with type="remediation"

5. Send debrief to ST after each report is posted, not at the end.
```

- [ ] **Step 2: Commit**

```bash
git add tools/athena-dashboard/agent_configs.py
git commit -m "feat: RP chunked report generation with pre-aggregated data"
```

---

## Phase 4: Dashboard Scaling (Later)

**Goal:** Dashboard handles 5000+ findings without lag.

### Task 9: Virtual Scrolling for Findings Table

- [ ] Add pagination to findings table (100 per page, lazy load)
- [ ] Add host_ip filter dropdown to findings page
- [ ] Limit Evidence Gallery to 50 items with "Load More" button

### Task 10: Attack Graph Clustering

- [ ] Cluster nodes by host at 100+ findings
- [ ] Collapse credentials into host-level summary at 50+ creds
- [ ] Add zoom/filter controls

### Task 11: Streaming Dashboard Updates

- [ ] Throttle WebSocket broadcasts to max 1/second per widget
- [ ] Batch KPI updates instead of per-finding updates
- [ ] Add loading states for slow queries

---

## Phase 5: Cloud Target Support (Future)

### Task 12: Resource-Based Finding Model

- [ ] Add `resource_arn` field to Finding (alongside `host_ip`)
- [ ] Support AWS ARN, Azure Resource ID, GCP Resource Name
- [ ] Cloud-specific agents (AWS recon, Azure recon)

---

## Validation Plan

### Phase 1 Validation
- Spin up 2x Metasploitable (10.1.1.25, 10.1.1.26) on Antsle
- Create engagement with scope "10.1.1.25, 10.1.1.26"
- Verify: scope parsed into 2 targets, findings have correct host_ip, per-host stats work

### Phase 2 Validation
- Run full autonomous engagement against 2 hosts
- Verify: EX works one host at a time, findings don't cross-merge, exploit-stats per-host

### Phase 3 Validation
- Run engagement to completion with RP
- Verify: RP generates all 3 reports without stalling, technical report has per-host sections

### Scale Test
- DVWA + Metasploitable + Juice Shop (3 different targets)
- Verify: different vuln types per host, WV on web targets, AR on network targets

---

## Dependencies Between Phases

```
Phase 1 (scope + host model) ←── required by ──→ Phase 2 (per-host routing)
Phase 1 ←── required by ──→ Phase 3 (per-host reports)
Phase 2 ←── optional for ──→ Phase 3 (works without but better with)
Phase 3 ←── independent of ──→ Phase 4 (dashboard scaling)
```

Phase 1 is the foundation — everything else depends on it.
