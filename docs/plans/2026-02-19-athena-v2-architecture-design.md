# ATHENA v2.0 Architecture Design

**Date:** February 19, 2026
**Author:** Kelvin Lomboy + Vex
**Status:** Approved
**Research Base:** 27 parallel agents, 120+ sources, 5 research reports (Feb 19, 2026)

---

## 1. System Architecture Overview

### Vision

ATHENA v2.0 is a multi-agent AI penetration testing platform that uses Claude Code Agent Teams as the orchestration backbone, with dedicated MCP tool servers providing structured JSON I/O to real security tools, and Neo4j as the shared knowledge graph for all agents.

### Goals (Staged)

1. **Stage 1 (Weeks 1-4):** Run real napoleontek/VERSANT engagements
2. **Stage 2 (Weeks 5-8):** Productize as 0K AI Pentest Kit
3. **Stage 3 (Months 3-6):** Compete with PentAGI/HexStrike in open-source market

### High-Level Architecture

```
                    ┌─────────────────────────────┐
                    │     ATHENA Dashboard (UI)    │
                    │  FastAPI + WebSocket + HTML  │
                    └──────────────┬───────────────┘
                                   │
                    ┌──────────────▼───────────────┐
                    │     Engagement Orchestrator    │
                    │   (Claude Code Agent Teams)    │
                    │         Opus 4.6               │
                    └──────────────┬───────────────┘
                                   │
              ┌────────────────────┼────────────────────┐
              │                    │                     │
   ┌──────────▼──────────┐ ┌──────▼──────┐ ┌───────────▼───────────┐
   │  13 Specialist       │ │   Neo4j     │ │  12 MCP Tool Servers  │
   │  Agents              │ │  Knowledge  │ │  (8 external +        │
   │  (Opus/Sonnet/Haiku) │ │  Graph      │ │   4 internal pentest) │
   └──────────────────────┘ └─────────────┘ └───────────────────────┘
```

### Execution Model

- **Orchestrator:** Opus 4.6 — strategic planning, phase transitions, HITL coordination
- **Strategic Agents:** Opus 4.6 — Attack Path Analyzer, Exploit Crafter, Report Generator
- **Worker Agents:** Sonnet 4.5 / Haiku 4.5 — recon, scanning, enumeration tasks
- **Verification Agent:** Sonnet 4.5 — independent exploit verification (never the same model instance as finder)

### Key Design Principles

1. **PTES-aligned** — 7-phase methodology maps to agent specializations
2. **Evidence-based verification** — "the finder is not the verifier" (XBOW principle)
3. **Human-in-the-loop at scope layer** — humans define boundaries, AI executes within them
4. **Knowledge persistence** — Neo4j graph survives across sessions and engagements
5. **MCP-native tooling** — structured JSON I/O, no raw shell scraping
6. **Defense-in-depth on offensive tools** — prompt injection protection on tool outputs

---

## 2. Agent Inventory (13 Agents)

### 9 Modernized Existing Agents

| # | Agent | PTES Phase | Model | Key Changes in v2.0 |
|---|-------|-----------|-------|---------------------|
| 1 | **Engagement Orchestrator (EO)** | All | Opus 4.6 | Agent Teams coordination, Neo4j state, phase-aware routing |
| 2 | **Passive Recon (PR)** | Intelligence Gathering | Haiku 4.5 | OSINT expansion (infrastructure, people/org, credential, technology), Shodan/Censys MCP |
| 3 | **Active Recon (AR)** | Intelligence Gathering | Sonnet 4.5 | Naabu MCP (replaces legacy scanners), Httpx for service fingerprinting |
| 4 | **Vulnerability Scanner (VS)** | Vulnerability Analysis | Sonnet 4.5 | Nuclei MCP with custom templates, CVE correlation via Neo4j |
| 5 | **Exploitation (EX)** | Exploitation | Opus 4.6 | Structured ExploitResult output, HITL gate before execution, evidence capture |
| 6 | **Post-Exploitation (PE)** | Post-Exploitation | Sonnet 4.5 | Internal pivoting, credential harvesting → Neo4j, BloodHound MCP for AD |
| 7 | **Cleanup & Verification (CV)** | Reporting | Sonnet 4.5 | Artifact removal verification, evidence integrity checks |
| 8 | **Report Generator (RG)** | Reporting | Opus 4.6 | White-label templates (branding.yml), CVSS auto-scoring, executive + technical sections |
| 9 | **Web Vuln Scanner (WV)** | Vulnerability Analysis | Sonnet 4.5 | Nuclei web templates, Katana for crawling, authenticated scanning |

### 4 New Agents

| # | Agent | PTES Phase | Model | Purpose |
|---|-------|-----------|-------|---------|
| 10 | **Verification Agent (VA)** | Exploitation | Sonnet 4.5 | Independent exploit re-verification with structured EvidencePackage |
| 11 | **Attack Path Analyzer (APA)** | Vulnerability Analysis | Opus 4.6 | Neo4j graph traversal to discover multi-step kill chains |
| 12 | **Exploit Crafter (EC)** | Exploitation | Opus 4.6 | Novel payload generation with self-verification loop (Big Sleep/XBOW pattern) |
| 13 | **Detection Validator (DV)** | Post-Exploitation | Sonnet 4.5 | Purple team — validates if defensive controls detected the exploit |

### Agent Communication

```
EO (Orchestrator)
├── PR (Passive Recon) ──writes──▶ Neo4j
├── AR (Active Recon) ──writes──▶ Neo4j
├── VS (Vuln Scanner) ──writes──▶ Neo4j
├── APA (Attack Path) ──reads───▶ Neo4j ──produces──▶ Kill Chains
├── EX (Exploitation) ──reads───▶ Kill Chains ──produces──▶ ExploitResult
│   └── HITL Gate ──approved──▶ Execute
├── VA (Verification) ──reads───▶ ExploitResult ──produces──▶ EvidencePackage
├── EC (Exploit Crafter) ──reads──▶ Neo4j ──produces──▶ Custom Payloads
├── PE (Post-Exploit) ──writes──▶ Neo4j (credentials, pivots)
├── DV (Detection Validator) ──reads──▶ ExploitResult ──checks──▶ SIEM/EDR
├── CV (Cleanup) ──reads──▶ Neo4j ──removes──▶ Artifacts
└── RG (Report) ──reads──▶ Neo4j ──generates──▶ PDF/DOCX
```

---

## 3. MCP Tool Servers (12 Total)

### 8 External Recon/Scanning Tool Servers

| # | MCP Server | Wraps | Used By | Key Capabilities |
|---|-----------|-------|---------|-----------------|
| 1 | **naabu-mcp** | Naabu (ProjectDiscovery) | AR | Port scanning, SYN/CONNECT, service detection, JSON output |
| 2 | **httpx-mcp** | Httpx (ProjectDiscovery) | AR, WV | HTTP probing, tech detection, status codes, CDN detection |
| 3 | **nuclei-mcp** | Nuclei (ProjectDiscovery) | VS, WV | Template-based vuln scanning, custom templates, severity filtering |
| 4 | **katana-mcp** | Katana (ProjectDiscovery) | WV | Web crawling, JS rendering, form discovery, endpoint extraction |
| 5 | **gau-mcp** | GAU (GetAllUrls) | PR, WV | Wayback Machine, CommonCrawl, AlienVault URL enumeration |
| 6 | **shodan-mcp** | Shodan API | PR | Internet-wide scanning data, banner grabbing, CVE correlation |
| 7 | **subfinder-mcp** | Subfinder (ProjectDiscovery) | PR | Passive subdomain enumeration, multi-source aggregation |
| 8 | **neo4j-mcp** | Neo4j Driver | ALL | CRUD on knowledge graph, Cypher queries, graph traversal |

### 4 Internal Pentest Tool Servers

| # | MCP Server | Wraps | Used By | Key Capabilities |
|---|-----------|-------|---------|-----------------|
| 9 | **bloodhound-mcp** | BloodHound CE | PE, APA | AD enumeration, attack path discovery, domain privilege mapping |
| 10 | **impacket-mcp** | Impacket Suite | EX, PE | SMB, WMI, Kerberos, secretsdump, psexec, dcomexec |
| 11 | **netexec-mcp** | NetExec (CrackMapExec successor) | EX, PE | Network-wide credential testing, share enum, AD operations |
| 12 | **certipy-mcp** | Certipy | PE, APA | AD Certificate Services abuse, ESC1-ESC13 vectors |

### MCP Server Standard Interface

Each MCP tool server follows the same pattern:

```python
# Standard MCP server structure
class ToolMCPServer:
    """
    - Receives structured JSON input (target, options, scope constraints)
    - Executes underlying tool in sandboxed subprocess
    - Returns structured JSON output (findings, errors, metadata)
    - Writes results to Neo4j via neo4j-mcp
    - Enforces scope boundaries (IP ranges, domains, ports)
    - Sanitizes output for prompt injection prevention
    """
```

### Scope Enforcement

Every MCP tool server enforces scope at the tool level:

```yaml
scope:
  allowed_targets:
    - 10.0.0.0/24
    - example.com
    - "*.example.com"
  excluded_targets:
    - 10.0.0.1  # gateway
  allowed_ports: [1-65535]
  max_threads: 50
  timeout_seconds: 300
```

---

## 4. Neo4j Knowledge Graph Schema

### Node Types

```cypher
// Infrastructure nodes
(:Host {ip, hostname, os, os_version, status, first_seen, last_seen, engagement_id})
(:Service {port, protocol, name, version, banner, state, host_ip, engagement_id})
(:Domain {name, registrar, nameservers, whois_data, engagement_id})
(:Subdomain {name, resolved_ips, source, engagement_id})
(:URL {url, status_code, content_type, tech_stack, engagement_id})

// Vulnerability nodes
(:Vulnerability {cve_id, name, description, cvss_score, severity, nuclei_template, status, engagement_id})
(:Credential {username, hash_type, hash_value, plaintext, source, domain, engagement_id})
(:Certificate {subject, issuer, san, expiry, template_name, engagement_id})

// Attack path nodes
(:AttackPath {name, steps, complexity, impact, probability, engagement_id})
(:ExploitResult {technique, target, success, output_hash, timestamp, agent_id, engagement_id})
(:EvidencePackage {type, data_hash, screenshots, http_pairs, timing_data, verified_by, engagement_id})

// Reporting nodes
(:Finding {title, description, severity, cvss, remediation, references, status, engagement_id})
(:Engagement {name, client, scope, start_date, end_date, status, methodology})

// OSINT nodes
(:Person {name, role, email, phone, social_profiles, source, engagement_id})
(:Organization {name, industry, size, technologies, engagement_id})
(:LeakedCredential {email, source_breach, password_hash, date_leaked, engagement_id})
```

### Relationship Types

```cypher
// Infrastructure relationships
(:Host)-[:HAS_SERVICE]->(:Service)
(:Host)-[:RESOLVES_TO]->(:Domain)
(:Domain)-[:HAS_SUBDOMAIN]->(:Subdomain)
(:Subdomain)-[:RESOLVES_TO]->(:Host)
(:Host)-[:HAS_URL]->(:URL)
(:URL)-[:USES_TECH]->(:Technology)

// Vulnerability relationships
(:Service)-[:HAS_VULNERABILITY]->(:Vulnerability)
(:Host)-[:HAS_VULNERABILITY]->(:Vulnerability)
(:URL)-[:HAS_VULNERABILITY]->(:Vulnerability)
(:Vulnerability)-[:EXPLOITED_BY]->(:ExploitResult)
(:ExploitResult)-[:VERIFIED_BY]->(:EvidencePackage)
(:ExploitResult)-[:PRODUCED]->(:Credential)

// Attack path relationships
(:AttackPath)-[:STARTS_AT]->(:Host)
(:AttackPath)-[:TRAVERSES]->(:Service)
(:AttackPath)-[:ENDS_AT]->(:Host)
(:AttackPath)-[:EXPLOITS]->(:Vulnerability)

// Finding relationships
(:Finding)-[:AFFECTS]->(:Host)
(:Finding)-[:REFERENCES]->(:Vulnerability)
(:Finding)-[:EVIDENCED_BY]->(:EvidencePackage)
(:Engagement)-[:CONTAINS]->(:Finding)
(:Engagement)-[:TARGETS]->(:Host)

// OSINT relationships
(:Person)-[:WORKS_AT]->(:Organization)
(:Person)-[:HAS_EMAIL]->(:LeakedCredential)
(:Organization)-[:OWNS]->(:Domain)

// AD-specific relationships
(:Host)-[:MEMBER_OF]->(:ADGroup)
(:Host)-[:HAS_SESSION]->(:Credential)
(:Certificate)-[:ISSUED_BY]->(:CertificateAuthority)
(:Host)-[:TRUSTS]->(:Domain)
```

### Cross-Engagement Queries

```cypher
// Find recurring vulnerabilities across engagements
MATCH (v:Vulnerability)<-[:HAS_VULNERABILITY]-(s:Service)
WHERE v.severity IN ['CRITICAL', 'HIGH']
RETURN v.cve_id, v.name, count(DISTINCT s) AS affected_services,
       collect(DISTINCT s.engagement_id) AS engagements
ORDER BY affected_services DESC

// Attack path from external to domain admin
MATCH path = shortestPath(
  (entry:Host {status: 'external'})-[*]-(da:Host {role: 'domain_controller'})
)
WHERE ALL(r IN relationships(path) WHERE type(r) IN
  ['HAS_VULNERABILITY', 'EXPLOITED_BY', 'PRODUCED', 'HAS_SESSION'])
RETURN path
```

### Neo4j Deployment

- **Location:** ATHENA mini-PC (Kali Linux)
- **Version:** Neo4j Community Edition 5.x
- **Access:** Bolt protocol via neo4j-mcp server
- **Backup:** Daily snapshots to engagement archive
- **Security:** Local-only binding, authentication required

---

## 5. Verification Pipeline

### Principle: "The Finder Is Not the Verifier"

Adapted from XBOW's canary verification for real-world client engagements where canary tokens cannot be pre-planted.

### Pipeline Flow

```
┌──────────────┐     ┌──────────┐     ┌──────────────────┐     ┌────────────────┐
│ Exploitation │────▶│  HITL    │────▶│   Verification   │────▶│   Finding      │
│ Agent (EX)   │     │  Gate    │     │   Agent (VA)     │     │  (Confirmed)   │
└──────────────┘     └──────────┘     └──────────────────┘     └────────────────┘
       │                  │                    │                        │
       ▼                  ▼                    ▼                        ▼
  ExploitResult     Human approves      EvidencePackage          Neo4j Finding
  (technique,       or rejects          (http_pairs,             (severity,
   target,          exploitation        timing_data,              remediation,
   predicted                            screenshots,              evidence)
   impact)                              response_diffs)
```

### ExploitResult Schema

```json
{
  "id": "uuid",
  "technique": "SQL Injection - Union Based",
  "target": {"host": "10.0.0.5", "service": "http/443", "endpoint": "/api/users"},
  "predicted_impact": "Database read access",
  "payload": "' UNION SELECT username,password FROM users--",
  "prerequisites": ["Valid session cookie", "POST to /api/users"],
  "agent_id": "exploitation-agent",
  "timestamp": "2026-02-19T14:30:00Z",
  "status": "pending_verification"
}
```

### EvidencePackage Schema

```json
{
  "id": "uuid",
  "exploit_result_id": "uuid",
  "verification_method": "independent_replay",
  "evidence": {
    "http_pairs": [
      {
        "request": "POST /api/users HTTP/1.1\n...",
        "response": "HTTP/1.1 200 OK\n...",
        "timestamp": "2026-02-19T14:35:00Z"
      }
    ],
    "timing_data": {
      "baseline_ms": 45,
      "exploit_ms": 5230,
      "delta_ms": 5185,
      "consistent_across_runs": true
    },
    "screenshots": ["evidence/sqli-01.png", "evidence/sqli-02.png"],
    "response_diffs": {
      "baseline_length": 1234,
      "exploit_length": 45678,
      "unique_strings": ["admin", "password_hash"]
    }
  },
  "verified_by": "verification-agent",
  "confidence": "HIGH",
  "timestamp": "2026-02-19T14:35:30Z",
  "status": "confirmed"
}
```

### Verification Methods by Vuln Type

| Vulnerability Type | Verification Method | Evidence Required |
|-------------------|-------------------|-------------------|
| SQL Injection | Independent replay + response diff | HTTP pairs, timing data, extracted data proof |
| XSS | DOM inspection + screenshot | HTTP pairs, DOM snapshot, rendered screenshot |
| RCE | Command output verification | HTTP pairs, command output, file creation proof |
| SSRF | Out-of-band callback | HTTP pairs, callback log, DNS log |
| Auth Bypass | Session comparison | HTTP pairs before/after, privilege proof |
| Path Traversal | File content verification | HTTP pairs, known file content match |
| AD Privilege Escalation | BloodHound path validation | AD query results, session proof |
| Certificate Abuse | Certificate issuance proof | Certificate details, authentication proof |

### Self-Verification Loop (Exploit Crafter)

```
EC generates payload → EC tests in sandbox →
  Success? → EC submits ExploitResult → VA verifies independently
  Failure? → EC iterates (max 3 attempts) →
    Still failing? → EC reports as "unconfirmed potential"
```

---

## 6. Engagement Lifecycle

### Phase 0: Engagement Setup

```yaml
engagement:
  name: "Client-Name_YYYY-MM-DD_Type"
  client: "Client Name"
  type: "external|internal|web|hybrid"
  scope:
    targets:
      - 10.0.0.0/24
      - "*.example.com"
    exclusions:
      - 10.0.0.1
      - "admin.example.com"
    allowed_ports: [1-65535]
    testing_window: "Mon-Fri 09:00-17:00 AST"
    rules_of_engagement: "No DoS, no social engineering, no physical"
  branding:
    config: "branding.yml"  # White-label report configuration
  neo4j:
    database: "engagement_2026_02_19"
```

### Phase 1: Pre-Engagement (Orchestrator)

- Load scope configuration
- Initialize Neo4j database for engagement
- Validate tool availability (MCP health checks)
- Create engagement node in Neo4j
- Brief all agents on scope constraints

### Phase 2: Intelligence Gathering (PR + AR)

**Passive Recon Agent (PR) — OSINT Operations:**

| OSINT Category | Tools/Sources | Output |
|---------------|---------------|--------|
| **Infrastructure OSINT** | Subfinder, GAU, Shodan, Censys, DNS records, WHOIS, certificate transparency | Subdomains, IPs, historical URLs, exposed services |
| **People/Organization OSINT** | LinkedIn (manual), Hunter.io, public records, org charts, job postings | Email patterns, key personnel, org structure, tech stack hints |
| **Credential OSINT** | HaveIBeenPwned API, breach databases, paste sites, GitHub dorking | Leaked credentials, email-password pairs, API keys |
| **Technology OSINT** | Wappalyzer, BuiltWith, Httpx tech detection, JavaScript analysis | Tech stack, frameworks, CMS versions, WAF detection |

All OSINT results written to Neo4j as Person, Organization, LeakedCredential, Domain, Subdomain nodes.

**Active Recon Agent (AR) — Active Scanning:**

| Step | Tool (MCP) | Output |
|------|-----------|--------|
| Port scan | naabu-mcp | Host + Service nodes |
| HTTP probing | httpx-mcp | URL nodes with tech stack |
| Service fingerprinting | httpx-mcp + nuclei-mcp (info templates) | Service version details |

### Phase 3: Vulnerability Analysis (VS + WV + APA)

| Step | Agent | Tool (MCP) | Output |
|------|-------|-----------|--------|
| Network vuln scan | VS | nuclei-mcp (network templates) | Vulnerability nodes |
| Web vuln scan | WV | nuclei-mcp (web templates) + katana-mcp | Vulnerability nodes |
| Authenticated scan | WV | nuclei-mcp (authenticated) | Additional vulns behind auth |
| Attack path analysis | APA | neo4j-mcp (graph traversal) | AttackPath nodes |
| Kill chain mapping | APA | neo4j-mcp + bloodhound-mcp (if AD) | Prioritized attack paths |

### Phase 4: Exploitation (EX + EC + VA)

```
For each AttackPath (priority order):
  1. EX reads AttackPath from Neo4j
  2. EX selects or EC crafts exploit
  3. EX produces ExploitResult → HITL GATE
  4. Human approves/rejects in Dashboard
  5. If approved: EX executes exploit
  6. VA independently verifies → EvidencePackage
  7. If verified: Finding created in Neo4j
  8. If not verified: Marked "unconfirmed", EX may retry
```

### Phase 5: Post-Exploitation (PE)

| Step | Agent | Tool (MCP) | Output |
|------|-------|-----------|--------|
| Credential harvesting | PE | impacket-mcp (secretsdump) | Credential nodes |
| AD enumeration | PE | bloodhound-mcp | AD relationships |
| Lateral movement | PE | netexec-mcp, impacket-mcp | New Host access |
| Certificate abuse | PE | certipy-mcp | Certificate nodes, escalation paths |
| Privilege escalation | PE | impacket-mcp, netexec-mcp | Elevated credentials |
| Detection check | DV | SIEM API (if available) | Detection coverage report |

Each pivot and escalation loops back to Phase 3 (scan new scope) and Phase 4 (exploit new targets).

### Phase 6: Cleanup & Verification (CV)

- Remove all artifacts (shells, accounts, files)
- Verify removal via independent checks
- Document all changes made during engagement
- Snapshot Neo4j database for archive

### Phase 7: Reporting (RG)

| Deliverable | Format | Content |
|------------|--------|---------|
| Executive Summary | PDF/DOCX | Business impact, risk rating, key findings |
| Technical Report | PDF/DOCX | All findings with evidence, remediation, CVSS |
| Attack Narrative | PDF/DOCX | Step-by-step attack path story |
| Remediation Roadmap | PDF/DOCX | Prioritized fix list with effort estimates |
| Raw Evidence Archive | ZIP | All EvidencePackages, screenshots, logs |

**White-Label Reports:** Configurable via `branding.yml`:

```yaml
# branding.yml — White-label report configuration
company:
  name: "Your Company Name"
  logo: "assets/logo.png"
  logo_width: "150px"
  tagline: "Your Tagline"
colors:
  primary: "#1a1a2e"
  accent: "#e94560"
  text: "#ffffff"
  background: "#0f0f23"
templates:
  executive: "templates/executive-summary.md"
  technical: "templates/technical-report.md"
  narrative: "templates/attack-narrative.md"
contact:
  name: "Lead Pentester"
  email: "pentest@company.com"
  phone: "+1-xxx-xxx-xxxx"
classification: "CONFIDENTIAL"
```

For Kelvin's use: `/versant-docs` skill provides napoleontek/VERSANT branding.
For public product (Stage 2+): `branding.yml` config allows any pentester to customize.

---

## 7. Dashboard Evolution

### Current State (v1)

Single-file HTML dashboard (`index.html`, ~3952 lines) with:
- Agent grid with status chips
- AI Assistant drawer with expandable ThinkingCards and ToolExecutionCards
- Streaming tool output with blinking cursor
- HITL approval modals
- Phase badge
- Chip filtering by agent
- Default and Minimal themes

### v2.0 Additions

#### AI Assistant Drawer Enhancements

**Engagement Selector (top of drawer):**
```
┌─────────────────────────────────────────┐
│ Engagement: [Client_2026-02-19_Web ▾]   │
│ Phase: EXPLOITATION  Status: ACTIVE     │
├─────────────────────────────────────────┤
│ [PR] [AR] [VS] [WV] [APA] [EX] ...    │  ← Agent chips
├─────────────────────────────────────────┤
│ Timeline cards (existing)               │
│ ThinkingCard, ToolExecutionCard, etc.   │
└─────────────────────────────────────────┘
```

- Dropdown to select active engagement
- Shows current phase and status
- Switching engagement reloads timeline and graph

#### Sidebar Additions

**Engagement List:**
```
┌───────────────────────┐
│ Engagements           │
├───────────────────────┤
│ ● Client_02-19_Web    │  ← Active (green dot)
│ ○ Client_02-15_Int    │  ← Completed (gray dot)
│ ○ DryRun_02-19        │  ← Archived
│ + New Engagement      │
└───────────────────────┘
```

#### New Dashboard Views (Tabs)

| Tab | Content | Library |
|-----|---------|---------|
| **Overview** | Agent grid, phase progress, key metrics (existing, enhanced) | Vanilla JS |
| **Findings** | Table with severity badges, status filters, CVSS scores | Vanilla JS |
| **Attack Graph** | Interactive Neo4j visualization — hosts, paths, exploits | Neovis.js |
| **Evidence** | Gallery of screenshots, HTTP pairs, verification status | Vanilla JS |
| **Coverage** | Detection heatmap — what was detected vs. missed (DV output) | Vanilla JS |

#### Attack Graph View (Neovis.js)

```javascript
// Neo4j visualization configuration
const vizConfig = {
  containerId: "attack-graph",
  neo4j: { serverUrl: "bolt://athena-mini:7687" },
  labels: {
    Host: { label: "hostname", color: "#4CAF50", size: "degree" },
    Service: { label: "name", color: "#2196F3" },
    Vulnerability: { label: "severity", color: { CRITICAL: "#f44336", HIGH: "#ff9800" } },
    Credential: { label: "username", color: "#9C27B0" },
    Finding: { label: "title", color: "#E91E63" }
  },
  relationships: {
    HAS_VULNERABILITY: { color: "#ff9800" },
    EXPLOITED_BY: { color: "#f44336", width: 3 },
    PRODUCED: { color: "#9C27B0" }
  }
};
```

#### Findings Table

```
┌──────┬─────────────────────────┬──────────┬────────┬──────────┬──────────┐
│ ID   │ Title                   │ Severity │ CVSS   │ Status   │ Evidence │
├──────┼─────────────────────────┼──────────┼────────┼──────────┼──────────┤
│ F-01 │ SQL Injection /api/users│ CRITICAL │ 9.8    │ Verified │ 3 items  │
│ F-02 │ Weak TLS Configuration  │ MEDIUM   │ 5.3    │ Confirmed│ 1 item   │
│ F-03 │ Default Admin Creds     │ HIGH     │ 8.1    │ Verified │ 2 items  │
└──────┴─────────────────────────┴──────────┴────────┴──────────┴──────────┘
```

### Technology Approach

- **No framework rewrite** — continue single-file HTML with vanilla JS
- **Neovis.js** — only external library addition (CDN, ~100KB)
- **WebSocket** — existing infrastructure handles all new real-time data
- **CSS** — extend existing theme system for new views

---

## 8. Staging Plan

### Stage 1: Own Engagements (Weeks 1-4)

**Goal:** Run real napoleontek/VERSANT pentests with ATHENA v2.0

| Week | Focus | Deliverables |
|------|-------|-------------|
| 1 | Neo4j setup + neo4j-mcp + schema migration | Working knowledge graph on mini-PC |
| 1 | Modernize PR/AR agents with new MCP tools | naabu-mcp, httpx-mcp, subfinder-mcp, gau-mcp |
| 2 | Modernize VS/WV agents + nuclei-mcp + katana-mcp | Full scanning pipeline |
| 2 | Build Verification Agent + EvidencePackage flow | Working verification pipeline |
| 3 | Build Attack Path Analyzer + kill chain queries | Graph-driven attack prioritization |
| 3 | Build Exploit Crafter with self-verification | Novel payload generation |
| 4 | Dashboard: engagement selector, findings table, attack graph | Visual engagement monitoring |
| 4 | End-to-end dry run on test environment | Full engagement lifecycle validated |

**Mini-PC Required:** Week 1 (Neo4j deployment, tool installation)

### Stage 2: Productize (Weeks 5-8)

**Goal:** Package as 0K AI Pentest Kit

| Week | Focus | Deliverables |
|------|-------|-------------|
| 5 | Docker Compose deployment (all MCP servers + Neo4j) | One-command install |
| 5 | `branding.yml` white-label system | Any pentester can customize reports |
| 6 | Internal pentest MCP servers (BloodHound, Impacket, NetExec, Certipy) | AD engagement capability |
| 6 | Detection Validator agent | Purple team capability |
| 7 | Documentation, setup wizard, example engagements | User onboarding |
| 7 | Build Detection Validator agent | Purple team capability |
| 8 | Beta testing with select pentesters | Feedback and iteration |

### Stage 3: Compete (Months 3-6)

**Goal:** Open-source release, compete with PentAGI/HexStrike

| Month | Focus | Deliverables |
|-------|-------|-------------|
| 3 | GitHub release, documentation site | Public launch |
| 3 | CI/CD pipeline, automated testing | Release quality |
| 4 | Community contributions, plugin system | Ecosystem growth |
| 5 | Advanced features: cross-engagement learning, custom templates | Differentiation |
| 6 | Conference talk / blog series on 0k.cool | Market presence |

### Competitive Positioning

| Feature | ATHENA v2.0 | PentAGI | HexStrike |
|---------|------------|---------|-----------|
| Agent framework | Claude Code Agent Teams | Custom Python | Custom |
| Knowledge graph | Neo4j | Neo4j (Graphiti) | None |
| Verification | Multi-agent + evidence | None | None |
| MCP integration | Native (12 servers) | None | 150+ tools (MCP) |
| HITL | Dashboard + approval gates | Limited | None |
| White-label reports | branding.yml | None | None |
| Streaming dashboard | WebSocket + live output | None | None |
| Internal pentest | BloodHound + Impacket + Certipy | Limited | Limited |
| Open-source | Stage 3 | Yes | Yes |

---

## 9. Risk Mitigations

### Technical Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| Context window overflow | Agent loses earlier findings | Summarization between phases, Neo4j as persistent state |
| Hallucinated exploits | False positives in report | Multi-agent verification pipeline, evidence requirements |
| Prompt injection from targets | Agent manipulated by hostile target | Output sanitization on all MCP tool results, input validation |
| Neo4j availability | Engagement blocked | Local deployment on mini-PC, daily backups, fallback to file-based state |
| Tool breakage | MCP server fails mid-engagement | Health checks, graceful degradation, manual tool fallback |
| LLM cost overrun | Budget exceeded | Spend alerting (PAI L17), Haiku for worker tasks, token budgets per agent |

### Operational Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| Mini-PC offline | Can't run engagement | Kelvin notifies, can run recon-only from laptop |
| Scope creep during engagement | Out-of-scope testing | Scope enforcement at MCP tool level + HITL gates |
| Client data in LLM context | Confidentiality breach | Local Neo4j, no cloud APIs, Governor Agent (PAI L1) |
| False negatives | Missed vulnerabilities | Cross-reference multiple scanners, manual spot checks |

---

## 10. Dependencies & Prerequisites

### Hardware

- **ATHENA mini-PC** (Kali Linux): Neo4j, all MCP tool servers, security tools
- **Kelvin's MacBook**: Claude Code, ATHENA dashboard, agent orchestration

### Software

| Component | Version | Status |
|-----------|---------|--------|
| Neo4j Community | 5.x | To install on mini-PC |
| ProjectDiscovery suite | Latest | Naabu, Httpx, Nuclei, Katana, Subfinder, GAU |
| BloodHound CE | Latest | To install on mini-PC |
| Impacket | Latest | Already on Kali |
| NetExec | Latest | To install |
| Certipy | Latest | To install |
| Neovis.js | 2.x | CDN (dashboard only) |
| Claude Code | Latest | Already installed |

### API Keys / Accounts

- Shodan API key (for shodan-mcp)
- HaveIBeenPwned API key (for credential OSINT)
- No cloud LLM APIs needed (Claude Code handles all AI)

---

## Appendix A: Research Sources

This design is informed by comprehensive competitive research:

1. **Multi-Agent AI Pentesting Landscape** — 35+ sources, 9 agents
2. **Anthropic Cybersecurity Comprehensive Research** — 35+ sources, 9 agents
3. **OpenAI Cybersecurity Comprehensive Research** — 50+ sources, 9 agents
4. **AI Cybersecurity Landscape Synthesis** — Cross-cutting analysis
5. **Competitive Pentest Platform Deep-Dive** — XBOW, NodeZero, PentestAgent internals

Key validated patterns:
- Hierarchical planner + specialist workers (PentestAgent, HPTSA)
- Pipeline/stage-by-stage execution (NodeZero, XBOW)
- MCP-based tool coordination (CALDERA, BloodHound, HexStrike)
- Knowledge graph persistence (PentAGI, Team Atlanta)
- Self-verification loops (XBOW canary system)
- Human augmentation doubles solve rate (21% auto → 64% semi-auto)

---

## Appendix B: File Structure (Planned)

```
ATHENA/
├── agents/                    # Agent definitions
│   ├── orchestrator.md
│   ├── passive-recon.md
│   ├── active-recon.md
│   ├── vuln-scanner.md
│   ├── web-vuln-scanner.md
│   ├── attack-path-analyzer.md
│   ├── exploitation.md
│   ├── exploit-crafter.md
│   ├── verification.md
│   ├── post-exploitation.md
│   ├── detection-validator.md
│   ├── cleanup.md
│   └── report-generator.md
├── mcp-servers/               # MCP tool server implementations
│   ├── naabu-mcp/
│   ├── httpx-mcp/
│   ├── nuclei-mcp/
│   ├── katana-mcp/
│   ├── gau-mcp/
│   ├── shodan-mcp/
│   ├── subfinder-mcp/
│   ├── neo4j-mcp/
│   ├── bloodhound-mcp/
│   ├── impacket-mcp/
│   ├── netexec-mcp/
│   └── certipy-mcp/
├── tools/
│   └── athena-dashboard/      # Dashboard (existing, evolving)
│       ├── server.py
│       ├── index.html
│       └── start.sh
├── engagements/               # Engagement data (existing)
├── templates/                 # Report templates
│   ├── branding.yml           # White-label config
│   ├── executive-summary.md
│   ├── technical-report.md
│   └── attack-narrative.md
├── neo4j/                     # Neo4j configuration
│   ├── schema.cypher          # Schema creation script
│   ├── queries/               # Reusable Cypher queries
│   └── backup/                # Database snapshots
├── docs/
│   ├── architecture/          # Architecture docs (existing)
│   ├── planning/              # Planning docs (existing)
│   └── plans/                 # Design & implementation plans
└── docker/                    # Docker Compose (Stage 2)
    ├── docker-compose.yml
    └── configs/
```

---

**Approved by:** Kelvin Lomboy
**Date:** February 19, 2026
**Next Step:** Implementation plan via writing-plans skill
