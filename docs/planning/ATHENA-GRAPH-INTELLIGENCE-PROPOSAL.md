# ATHENA Graph Intelligence Proposal
## Upgrading from SQLite Tracker to Neo4j Attack Surface Graph

**Document Status:** Planning / Pre-Implementation
**Author:** Kelvin Lomboy (VERSANT)
**Date:** 2026-02-17
**Version:** 1.0
**References:** RedAmon v1.2.0 (samugit83/redamon), ATHENA v1.0, PTES Methodology

---

## Executive Summary

ATHENA currently tracks engagement data in a flat SQLite database with five tables: `engagements`, `commands`, `findings`, `services`, and `hitl_approvals`. This works well as an audit trail but has a fundamental limitation: it cannot reason about relationships between findings.

This proposal upgrades ATHENA with a Neo4j knowledge graph running alongside the existing SQLite database. The graph becomes the **intelligence layer** - enabling attack path analysis, vulnerability chaining, and natural language queries like "show all critical findings reachable from the DMZ" or "what attack paths lead from the web tier to Active Directory?" The SQLite database is retained as the immutable audit trail.

**Primary reference:** RedAmon (samugit83/redamon) - an AI-powered red team framework using Neo4j with 17 node types and 24 relationship types. ATHENA adapts this design for authorized, HITL-supervised, PTES-aligned penetration testing.

---

## Part 1: RedAmon Neo4j Schema Analysis

### 1.1 Architecture Overview

RedAmon uses Neo4j as its single source of truth for attack surface intelligence. The graph is populated by a six-phase automated recon pipeline (subdomain discovery, port scan, HTTP probe, resource enumeration, vulnerability scan, GitHub secret hunting) and queried by a LangGraph-based AI agent using text-to-Cypher translation.

The Neo4j instance runs as a Docker container (neo4j:5.26-community with APOC plugin) accessible on:
- Port 7474: Browser UI
- Port 7687: Bolt protocol (Python driver)

Multi-tenancy is enforced by injecting `user_id` and `project_id` as properties on every node. The AI agent never writes tenant filters - they are injected automatically by a regex-based filter layer before query execution.

### 1.2 RedAmon Node Types (17 Total)

**Category 1: Infrastructure Nodes** - Network topology layer

| Node Label | Key Properties | Description |
|------------|---------------|-------------|
| `Domain` | name, registrar, creation_date, expiration_date, organization, country, name_servers, whois_emails | Root domain with full WHOIS data |
| `Subdomain` | name, has_dns_records | Discovered hostname |
| `IP` | address, version, is_cdn, cdn_name, asn | Resolved IP with CDN/ASN metadata |
| `Port` | number, protocol, state, ip_address | Open port on an IP |
| `Service` | name, product, version, banner, port_number | Running service with version fingerprint |

**Category 2: Web Application Nodes** - Application layer

| Node Label | Key Properties | Description |
|------------|---------------|-------------|
| `BaseURL` | url, status_code, title, server, response_time_ms, resolved_ip | Live HTTP endpoint with response metadata |
| `Endpoint` | path, method, has_parameters, is_form, source | Discovered URL path with HTTP method |
| `Parameter` | name, position (query/body/header/path), is_injectable | Input parameter, flagged when injectable |

**Category 3: Technology and Security Nodes** - Software and security posture

| Node Label | Key Properties | Description |
|------------|---------------|-------------|
| `Technology` | name, version, categories, confidence, detected_by, known_cve_count, cpe | Detected framework, library, or server |
| `Header` | name, value, is_security_header, baseurl | HTTP response header |
| `Certificate` | subject_cn, issuer, not_after, san, tls_version | TLS certificate details |
| `DNSRecord` | type (A/AAAA/MX/NS/TXT/SOA), value, ttl | DNS record for a subdomain |
| `Traceroute` | target_ip, hops | Network path to target |

**Category 4: Vulnerability and Exploitation Nodes** - Security findings

| Node Label | Key Properties | Description |
|------------|---------------|-------------|
| `Vulnerability` | id, name, severity (lowercase), source (nuclei/gvm), category, curl_command | Scanner finding with evidence |
| `CVE` | id, cvss, severity (uppercase), description, published, source | NVD vulnerability entry |
| `MitreData` | cve_id, cwe_id, cwe_name, abstraction | CWE weakness mapping |
| `Capec` | capec_id, name, likelihood, severity, execution_flow | MITRE CAPEC attack pattern |
| `Exploit` | id, attack_type, target_ip, session_id, cve_ids, metasploit_module, payload | Successful exploitation record |
| `ExploitGvm` | id, attack_type, target_ip, cve_ids, metasploit_module | GVM-sourced exploit record |

**Category 5: GitHub Intelligence Nodes** - Secret hunting

| Node Label | Key Properties | Description |
|------------|---------------|-------------|
| `GithubHunt` | id, target_domain, scan_timestamp | Secret hunt session |
| `GithubRepository` | id, name, full_name, url | GitHub repository |
| `GithubPath` | id, path, file_url | File path containing secrets |
| `GithubSecret` | id, secret_type, matched_value, entropy | Detected credential or key |
| `GithubSensitiveFile` | id, file_type, path | Sensitive file (e.g., .env, id_rsa) |

**Actual count: 22 node types** (README states 17, but the schema includes 22 when counting all GitHub hunt nodes which were added after the README was written).

### 1.3 RedAmon Relationship Types (24 Total)

Extracted from neo4j_client.py MERGE statements:

**Infrastructure chain:**

```
[:BELONGS_TO]           Subdomain    --> Domain
[:RESOLVES_TO]          Subdomain    --> IP          (props: record_type)
[:HAS_DNS_RECORD]       Subdomain    --> DNSRecord
[:HAS_PORT]             IP           --> Port
[:RUNS_SERVICE]         Port         --> Service
[:SERVES_URL]           Service      --> BaseURL
[:HAS_CERTIFICATE]      IP           --> Certificate
[:HAS_CERTIFICATE]      BaseURL      --> Certificate
[:HAS_TRACEROUTE]       IP           --> Traceroute
```

**Web application chain:**

```
[:HAS_ENDPOINT]         BaseURL      --> Endpoint
[:HAS_PARAMETER]        Endpoint     --> Parameter
[:HAS_HEADER]           BaseURL      --> Header
[:USES_TECHNOLOGY]      BaseURL      --> Technology  (props: confidence, detected_by)
[:USES_TECHNOLOGY]      IP           --> Technology  (props: detected_by='gvm')
[:USES_TECHNOLOGY]      Port         --> Technology  (props: detected_by='gvm')
```

**Vulnerability chains:**

```
[:HAS_VULNERABILITY]    Subdomain    --> Vulnerability
[:HAS_VULNERABILITY]    IP           --> Vulnerability
[:HAS_VULNERABILITY]    Port         --> Vulnerability
[:HAS_VULNERABILITY]    BaseURL      --> Vulnerability
[:HAS_VULNERABILITY]    Technology   --> Vulnerability
[:HAS_VULNERABILITY]    Domain       --> Vulnerability
[:FOUND_AT]             Vulnerability --> Endpoint
[:AFFECTS_PARAMETER]    Vulnerability --> Parameter
[:HAS_KNOWN_CVE]        Technology   --> CVE
[:HAS_CWE]              CVE          --> MitreData
[:HAS_CAPEC]            CVE          --> Capec
```

**Exploitation records:**

```
[:EXPLOITED_CVE]        Exploit      --> CVE
[:WAF_BYPASS_VIA]       Subdomain    --> BaseURL     (props: technique, timestamp)
```

**GitHub secret hunting:**

```
[:HAS_GITHUB_HUNT]      Domain       --> GithubHunt
[:HAS_REPOSITORY]       GithubHunt   --> GithubRepository
[:HAS_PATH]             GithubRepository --> GithubPath
[:CONTAINS_SECRET]      GithubPath   --> GithubSecret
[:CONTAINS_SENSITIVE_FILE] GithubPath --> GithubSensitiveFile
```

### 1.4 How RedAmon Queries the Graph (Text-to-Cypher)

RedAmon's AI agent uses LangChain + LangGraph with a `query_graph` tool. The flow:

1. User asks a natural language question via WebSocket chat
2. LLM generates a Cypher query from the question using the live schema
3. A regex-based tenant filter injects `user_id` and `project_id` properties into every node pattern (prevents cross-project data leakage)
4. Query executes against Neo4j; on failure, retries with error context (up to 3 attempts)
5. Results returned as natural language

The system prompt includes 25+ example query patterns covering the common traversal paths (Domain -> Subdomain -> IP -> Port -> Service -> Vulnerability -> CVE).

### 1.5 How Findings Flow Into the Graph

The pipeline processes findings in dependency order:

```
Phase 1: domain_discovery   --> Domain, Subdomain, IP, DNSRecord nodes
Phase 2: port_scan          --> Port, Service nodes
Phase 3: http_probe         --> BaseURL, Technology, Header, Certificate nodes
Phase 4: resource_enum      --> Endpoint, Parameter nodes (Katana crawler)
Phase 5: vuln_scan          --> Vulnerability, CVE, MitreData, Capec nodes (Nuclei)
Phase 6: gvm_scan           --> Vulnerability, CVE nodes (OpenVAS - network layer)
Standalone: github_hunt     --> GithubHunt, GithubRepository, GithubPath, GithubSecret nodes
```

All phases write to the same graph. Each phase uses MERGE operations so re-running is idempotent. Nuclei vulnerabilities link to specific Endpoint and Parameter nodes. GVM vulnerabilities link directly to IP and Subdomain nodes.

---

## Part 2: ATHENA Graph Intelligence Design

### 2.1 Design Philosophy

ATHENA's graph differs from RedAmon in three critical ways:

1. **Authorized, supervised testing** - ATHENA adds Engagement, Scope, HITLApproval, and Authorization nodes that RedAmon lacks entirely. Every offensive action requires authorization tracing.

2. **Evidence-first architecture** - Every finding links to its evidence: screenshots, command logs, tool output. The graph becomes a queryable evidence chain for client reports.

3. **PTES phase awareness** - Nodes carry phase metadata (recon, scanning, exploitation, post-exploitation) enabling phase-specific queries ("what did we find in the scanning phase?").

The SQLite database (`athena_tracker.db`) is **not replaced**. It remains the immutable audit trail. The Neo4j graph is a separate intelligence layer that enriches the raw data with relationships.

### 2.2 ATHENA Node Types (25 Total)

```
ATHENA Neo4j Node Taxonomy
==========================

ENGAGEMENT LAYER (5 nodes) - ATHENA-specific, not in RedAmon
  Engagement       - Root node for the entire pentest engagement
  Scope            - In-scope targets (IP ranges, domains, URLs)
  Authorization    - Written authorization document record
  RulesOfEngagement - Testing constraints and restrictions
  HITLApproval     - Human-in-the-loop approval checkpoint

INFRASTRUCTURE LAYER (5 nodes) - Adapted from RedAmon
  Host             - IP address or hostname (RedAmon: IP + Subdomain merged)
  Port             - Open port on a Host
  Service          - Running service with version info
  Domain           - Root domain (external engagements)
  Subnet           - Network segment (internal engagements)

WEB APPLICATION LAYER (4 nodes) - Adapted from RedAmon
  WebApp           - Web application endpoint (RedAmon: BaseURL)
  Endpoint         - Discovered URL path
  Parameter        - Input parameter, flagged when injectable
  Technology       - Detected framework, library, or server

VULNERABILITY LAYER (4 nodes) - Extended from RedAmon
  Finding          - ATHENA finding (maps to SQLite findings table)
  CVE              - Known vulnerability from NVD
  MitreAttack      - MITRE ATT&CK technique mapping
  Weakness         - CWE weakness classification

EXPLOITATION LAYER (2 nodes) - Adapted from RedAmon
  ExploitAttempt   - Validated exploitation proof-of-concept
  Session          - Active session (when applicable to engagement scope)

CREDENTIAL LAYER (2 nodes) - New for ATHENA
  Credential       - Discovered credential (hash, cleartext, etc.)
  CredentialStore  - Where credentials were found (DB, file, memory)

EVIDENCE LAYER (3 nodes) - New for ATHENA
  Evidence         - Screenshot, log, or artifact
  Command          - Executed command (maps to SQLite commands table)
  ScanResult       - Raw tool output (nmap XML, nikto log, etc.)
```

### 2.3 ATHENA Node Schemas

**Engagement (root node)**

```cypher
(:Engagement {
  id: STRING,              // UUID
  name: STRING,            // "AcmeCorp_2025-01-15_External"
  client: STRING,          // Client name
  engagement_type: STRING, // "external" | "internal" | "web-app" | "cloud"
  phase: STRING,           // current PTES phase
  status: STRING,          // "active" | "completed" | "on-hold"
  started_at: DATETIME,
  completed_at: DATETIME,
  tester: STRING,          // "Kelvin Lomboy / VERSANT"
  methodology: STRING,     // "PTES" | "OWASP" | "NIST-800-115"
  authorization_verified: BOOLEAN,
  authorization_ref: STRING // link to Authorization node
})
```

**Host (core infrastructure node)**

```cypher
(:Host {
  id: STRING,              // UUID
  engagement_id: STRING,   // tenant isolation
  ip_address: STRING,      // "10.0.0.5" or "203.0.113.10"
  hostname: STRING,        // "dc01.corp.local"
  os: STRING,              // "Windows Server 2019" (from nmap)
  os_confidence: INTEGER,  // 95
  is_in_scope: BOOLEAN,
  network_segment: STRING, // "DMZ" | "internal" | "internet-facing"
  asset_criticality: STRING, // "critical" | "high" | "medium" | "low"
  first_seen: DATETIME,
  last_scanned: DATETIME,
  is_cdn: BOOLEAN,
  cdn_name: STRING
})
```

**Port**

```cypher
(:Port {
  id: STRING,
  engagement_id: STRING,
  number: INTEGER,
  protocol: STRING,        // "tcp" | "udp"
  state: STRING,           // "open" | "filtered"
  host_ip: STRING,         // denormalized for query performance
  discovered_by: STRING,   // "nmap" | "naabu"
  discovered_at: DATETIME
})
```

**Service**

```cypher
(:Service {
  id: STRING,
  engagement_id: STRING,
  name: STRING,            // "http" | "ssh" | "smb"
  product: STRING,         // "Apache httpd" | "OpenSSH"
  version: STRING,         // "2.4.49" | "8.2p1"
  banner: STRING,          // raw banner grab
  extra_info: STRING,      // nmap extrainfo field
  cpe: STRING              // CPE 2.3 identifier
})
```

**Finding (core vulnerability node)**

```cypher
(:Finding {
  id: STRING,              // maps to SQLite findings.id
  engagement_id: STRING,
  title: STRING,
  severity: STRING,        // "critical" | "high" | "medium" | "low" | "info"
  cvss_score: FLOAT,
  category: STRING,        // "sqli" | "xss" | "rce" | "misconfig" | "auth"
  cve_id: STRING,          // if applicable
  description: STRING,
  impact: STRING,
  remediation: STRING,
  status: STRING,          // "identified" | "validated" | "remediated"
  validated: BOOLEAN,
  non_destructive: BOOLEAN, // was POC non-destructive?
  ptes_phase: STRING,      // which PTES phase discovered this
  discovered_by: STRING,   // tool name
  discovered_at: DATETIME,
  evidence_count: INTEGER  // denormalized count of linked Evidence nodes
})
```

**HITLApproval (ATHENA-specific)**

```cypher
(:HITLApproval {
  id: STRING,
  engagement_id: STRING,
  approval_type: STRING,   // "phase-transition" | "exploit-attempt" | "lateral-movement"
  action_requested: STRING, // what was proposed
  approved_by: STRING,     // "Kelvin Lomboy"
  approved_at: DATETIME,
  rationale: STRING,       // why approved
  constraints: STRING,     // any conditions on approval
  ptes_phase: STRING
})
```

**ExploitAttempt**

```cypher
(:ExploitAttempt {
  id: STRING,
  engagement_id: STRING,
  target_ip: STRING,
  target_port: INTEGER,
  attack_type: STRING,     // "cve-exploit" | "sqli" | "auth-bypass" | "brute-force"
  tool: STRING,            // "metasploit" | "sqlmap" | "manual"
  module: STRING,          // metasploit module or tool flag
  payload: STRING,
  cve_ids: LIST<STRING>,
  outcome: STRING,         // "success" | "failed" | "partial"
  session_id: STRING,      // if session established
  non_destructive: BOOLEAN,
  hitl_approval_id: STRING, // required: approval before exploit
  attempted_at: DATETIME
})
```

**Evidence**

```cypher
(:Evidence {
  id: STRING,
  engagement_id: STRING,
  type: STRING,            // "screenshot" | "log" | "request" | "response" | "artifact"
  filename: STRING,        // "001-CRITICAL-SQLI-login-bypass-20250106-143022.png"
  path: STRING,            // relative path in engagement folder
  sha256: STRING,          // integrity hash
  description: STRING,
  captured_at: DATETIME,
  tool: STRING             // what tool captured it
})
```

**Command**

```cypher
(:Command {
  id: STRING,              // maps to SQLite commands.id
  engagement_id: STRING,
  tool: STRING,            // "nmap" | "gobuster" | "nikto" | "sqlmap" | "metasploit"
  command_line: STRING,    // exact command executed
  target: STRING,
  ptes_phase: STRING,
  status: STRING,          // "executed" | "failed" | "skipped"
  duration_seconds: FLOAT,
  executed_at: DATETIME,
  output_path: STRING      // where output was saved
})
```

**Credential**

```cypher
(:Credential {
  id: STRING,
  engagement_id: STRING,
  credential_type: STRING, // "hash" | "cleartext" | "key" | "token" | "certificate"
  username: STRING,
  value_hint: STRING,      // first 4 chars only, never full credential in graph
  hash_type: STRING,       // "ntlm" | "sha256" | "bcrypt"
  service: STRING,         // where it was used
  cracked: BOOLEAN,
  found_at: DATETIME,
  finding_ref: STRING      // link to Finding node
})
```

### 2.4 ATHENA Relationship Types (28 Total)

**Engagement structure:**

```
[:HAS_SCOPE]         Engagement    --> Scope
[:HAS_AUTHORIZATION] Engagement    --> Authorization
[:HAS_ROE]           Engagement    --> RulesOfEngagement
[:COVERS]            Scope         --> Host
[:COVERS]            Scope         --> Domain
[:COVERS]            Scope         --> Subnet
[:REQUIRED_APPROVAL] ExploitAttempt --> HITLApproval
[:APPROVED_BY]       HITLApproval  --> Engagement
```

**Infrastructure topology:**

```
[:HAS_PORT]          Host          --> Port
[:RUNS_SERVICE]      Port          --> Service
[:BELONGS_TO_SUBNET] Host          --> Subnet
[:RESOLVES_TO]       Domain        --> Host
[:HOSTS]             Host          --> WebApp
[:USES_TECHNOLOGY]   WebApp        --> Technology
[:USES_TECHNOLOGY]   Service       --> Technology
```

**Web application:**

```
[:HAS_ENDPOINT]      WebApp        --> Endpoint
[:HAS_PARAMETER]     Endpoint      --> Parameter
```

**Finding relationships:**

```
[:HAS_FINDING]       Host          --> Finding
[:HAS_FINDING]       Port          --> Finding
[:HAS_FINDING]       WebApp        --> Finding
[:HAS_FINDING]       Endpoint      --> Finding
[:HAS_FINDING]       Service       --> Finding
[:HAS_FINDING]       Technology    --> Finding
[:AFFECTS_PARAMETER] Finding       --> Parameter
[:HAS_CVE]           Finding       --> CVE
[:MAPS_TO_ATTACK]    Finding       --> MitreAttack
[:CLASSIFIED_AS]     Finding       --> Weakness
[:HAS_KNOWN_CVE]     Technology    --> CVE
[:CHAINS_TO]         Finding       --> Finding       // vulnerability chaining
```

**Exploitation and evidence:**

```
[:EXPLOITS]          ExploitAttempt --> Finding
[:EXPLOITED_CVE]     ExploitAttempt --> CVE
[:YIELDS_SESSION]    ExploitAttempt --> Session
[:DISCOVERS]         ExploitAttempt --> Credential
[:FOUND_IN]          Credential    --> CredentialStore
[:EVIDENCED_BY]      Finding       --> Evidence
[:EVIDENCED_BY]      ExploitAttempt --> Evidence
[:EXECUTED_DURING]   Command       --> Finding
[:EXECUTED_DURING]   Command       --> ExploitAttempt
[:PRODUCED]          Command       --> ScanResult
[:INFORMS]           ScanResult    --> Finding
```

---

## Part 3: Architecture Design

### 3.1 Dual-Database Architecture

```
ATHENA Data Architecture
========================

  ┌─────────────────────────────────────────────────────┐
  │                    ATHENA CLAUDE CODE                │
  │                                                     │
  │  /engage  /scan  /validate  /evidence  /report      │
  └─────────────┬───────────────────────┬───────────────┘
                │                       │
                v                       v
  ┌─────────────────────┐   ┌───────────────────────────┐
  │   SQLite Database   │   │    Neo4j Graph Database   │
  │  athena_tracker.db  │   │    (Intelligence Layer)   │
  │                     │   │                           │
  │  [AUDIT TRAIL]      │   │  [RELATIONSHIP ANALYSIS]  │
  │                     │   │                           │
  │  engagements        │   │  Attack surface graph     │
  │  commands           │   │  Vulnerability chains     │
  │  findings           │   │  Attack path analysis     │
  │  services           │   │  Evidence relationships   │
  │  hitl_approvals     │   │  Natural language queries │
  │                     │   │                           │
  │  Immutable audit    │   │  Queryable intelligence   │
  │  Sequential IDs     │   │  Graph traversals         │
  │  Simple queries     │   │  Pattern matching         │
  └─────────────────────┘   └───────────────────────────┘
                │                       │
                └───────────┬───────────┘
                            │
                    athena_graph_sync.py
                    (SQLite -> Neo4j bridge)
```

### 3.2 Component Architecture

```
ATHENA Components
=================

  tools/
  ├── athena-monitor/
  │   ├── athena_tracker.db        (existing SQLite)
  │   ├── athena_monitor.py        (existing NiceGUI dashboard)
  │   └── athena_monitor_v2.py     (existing)
  │
  └── athena-graph/                (NEW)
      ├── docker-compose.yml       (Neo4j container)
      ├── neo4j_client.py          (graph write/read operations)
      ├── athena_graph_sync.py     (SQLite -> Neo4j sync)
      ├── graph_queries.py         (pre-built Cypher query library)
      ├── text_to_cypher.py        (natural language -> Cypher via Claude)
      └── requirements.txt

  .claude/commands/
  ├── engage.md                    (existing - add graph init)
  ├── scan.md                      (existing - add graph writes)
  ├── validate.md                  (existing - add exploit nodes)
  ├── evidence.md                  (existing - add evidence nodes)
  ├── graph.md                     (NEW - graph query interface)
  └── attack-paths.md              (NEW - attack path analysis)
```

### 3.3 Full Graph Schema (ASCII Diagram)

```
ATHENA Neo4j Graph Schema
=========================

[Engagement]──HAS_SCOPE──>[Scope]──COVERS──>[Host]──HAS_PORT──>[Port]──RUNS_SERVICE──>[Service]
     │                                │                                                    │
     HAS_AUTHORIZATION                COVERS                                         USES_TECHNOLOGY
     │                                │                                                    │
     v                                v                                                    v
[Authorization]              [Domain]──RESOLVES_TO──>[Host]                         [Technology]
                                                                                          │
                                                                                    HAS_KNOWN_CVE
[RulesOfEngagement]<──HAS_ROE──[Engagement]                                               │
                                                                                          v
[HITLApproval]<──REQUIRED_APPROVAL──[ExploitAttempt]──EXPLOITS──>[Finding]────────>[CVE]
                                          │                          │
                              YIELDS_SESSION    EVIDENCED_BY    MAPS_TO_ATTACK
                                          │         │                │
                                          v         v                v
                                      [Session]  [Evidence]  [MitreAttack]

[Host]──HOSTS──>[WebApp]──HAS_ENDPOINT──>[Endpoint]──HAS_PARAMETER──>[Parameter]
  │                 │                         │
  HAS_FINDING   HAS_FINDING            HAS_FINDING
  │                 │                         │
  v                 v                         v
[Finding]────────────────────────────────[Finding]
  │                                          │
  CHAINS_TO                           AFFECTS_PARAMETER
  │                                          │
  v                                          v
[Finding]                              [Parameter]

[Finding]──CLASSIFIED_AS──>[Weakness]
[Finding]──HAS_CVE──>[CVE]──HAS_CWE──>[Weakness]
[CVE]──HAS_CAPEC──>[MitreAttack]

[ExploitAttempt]──DISCOVERS──>[Credential]──FOUND_IN──>[CredentialStore]

[Command]──EXECUTED_DURING──>[Finding]
[Command]──PRODUCED──>[ScanResult]──INFORMS──>[Finding]
[ScanResult]──EVIDENCED_BY──>[Evidence]
```

---

## Part 4: Findings Flow into the Graph

### 4.1 Slash Command Integration

Each ATHENA slash command writes to both SQLite and Neo4j:

**`/scan [TARGET]`**

```
Tool execution (nmap/gobuster/nikto)
         |
         v
SQLite: INSERT INTO commands
SQLite: INSERT INTO services
SQLite: INSERT INTO findings
         |
         v (graph writes)
Neo4j: MERGE (:Host {ip_address: target})
Neo4j: MERGE (:Port {number: port}) -[:HAS_PORT]-> Host
Neo4j: MERGE (:Service {name: svc}) -[:RUNS_SERVICE]-> Port
Neo4j: MERGE (:WebApp {url: url}) -[:HOSTS]-> Host
Neo4j: MERGE (:Technology {name: tech}) -[:USES_TECHNOLOGY]-> WebApp
Neo4j: MERGE (:Finding {severity: sev}) -[:HAS_FINDING]-> Host/Port/WebApp
Neo4j: MERGE (:CVE {id: cve}) -[:HAS_CVE]-> Finding (if CVE known)
```

**`/validate [VULNERABILITY]`**

```
HITL approval checkpoint
         |
         v
HITLApproval node created
         |
         v (after approval)
Non-destructive POC executed
         |
         v
SQLite: UPDATE findings SET validated=1
Neo4j: MERGE (:ExploitAttempt {outcome: 'success'}) -[:EXPLOITS]-> Finding
Neo4j: HITLApproval -[:APPROVED_BY]-> ExploitAttempt
Neo4j: Evidence nodes created and linked
Neo4j: Finding.validated = true
```

**`/evidence [ENGAGEMENT]`**

```
Screenshot collection
         |
         v
Neo4j: MERGE (:Evidence {filename: file, sha256: hash})
Neo4j: Finding -[:EVIDENCED_BY]-> Evidence
Neo4j: Command -[:PRODUCED]-> ScanResult -[:INFORMS]-> Finding
```

### 4.2 Graph Population Order (Dependency Chain)

```
1. /engage   --> Engagement, Scope, Authorization, RulesOfEngagement nodes
2. /scan     --> Host, Port, Service, WebApp, Endpoint, Technology nodes
3. /scan     --> Finding nodes (from nikto, nuclei, manual)
4. /validate --> ExploitAttempt, HITLApproval, Evidence nodes
5. /evidence --> Evidence nodes bulk-linked to Findings
6. /report   --> Query graph for report generation
```

---

## Part 5: Example Cypher Queries

### 5.1 Attack Surface Overview

```cypher
-- All critical and high findings for this engagement
MATCH (e:Engagement {id: $engagement_id})
MATCH (e)-[:HAS_SCOPE]->(s:Scope)-[:COVERS]->(h:Host)
MATCH (h)-[:HAS_FINDING]->(f:Finding)
WHERE f.severity IN ['critical', 'high']
RETURN h.ip_address, h.hostname, f.title, f.severity, f.cvss_score, f.status
ORDER BY f.cvss_score DESC
LIMIT 50
```

```cypher
-- Technology inventory with known CVEs
MATCH (e:Engagement {id: $engagement_id})
MATCH (e)-[:HAS_SCOPE]->(s:Scope)-[:COVERS]->(h:Host)
MATCH (h)-[:HOSTS]->(w:WebApp)-[:USES_TECHNOLOGY]->(t:Technology)
OPTIONAL MATCH (t)-[:HAS_KNOWN_CVE]->(c:CVE)
WHERE c.cvss >= 7.0
RETURN t.name, t.version, count(c) AS critical_cves, collect(c.id)[0..5] AS sample_cves
ORDER BY critical_cves DESC
```

### 5.2 Attack Path Analysis

```cypher
-- Attack paths from internet-facing hosts to internal systems
MATCH path = (h1:Host {network_segment: 'internet-facing'})-[:HAS_PORT|RUNS_SERVICE|HAS_FINDING*1..4]->(f:Finding)
MATCH (f)-[:CHAINS_TO*1..3]->(f2:Finding)-[:HAS_FINDING]-(h2:Host {network_segment: 'internal'})
WHERE f.severity IN ['critical', 'high'] AND f2.severity IN ['critical', 'high']
RETURN h1.ip_address AS entry_point,
       h2.ip_address AS target,
       [node in nodes(path) | labels(node)[0] + ': ' + coalesce(node.title, node.ip_address, node.name, '')] AS path
LIMIT 20
```

```cypher
-- What attack paths lead to domain admin?
MATCH (e:Engagement {id: $engagement_id})
MATCH (dc:Host)-[:RUNS_SERVICE]->(svc:Service)
WHERE svc.name IN ['ldap', 'kerberos', 'msrpc']
   OR dc.hostname CONTAINS 'DC'
   OR dc.hostname CONTAINS 'dc'
MATCH path = shortestPath(
  (entry:Host {network_segment: 'internet-facing'})-[*1..10]-(dc)
)
WHERE entry <> dc
RETURN length(path) AS hop_count,
       [n in nodes(path) | coalesce(n.ip_address, n.hostname, n.name, n.title)] AS path_nodes
ORDER BY hop_count ASC
LIMIT 10
```

```cypher
-- All critical vulnerabilities reachable from the DMZ
MATCH (subnet:Subnet {name: 'DMZ'})
MATCH (h:Host)-[:BELONGS_TO_SUBNET]->(subnet)
MATCH path = (h)-[:HAS_PORT|HAS_FINDING|CHAINS_TO*1..5]->(f:Finding)
WHERE f.severity = 'critical'
RETURN DISTINCT h.ip_address AS host,
       f.title AS vulnerability,
       f.cve_id AS cve,
       f.cvss_score AS cvss,
       length(path) AS hops_from_dmz
ORDER BY cvss DESC
```

### 5.3 Vulnerability Chain Analysis

```cypher
-- Find multi-step vulnerability chains (composite attack paths)
MATCH (f1:Finding)-[:CHAINS_TO]->(f2:Finding)-[:CHAINS_TO]->(f3:Finding)
WHERE f1.severity IN ['high', 'critical']
RETURN f1.title AS step1,
       f1.category AS category1,
       f2.title AS step2,
       f2.category AS category2,
       f3.title AS step3,
       f3.category AS category3
LIMIT 20
```

```cypher
-- CVE exploitation feasibility (known CVE + open port + detected version)
MATCH (h:Host {engagement_id: $engagement_id})
MATCH (h)-[:HAS_PORT]->(p:Port)-[:RUNS_SERVICE]->(svc:Service)
MATCH (svc)-[:USES_TECHNOLOGY]->(t:Technology)
MATCH (t)-[:HAS_KNOWN_CVE]->(c:CVE)
WHERE c.cvss >= 9.0
  AND NOT (h)-[:HAS_FINDING]->(:Finding {cve_id: c.id, status: 'validated'})
RETURN h.ip_address, p.number, svc.product, svc.version,
       t.name, c.id, c.cvss, c.description
ORDER BY c.cvss DESC
LIMIT 30
```

### 5.4 HITL and Compliance Queries

```cypher
-- All exploit attempts and their approvals (audit trail)
MATCH (e:Engagement {id: $engagement_id})
MATCH (ea:ExploitAttempt)-[:REQUIRED_APPROVAL]->(hitl:HITLApproval)
WHERE ea.engagement_id = e.id
RETURN ea.attack_type, ea.target_ip, ea.target_port, ea.outcome,
       hitl.approved_by, hitl.approved_at, hitl.rationale,
       ea.non_destructive
ORDER BY ea.attempted_at
```

```cypher
-- Findings without evidence (gaps in documentation)
MATCH (e:Engagement {id: $engagement_id})
MATCH (f:Finding {engagement_id: e.id})
WHERE f.severity IN ['critical', 'high']
  AND NOT (f)-[:EVIDENCED_BY]->(:Evidence)
RETURN f.title, f.severity, f.status, f.host_ip
ORDER BY f.severity
```

```cypher
-- Complete evidence chain for a specific finding (for report)
MATCH (f:Finding {id: $finding_id})
OPTIONAL MATCH (h:Host)-[:HAS_FINDING]->(f)
OPTIONAL MATCH (p:Port)-[:HAS_FINDING]->(f)
OPTIONAL MATCH (w:WebApp)-[:HAS_FINDING]->(f)
OPTIONAL MATCH (f)-[:EVIDENCED_BY]->(ev:Evidence)
OPTIONAL MATCH (f)-[:HAS_CVE]->(cve:CVE)
OPTIONAL MATCH (f)-[:MAPS_TO_ATTACK]->(ma:MitreAttack)
OPTIONAL MATCH (cmd:Command)-[:EXECUTED_DURING]->(f)
RETURN f, h, p, w, collect(ev) AS evidence_items,
       cve, ma, collect(cmd) AS commands_used
```

### 5.5 Service Inventory and Fingerprinting

```cypher
-- Complete service inventory for engagement
MATCH (e:Engagement {id: $engagement_id})
MATCH (e)-[:HAS_SCOPE]->(s:Scope)-[:COVERS]->(h:Host)
MATCH (h)-[:HAS_PORT]->(p:Port)-[:RUNS_SERVICE]->(svc:Service)
WHERE p.state = 'open'
RETURN h.ip_address, h.hostname, p.number, p.protocol,
       svc.name, svc.product, svc.version, svc.banner
ORDER BY h.ip_address, p.number
```

```cypher
-- All web applications and their technology stacks
MATCH (e:Engagement {id: $engagement_id})
MATCH (h:Host)-[:HOSTS]->(w:WebApp)-[:USES_TECHNOLOGY]->(t:Technology)
WHERE h.engagement_id = e.id
RETURN w.url, collect(t.name + ' ' + coalesce(t.version, '')) AS stack,
       w.status_code, w.server
ORDER BY w.url
```

### 5.6 Credential and Post-Exploitation Queries

```cypher
-- All discovered credentials (redacted values) and where they apply
MATCH (cred:Credential {engagement_id: $engagement_id})
OPTIONAL MATCH (cred)-[:FOUND_IN]->(cs:CredentialStore)
OPTIONAL MATCH (ea:ExploitAttempt)-[:DISCOVERS]->(cred)
RETURN cred.credential_type, cred.username, cred.value_hint,
       cred.hash_type, cred.cracked, cred.service,
       cs.location, ea.target_ip
ORDER BY cred.credential_type
```

---

## Part 6: Migration Path

### 6.1 Overview

Migration is additive - SQLite is never modified or replaced. Neo4j starts empty and is populated from existing SQLite data via a sync script, then kept in sync by ATHENA's slash commands going forward.

```
Migration Phases
================

Phase 1: Infrastructure Setup (Week 1)
  - Neo4j container deployment (Docker)
  - neo4j_client.py implementation
  - Schema initialization (constraints + indexes)
  - Connection verification

Phase 2: Historical Migration (Week 1)
  - athena_graph_sync.py: read SQLite, write Neo4j
  - Engagement nodes from SQLite engagements table
  - Host/Port/Service nodes from SQLite services table
  - Finding nodes from SQLite findings table
  - Command nodes from SQLite commands table
  - Basic relationships (Finding -> Host, Command -> Finding)

Phase 3: Slash Command Integration (Week 2)
  - Update /engage to initialize Engagement + Scope nodes
  - Update /scan to write Host/Port/Service/Finding nodes
  - Update /validate to write ExploitAttempt + HITLApproval nodes
  - Update /evidence to write Evidence nodes
  - Add /graph command for natural language queries

Phase 4: Intelligence Layer (Week 3)
  - Vulnerability chaining (Finding [:CHAINS_TO] Finding)
  - CVE enrichment (Technology [:HAS_KNOWN_CVE] CVE via NVD API)
  - MITRE ATT&CK mapping (Finding [:MAPS_TO_ATTACK] MitreAttack)
  - CWE weakness classification

Phase 5: Query Interface (Week 3-4)
  - text_to_cypher.py: Claude API for natural language queries
  - /attack-paths slash command
  - /graph-report for report generation
  - graph_queries.py: pre-built query library
```

### 6.2 SQLite to Neo4j Mapping

| SQLite Table | SQLite Columns | Neo4j Node(s) | Neo4j Relationships |
|---|---|---|---|
| engagements | id, name, client, engagement_type, started_at, status, scope, authorization_verified | Engagement, Scope | HAS_SCOPE |
| commands | id, timestamp, engagement, host, phase, command, tool, target, status, duration_seconds | Command, Host | EXECUTED_DURING |
| findings | id, timestamp, engagement, host, severity, category, title, description, target, port, protocol, cve_id, cvss_score, status, validated | Finding, Host, Port, CVE | HAS_FINDING, HAS_CVE |
| services | id, timestamp, engagement, host, port, protocol, state, name, product, version | Host, Port, Service | HAS_PORT, RUNS_SERVICE |

### 6.3 Data Integrity During Migration

1. SQLite remains the source of truth for historical data
2. Neo4j IDs reference SQLite IDs where applicable (findings.id, commands.id)
3. Graph sync is idempotent (MERGE operations, safe to re-run)
4. New engagements write to both simultaneously from day one of Phase 3

---

## Part 7: Docker Setup

### 7.1 Neo4j Container Configuration

**File: `tools/athena-graph/docker-compose.yml`**

```yaml
# ATHENA Neo4j Graph Intelligence Layer
# Runs alongside the existing ATHENA Monitor (port 8080)
# Neo4j Browser: http://localhost:7474
# Bolt:          bolt://localhost:7687

services:
  neo4j:
    image: neo4j:5.26-community
    container_name: athena-neo4j
    ports:
      - "7474:7474"   # Browser UI (do not expose externally)
      - "7687:7687"   # Bolt protocol for Python driver
    environment:
      - NEO4J_AUTH=neo4j/${ATHENA_NEO4J_PASSWORD}
      - NEO4J_PLUGINS=["apoc"]
      - NEO4J_dbms_security_procedures_unrestricted=apoc.*
      - NEO4J_dbms_security_procedures_allowlist=apoc.*
      - NEO4J_server_memory_heap_initial__size=512m
      - NEO4J_server_memory_heap_max__size=1G
      - NEO4J_server_memory_pagecache__size=512m
    volumes:
      - athena_neo4j_data:/data
      - athena_neo4j_logs:/logs
      - athena_neo4j_import:/var/lib/neo4j/import
      - athena_neo4j_plugins:/plugins
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "wget", "-q", "--spider", "http://localhost:7474"]
      interval: 15s
      timeout: 10s
      retries: 5
      start_period: 30s

volumes:
  athena_neo4j_data:
    name: athena_neo4j_data
  athena_neo4j_logs:
    name: athena_neo4j_logs
  athena_neo4j_import:
    name: athena_neo4j_import
  athena_neo4j_plugins:
    name: athena_neo4j_plugins
```

**1Password secret reference (`.env.1password`):**

```
ATHENA_NEO4J_PASSWORD=op://Private/ATHENA Neo4j/password
```

**Run with:**

```bash
op run --env-file=.claude/.env.1password -- docker compose -f tools/athena-graph/docker-compose.yml up -d
```

### 7.2 Mini-PC Deployment (Kali alongside Neo4j)

On Kelvin's mini-PC running ATHENA, the full stack is:

```
Mini-PC Docker Stack
====================

  Port 8080  - ATHENA Monitor (NiceGUI dashboard, existing)
  Port 7474  - Neo4j Browser UI (localhost only)
  Port 7687  - Neo4j Bolt (Python driver, internal)
  Port [varies] - Kali MCP Server (existing)

  Volumes:
    athena_neo4j_data  - Graph data (persistent across container restarts)
    athena_tracker.db  - SQLite audit trail (host filesystem, gitignored)

  Memory allocation (recommended for mini-PC):
    Neo4j heap:      1G
    Neo4j pagecache: 512m
    Remaining:       For Kali tools and ATHENA processes
```

**Network isolation:** Neo4j container should only accept connections from localhost. Do not expose ports 7474/7687 to the network during client engagements.

```bash
# Verify Neo4j is not listening externally
netstat -tlnp | grep 7687
# Should show 127.0.0.1:7687, NOT 0.0.0.0:7687
```

To restrict to localhost only, modify the port mapping:

```yaml
ports:
  - "127.0.0.1:7474:7474"
  - "127.0.0.1:7687:7687"
```

---

## Part 8: Integration with ATHENA AI

### 8.1 Natural Language Query Interface (`/graph`)

The `/graph` slash command will expose graph intelligence through Claude:

```
/graph show all critical findings reachable from the DMZ
/graph what attack paths lead to the database server?
/graph which technologies have unpatched CVEs above 8.0?
/graph show the complete evidence chain for VULN-003
/graph what credentials were discovered during the engagement?
```

**Implementation approach:** ATHENA passes the question to a `text_to_cypher.py` module that:

1. Retrieves the current Neo4j schema
2. Prompts Claude with the schema + example patterns + engagement context
3. Generates Cypher with engagement_id filter auto-injected
4. Executes query; retries with error context on failure (max 3 attempts)
5. Returns results formatted for inclusion in Claude's response

**Critical difference from RedAmon:** RedAmon uses LangChain's built-in graph QA. ATHENA will use Claude directly (already in context), avoiding an additional API call and keeping costs near zero.

### 8.2 Report Generation Integration (`/report`)

The graph enables richer report generation:

```
/report [ENGAGEMENT] --use-graph
```

The command queries the graph to assemble:

- Attack surface summary (Host/Port/Service/WebApp counts by segment)
- Finding distribution by severity (graph aggregation vs. manual counting)
- Attack paths discovered (automated from graph traversal)
- Technology risk summary (Technology -> CVE chains)
- Evidence chain per finding (complete provenance for each vulnerability)
- MITRE ATT&CK coverage matrix (from MitreAttack nodes)
- Remediation roadmap (ordered by severity + attack path impact)

### 8.3 Graph Reasoning During Pentests

When ATHENA's AI is mid-engagement, it can query the graph before choosing its next action:

```
Before running sqlmap:
  MATCH (f:Finding {category: 'sqli', engagement_id: $id})
  RETURN count(f) AS existing_sqli_findings
  -> If count > 0, don't re-scan, review existing findings first

Before requesting HITL approval for exploitation:
  MATCH (ea:ExploitAttempt {target_ip: $ip, engagement_id: $id})
  RETURN ea.outcome
  -> If previous attempt failed, include failure context in approval request

Before reporting:
  MATCH (f:Finding {engagement_id: $id}) WHERE NOT (f)-[:EVIDENCED_BY]->(:Evidence)
  -> Flag findings without evidence before generating report
```

---

## Part 9: Key Differences from RedAmon

| Dimension | RedAmon | ATHENA |
|---|---|---|
| Purpose | Autonomous offensive red team | Supervised authorized pentest |
| HITL | Optional approval gates | Mandatory - baked into schema |
| Evidence | Not modeled in graph | First-class graph citizens |
| Engagement scoping | Not modeled (single target) | Scope nodes with authorization tracing |
| SQLite | Not used | Retained as immutable audit trail |
| GitHub hunting | Integrated | Out of initial scope |
| Multi-tenancy | user_id + project_id on every node | engagement_id on every node |
| Text-to-Cypher | LangChain + LangGraph agent | Claude directly (in-context) |
| Exploitation nodes | Exploit node (autonomous) | ExploitAttempt node (requires HITLApproval) |
| Non-destructive policy | Not enforced in graph | non_destructive boolean on ExploitAttempt |
| Phase tracking | Informational/Exploitation/Post | PTES 9 phases on Command and Finding nodes |

---

## Part 10: Implementation Priorities

### P0 - Must Have for Initial Release

1. Neo4j Docker container running and accessible
2. Schema initialization (25 node types, 28 relationship types, constraints, indexes)
3. athena_graph_sync.py - migrate existing SQLite data to graph
4. neo4j_client.py - MERGE operations for all node types
5. `/engage` integration - create Engagement + Scope nodes
6. `/scan` integration - write Host/Port/Service/Finding nodes
7. `/validate` integration - write ExploitAttempt + HITLApproval nodes
8. Basic `/graph` command with 10 pre-built queries

### P1 - High Value

1. text_to_cypher.py - natural language queries via Claude
2. CVE enrichment from NVD API (Technology -> CVE relationships)
3. MITRE ATT&CK mapping (Finding -> MitreAttack)
4. Vulnerability chaining (Finding [:CHAINS_TO] Finding)
5. Evidence nodes from `/evidence` command
6. Attack path queries in `/graph`

### P2 - Future Enhancements

1. `/report --use-graph` with graph-driven sections
2. Real-time ATHENA Monitor dashboard with graph visualization
3. CWE weakness classification (CVE -> Weakness)
4. Credential graph (Credential + CredentialStore nodes)
5. CAPEC attack patterns
6. Neo4j Bloom visualization for client presentations

---

## Appendix A: Schema Constraints and Indexes

```cypher
-- Uniqueness constraints
CREATE CONSTRAINT engagement_unique IF NOT EXISTS
  FOR (e:Engagement) REQUIRE e.id IS UNIQUE;

CREATE CONSTRAINT host_unique IF NOT EXISTS
  FOR (h:Host) REQUIRE (h.ip_address, h.engagement_id) IS UNIQUE;

CREATE CONSTRAINT finding_unique IF NOT EXISTS
  FOR (f:Finding) REQUIRE f.id IS UNIQUE;

CREATE CONSTRAINT cve_unique IF NOT EXISTS
  FOR (c:CVE) REQUIRE c.id IS UNIQUE;

CREATE CONSTRAINT exploit_unique IF NOT EXISTS
  FOR (ea:ExploitAttempt) REQUIRE ea.id IS UNIQUE;

CREATE CONSTRAINT hitl_unique IF NOT EXISTS
  FOR (h:HITLApproval) REQUIRE h.id IS UNIQUE;

-- Performance indexes
CREATE INDEX idx_host_engagement IF NOT EXISTS
  FOR (h:Host) ON (h.engagement_id);

CREATE INDEX idx_finding_engagement IF NOT EXISTS
  FOR (f:Finding) ON (f.engagement_id);

CREATE INDEX idx_finding_severity IF NOT EXISTS
  FOR (f:Finding) ON (f.severity);

CREATE INDEX idx_finding_status IF NOT EXISTS
  FOR (f:Finding) ON (f.status);

CREATE INDEX idx_port_engagement IF NOT EXISTS
  FOR (p:Port) ON (p.engagement_id);

CREATE INDEX idx_service_product IF NOT EXISTS
  FOR (s:Service) ON (s.product, s.version);

CREATE INDEX idx_tech_name IF NOT EXISTS
  FOR (t:Technology) ON (t.name, t.version);

CREATE INDEX idx_cve_cvss IF NOT EXISTS
  FOR (c:CVE) ON (c.cvss);

CREATE INDEX idx_exploit_outcome IF NOT EXISTS
  FOR (ea:ExploitAttempt) ON (ea.outcome, ea.engagement_id);
```

---

## Appendix B: Reference Links

- RedAmon Repository: https://github.com/samugit83/redamon
- RedAmon Neo4j Client: graph_db/neo4j_client.py (198KB, primary schema source)
- Neo4j Community 5.26: https://hub.docker.com/_/neo4j
- APOC Plugin: https://neo4j.com/labs/apoc/
- PTES Methodology: http://www.pentest-standard.org/
- MITRE ATT&CK: https://attack.mitre.org/
- NVD CVE API: https://nvd.nist.gov/developers/vulnerabilities

---

*This document is confidential - VERSANT internal planning material.*
*ATHENA is designed for authorized penetration testing only.*
*All testing activities must comply with signed authorization documents.*
