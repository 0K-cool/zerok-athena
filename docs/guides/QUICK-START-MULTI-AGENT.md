# Quick Start Guide: Multi-Agent Penetration Testing System

**Get started with automated AI-powered penetration testing in 5 minutes.**

**Supports**: External Penetration Testing, Internal Network Penetration Testing, Web Application Assessments, Red Team Engagements

---

## Prerequisites

### 1. Verify MCP Servers Running

```bash
# Check Kali MCP server
curl http://localhost:8000/health

# Check Playwright MCP server
# (should respond if configured)

# Check Velociraptor MCP (optional - for IR/forensics)
```

### 2. Launch Pentest Monitor Dashboard

```bash
cd tools/athena-monitor
source venv/bin/activate  # If not already activated
python athena_monitor.py
```

**Dashboard**: http://localhost:8080

Keep this running in a separate terminal - it provides real-time monitoring.

---

## 5-Minute Quick Start

### Option 1: Full Automated Pentest (Recommended)

**External Pentest**:
```bash
/orchestrate TestCorp - External Pentest
```

**Internal Pentest**:
```bash
/orchestrate TestCorp - Internal Pentest
```

**What happens**:
1. ✅ **Planning Agent** validates authorization (you confirm)
2. ✅ **Passive OSINT Agent** gathers intelligence (zero target contact)
3. ✅ **Active Recon Agent** scans network and services
4. ✅ **Web Vuln Scanner Agent** tests for OWASP Top 10
5. 🚨 **HITL Approval** - You approve exploitation
6. ✅ **Exploitation Agent** validates vulnerabilities (safe POC)
7. ✅ **Post-Exploitation Agent** models attack scenarios (lateral movement for internal)
8. ✅ **Reporting Agent** generates professional deliverables

**Duration**: ~8-12 hours (external), ~12-24 hours (internal - larger attack surface)

**Output**:
- Executive Summary (PDF)
- Technical Report (PDF)
- Remediation Roadmap (Excel)
- Evidence Package (Encrypted ZIP)

---

## External vs Internal Pentesting

### External Penetration Test

**Focus**: Public-facing attack surface
**Network Position**: Outside firewall (internet)
**Typical Scope**:
- Public IP ranges
- Domain names (example.com, *.example.com)
- Web applications
- VPN endpoints
- Email servers

**Example**:
```bash
/engage ACME Corporation - External Pentest

# Scope examples:
# - Domains: acme.com, *.acme.com
# - IPs: 203.0.113.0/24
# - Web apps: https://app.acme.com, https://portal.acme.com

/orchestrate ACME_2025-12-16_External
```

**Primary Findings**:
- Web application vulnerabilities (OWASP Top 10)
- Exposed services
- SSL/TLS misconfigurations
- Information disclosure
- Authentication weaknesses

---

### Internal Network Penetration Test

**Focus**: Internal network security (assumes breach)
**Network Position**: Inside network (simulates insider threat or compromised workstation)
**Typical Scope**:
- Internal IP ranges (10.x.x.x, 172.16.x.x, 192.168.x.x)
- Internal web applications (intranet sites)
- File shares (SMB/CIFS)
- Active Directory
- Internal databases
- Workstations and servers

**Example**:
```bash
/engage ACME Corporation - Internal Pentest

# Scope examples:
# - Internal IPs: 10.10.0.0/16, 172.16.50.0/24
# - Domain: corp.local
# - Focus: Active Directory, file shares, lateral movement

/orchestrate ACME_2025-12-16_Internal
```

**Primary Findings**:
- Privilege escalation paths
- Lateral movement opportunities
- Active Directory weaknesses
- Insecure SMB shares
- Weak domain user passwords
- Unpatched internal systems
- Network segmentation issues

**What the agents do differently for internal**:
- **Active Recon Agent**: Focuses on SMB enumeration (enum4linux), internal DNS, LDAP
- **Post-Exploitation Agent**: Emphasizes lateral movement, privilege escalation to Domain Admin
- **Reporting Agent**: Includes internal-specific recommendations (network segmentation, AD hardening)

---

### Option 2: Phase-by-Phase Control

**External Example**:
```bash
# Phase 1: Planning & Authorization
/engage TestCorp - External Pentest

# Phase 2a: Passive Intelligence Gathering
/recon testcorp.com

# Review OSINT findings, then proceed...

# Phase 2b & 4: Active Scanning
/scan testcorp.com

# Review vulnerability findings, then proceed...

# Phase 5: Validate Critical Findings
/validate VULN-001

# Phase 7: Generate Report
/report TestCorp_2025-12-16_External
```

**Internal Example**:
```bash
# Phase 1: Planning & Authorization
/engage ACME - Internal Pentest

# Phase 2a: Internal Intelligence Gathering
/recon corp.local  # Internal DNS, AD user enumeration

# Phase 2b & 4: Internal Network Scanning
/scan 10.10.0.0/16  # Scan entire internal network

# Phase 5: Validate Findings
/validate VULN-005  # SMB null session
/validate VULN-012  # Kerberoasting possible

# Phase 7: Generate Report
/report ACME_2025-12-16_Internal
```

---

## Typical Workflows

### Workflow 1: External Network Pentest

```bash
# 1. Start engagement
/engage ACME Corporation - External Pentest

# Provide authorization details when prompted:
# - Client: ACME Corporation
# - Type: External
# - Scope: acme.com, *.acme.com, 192.0.2.0/24
# - Authorization: Signed contract on file
# - RoE: 24/7 testing, moderate rate limits

# 2. Full automated execution
/orchestrate ACME_2025-12-16_External

# 3. Wait for HITL approval prompts
# You'll be asked to approve exploitation for high-severity findings

# 4. Review deliverables
# Check: 09-reporting/final/
```

---

### Workflow 2: Internal Network Pentest

```bash
# 1. Start engagement
/engage ACME Corporation - Internal Pentest

# Provide authorization details:
# - Client: ACME Corporation
# - Type: Internal
# - Scope: 10.10.0.0/16, 172.16.50.0/24, corp.local
# - Network Position: Assumed compromised workstation
# - Authorization: Signed contract + VPN credentials provided
# - RoE: Business hours only, no production DB testing

# 2. Full automated execution
/orchestrate ACME_2025-12-16_Internal

# What happens (internal-specific):
# - Active Recon: Scans internal networks, SMB enumeration
# - Vuln Analysis: Tests intranet apps, file shares, AD
# - Post-Exploit: Maps lateral movement paths, privilege escalation to Domain Admin
# - Reporting: Internal-specific findings (AD weaknesses, segmentation issues)

# 3. Review deliverables focused on:
# - Privilege escalation paths
# - Lateral movement opportunities
# - Active Directory attack paths
# - Network segmentation weaknesses
```

---

### Workflow 3: Web Application Assessment

```bash
# 1. Start engagement
/engage ClientCo - Web App Assessment

# 2. Quick recon to identify technology stack
/recon webapp.client.com

# Result shows: React SPA detected

# 3. Use Playwright-enhanced web scanning
/scan webapp.client.com

# Web Vuln Scanner Agent automatically detects SPA
# and uses Playwright for JavaScript-heavy testing

# 4. Validate findings
/validate VULN-002  # XSS in comment field
/validate VULN-005  # IDOR in API endpoint

# 5. Generate report
/report ClientCo_2025-12-16_WebApp
```

---

### Workflow 4: Quick Security Check (No Exploitation)

```bash
# Skip exploitation phase entirely
/orchestrate TestCorp --skip-exploitation

# What runs:
# - Planning
# - OSINT
# - Active Recon
# - Vulnerability Scanning
# - Reporting (findings documented as theoretical)

# Use case: Compliance scans, pre-launch security checks
```

---

## Understanding Agent Dispatch

When you run `/orchestrate`, here's what happens behind the scenes:

```
┌─────────────────────────────────────────────────────────────┐
│                  YOU RUN: /orchestrate                      │
│     (External OR Internal Pentest)                          │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│         ORCHESTRATOR AGENT (Opus Model)                     │
│  • Validates authorization                                  │
│  • Detects engagement type (External/Internal)              │
│  • Dispatches specialized subagents in optimal order        │
│  • Adjusts testing strategy based on network position       │
│  • Aggregates results from all agents                       │
│  • Requests HITL approvals at checkpoints                   │
└─────────────────────────────────────────────────────────────┘
                            ↓
        ┌───────────────────┼───────────────────┐
        │                   │                   │
        ▼                   ▼                   ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Planning   │     │ Passive     │     │   Active    │
│   Agent     │     │   OSINT     │     │    Recon    │
│  (Sonnet)   │     │  (Haiku)    │     │  (Sonnet)   │
│             │     │             │     │             │
│ Validates   │     │ External:   │     │ External:   │
│ scope &     │     │ • Public    │     │ • Port scan │
│ determines  │     │   databases │     │ • Service   │
│ engagement  │     │ • Search    │     │   versions  │
│ type        │     │   engines   │     │             │
│             │     │             │     │ Internal:   │
│             │     │ Internal:   │     │ • SMB enum  │
│             │     │ • Internal  │     │ • LDAP enum │
│             │     │   DNS       │     │ • AD recon  │
│             │     │ • AD users  │     │ • Shares    │
└─────────────┘     └─────────────┘     └─────────────┘
        │                   │                   │
        └───────────────────┼───────────────────┘
                            ↓
                    DATA AGGREGATION
              (Asset Inventory Created)
                            ↓
        ┌───────────────────┼───────────────────┐
        │                   │                   │
        ▼                   ▼                   ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│    Web      │     │ Exploitation│     │    Post-    │
│   Vuln      │     │   Agent     │     │    Exploit  │
│  Scanner    │     │  (Sonnet)   │     │   Agent     │
│  (Sonnet)   │     │             │     │  (Sonnet)   │
│             │     │ 🚨 HITL     │     │             │
│ Tests:      │     │ Approval    │     │ External:   │
│ • External  │     │ Required    │     │ • Simulate  │
│   web apps  │     │             │     │   only      │
│ • Internal  │     │ Safe POC    │     │             │
│   intranet  │     │ validation  │     │ Internal:   │
│ • Both use  │     │             │     │ • Lateral   │
│   OWASP     │     │             │     │   movement  │
│   Top 10    │     │             │     │ • Privesc   │
│             │     │             │     │   to DA     │
└─────────────┘     └─────────────┘     └─────────────┘
        │                   │                   │
        └───────────────────┼───────────────────┘
                            ↓
                    ┌─────────────┐
                    │  Reporting  │
                    │    Agent    │
                    │  (Sonnet)   │
                    │             │
                    │ Generates   │
                    │ engagement- │
                    │ specific    │
                    │ reports     │
                    └─────────────┘
                            ↓
                    FINAL DELIVERABLES
        (External or Internal-focused reports)
```

---

## Internal Pentesting: Current Capabilities

The multi-agent system **already supports internal pentesting** with these tools:

**Active Reconnaissance Agent** (Internal):
- ✅ SMB/Samba enumeration (enum4linux)
- ✅ LDAP enumeration
- ✅ SNMP enumeration
- ✅ Internal network scanning (10.x, 172.16.x, 192.168.x)
- ✅ Service version detection (internal services)

**Post-Exploitation Agent** (Internal-focused):
- ✅ Privilege escalation path mapping (SUID, sudo, kernel exploits)
- ✅ Lateral movement simulation (password reuse, SSH keys, Pass-the-Hash)
- ✅ Active Directory attack paths (documented)
- ✅ Network segmentation analysis
- ✅ Persistence mechanism identification

**Reporting Agent** (Internal-aware):
- ✅ Internal-specific remediation (AD hardening, network segmentation)
- ✅ Privilege escalation defense recommendations
- ✅ Lateral movement prevention guidance

**Coming Soon** (Future Enhancement):
- 🔜 **Internal Pentest Specialist Agent** - Dedicated AD-focused testing
  - BloodHound integration
  - Kerberoasting automation
  - Responder/LLMNR poisoning simulation
  - Domain trust analysis
  - GPO vulnerability assessment

---

## HITL Approval Example

During `/orchestrate`, you'll see approval prompts like this:

**External Pentest**:
```
┌────────────────────────────────────────────────────────────┐
│ 🚨 HITL CHECKPOINT: Exploitation Approval Required         │
├────────────────────────────────────────────────────────────┤
│                                                            │
│ Found 2 CRITICAL and 5 HIGH severity findings.            │
│                                                            │
│ CRITICAL Findings:                                         │
│ • VULN-001: SQL Injection in login form                   │
│ • VULN-003: Remote Code Execution in upload function      │
│                                                            │
│ HIGH Findings:                                             │
│ • VULN-002: Stored XSS in comment system                  │
│ • VULN-005: Authentication bypass on admin panel          │
│ • VULN-007: Insecure Direct Object Reference (IDOR)       │
│ • VULN-009: File upload vulnerability                     │
│ • VULN-012: Weak password policy                          │
│                                                            │
│ Proceed with non-destructive validation?                  │
│                                                            │
│ Validation Method:                                         │
│ • SQL Injection: Read-only queries (SELECT @@version)     │
│ • RCE: Safe commands only (whoami, id, hostname)          │
│ • XSS: Alert box with benign payload                      │
│ • Auth Bypass: View admin panel, immediate logout         │
│                                                            │
│ ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│ │ Approve All  │  │ CRITICAL Only│  │ Skip All     │     │
│ └──────────────┘  └──────────────┘  └──────────────┘     │
└────────────────────────────────────────────────────────────┘
```

**Internal Pentest**:
```
┌────────────────────────────────────────────────────────────┐
│ 🚨 HITL CHECKPOINT: Exploitation Approval Required         │
├────────────────────────────────────────────────────────────┤
│                                                            │
│ Found 1 CRITICAL and 4 HIGH severity findings.            │
│                                                            │
│ CRITICAL Findings:                                         │
│ • VULN-015: SMB Null Session - Full user enumeration     │
│                                                            │
│ HIGH Findings:                                             │
│ • VULN-008: Kerberoastable service accounts              │
│ • VULN-011: Weak domain user passwords                   │
│ • VULN-019: Writable SMB share with sensitive data       │
│ • VULN-023: Outdated Windows Server (EternalBlue)        │
│                                                            │
│ Proceed with non-destructive validation?                  │
│                                                            │
│ Validation Method:                                         │
│ • SMB Null Session: Enumerate users (read-only)          │
│ • Kerberoasting: Request TGS tickets (no cracking)       │
│ • Weak Passwords: Test 3 attempts only (no lockout)      │
│ • SMB Share: List files (no download)                    │
│                                                            │
│ ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│ │ Approve All  │  │ CRITICAL Only│  │ Skip All     │     │
│ └──────────────┘  └──────────────┘  └──────────────┘     │
└────────────────────────────────────────────────────────────┘
```

---

## Dashboard Monitoring

While `/orchestrate` runs, watch the dashboard: http://localhost:8080

**External Pentest Dashboard**:
```
┌─────────────────────────────────────────────────────────┐
│ Engagement: TestCorp_2025-12-16_External                │
├─────────────────────────────────────────────────────────┤
│ Status: Running                                         │
│ Type: External Penetration Test                        │
│ Duration: 3h 24m                                        │
│                                                         │
│ Phase Progress:                                         │
│ ✅ Planning (100%)                                      │
│ ✅ Passive OSINT (100%)                                 │
│ ✅ Active Recon (100%)                                  │
│ ✅ Vulnerability Analysis (100%)                        │
│ 🔄 Exploitation (42% - Validating VULN-003)            │
│ ⏳ Post-Exploitation (Queued)                           │
│ ⏳ Reporting (Queued)                                   │
│                                                         │
│ Findings: 21 total                                      │
│ • CRITICAL: 2 (SQL Injection, RCE)                     │
│ • HIGH: 5 (XSS, Auth Bypass, IDOR)                     │
│ • MEDIUM: 9                                             │
│ • LOW: 5                                                │
└─────────────────────────────────────────────────────────┘
```

**Internal Pentest Dashboard**:
```
┌─────────────────────────────────────────────────────────┐
│ Engagement: ACME_2025-12-16_Internal                    │
├─────────────────────────────────────────────────────────┤
│ Status: Running                                         │
│ Type: Internal Network Penetration Test                │
│ Duration: 8h 12m                                        │
│                                                         │
│ Phase Progress:                                         │
│ ✅ Planning (100%)                                      │
│ ✅ Internal OSINT (100%)                                │
│ ✅ Active Recon (100%)                                  │
│ ✅ Vulnerability Analysis (100%)                        │
│ ✅ Exploitation (100%)                                  │
│ 🔄 Post-Exploitation (78% - Mapping lateral movement)  │
│ ⏳ Reporting (Queued)                                   │
│                                                         │
│ Findings: 18 total                                      │
│ • CRITICAL: 1 (SMB Null Session)                       │
│ • HIGH: 4 (Kerberoasting, Weak passwords, SMB shares) │
│ • MEDIUM: 8                                             │
│ • LOW: 5                                                │
│                                                         │
│ Attack Paths Identified:                                │
│ • Workstation → File Server (password reuse)           │
│ • Domain User → Domain Admin (Kerberoasting)           │
│ • Compromised host → All domain workstations (LLMNR)   │
└─────────────────────────────────────────────────────────┘
```

---

## Common Scenarios

### Scenario 1: External Pentest - "I want the fastest possible scan"

```bash
# Use aggressive scan speed
/orchestrate TestCorp_External --speed aggressive

# What changes:
# - Nmap: -T5 (Insane timing)
# - Gobuster: 50+ threads
# - Minimal delays
# - Risk: Higher IDS/IPS detection
```

### Scenario 2: Internal Pentest - "I need stealth (Red Team)"

```bash
# Use stealth mode for internal Red Team
/orchestrate ACME_Internal --speed stealth

# What changes:
# - Nmap: -T2 (Polite timing)
# - SMB enum: Slower, randomized delays
# - Evade internal IDS/IPS
# - Duration: 2-3x longer
```

### Scenario 3: "I only want to scan, no exploitation"

```bash
# External or Internal - skip exploitation
/orchestrate TestCorp --skip-exploitation

# What runs:
# - Planning, OSINT, Active Recon, Vuln Scanning, Reporting
# What skips:
# - Exploitation (all findings marked "theoretical")
```

### Scenario 4: Internal Pentest - "Focus on Active Directory only"

```bash
# Future: Will use Internal Pentest Specialist Agent
# Current workaround:
/engage ACME - Internal AD Assessment
/scan corp.local  # Active Recon Agent handles AD enumeration
/validate VULN-008  # Kerberoasting
/report ACME_2025-12-16_AD
```

### Scenario 5: "Testing was interrupted, resume where it left off"

```bash
# Works for both external and internal
/orchestrate TestCorp_2025-12-16_External --resume
/orchestrate ACME_2025-12-16_Internal --resume

# What happens:
# - Checks database for last completed phase
# - Skips completed phases
# - Resumes from next phase
# - Preserves all previous results
```

---

## Evidence Collection

All evidence is automatically organized (same structure for external/internal):

**External Pentest**:
```
TestCorp_2025-12-16_External/
├── 02-reconnaissance/
│   └── osint/
│       ├── subdomains.txt (28 public subdomains)
│       ├── emails.txt (15 email addresses)
│       └── technology-stack.md
│
├── 03-scanning/
│   ├── network/
│   │   └── nmap-external-scan.xml
│   └── web/
│       ├── gobuster-dirs.txt
│       └── nikto-results.txt
│
├── 05-vulnerability-analysis/
│   └── findings/
│       ├── VULN-001-sql-injection.md
│       └── vulnerability-summary.md (21 total)
```

**Internal Pentest**:
```
ACME_2025-12-16_Internal/
├── 02-reconnaissance/
│   └── internal-recon/
│       ├── internal-dns.txt
│       ├── ad-users-enumerated.txt (142 domain users)
│       └── smb-shares-discovered.txt
│
├── 03-scanning/
│   ├── network/
│   │   ├── nmap-internal-10.10.0.0-16.xml
│   │   └── nmap-internal-172.16.50.0-24.xml
│   └── smb/
│       ├── enum4linux-results.txt
│       └── writable-shares.txt
│
├── 05-vulnerability-analysis/
│   └── findings/
│       ├── VULN-008-kerberoasting.md
│       ├── VULN-015-smb-null-session.md
│       └── vulnerability-summary.md (18 total)
│
├── 07-post-exploitation/
│   └── attack-paths/
│       ├── lateral-movement-map.md
│       ├── privilege-escalation-to-DA.md
│       └── network-segmentation-analysis.md
```

---

## Summary: Getting Started Right Now

**External Pentest**:
1. Launch Pentest Monitor: `python athena_monitor.py`
2. Run: `/orchestrate [CLIENT] - External Pentest`
3. Confirm authorization when prompted
4. Approve exploitation when HITL checkpoint appears
5. Review deliverables in `09-reporting/final/`

**Internal Pentest**:
1. Launch Pentest Monitor: `python athena_monitor.py`
2. Run: `/orchestrate [CLIENT] - Internal Pentest`
3. Provide internal scope (10.x.x.x networks, domain name)
4. Confirm authorization + VPN access details
5. Approve exploitation when HITL checkpoint appears
6. Review internal-specific findings (AD paths, lateral movement)

**That's it!** The multi-agent system handles everything else.

---

## Roadmap: Future Enhancements

**Coming Soon**:
- 🔜 **Internal Pentest Specialist Agent** - Dedicated Active Directory testing
  - BloodHound integration (AD attack path visualization)
  - Kerberoasting automation
  - Responder/LLMNR poisoning simulation
  - AS-REP roasting
  - Domain trust enumeration
  - GPO vulnerability assessment
  - Pass-the-Hash/Pass-the-Ticket simulation

---

## Support & Documentation

- **System Architecture**: `MULTI-AGENT-ARCHITECTURE.md`
- **Agent Documentation**: `.claude/agents/*.md`
- **Command Reference**: `.claude/commands/*.md`
- **Pentest Monitor**: `tools/athena-monitor/README.md`
- **Project Instructions**: `CLAUDE.md`

---

**Created**: December 16, 2025
**Version**: 1.0
**System**: Multi-Agent Penetration Testing Framework
**Supports**: External & Internal Penetration Testing
**Designed for**: Professional penetration testing with AI automation
**Speed**: 5-10x faster than manual testing
**Safety**: PTES compliant with HITL checkpoints and authorization enforcement
