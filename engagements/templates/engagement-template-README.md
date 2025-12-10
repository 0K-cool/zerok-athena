# Penetration Test Engagement Template

## Overview
This template provides a standardized structure for penetration testing engagements following industry best practices (PTES, OWASP, NIST SP 800-115).

## Usage
When starting a new engagement:
```bash
# Copy this template to active engagements directory
cp -r engagements/templates/engagement-structure engagements/active/[CLIENT]_YYYY-MM-DD_[TYPE]/

# Example:
cp -r engagements/templates/engagement-structure engagements/active/AcmeCorp_2025-01-15_External/
```

Or use Claude Code slash command:
```
/engage AcmeCorp External Penetration Test
```

## Folder Structure Explained

### 01-planning/
**Purpose**: Pre-engagement documentation and authorization
- `authorization.pdf` - Signed authorization letter or contract
- `scope.md` - Detailed scope definition (in-scope vs out-of-scope)
- `rules-of-engagement.md` - Testing constraints, time windows, prohibited actions
- `contact-sheet.md` - Emergency contacts and escalation procedures
- `timeline.md` - Testing schedule and milestones

**Critical**: Do not proceed with testing until authorization is documented here.

---

### 02-reconnaissance/
**Purpose**: Passive information gathering (OSINT)
- `osint/` - Open-source intelligence findings
  - `domains.txt` - Discovered domains and subdomains
  - `emails.txt` - Harvested email addresses
  - `employees.txt` - Public employee information
  - `social-media.md` - Social media reconnaissance
- `dns-enumeration.txt` - DNS records, zone transfers
- `whois-data.txt` - Domain registration information
- `google-dorking.md` - Search engine reconnaissance findings

**Approach**: Passive only - no direct interaction with target systems.

---

### 03-scanning/
**Purpose**: Active reconnaissance and vulnerability scanning
- `network/` - Network-level scanning
  - `nmap-discovery.txt` - Host discovery scans
  - `nmap-full-tcp.xml` - Full TCP port scans
  - `nmap-version-detection.xml` - Service version detection
  - `nmap-vuln-scan.xml` - Nmap NSE vulnerability scripts
  - `service-versions.md` - Parsed service version summary
- `web/` - Web application scanning
  - `gobuster-dirs.txt` - Directory brute-forcing results
  - `nikto-scan.txt` - Web vulnerability scan
  - `wpscan-results.txt` - WordPress vulnerabilities (if applicable)
  - `sqlmap-targets.txt` - SQL injection testing targets
- `wireless/` - Wireless assessment (if in scope)

**Tools**: Nmap, Gobuster, Nikto, Dirb, WPScan, SQLmap

---

### 04-enumeration/
**Purpose**: Deep enumeration of discovered services
- `smb-enumeration.txt` - SMB shares and permissions
- `ldap-enumeration.txt` - Active Directory enumeration
- `snmp-enumeration.txt` - SNMP service information
- `rpc-enumeration.txt` - RPC service enumeration

**Tools**: Enum4linux, ldapsearch, snmpwalk

---

### 05-vulnerability-analysis/
**Purpose**: Identify and analyze vulnerabilities
- `findings/` - Individual vulnerability findings
  - `VULN-001-sql-injection.md` - Detailed writeup per vulnerability
  - `VULN-002-xss-reflected.md`
  - `VULN-003-weak-credentials.md`
- `vulnerability-summary.md` - Consolidated vulnerability list
- `cvss-scoring.xlsx` - Risk scoring and prioritization
- `false-positives.md` - Documented false positive findings

**Process**: Cross-reference scan results with CVE databases, assess exploitability.

---

### 06-exploitation/
**Purpose**: Non-destructive vulnerability validation (Proof of Concept)
- `validated-vulns/` - Confirmed exploitable vulnerabilities
  - `VULN-001-SQL-Injection/`
    - `screenshots/` - Visual proof
    - `logs/` - Tool outputs
    - `payloads/` - Payloads used
    - `writeup.md` - Complete POC documentation
- `exploitation-notes.md` - Testing methodology and approach
- `recommended-tests.md` - Client-approved validation tests

**CRITICAL**: Non-destructive testing only. Validate without causing harm.

---

### 07-post-exploitation/
**Purpose**: Simulation of post-exploitation activities (if authorized)
- `privilege-escalation.md` - Simulated privilege escalation paths
- `lateral-movement.md` - Simulated network traversal
- `persistence-mechanisms.md` - Identified persistence opportunities
- `data-exfiltration-paths.md` - Simulated exfiltration routes

**Note**: Simulation only, no actual exploitation beyond POC.

---

### 08-evidence/
**Purpose**: Comprehensive evidence collection for client deliverable
- `screenshots/` - All visual evidence
  - Naming: `[NUM]-[SEVERITY]-[CATEGORY]-[DESCRIPTION]-YYYYMMDD-HHMMSS.png`
  - Example: `001-CRITICAL-SQLI-login-bypass-20250106-143022.png`
- `logs/` - Tool output logs (nmap, gobuster, nikto, etc.)
- `artifacts/` - Captured artifacts
  - `captured-requests.txt` - HTTP requests showing vulnerabilities
  - `response-samples.txt` - Server responses
  - `config-files/` - Exposed configuration files
- `commands-used.md` - **ALL commands executed** with timestamps
- `evidence-manifest.md` - Chain of custody for all evidence

**Requirement**: Every finding must have evidence. Client must be able to reproduce.

---

### 09-reporting/
**Purpose**: Final deliverables for client
- `executive-summary.md` - Non-technical overview for leadership
- `technical-report.md` - Detailed technical findings
- `remediation-roadmap.md` - Prioritized remediation recommendations
- `retest-requirements.md` - Validation criteria for fixes
- `appendices/` - Supporting documentation
  - `methodology.md` - Testing methodology (PTES phases)
  - `tools-used.md` - Tools and versions
  - `references.md` - CVE references and external resources
- `final-presentation.pptx` - Client presentation deck

**Deliverable Format**: Professional report with executive and technical sections.

---

### 10-retest/
**Purpose**: Post-remediation validation
- `retest-plan.md` - Retest scope and approach
- `retest-findings.md` - Validation results (fixed/not fixed)
- `retest-evidence/` - Screenshots of remediated vulnerabilities

**Process**: Validate that client fixes are effective and complete.

---

### README.md
**Purpose**: Engagement overview and quick reference
- Engagement summary
- Key findings count
- Testing dates and timeline
- Client contacts
- Report status

---

## Engagement Workflow

### 1. Pre-Engagement (Planning)
- [ ] Obtain signed authorization letter
- [ ] Define scope (IP ranges, domains, systems)
- [ ] Document Rules of Engagement
- [ ] Verify emergency contacts
- [ ] Set up evidence storage (encrypted external drive or NAS)
- [ ] Schedule kickoff meeting with client

**Command**: `/engage [CLIENT_NAME]`

---

### 2. Reconnaissance
- [ ] Passive OSINT gathering
- [ ] DNS enumeration
- [ ] Subdomain discovery
- [ ] Email harvesting
- [ ] Social media reconnaissance
- [ ] Technology stack identification

**Duration**: 1-2 days

---

### 3. Scanning & Enumeration
- [ ] Network port scanning (Nmap)
- [ ] Service version detection
- [ ] Web directory brute-forcing (Gobuster)
- [ ] Web vulnerability scanning (Nikto)
- [ ] Subdomain enumeration
- [ ] Service-specific enumeration (SMB, SNMP, etc.)

**Command**: `/scan [TARGET]`
**Duration**: 2-3 days

---

### 4. Vulnerability Analysis
- [ ] Analyze scan results
- [ ] Cross-reference with CVE databases
- [ ] Assess exploitability
- [ ] Calculate CVSS scores
- [ ] Prioritize findings (Critical → Low)
- [ ] Eliminate false positives

**Duration**: 1-2 days

---

### 5. Exploitation Validation (Non-Destructive)
- [ ] SQL injection POC (read-only)
- [ ] XSS demonstration (alert boxes)
- [ ] RCE validation (safe commands)
- [ ] Authentication bypass (immediate logout)
- [ ] File upload testing (benign files)
- [ ] Screenshot every finding
- [ ] Document reproduction steps

**Command**: `/validate [VULNERABILITY]`
**Duration**: 2-3 days

---

### 6. Evidence Compilation
- [ ] Organize all screenshots
- [ ] Save all tool outputs
- [ ] Document command history
- [ ] Create evidence manifest
- [ ] Package in encrypted archive
- [ ] Generate SHA256 hash

**Command**: `/evidence [ENGAGEMENT_NAME]`
**Duration**: 1 day

---

### 7. Reporting
- [ ] Write executive summary
- [ ] Document technical findings
- [ ] Create remediation roadmap
- [ ] Develop presentation deck
- [ ] Review and QA report
- [ ] Deliver to client

**Command**: `/report [ENGAGEMENT_NAME]`
**Duration**: 3-5 days

---

### 8. Debrief & Retest
- [ ] Present findings to client
- [ ] Answer technical questions
- [ ] Provide remediation support
- [ ] Schedule retest
- [ ] Validate fixes

**Command**: `/retest [ENGAGEMENT_NAME]`
**Duration**: 1-2 days (after client remediation)

---

## Evidence Requirements

### Screenshots
- **Every finding MUST have screenshots**
- Include command execution and output
- Show context (URL bar, terminal prompt)
- Use consistent naming convention
- Capture full screen (no cropping important info)

### Command Logging
- Document ALL commands in `commands-used.md`
- Include timestamp, purpose, results
- Reference screenshot for each command
- Provide exact syntax for client reproduction

### Artifacts
- Save all tool outputs (XML, JSON, TXT)
- Capture vulnerable HTTP requests/responses
- Document any exposed configuration files
- Preserve chain of custody

---

## Report Structure

### Executive Summary (1-2 pages)
- Engagement overview
- Key findings (count by severity)
- Overall risk rating
- Top recommendations
- Business impact

### Technical Report (10-30 pages)
For each vulnerability:
- Vulnerability ID and title
- Severity and CVSS score
- Location (system, URL, service)
- Technical description
- Proof of Concept steps
- Evidence (screenshots)
- Impact analysis
- Remediation recommendations
- References (CVE, CWE, OWASP)

### Remediation Roadmap
- Prioritized action plan
- Quick wins vs long-term fixes
- Effort estimation
- Validation criteria

### Appendices
- Testing methodology
- Tools and versions
- Scope definition
- Assumptions and limitations
- References

---

## Storage Planning

### Evidence Storage Options

**Option A: External Drive (Recommended)**
- Encrypted SSD/HDD (256GB+ for multiple engagements)
- Full-disk encryption (FileVault, BitLocker, LUKS)
- Physical security (labeled "CONFIDENTIAL")
- Chain of custody documentation

**Option B: Network Storage (Team Engagements)**
- Secure NAS with encryption
- VPN/secure connection required
- Access controls for team members
- Compliance with data residency requirements

**Option C: Local Storage (Small Engagements)**
- Use with caution (data loss risk)
- Encrypted local disk
- Immediate backup to external drive
- Not recommended for client-facing evidence

### Storage Estimate
- Small engagement (1-5 hosts): 1-3 GB
- Medium engagement (5-20 hosts): 3-10 GB
- Large engagement (20-100 hosts): 10-50 GB
- Enterprise engagement (100+ hosts): 50-500 GB

---

## Compliance & Standards

### Frameworks
- PTES (Penetration Testing Execution Standard)
- OWASP Testing Guide
- NIST SP 800-115

### Certifications
- OSCP, CEH, GPEN, CPSA/CPTE, PNPT

### Industry Compliance
- PCI DSS (payment card testing)
- HIPAA (healthcare)
- SOC 2 (trust services)
- GDPR (data protection)

---

## Safety & Ethics

### Non-Destructive Testing
- ✅ Read-only validation
- ✅ Safe POC commands
- ✅ Immediate cleanup
- ❌ No data exfiltration
- ❌ No destructive exploits
- ❌ No persistence/backdoors

### Authorization
- Always verify written authorization
- Confirm target is in-scope
- Respect testing constraints
- Stop if causing service impact
- Report critical findings immediately

### Professional Standards
- Maintain client confidentiality
- Report findings honestly
- Provide remediation guidance
- Operate ethically within boundaries
- Refuse unauthorized testing

---

## Quick Reference Commands

### Claude Code Slash Commands
- `/engage [CLIENT]` - Initialize new engagement
- `/scan [TARGET]` - Execute scanning phase
- `/validate [VULN]` - Non-destructive POC
- `/evidence [ENGAGEMENT]` - Compile evidence
- `/report [ENGAGEMENT]` - Generate report
- `/retest [ENGAGEMENT]` - Post-remediation validation

### Kali MCP Tools
- `nmap_scan()` - Port scanning
- `gobuster_scan()` - Directory brute-forcing
- `nikto_scan()` - Web vulnerability scanning
- `wpscan_analyze()` - WordPress testing
- `sqlmap_scan()` - SQL injection testing
- `enum4linux_scan()` - SMB enumeration
- `hydra_attack()` - Password testing (caution)

---

## Support & Documentation

For detailed guidance, refer to:
- `.claude/commands/engage.md` - Engagement setup
- `.claude/commands/scan.md` - Scanning procedures
- `.claude/commands/validate.md` - Validation methodology
- `.claude/commands/evidence.md` - Evidence compilation
- `CLAUDE.md` - Project configuration and role definition

---

**Template Version**: 1.0
**Last Updated**: 2025-01-06
**Framework**: PTES, OWASP, NIST SP 800-115
**License**: Internal Use - VERSANT Projects
