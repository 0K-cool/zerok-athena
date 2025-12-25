# ATHENA - Strategic Penetration Testing Platform

## Project Overview

**ATHENA** (Automated Tactical Hacking and Exploitation Network Architecture) is a comprehensive, AI-powered platform for conducting **authorized penetration testing engagements** following industry best practices. The framework emphasizes **multi-agent coordination**, **non-destructive testing**, **comprehensive evidence collection**, and **professional reporting** to help clients improve their security posture.

### Key Features
- ✅ **Automated Testing**: Leverage Kali Linux MCP for offensive security tools (Nmap, Gobuster, Nikto, SQLmap, etc.)
- ✅ **Modern Web App Testing**: Playwright browser automation for SPAs (React, Vue, Angular)
- ✅ **Real-Time Monitoring**: ATHENA Monitor dashboard tracks all commands, findings, and HITL approvals
- ✅ **AI-Powered Analysis**: Use Claude Code to simulate threat actor TTPs and analyze findings
- ✅ **Non-Destructive Validation**: Prove vulnerabilities exist without causing harm
- ✅ **Evidence Collection**: Screenshot and document every finding for client repeatability
- ✅ **Complete Audit Trail**: Database logging prevents duplicate scans and enables session recovery
- ✅ **Professional Reporting**: Generate executive and technical reports following PTES, OWASP, NIST standards
- ✅ **Compliance-Ready**: Support for PCI DSS, HIPAA, SOC 2, GDPR testing requirements

---

## Project Vision

**ATHENA** automates external and internal penetration tests through strategic multi-agent coordination while maintaining ethical boundaries and non-destructive testing practices. Leveraging AI to simulate real-world threat actor tactics (inspired by [Anthropic's AI Cyber Defenders](https://www.anthropic.com/research/building-ai-cyber-defenders) and [CrowdStrike's 2025 Threat Hunting Report](https://www.crowdstrike.com/en-us/blog/crowdstrike-2025-threat-hunting-report-ai-weapon-target/)), ATHENA demonstrates that **AI + Human oversight > AI alone** in professional security assessments.

---

## Directory Structure

```
ATHENA/
├── engagements/              # Client penetration testing engagements
│   ├── templates/            # Standardized engagement folder templates
│   ├── active/               # Ongoing engagements
│   └── archive/              # Completed engagements
│
├── intel/                    # Target intelligence and research
│   ├── targets/              # Target organization information
│   ├── vulnerabilities/      # CVE research and exploit databases
│   └── exploits/             # Proof-of-concept exploits (safe)
│
├── reconnaissance/           # OSINT and passive recon
│   ├── external/             # External reconnaissance findings
│   ├── internal/             # Internal network recon (if authorized)
│   ├── cloud/                # Cloud infrastructure reconnaissance
│   └── osint/                # Open-source intelligence gathering
│
├── scans/                    # Scan outputs and results
│   ├── network/              # Nmap and network scanning results
│   ├── web/                  # Web application scan results
│   ├── wireless/             # Wireless assessment results
│   └── cloud/                # Cloud infrastructure scan results (AWS/Azure/GCP)
│
├── evidence/                 # Testing evidence and artifacts
│   ├── screenshots/          # Visual proof of findings
│   ├── logs/                 # Tool output logs
│   ├── artifacts/            # Captured artifacts (requests, responses)
│   └── reports/              # Generated reports
│
├── tools/                    # Custom scripts and utilities
│   ├── scripts/              # Automation scripts
│   ├── exploits/             # Safe POC exploits
│   ├── payloads/             # Testing payloads (XSS, SQLi)
│   ├── wordlists/            # Custom wordlists
│   └── athena-monitor/       # 🔌 Real-time engagement tracking dashboard
│
├── playbooks/                # Attack scenario playbooks
│   ├── sql-injection-testing.md
│   └── cloud/                # Cloud-specific playbooks
│       └── cloud-pentest-overview.md
│
├── reports/                  # Report templates and drafts
│   ├── templates/            # Report templates
│   ├── drafts/               # Work-in-progress reports
│   └── final/                # Delivered final reports
│
├── .claude/                  # Claude Code configuration
│   ├── commands/             # Custom slash commands
│   │   ├── engage.md         # Start new engagement
│   │   ├── scan.md           # Execute scanning
│   │   ├── validate.md       # Non-destructive POC
│   │   ├── evidence.md       # Compile evidence
│   │   └── cloud-pentest.md  # Cloud penetration testing
│   └── templates/            # Document templates
│
├── CLAUDE.md                 # Project configuration
├── README.md                 # This file
└── .mcp.json                 # MCP server configuration
```

---

## Getting Started

### 1. Prerequisites
- **Kali Linux MCP Server**: Running and accessible (test with `mcp__kali_mcp__server_health()`)
- **Authorization**: Always obtain written authorization before testing
- **Evidence Storage**: Prepare encrypted external drive or NAS for evidence collection
- **ATHENA Monitor** (Optional but Recommended): Real-time dashboard for tracking engagement progress

### 2. Launch ATHENA Monitor (Recommended)

**Before starting any engagement**, launch the real-time monitoring dashboard:

```bash
cd tools/athena-monitor
source venv/bin/activate
python athena_monitor.py
```

**Dashboard URL**: http://localhost:8080

**What it does**:
- ✅ Tracks all commands executed (prevents redundant scanning)
- ✅ Logs findings in real-time (auto-updates as vulnerabilities discovered)
- ✅ Records HITL approval checkpoints (complete audit trail)
- ✅ Enables session resumption (if engagement interrupted)
- ✅ Provides complete audit trail for client deliverables

**Keep the dashboard running** in a separate terminal/browser tab throughout your engagement. All slash commands (`/engage`, `/scan`, `/validate`) automatically log to the database.

**Quick Start Guide**: See `tools/athena-monitor/QUICK-START.md` for 5-minute setup.

### 2.5. Configure OSINT APIs (Optional but Recommended)

For enhanced passive reconnaissance capabilities:

```bash
# 1. Copy the example .env file (if available) or create new
# See API-KEYS-SETUP.md for obtaining API keys

# 2. Add your API keys to .env file
# File location: /Users/kelvinlomboy/VERSANT/Projects/Pentest/.env

# 3. Test all APIs
./osint-api-wrapper.sh test
```

**Free tier API keys provide**:
- ✅ Subdomain discovery (Certificate Transparency - no key needed)
- ✅ Exposed service detection (Shodan - 100 queries/month)
- ✅ Email harvesting (Hunter.io - 50 searches/month)
- ✅ Secret scanning (GitHub - 5,000 req/hour)
- ✅ Threat intelligence (VirusTotal - 4 req/minute)
- ✅ Internet scanning data (Censys - 250 queries/month)

**Setup guide**: See `API-KEYS-SETUP.md` for detailed instructions.

**Troubleshooting**: If APIs return 401 errors, see `API-KEY-FIX.md` for solutions.

### 3. Starting a New Engagement

#### Using Claude Code Slash Command (Recommended)
```
/engage AcmeCorp External Penetration Test
```

This will:
- Create standardized engagement folder structure
- Prompt for authorization documentation
- Set up evidence storage
- Initialize scope and Rules of Engagement

#### Manual Setup
```bash
# Copy engagement template
cp -r engagements/templates/engagement-structure engagements/active/[CLIENT]_YYYY-MM-DD_[TYPE]/

# Example
cp -r engagements/templates/engagement-structure engagements/active/AcmeCorp_2025-01-15_External/
```

### 4. Engagement Workflow

**Phase 1: Planning (Days 0-1)**
- [ ] Obtain signed authorization letter
- [ ] Define scope (IP ranges, domains, systems)
- [ ] Document Rules of Engagement
- [ ] Establish communication protocols
- [ ] Set up encrypted evidence storage

**Phase 2: Reconnaissance (Days 1-2)**
- [ ] Passive OSINT gathering
- [ ] DNS enumeration
- [ ] Subdomain discovery
- [ ] Technology stack identification

**Phase 3: Scanning (Days 2-4)**
```
/scan [TARGET]
```
- [ ] Network port scanning (Nmap)
- [ ] Web directory brute-forcing (Gobuster)
- [ ] Web vulnerability scanning (Nikto)
- [ ] Service enumeration

**Phase 4: Vulnerability Analysis (Days 4-5)**
- [ ] Analyze scan results
- [ ] Cross-reference with CVE databases
- [ ] Calculate CVSS scores
- [ ] Prioritize findings (Critical → Low)

**Phase 5: Exploitation Validation (Days 5-7)**
```
/validate [VULNERABILITY]
```
- [ ] Non-destructive proof-of-concept
- [ ] Screenshot every finding
- [ ] Document reproduction steps
- [ ] Log all commands executed

**Phase 6: Evidence Compilation (Day 7)**
```
/evidence [ENGAGEMENT_NAME]
```
- [ ] Organize screenshots and logs
- [ ] Create evidence manifest
- [ ] Package in encrypted archive
- [ ] Generate SHA256 hash

**Phase 7: Reporting (Days 7-10)**
```
/report [ENGAGEMENT_NAME]
```
- [ ] Write executive summary
- [ ] Document technical findings
- [ ] Create remediation roadmap
- [ ] Prepare client presentation

**Phase 8: Debrief & Retest (Days 11-14)**
```
/retest [ENGAGEMENT_NAME]
```
- [ ] Present findings to client
- [ ] Answer technical questions
- [ ] Validate remediation efforts

---

## Available Tools

### Claude Code Slash Commands

| Command | Description | Usage |
|---------|-------------|-------|
| `/engage` | Initialize new engagement | `/engage [CLIENT] [TYPE]` |
| `/scan` | Execute scanning phase | `/scan [TARGET]` |
| `/scan-spa` | 🆕 Modern SPA/PWA testing (Playwright) | `/scan-spa [TARGET_URL]` |
| `/cloud-pentest` | Cloud penetration testing | `/cloud-pentest [AWS/Azure/GCP]` |
| `/validate` | Non-destructive POC | `/validate [VULNERABILITY]` |
| `/evidence` | Compile evidence | `/evidence [ENGAGEMENT]` |
| `/report` | Generate report | `/report [ENGAGEMENT]` |
| `/retest` | Post-remediation test | `/retest [ENGAGEMENT]` |

### Kali Linux MCP Tools

#### Network Reconnaissance
- `nmap_scan()` - Port scanning, service detection, vulnerability scanning
- `enum4linux_scan()` - SMB/Samba enumeration

#### Web Application Testing
- `gobuster_scan()` - Directory/DNS brute-forcing
- `dirb_scan()` - Web content scanner
- `nikto_scan()` - Web vulnerability scanner
- `wpscan_analyze()` - WordPress security scanner
- `sqlmap_scan()` - SQL injection testing

#### Exploitation & Validation
- `metasploit_run()` - Metasploit modules (validation only)
- `hydra_attack()` - Password brute-forcing (caution)
- `john_crack()` - Password hash cracking

#### Utility
- `server_health()` - Check Kali API status
- `execute_command()` - Execute arbitrary Kali commands

---

### 🆕 OSINT API Wrapper (Passive Reconnaissance)

**Location**: `osint-api-wrapper.sh`

Reliable wrapper script for passive OSINT API calls with automatic environment variable loading.

#### Supported Services (All Free Tier)
- **Shodan** - Exposed service discovery (100 queries/month)
- **Censys v3** - Internet-wide scanning data (250 queries/month)
- **Hunter.io** - Email address discovery (50 searches/month)
- **GitHub** - Secret scanning & repository search (5,000 req/hour)
- **VirusTotal** - Domain/IP intelligence (4 req/minute)

#### Quick Usage
```bash
# Test all APIs
./osint-api-wrapper.sh test

# Shodan searches
./osint-api-wrapper.sh shodan "org:\"Example Corp\""
./osint-api-wrapper.sh shodan-host 8.8.8.8

# Email discovery
./osint-api-wrapper.sh hunter example.com

# GitHub secret scanning
./osint-api-wrapper.sh github "example.com password"

# Domain intelligence
./osint-api-wrapper.sh virustotal example.com
```

**See Also**: `API-KEYS-SETUP.md` for configuration and `API-KEY-FIX.md` for troubleshooting.

---

### 🆕 Playwright MCP Tools (Modern Web App Testing)

#### Browser Automation & Navigation
- `playwright_navigate()` - Navigate to URLs with full JavaScript rendering
- `playwright_click()` - Click elements and trigger events
- `playwright_fill()` - Fill forms with payloads
- `playwright_screenshot()` - Capture visual evidence

#### Security Testing
- `playwright_evaluate()` - Execute JavaScript for security testing
- `playwright_content()` - Extract rendered content
- Network interception - Capture API requests/responses
- Storage inspection - Access cookies, localStorage, sessionStorage

#### Use Cases
- **SPA Testing**: React, Vue, Angular applications
- **Authenticated Workflows**: Automate complex login flows
- **XSS Testing**: Automated payload injection across inputs
- **CSRF Testing**: Token validation and bypass testing
- **IDOR Testing**: Multi-user context testing
- **API Discovery**: Monitor network traffic for endpoints

**See Also**: `/scan-spa` command and `playbooks/playwright-web-testing.md`

---

## Testing Methodology

### Frameworks
- **PTES** (Penetration Testing Execution Standard)
- **OWASP Testing Guide** (Web applications)
- **NIST SP 800-115** (Technical security testing)

### Standards & Compliance
- **PCI DSS v4.0** - Payment card industry testing
- **HIPAA** - Healthcare compliance testing
- **SOC 2** - Trust services criteria
- **GDPR** - Data protection compliance

---

## Non-Destructive Testing Policy

### ✅ Approved Methods
- Read-only database queries (`SELECT` statements)
- Safe command execution (`whoami`, `id`, `hostname`)
- Benign XSS payloads (alert boxes)
- Authentication bypass with immediate logout
- File upload testing with harmless files (phpinfo, test.txt)
- Simulation of attack paths without execution

### ❌ Prohibited Actions
- Data exfiltration or downloading sensitive information
- Creating, modifying, or deleting files/data
- Installing backdoors or persistent access
- Privilege escalation beyond proof-of-concept
- Lateral movement to other systems
- Denial of service attacks
- Production system impact

### Safety Guidelines
1. **Always verify written authorization** before testing
2. **Confirm targets are in-scope** per engagement agreement
3. **Use rate limiting** to avoid service degradation
4. **Monitor for impact** and stop if detected
5. **Have emergency contact** available during testing
6. **Prefer test/staging environments** over production
7. **Report critical findings immediately** to client
8. **Screenshot and document everything**

---

## Evidence Collection Standards

### Screenshot Requirements
Every finding MUST include:
- Command executed with visible terminal/browser
- Tool output showing vulnerability
- Proof of impact (database version, command output, file contents)
- Context (URL bar, system info, timestamp)

**Naming Convention**:
```
[NUM]-[SEVERITY]-[CATEGORY]-[DESCRIPTION]-YYYYMMDD-HHMMSS.png

Examples:
001-CRITICAL-SQLI-login-bypass-20250106-143022.png
002-HIGH-XSS-reflected-comment-20250106-143401.png
003-CRITICAL-RCE-command-execution-20250106-144512.png
```

### Command Logging
Document ALL commands in `08-evidence/commands-used.md`:
- Exact command syntax
- Timestamp (date and time)
- Purpose/objective
- Results/findings
- Screenshot reference
- Tool version

### Repeatability
- Client must be able to reproduce every finding
- Provide exact step-by-step instructions
- Include any custom payloads or wordlists
- Document network position (internal vs external)

---

## Reporting Requirements

### Executive Summary
- Engagement overview (dates, scope, objectives)
- Key findings summary (count by severity)
- Overall risk rating
- Top 3-5 recommendations
- Business impact in non-technical terms

### Technical Report
For each vulnerability:
- Vulnerability ID (VULN-001, VULN-002, etc.)
- Severity and CVSS score
- Location (system/URL/service)
- Technical description
- Proof of Concept steps
- Evidence (screenshots, logs)
- Impact analysis
- Remediation recommendations
- References (CVE, CWE, OWASP)

### Remediation Roadmap
- Prioritized action plan
- Quick wins vs long-term fixes
- Effort estimation (Low/Medium/High)
- Validation criteria

---

## Playbooks

Detailed testing guides for specific vulnerability types:
- **🆕 Playwright Web Application Testing** (`playbooks/playwright-web-testing.md`)
  - Modern SPA/PWA security testing
  - Browser automation for pentesting
  - XSS, CSRF, IDOR testing with Playwright
  - Authentication and authorization testing
  - Client-side security assessment
- **SQL Injection Testing** (`playbooks/sql-injection-testing.md`)
- **Cloud Penetration Testing** (`playbooks/cloud/cloud-pentest-overview.md`)
  - AWS Security Testing
  - Azure Security Testing
  - GCP Security Testing
  - Multi-Cloud Assessments
- XSS Testing (coming soon)
- RCE Validation (coming soon)
- Authentication Bypass (coming soon)
- File Upload Vulnerabilities (coming soon)

---

## Security & Ethics

### Legal Requirements
- ⚠️ **NEVER proceed without written authorization**
- Verify scope before testing any target
- Respect Rules of Engagement and testing constraints
- Stop immediately if causing service impact
- Report incidents or concerns to client
- Maintain professional liability insurance
- Have "get-out-of-jail letter" accessible

### Data Protection
- Encrypt all evidence at rest and in transit
- Sanitize sensitive data before reporting
- Follow data classification guidelines
- Comply with GDPR, HIPAA, PCI DSS as applicable
- Secure deletion after retention period

### Ethical Guidelines
- Test only authorized systems
- Do not exceed scope or authorization
- Maintain confidentiality of client data
- Report all findings honestly
- Provide remediation guidance, not just attacks
- Operate under "do no harm" principle

---

## Support & Resources

### Documentation
- **CLAUDE.md** - Project configuration and role definition
- **Engagement Template README** - Detailed engagement workflow
- **Slash Command Documentation** - `.claude/commands/*.md`
- **Playbooks** - Vulnerability-specific testing guides

### External Resources
- [PTES Technical Guidelines](http://www.pentest-standard.org/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [NIST SP 800-115](https://csrc.nist.gov/publications/detail/sp/800-115/final)
- [Kali Linux Documentation](https://www.kali.org/docs/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

### Industry Certifications
- OSCP (Offensive Security Certified Professional)
- CEH (Certified Ethical Hacker)
- GPEN (GIAC Penetration Tester)
- CPSA/CPTE (Certified Penetration Testing Specialist/Engineer)
- PNPT (Practical Network Penetration Tester)

---

## Project Maintenance

### Version Control
- Use Git for version control (recommended)
- Exclude sensitive client data from version control
- Maintain `.gitignore` for engagement-specific data

### Evidence Retention
- Follow contractual retention policy (typically 30-90 days)
- Store encrypted backups securely
- Document chain of custody
- Secure deletion after retention period

### Continuous Improvement
- Update playbooks with new techniques
- Refine templates based on engagement feedback
- Incorporate new tools and methodologies
- Stay current with vulnerability trends

---

## Quick Start Example

```bash
# 1. Verify Kali MCP is running
mcp__kali_mcp__server_health()

# 2. Start new engagement
/engage ExampleCorp External Pentest

# 3. After documenting authorization and scope, begin scanning
/scan 203.0.113.0/24

# 4. If modern web app detected, use Playwright
/scan-spa https://app.examplecorp.com

# 5. Analyze results and validate findings
/validate SQL Injection in login.php

# 6. Compile evidence
/evidence ExampleCorp_2025-01-15_External

# 7. Generate report
/report ExampleCorp_2025-01-15_External
```

---

## Contributing

This project is designed for internal use within VERSANT Projects. Contributions, improvements, and feedback are welcome.

---

## License

Internal Use - VERSANT Projects

---

## Disclaimer

This framework is designed for **authorized penetration testing only**. Unauthorized access to computer systems is illegal. Always obtain explicit written authorization before conducting any security testing. Users of this framework are solely responsible for ensuring all testing activities are legal and authorized.

---

**Platform**: ATHENA - Strategic Penetration Testing
**Status**: Production Ready
**Version**: 1.0
**Last Updated**: 2025-12-24
**Maintained By**: VERSANT Security Team

---

## Contact

For questions, support, or engagement requests, contact the VERSANT Security Team.

**Remember: Professional penetration testing requires authorization, ethical boundaries, non-destructive validation, and comprehensive evidence collection.**
