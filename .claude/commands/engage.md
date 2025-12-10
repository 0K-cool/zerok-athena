# Start New Penetration Test Engagement

Initialize a new authorized penetration testing engagement for: **$ARGUMENTS**

## Pre-Engagement Requirements

### 1. Authorization & Legal Compliance
**CRITICAL - DO NOT PROCEED WITHOUT:**
- [ ] **Signed Authorization Letter/Contract** from client
- [ ] **Rules of Engagement (RoE)** documented and approved
- [ ] **Scope Definition** with explicit IP ranges, domains, and systems
- [ ] **Emergency Contact Information** for client stakeholders
- [ ] **Legal Review** completed (liability, NDAs, compliance requirements)
- [ ] **Insurance Coverage** verified for professional liability
- [ ] **Get-Out-of-Jail Letter** obtained and accessible during testing

**WARNING**: Unauthorized penetration testing is ILLEGAL. Always verify explicit written authorization before any testing activities.

### 2. Storage Planning & Preparation
**Estimate Storage Requirements:**
- Network scans: ~50-500MB per engagement
- Web application scans: ~100MB-1GB per target
- Screenshots & evidence: ~500MB-2GB per engagement
- Full engagement (external + internal): ~2-5GB
- Large enterprise engagement: 10-50GB

**Storage Options:**

**Option A: External/Removable Drive (Recommended for client-facing evidence)**
- [ ] Insert encrypted external drive (USB 3.0+ / External SSD)
- [ ] Verify drive capacity (recommend 256GB+ for multiple engagements)
- [ ] Mount point: `/Volumes/[DRIVE_NAME]` (macOS) or `E:\` (Windows)
- [ ] Create engagement folder: `[MOUNT]/engagements/[CLIENT]_YYYY-MM-DD_[TYPE]/`
- [ ] **Enable full-disk encryption** (FileVault, BitLocker, LUKS)
- [ ] Set proper permissions (read/write for pentester only)
- [ ] Document drive serial number for evidence tracking
- [ ] **Physical security**: Label drive "CONFIDENTIAL - [CLIENT] PENTEST"

**Option B: Network Storage (For team-based engagements)**
- [ ] Mount secure network share/NAS with encryption
- [ ] Verify VPN/secure connection for remote testing
- [ ] Configure access controls (team members only)
- [ ] Document network path and access credentials
- [ ] Ensure compliance with client data residency requirements

**Option C: Local Storage (Development/training only)**
- [ ] Verify local disk space: `df -h` or `Get-PSDrive`
- [ ] Use: `engagements/[CLIENT]_YYYY-MM-DD_[TYPE]/`
- [ ] **NOT RECOMMENDED for production client engagements**
- [ ] Monitor disk usage during scanning

**Storage Decision Matrix:**
| Engagement Type | Estimated Size | Recommended Storage | Encryption Required |
|-----------------|----------------|---------------------|---------------------|
| External Pentest | 2-5GB | External SSD | Yes |
| Internal Pentest | 5-10GB | External SSD | Yes |
| Web App Pentest | 1-3GB | External SSD or Local | Yes |
| Full Red Team | 10-50GB | Encrypted NAS | Yes - Military Grade |
| Compliance Scan | 500MB-2GB | External or Local | Yes |

**Evidence Chain of Custody:**
- Storage Make/Model: __________
- Serial Number: __________
- Capacity: __________
- Encryption Method: __________
- SHA256 Hash (empty): __________
- Assigned To: __________
- Date/Time: __________
- Client Engagement: __________

### 3. Create Engagement Folder Structure
Create a standardized engagement folder (on selected storage):
```
[STORAGE_LOCATION]/engagements/[CLIENT]_YYYY-MM-DD_[TYPE]/
├── 01-planning/              # Pre-engagement planning and scoping
│   ├── authorization.pdf     # Signed authorization letter
│   ├── scope.md              # Detailed scope and boundaries
│   ├── rules-of-engagement.md # Testing constraints and rules
│   ├── contact-sheet.md      # Emergency contacts and escalation
│   └── timeline.md           # Testing schedule and milestones
│
├── 02-reconnaissance/        # Information gathering (passive)
│   ├── osint/                # Open-source intelligence
│   │   ├── domains.txt       # Discovered domains and subdomains
│   │   ├── emails.txt        # Harvested email addresses
│   │   ├── employees.txt     # Public employee information
│   │   └── social-media.md   # Social media reconnaissance
│   ├── dns-enumeration.txt   # DNS records and zone transfers
│   ├── whois-data.txt        # Domain registration information
│   └── google-dorking.md     # Search engine reconnaissance
│
├── 03-scanning/              # Active reconnaissance
│   ├── network/              # Network-level scanning
│   │   ├── nmap-discovery.txt      # Host discovery scans
│   │   ├── nmap-full-tcp.xml       # Full TCP port scans
│   │   ├── nmap-udp-top1000.xml    # UDP service discovery
│   │   ├── nmap-version-detection.xml # Service version detection
│   │   └── nmap-vuln-scan.xml      # Vulnerability script scans
│   ├── web/                  # Web application scanning
│   │   ├── gobuster-dirs.txt       # Directory brute-forcing
│   │   ├── nikto-scan.txt          # Web server vulnerabilities
│   │   ├── wpscan-results.txt      # WordPress vulnerabilities
│   │   └── sqlmap-targets.txt      # SQL injection testing targets
│   └── wireless/             # Wireless network assessment (if in scope)
│       ├── ap-discovery.txt        # Access point enumeration
│       └── wpa-handshakes/         # Captured authentication handshakes
│
├── 04-enumeration/           # Service and system enumeration
│   ├── smb-enumeration.txt   # SMB shares and permissions
│   ├── ldap-enumeration.txt  # Active Directory enumeration
│   ├── snmp-enumeration.txt  # SNMP service information
│   └── rpc-enumeration.txt   # RPC service enumeration
│
├── 05-vulnerability-analysis/ # Vulnerability identification
│   ├── findings/             # Individual vulnerability findings
│   │   ├── VULN-001-sql-injection.md
│   │   ├── VULN-002-xss-reflected.md
│   │   ├── VULN-003-weak-credentials.md
│   │   └── ...
│   ├── vulnerability-summary.md # Consolidated vulnerability list
│   ├── cvss-scoring.xlsx     # Risk scoring and prioritization
│   └── false-positives.md    # Documented false positive findings
│
├── 06-exploitation/          # **SIMULATION ONLY - NON-DESTRUCTIVE**
│   ├── validated-vulns/      # Confirmed exploitable vulnerabilities
│   │   ├── validated-001.md  # Proof of exploitability (simulated)
│   │   └── ...
│   ├── exploitation-notes.md # Testing methodology and approach
│   ├── **NO-ACTUAL-EXPLOITS.md** # Reminder: validation only
│   └── recommended-tests.md  # Client-approved validation tests
│
├── 07-post-exploitation/     # **SIMULATION ONLY** (if authorized)
│   ├── privilege-escalation.md   # Simulated privilege escalation paths
│   ├── lateral-movement.md       # Simulated network traversal
│   ├── persistence-mechanisms.md # Identified persistence opportunities
│   └── data-exfiltration-paths.md # Simulated exfiltration routes
│
├── 08-evidence/              # **CRITICAL: ALL TESTING EVIDENCE**
│   ├── screenshots/          # Visual proof of findings
│   │   ├── 001-nmap-scan-results.png
│   │   ├── 002-sql-injection-poc.png
│   │   ├── 003-admin-panel-access.png
│   │   └── ...
│   ├── logs/                 # Tool output logs
│   │   ├── nmap-verbose.log
│   │   ├── gobuster-output.log
│   │   ├── nikto-detailed.log
│   │   └── ...
│   ├── artifacts/            # Captured artifacts and payloads
│   │   ├── captured-requests.txt
│   │   ├── response-samples.txt
│   │   └── config-files/     # Exposed configuration files
│   ├── commands-used.md      # **ALL COMMANDS EXECUTED** (for repeatability)
│   └── evidence-manifest.md  # Chain of custody for all evidence
│
├── 09-reporting/             # Final deliverables
│   ├── executive-summary.md  # Non-technical overview for leadership
│   ├── technical-report.md   # Detailed technical findings
│   ├── remediation-roadmap.md # Prioritized remediation recommendations
│   ├── retest-requirements.md # Validation criteria for fixes
│   ├── appendices/           # Supporting documentation
│   │   ├── methodology.md    # Testing methodology (PTES, OWASP, etc.)
│   │   ├── tools-used.md     # Tools and versions
│   │   └── references.md     # CVE references and external resources
│   └── final-presentation.pptx # Client presentation deck
│
├── 10-retest/                # Post-remediation validation
│   ├── retest-plan.md        # Retest scope and approach
│   ├── retest-findings.md    # Validation results
│   └── retest-evidence/      # Screenshots of fixed vulnerabilities
│
└── README.md                 # Engagement overview and quick reference
```

### 4. Engagement Scope Definition
Document in `01-planning/scope.md`:

#### In-Scope Assets
- **IP Ranges**: [e.g., 203.0.113.0/24, 198.51.100.0/24]
- **Domain Names**: [e.g., example.com, *.example.com]
- **Web Applications**: [e.g., https://app.example.com, https://portal.example.com]
- **Wireless Networks**: [SSIDs if authorized]
- **Physical Locations**: [If physical testing authorized]
- **Social Engineering**: [If authorized - email phishing, vishing, etc.]

#### Out-of-Scope Assets
- **Third-party services**: [e.g., cloud providers, SaaS platforms]
- **Production databases**: [No direct DB access without approval]
- **Critical systems**: [List systems that must not be tested]
- **Specific subnets**: [Management networks, OT/ICS systems]

#### Testing Constraints
- **Testing Hours**: [e.g., Mon-Fri 9am-5pm EST, After-hours testing requires approval]
- **Rate Limiting**: [Max requests per second to avoid DoS]
- **Denial of Service**: PROHIBITED unless explicitly authorized
- **Data Exfiltration**: Simulation only - no actual data removal
- **Destructive Testing**: PROHIBITED - validation only
- **Social Engineering Limits**: [e.g., no C-level executives, no voicemail hacking]
- **Exploitation Boundaries**: Proof-of-concept only, no actual exploitation

#### Success Criteria
- [ ] All in-scope assets tested
- [ ] Vulnerabilities identified and validated (non-destructively)
- [ ] Evidence collected with screenshots for repeatability
- [ ] Findings documented with remediation guidance
- [ ] Client can reproduce all findings
- [ ] Final report delivered within [X] days of testing completion

### 5. Rules of Engagement (RoE)
Document in `01-planning/rules-of-engagement.md`:

#### Testing Methodology
- **Framework**: PTES (Penetration Testing Execution Standard)
- **Approach**: [Black Box / Gray Box / White Box]
- **Testing Type**: [External / Internal / Web Application / Red Team]
- **Stealth Level**: [Loud / Moderate / Stealthy]

#### Communication Protocols
- **Daily Status Updates**: [Time and method]
- **Critical Finding Notification**: [Immediate notification method]
- **Emergency Contact**: [24/7 contact for incidents]
- **Escalation Path**: [Primary → Secondary → Emergency contacts]

#### Incident Response Procedures
If testing causes disruption or discovers active compromise:
1. **STOP TESTING IMMEDIATELY**
2. Contact emergency POC: [Name, Phone, Email]
3. Document exactly what was executed
4. Preserve evidence of testing vs. actual compromise
5. Await client guidance before resuming

#### Tool Usage Guidelines
- **Approved Tools**: [List specific tools approved by client]
- **Prohibited Tools**: [e.g., No metasploit modules, no kernel exploits]
- **Traffic Generation**: Max [X] requests/second per target
- **Credential Testing**: Max [X] attempts per account (avoid lockouts)

### 6. Pre-Engagement Checklist
- [ ] **Storage prepared and encrypted**
- [ ] **Engagement folder structure created**
- [ ] **Authorization letter saved** (`01-planning/authorization.pdf`)
- [ ] **Scope documented** with in-scope and out-of-scope assets
- [ ] **Rules of Engagement defined** and approved
- [ ] **Emergency contacts verified** (test phone numbers)
- [ ] **Testing tools prepared** (Kali Linux MCP, Nmap, Gobuster, Nikto, etc.)
- [ ] **VPN/Network access** configured (if internal testing)
- [ ] **Backup communication channels** established
- [ ] **Evidence collection system** tested (screenshots, logging)
- [ ] **Client notification** sent for testing start date/time
- [ ] **Legal review** completed
- [ ] **Insurance coverage** confirmed
- [ ] **Kickoff meeting** scheduled with client team

### 7. Kali Linux MCP Tool Verification
Verify available tools for the engagement:
- [ ] **Nmap** - Network discovery and port scanning
- [ ] **Gobuster** - Directory and DNS brute-forcing
- [ ] **Nikto** - Web server vulnerability scanning
- [ ] **Dirb** - Web content discovery
- [ ] **SQLmap** - SQL injection testing
- [ ] **Hydra** - Password brute-forcing (use cautiously)
- [ ] **Enum4linux** - SMB/Samba enumeration
- [ ] **Metasploit** - Exploitation framework (validation only)
- [ ] **Custom Commands** - Execute arbitrary Kali commands

**Test MCP Connection:**
```bash
# Verify Kali MCP server health
mcp__kali_mcp__server_health()
```

### 8. Evidence Collection Protocol

#### Screenshot Requirements
Every finding MUST include:
1. **Command executed** with timestamp
2. **Tool output** showing vulnerability
3. **Browser/application** showing impact
4. **Context** (URL bar, system info, etc.)

**Screenshot Naming Convention:**
```
[NUM]-[SEVERITY]-[CATEGORY]-[BRIEF-DESC]-YYYYMMDD-HHMMSS.png

Examples:
001-CRITICAL-SQLI-login-bypass-20250106-143022.png
002-HIGH-XSS-reflected-comment-20250106-143401.png
003-MEDIUM-INFO-disclosure-version-20250106-144512.png
```

#### Command Logging
Maintain `08-evidence/commands-used.md` with ALL commands:
```markdown
# Commands Executed - [CLIENT] Engagement

## Network Scanning
### 2025-01-06 14:30:00 EST
```bash
nmap -sV -sC -p- 203.0.113.45 -oA nmap-full-scan
```
**Purpose**: Full TCP port scan with version detection
**Results**: See `03-scanning/network/nmap-full-tcp.xml`
**Screenshot**: `001-nmap-scan-results.png`

### 2025-01-06 15:15:00 EST
```bash
gobuster dir -u https://app.example.com -w /usr/share/wordlists/dirb/common.txt -o gobuster-dirs.txt
```
**Purpose**: Directory enumeration
**Results**: See `03-scanning/web/gobuster-dirs.txt`
**Screenshot**: `005-gobuster-hidden-dirs.png`
```

#### Repeatability Requirements
- **Client must be able to reproduce findings**
- Provide exact commands with parameters
- Document tool versions used
- Include any custom wordlists or payloads
- Note any timing or rate-limiting used
- Specify network position (internal/external)

### 9. AI-Powered Testing Philosophy

Following research from [Anthropic's AI Cyber Defenders](https://www.anthropic.com/research/building-ai-cyber-defenders) and [CrowdStrike's 2025 Threat Hunting Report](https://www.crowdstrike.com/en-us/blog/crowdstrike-2025-threat-hunting-report-ai-weapon-target/):

#### Threat Actor Simulation
- **AI-Enhanced Reconnaissance**: Use Claude to analyze targets like real attackers
- **Intelligent Vulnerability Chaining**: Connect multiple low-severity findings into critical paths
- **Adaptive Testing**: Adjust methodology based on discovered architecture
- **Defender Perspective**: Think like both attacker AND defender

#### Automation with Human Oversight
- **Automated Scanning**: Use Kali MCP for broad coverage
- **AI Analysis**: Claude analyzes scan results for patterns and anomalies
- **Human Validation**: Pentester confirms and validates findings
- **Ethical Boundaries**: AI assists but human maintains control and ethics

#### Non-Destructive Validation
- **Proof of Concept**: Demonstrate exploitability without causing harm
- **Simulation**: Model attack paths without executing exploits
- **Safe Testing**: Use read-only operations where possible
- **Risk Assessment**: Evaluate potential impact before testing

### 10. Stakeholder Communication Matrix
Create `01-planning/contact-sheet.md`:

| Role | Name | Contact | Notification Type | Response Time |
|------|------|---------|-------------------|---------------|
| Project Manager | | | Daily updates | 4 hours |
| Technical Lead | | | Technical questions | 2 hours |
| Security Team Lead | | | Findings, coordination | 1 hour |
| Emergency Contact | | | System impact, incidents | 15 minutes |
| Legal Contact | | | Legal/compliance issues | 1 hour |
| Executive Sponsor | | | Critical findings | 4 hours |

**Communication Schedule:**
- **Daily Status Email**: [Time] to [Recipients]
- **End-of-Day Summary**: Brief findings summary
- **Critical Finding Alert**: Immediate notification via [phone/email/slack]
- **Mid-Engagement Briefing**: [Date/Time]
- **Final Debrief**: [Date/Time] with technical and executive teams

### 11. Engagement Timeline
Create `01-planning/timeline.md`:

#### Phase 1: Reconnaissance (Days 1-2)
- Passive information gathering
- OSINT and public data collection
- DNS enumeration
- Subdomain discovery

#### Phase 2: Active Scanning (Days 2-3)
- Network port scanning
- Service version detection
- Web application discovery
- Vulnerability scanning

#### Phase 3: Enumeration (Days 3-4)
- Service-specific enumeration
- User/group enumeration (if applicable)
- Share/directory enumeration
- Technology stack identification

#### Phase 4: Vulnerability Analysis (Days 4-5)
- Vulnerability identification
- False positive elimination
- Risk assessment and CVSS scoring
- Exploitation feasibility analysis

#### Phase 5: Exploitation Validation (Days 5-6)
- **NON-DESTRUCTIVE** proof of concept
- Vulnerability confirmation
- Impact demonstration
- Evidence collection with screenshots

#### Phase 6: Post-Exploitation Simulation (Days 6-7)
- Privilege escalation path identification
- Lateral movement simulation
- Persistence mechanism discovery
- Data access and exfiltration path analysis

#### Phase 7: Reporting (Days 7-10)
- Evidence compilation and organization
- Report writing (executive + technical)
- Remediation guidance development
- Presentation preparation

#### Phase 8: Debrief & Retest (Days 11-14)
- Client presentation and walkthrough
- Findings discussion and Q&A
- Remediation support
- Retest scheduling

### 12. Compliance & Standards

#### Industry Frameworks
- [ ] **PTES** (Penetration Testing Execution Standard)
- [ ] **OWASP Testing Guide** (for web applications)
- [ ] **NIST SP 800-115** (Technical Security Testing)
- [ ] **PCI DSS** (if payment card testing)
- [ ] **HIPAA** (if healthcare data involved)
- [ ] **SOC 2** (if compliance-driven)

#### Certification References
- CEH (Certified Ethical Hacker)
- OSCP (Offensive Security Certified Professional)
- GPEN (GIAC Penetration Tester)
- CPSA/CPTE (Certified Penetration Testing Specialist/Engineer)

### 13. Risk Management

#### Testing Risk Assessment
| Activity | Risk Level | Mitigation | Approval Required |
|----------|-----------|------------|-------------------|
| Port Scanning | Low | Rate limiting | Standard authorization |
| Web Directory Brute-Force | Medium | Throttling, off-hours | Standard authorization |
| SQL Injection Testing | Medium | Read-only queries, test DB | Technical approval |
| Password Brute-Force | High | Account lockout monitoring | Explicit approval |
| Exploit Execution | HIGH | **PROHIBITED** - Simulation only | N/A |
| Denial of Service | CRITICAL | **PROHIBITED** unless explicit written approval | Executive approval |

#### Safeguards
- Always test in isolated/staging environments when available
- Use read-only operations whenever possible
- Implement rate limiting to prevent service degradation
- Monitor target system health during testing
- Maintain rollback procedures for any changes
- Document all actions for audit trail

---

## Deliverables
At the end of engagement setup, you should have:
1. ✅ Encrypted storage prepared with engagement folder structure
2. ✅ Signed authorization letter and legal documentation
3. ✅ Complete scope definition with in-scope/out-of-scope assets
4. ✅ Rules of Engagement documented and approved
5. ✅ Emergency contact information verified
6. ✅ Evidence collection protocol established
7. ✅ Kali Linux MCP tools verified and ready
8. ✅ Communication plan with stakeholders
9. ✅ Timeline with milestones and deliverable dates
10. ✅ Risk management and safeguards documented

## Next Steps
After initialization:
1. **Verify Kali MCP connectivity** and tool availability
2. **Notify client** of testing start date/time
3. **Begin passive reconnaissance** (OSINT, DNS, subdomains)
4. **Execute network discovery** scans (Nmap host discovery)
5. **Document all activities** in engagement folder
6. **Collect screenshots** of every command and finding
7. **Send daily status updates** to project manager
8. **Report critical findings** immediately upon discovery

---

## Next Commands in Pentest Workflow
After engagement setup, use these commands to progress through the penetration testing lifecycle:

### Reconnaissance & Scanning:
- **`/recon`** - Execute passive reconnaissance and OSINT gathering
- **`/scan`** - Perform active scanning (network, web, wireless)
- **`/enumerate`** - Deep enumeration of discovered services

### Vulnerability Analysis:
- **`/vuln-assess`** - Analyze vulnerabilities and assess exploitability
- **`/validate`** - Non-destructively validate vulnerabilities (POC)

### Reporting:
- **`/evidence`** - Compile and organize evidence with screenshots
- **`/report`** - Generate professional penetration test report
- **`/remediate`** - Create remediation roadmap for findings

### Advanced:
- **`/threat-model`** - Model real-world threat actor TTPs
- **`/retest`** - Validate client remediation efforts

### Typical Pentest Workflow:
1. `/engage` → Engagement setup and authorization (YOU ARE HERE)
2. `/recon` → Passive information gathering
3. `/scan` → Active reconnaissance and scanning
4. `/enumerate` → Service and system enumeration
5. `/vuln-assess` → Vulnerability identification and analysis
6. `/validate` → Non-destructive proof-of-concept
7. `/evidence` → Evidence compilation and organization
8. `/report` → Final report generation
9. `/retest` → Post-remediation validation

---

**Engagement Status**: AUTHORIZED - READY TO BEGIN
**Created**: [Auto-populate timestamp]
**Lead Pentester**: [Your name]
**Client**: [Client organization]
**Engagement Type**: [External/Internal/Web App/Red Team]
**Storage Location**: [Path to encrypted storage]
**Testing Start Date**: [YYYY-MM-DD]
**Expected Completion**: [YYYY-MM-DD]

---

## CRITICAL REMINDERS

🔴 **ALWAYS VERIFY AUTHORIZATION** before any testing activities
🔴 **NON-DESTRUCTIVE TESTING ONLY** - Validate, don't exploit
🔴 **COLLECT EVIDENCE** - Screenshots and commands for every finding
🔴 **ENCRYPTED STORAGE** - All evidence must be on encrypted media
🔴 **CLIENT REPEATABILITY** - Provide exact steps to reproduce findings
🔴 **EMERGENCY CONTACTS** - Have client emergency contact immediately available
🔴 **STOP IF CAUSING HARM** - Halt testing immediately if systems are impacted

**Unauthorized hacking is illegal. Professional penetration testing requires explicit written authorization.**
