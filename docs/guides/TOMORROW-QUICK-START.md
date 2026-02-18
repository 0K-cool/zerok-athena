# Penetration Testing - Quick Start Guide
**Date:** December 16, 2025
**Purpose:** Rapid deployment for external and internal penetration tests
**Status:** Production Ready with API Keys ✅

---

## 🎯 NEW FEATURES (Just Implemented!)

### 1. Combined Reporting (External + Internal)
Generate ONE comprehensive report combining both external and internal pentests:
- Shows complete attack paths (external → internal)
- Unified remediation roadmap prioritized by breaking attack chains
- Dual-perspective executive summary
- **Command:** `/report-combined [CLIENT_NAME]`

### 2. Passive OSINT API Integration
All 5 API keys configured and tested:
- ✅ Shodan (100 queries/month)
- ✅ Censys (250 queries/month)
- ✅ Hunter.io (50 searches/month)
- ✅ GitHub (5,000 req/hour)
- ✅ VirusTotal (4 req/min)

**Load keys:** `source load-api-keys.sh`

### 3. Real-Time Monitoring Dashboard
Launch dashboard BEFORE starting engagement for real-time tracking:

```bash
# Terminal 1: Launch Pentest Monitor Dashboard
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-monitor
source venv/bin/activate
python athena_monitor.py
```

**Dashboard URL:** http://localhost:8080

**What it does:**
- ✅ Logs all commands automatically (prevents duplicate work)
- ✅ Tracks findings in real-time (see vulnerabilities as discovered)
- ✅ Records HITL approvals (complete audit trail)
- ✅ Enables session resumption (recover from interruptions)

**Keep dashboard terminal running throughout engagement!**

**Documentation:**
- `tools/athena-monitor/QUICK-START.md`
- `tools/athena-monitor/INTEGRATION-GUIDE.md`
- `API-KEYS-SETUP.md` - Complete API setup guide
- `COMBINED-REPORTING-GUIDE.md` - Combined reporting feature

---

## ⚡ PRE-ENGAGEMENT (Complete Tonight)

### 1. Review Authorization & Scope
- [ ] Verify signed authorization letter received
- [ ] Confirm external IP ranges/domains in-scope
- [ ] Review Rules of Engagement (RoE)
- [ ] Note testing time windows
- [ ] Verify emergency contact information

### 2. Prepare Evidence Storage
- [ ] Insert encrypted external SSD
- [ ] Verify encryption enabled (FileVault/BitLocker)
- [ ] Create engagement folder: `[CLIENT]_2025-12-16_External/`
- [ ] Test write permissions
- [ ] Document drive serial number

### 3. Load API Keys for Enhanced OSINT (NEW!)
```bash
# Load all 5 API keys
source load-api-keys.sh

# Expected output:
# ✅ Shodan API key loaded
# ✅ Censys API token loaded
# ✅ Hunter.io API key loaded
# ✅ GitHub token loaded
# ✅ VirusTotal API key loaded

# Verify keys are active
echo $SHODAN_API_KEY     # Should show your key
echo $CENSYS_API_TOKEN   # Should show your token
```

**What this enables:**
- Shodan: Exposed service discovery (100 queries/month)
- Censys: Internet-wide scanning data (250 queries/month)
- Hunter.io: Email address discovery (50 searches/month)
- GitHub: Secret scanning (5,000 req/hour)
- VirusTotal: Domain/IP intelligence (4 req/min)

**Security:** API keys stored in `.env` (chmod 600, in .gitignore)

### 4. Setup Pentest Monitor Dashboard (NEW!)
```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-monitor

# Install dependencies (one-time)
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Test dashboard
python athena_monitor.py
# Opens at http://localhost:8080

# Generate test data to verify
# Navigate to: http://localhost:8080/test
# Click buttons to create sample engagement

# Stop dashboard (Ctrl+C) - restart tomorrow before engagement
```

### 5. Verify Tool Connectivity
```bash
# Test Kali MCP
mcp__kali_mcp__server_health()

# Test Playwright MCP (for modern web apps)
mcp__playwright__playwright_navigate("https://example.com")
```

### 6. Create HITL Checkpoint Card (Print or Keep On-Screen)
```
🔴 HITL CHECKPOINTS - NEVER SKIP
├─ Authorization verified before ANY testing
├─ Scope confirmed before scanning new targets
├─ User approves EACH vulnerability validation
├─ Credential testing approved (lockout risk)
├─ Critical findings reviewed before client notification
└─ Final report approved before delivery

✅ ALL HITL checkpoints automatically logged to dashboard!
   View at: http://localhost:8080/engagement/[NAME] → HITL Approvals tab
```

---

## 🚀 ENGAGEMENT WORKFLOW (Tomorrow)

### Phase 0: Launch Dashboard & Load API Keys (2 min) 🆕
```bash
# Terminal 1: Launch dashboard FIRST
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-monitor
source venv/bin/activate
python athena_monitor.py

# Dashboard opens at http://localhost:8080
# Keep this terminal running!
```

```bash
# Terminal 2: Load API keys
cd /Users/kelvinlomboy/VERSANT/Projects/Pentest
source load-api-keys.sh

# Expected output:
# ✅ Shodan API key loaded
# ✅ Censys API token loaded
# ✅ Hunter.io API key loaded
# ✅ GitHub token loaded
# ✅ VirusTotal API key loaded
```

**Why launch dashboard first?**
- Logs all commands automatically
- Prevents duplicate scanning
- Records HITL decisions
- Enables session resumption

**Why load API keys?**
- Enhanced passive OSINT reconnaissance
- 5 API services automatically used during scanning
- ~95% intelligence coverage vs ~70% without keys

---

### Phase 1: Engagement Initialization (15 min)
```bash
# Terminal 2: Start engagement
cd /Users/kelvinlomboy/VERSANT/Projects/Pentest
/engage [CLIENT_NAME] External Penetration Test
```

**Dashboard automatically logs:**
- ✅ Engagement creation
- ✅ Authorization HITL checkpoint
- ✅ Folder structure creation

**HITL Checkpoint 1:**
- [ ] Authorization letter confirmed
- [ ] External scope confirmed (IP ranges/domains)
- [ ] Evidence storage path: `[PATH]`
- [ ] Emergency contact: `[NAME/PHONE]`
- [ ] **USER APPROVES:** Proceed with testing

**What This Does:**
- Creates standardized engagement folder structure
- Documents authorization and scope
- Sets up evidence directories
- Establishes communication protocols

---

### Phase 2: Automated Reconnaissance (30-60 min)

**Execute:**
```bash
# Use integrated scan command (auto-logs to dashboard)
/scan [TARGET_NETWORK]

# Claude automatically:
# - Checks if target already scanned (prevents duplicates)
# - Logs each command before execution
# - Updates dashboard in real-time
# - Records findings as discovered
```

**Dashboard shows (real-time):**
- 📊 Command history as scans execute
- 🔍 Live hosts and open ports discovered
- 🚨 Findings appearing as vulnerabilities found
- ⏱️ Scan progress (prevents duplicate work)

**AI Assists:**
- Parse scan results automatically
- Identify live hosts and open ports
- Prioritize high-value targets (web servers, databases, etc.)
- Generate reconnaissance summary
- **Check database before re-scanning** (saves time!)

**HITL Checkpoint 2:**
- [ ] AI Summary: `X live hosts, Y open ports, Z web apps discovered`
- [ ] User reviews prioritized targets
- [ ] User confirms: All targets are in-scope
- [ ] **USER APPROVES:** Proceed with comprehensive scanning

**Dashboard logs:**
- ✅ HITL approval recorded
- ✅ Complete command history
- ✅ All discovered targets listed

---

### Phase 3: Comprehensive Scanning (2-4 hours)

**Network Scanning:**
```bash
# Full TCP scan (prioritized targets)
mcp__kali_mcp__nmap_scan(
  target="[TARGET]",
  scan_type="-p- -T4",
  additional_args="-sV -sC -oA full-tcp-scan"
)

# Vulnerability scripts
mcp__kali_mcp__nmap_scan(
  target="[TARGET]",
  scan_type="--script vuln",
  ports="[OPEN_PORTS]",
  additional_args="-oA vuln-scan"
)
```

**Web Application Scanning:**
```bash
# Directory enumeration
mcp__kali_mcp__gobuster_scan(
  url="[TARGET_URL]",
  mode="dir",
  wordlist="/usr/share/wordlists/dirb/common.txt"
)

# Web vulnerability scanning
mcp__kali_mcp__nikto_scan(
  target="[TARGET_URL]",
  additional_args="-output nikto-results.txt"
)

# Modern SPA Testing (if React/Vue/Angular detected)
/scan-spa [TARGET_URL]
```

**Parallel Execution Tips:**
- Run multiple nmap scans concurrently (different targets)
- Scan web apps while network scans complete
- Use background processes for long-running scans

**AI Assists:**
- Auto-capture screenshots of all tool outputs
- Parse results for vulnerabilities
- Cross-reference with CVE database
- Calculate CVSS scores
- Flag false positives

**Evidence Collection (Automated):**
- Screenshots: Auto-named with timestamps
- Command logs: Automatically documented
- Tool outputs: Saved in organized structure

**HITL Checkpoint 3:**
- [ ] AI Summary: `X critical, Y high, Z medium vulnerabilities found`
- [ ] User reviews vulnerability list
- [ ] User identifies false positives
- [ ] User selects vulnerabilities to validate
- [ ] **USER APPROVES:** Proceed with validation (one-by-one)

---

### Phase 4: Vulnerability Validation (1-2 hours)

**For EACH Selected Vulnerability:**

**AI Proposes Validation:**
```
Vulnerability: SQL Injection in /login.php parameter 'username'
Method: Read-only query (SELECT @@version)
Risk: Medium (no data exfiltration)
Expected Impact: Database version disclosure
Command: sqlmap -u "URL" --batch --banner --risk=1 --level=1
```

**HITL Checkpoint (Per Vulnerability):**
- [ ] User reviews proposed validation method
- [ ] User confirms non-destructive approach
- [ ] **USER APPROVES:** Execute this specific validation
- [ ] AI executes POC
- [ ] AI captures evidence
- [ ] AI documents reproduction steps
- [ ] Repeat for next vulnerability

**Dashboard shows:**
- ✅ Each HITL approval logged with timestamp
- ✅ Approved/denied decisions recorded
- ✅ Validation commands logged
- ✅ Findings marked "Validated ✅"

**Non-Destructive Testing Reminders:**
- ✅ SQL Injection: `SELECT @@version` only (no data dump)
- ✅ XSS: Alert boxes only (benign payload)
- ✅ RCE: `whoami`, `id` commands only
- ✅ Auth Bypass: Immediate logout after proof
- ✅ File Upload: phpinfo() or test.txt (delete after)
- ❌ NEVER exfiltrate actual data
- ❌ NEVER cause service disruption

---

### Phase 5: Evidence Compilation (30 min)
```bash
/evidence [ENGAGEMENT_NAME]
```

**AI Executes:**
- Organizes all screenshots (proper naming)
- Compiles command logs with timestamps
- Creates vulnerability writeups
- Packages evidence in encrypted archive
- Generates SHA256 hash

**Output:** Complete evidence package ready for reporting

---

### Phase 6: Reporting (1-2 hours)

**Option A: Single Engagement Report (External OR Internal only)**
```bash
/report [ENGAGEMENT_NAME]
```

**AI Generates (Draft):**
- Executive summary (non-technical, business impact)
- Technical findings (detailed with evidence references)
- CVSS scores and risk prioritization
- Remediation recommendations (specific, actionable)
- MITRE ATT&CK technique mapping
- Appendices (methodology, tools, references)

**Option B: Combined Report (External + Internal) 🆕**
```bash
# After BOTH external and internal engagements complete:
/report-combined [CLIENT_NAME]
```

**AI Generates (Enhanced):**
- Dual-perspective executive summary (external + internal)
- Attack chain analysis (external → internal progression)
- Combined technical findings (64+ vulnerabilities)
- Unified remediation roadmap (prioritized by breaking attack chain)
- Risk multiplier effect analysis
- Complete evidence package (both engagements)

**Deliverables:**
- Executive Summary PDF (15 pages)
- Technical Report PDF (156 pages) with Attack Chain Analysis
- Remediation Roadmap Excel (prioritized by attack chain disruption)
- Evidence Package (encrypted ZIP with both engagements)
- Presentation PPTX (38 slides)

**HITL Checkpoint 4:**
- [ ] User reviews draft report thoroughly
- [ ] User validates accuracy of all findings
- [ ] User customizes client-specific context
- [ ] User checks for sensitive information exposure
- [ ] **USER APPROVES:** Final report for client delivery

---

### Phase 7: Combined Reporting Workflow (For External + Internal) 🆕

**When to use combined reporting:**
- ✅ Both external AND internal pentests completed
- ✅ Client wants complete security posture assessment
- ✅ Need to show attack chain analysis
- ✅ Compliance requires holistic view

**Workflow:**
```bash
# Day 1-2: External Engagement
source load-api-keys.sh
/orchestrate [CLIENT] - External Pentest
# Wait for completion (8-12 hours)

# Day 3-4: Internal Engagement
/orchestrate [CLIENT] - Internal Pentest
# Wait for completion (8-12 hours)

# Day 4: Generate Combined Report
/report-combined [CLIENT]
# Result: ONE comprehensive deliverable
```

**What's Different:**
- Shows how external vulnerabilities lead to internal compromise
- Prioritizes remediation by breaking the attack chain
- Higher perceived value for clients
- One unified deliverable instead of two separate reports

**Example Attack Chain:**
```
1. External SQL Injection (EXTERNAL-001)
   ↓ Credential Theft
2. VPN Password Reuse (INTERNAL-005)
   ↓ Internal Network Access
3. Kerberoasting (INTERNAL-001)
   ↓ Service Account Compromise
4. GPO Misconfiguration (INTERNAL-008)
   ↓ Domain Admin Access

RESULT: Complete organizational compromise
TIME TO COMPROMISE: 8-12 hours
BUSINESS IMPACT: $10-20M
```

**Documentation:** See `COMBINED-REPORTING-GUIDE.md` for complete details

---

## 🎯 QUICK REFERENCE: HITL DECISION POINTS

| Phase | HITL Checkpoint | Why Human Decision Required |
|-------|-----------------|----------------------------|
| Start | Authorization verification | Legal compliance, liability |
| Recon | Scope confirmation | Avoid unauthorized scanning |
| Scan | Target prioritization | Resource allocation, time management |
| Validate | **Per-vulnerability approval** | Risk of service impact, ethical boundaries |
| Exploit | Credential testing | Account lockout risk |
| Report | Critical finding notification | Client communication sensitivity |
| Delivery | Final report approval | Professional responsibility |

---

## 🚨 EMERGENCY PROTOCOLS

### If Service Impact Detected
1. **STOP ALL TESTING IMMEDIATELY**
2. Contact client emergency POC: `[PHONE/EMAIL]`
3. Document exactly what was executed
4. Preserve evidence of testing activities
5. Await client guidance before resuming

### If Critical Vulnerability Found
1. **DO NOT** exploit further without approval
2. Capture non-destructive proof only
3. Immediately notify client (don't wait for report)
4. Provide preliminary details and impact assessment
5. Recommend immediate containment actions

### If Locked Out / Access Lost
1. Stop credential testing immediately
2. Notify client of account lockout
3. Request password reset/unlock
4. Adjust testing approach (reduce attempts)
5. Document in engagement notes

---

## 📊 END-OF-DAY CHECKLIST

### Evidence Verification
- [ ] All screenshots captured and properly named
- [ ] All commands logged in `commands-used.md`
- [ ] All tool outputs saved (XML, JSON, TXT)
- [ ] Evidence integrity verified (SHA256 hash)
- [ ] Backup created on secondary storage

### Client Communication
- [ ] Daily status email sent to project manager
- [ ] Critical findings escalated to security team
- [ ] Any service impacts reported immediately
- [ ] Tomorrow's activities previewed

### Security Hygiene
- [ ] Evidence storage encrypted and secured
- [ ] No client data stored on local machine
- [ ] Engagement notes sanitized
- [ ] Tool sessions closed and logs cleared

---

## 💡 AUTOMATION TIPS FOR TOMORROW

### Parallel Execution
```bash
# Scan multiple targets simultaneously
nmap [TARGET1] & nmap [TARGET2] & nmap [TARGET3]

# Run web scanning while network scanning
gobuster [URL] &
nikto [URL] &
wait  # Wait for all background jobs
```

### Evidence Automation
```bash
# Auto-screenshot wrapper (quick hack)
function pentest_run() {
  screenshot "before-$1"
  eval "$@"
  screenshot "after-$1"
}

# Usage: pentest_run "nmap -p- target.com"
```

### Vulnerability Chaining Notes
```
Keep mental model of:
- Information disclosure → Combine with weak creds → RCE
- SSRF → Chain with internal service → Privilege escalation
- XSS → Combine with CSRF → Account takeover
```

---

## 🔧 TROUBLESHOOTING

### Kali MCP Not Responding
```bash
# Check server health
mcp__kali_mcp__server_health()

# If failed, verify network connectivity
ping kali.linux.vkloud.antsle.us

# Check MCP configuration
cat ~/.claude/mcp.json
```

### Playwright MCP Issues
```bash
# Test basic navigation
mcp__playwright__playwright_navigate("https://example.com")

# If failed, check browser installation
# May need to restart Claude Code
```

### Scan Taking Too Long
```bash
# Reduce timing (faster, louder)
nmap -T5 [TARGET]  # Insane speed

# Or increase timing (slower, stealthy)
nmap -T2 [TARGET]  # Polite speed

# Limit port range
nmap --top-ports 100 [TARGET]  # Only common ports
```

---

## 📋 TOOL QUICK REFERENCE

### Network Scanning
```bash
# Host discovery
nmap -sn [NETWORK]

# Quick scan (top 1000 ports)
nmap -T4 --top-ports 1000 [TARGET]

# Full TCP scan
nmap -p- -T4 [TARGET]

# Service version detection
nmap -sV -sC -p [PORTS] [TARGET]

# Vulnerability scanning
nmap --script vuln -p [PORTS] [TARGET]
```

### Web Scanning
```bash
# Directory brute-force
gobuster dir -u [URL] -w [WORDLIST]

# Subdomain enumeration
gobuster dns -d [DOMAIN] -w [WORDLIST]

# Web vulnerability scan
nikto -h [URL]

# WordPress scan
wpscan --url [URL] --enumerate u,p,t

# SQL injection testing
sqlmap -u "[URL]" --batch --risk=1 --level=1
```

### Modern Web Apps
```bash
# SPA testing
/scan-spa [URL]

# Or manual Playwright
mcp__playwright__playwright_navigate("[URL]")
mcp__playwright__playwright_screenshot("evidence/screenshot.png")
```

---

## ✅ SUCCESS CRITERIA

### Single Engagement (External OR Internal)
By end of day, you should have:
- [ ] Complete reconnaissance of attack surface
- [ ] Comprehensive vulnerability assessment with CVSS scores
- [ ] Non-destructive validation of all critical/high findings
- [ ] Complete evidence package (screenshots, logs, artifacts)
- [ ] Draft report ready for final review
- [ ] Client status update delivered
- [ ] No service disruptions or unauthorized actions

### Combined Engagement (External + Internal) 🆕
By end of engagement, you should have:
- [ ] External pentest completed (30-50 findings)
- [ ] Internal pentest completed (25-40 findings)
- [ ] Attack chain analysis documented (external → internal)
- [ ] Combined report generated with unified remediation roadmap
- [ ] Complete evidence package (both engagements)
- [ ] Professional deliverable ready for client
- [ ] Risk multiplier effect clearly communicated

---

**Good luck! Remember: Authorization first, HITL checkpoints always, non-destructive validation only. You've got this! 🦖⚡**

---

## 📚 DOCUMENTATION QUICK REFERENCE

**Core Documentation:**
- `CLAUDE.md` - Project context and tools reference
- `AUTOMATION-ROADMAP.md` - Detailed long-term strategy
- `API-KEYS-SETUP.md` - Complete API setup guide (NEW!)
- `COMBINED-REPORTING-GUIDE.md` - Combined reporting feature (NEW!)

**Slash Commands:**
- `/engage` - Engagement initialization
- `/scan` - Automated scanning with duplicate detection
- `/scan-spa` - Modern web app testing (Playwright)
- `/validate` - Non-destructive POC validation
- `/evidence` - Evidence compilation
- `/report` - Generate single engagement report
- `/report-combined` - Generate combined external + internal report (NEW!)

**Dashboard & Monitoring:**
- `tools/athena-monitor/README.md` - Dashboard features
- `tools/athena-monitor/QUICK-START.md` - 5-minute setup
- `tools/athena-monitor/INTEGRATION-GUIDE.md` - Detailed integration

**Agents:**
- `.claude/agents/orchestrator.md` - Multi-agent coordination
- `.claude/agents/passive-osint.md` - Passive reconnaissance (uses API keys)
- `.claude/agents/active-recon.md` - Network scanning
- `.claude/agents/web-vuln-scanner.md` - Web application testing
- `.claude/agents/exploitation.md` - Vulnerability validation
- `.claude/agents/reporting-agent.md` - Report generation (single + combined modes)
