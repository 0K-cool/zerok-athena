# Execute Security Scanning

Perform comprehensive security scanning for: **$ARGUMENTS**

## Pre-Scan Verification

### CRITICAL SAFETY CHECKS
- [ ] **Authorization confirmed** for target: $ARGUMENTS
- [ ] **Target is in-scope** per engagement documentation
- [ ] **Rules of Engagement reviewed** for rate limiting and constraints
- [ ] **Emergency contact available** in case of service impact
- [ ] **Evidence storage prepared** for logs and screenshots

**⚠️ STOP**: If authorization is not confirmed, DO NOT PROCEED with scanning.

### User Confirmation Required
**Before executing any scans, ask the user:**
1. **Storage location for evidence**: Where should scan results and screenshots be saved?
   - Option A: External drive (specify mount point)
   - Option B: NAS (specify network path)
   - Option C: Local disk (specify full path)
2. **Confirm target**: Is `$ARGUMENTS` the correct target?
3. **Scan intensity**: Loud/Moderate/Stealth approach?
4. **Time window**: Any time restrictions for scanning?

### Evidence Storage Setup
```bash
# User specifies storage location
EVIDENCE_BASE="[USER_SPECIFIED_PATH]"

# Create scan evidence directory
SCAN_DIR="$EVIDENCE_BASE/03-scanning"
mkdir -p "$SCAN_DIR"/{network,web,wireless,logs}

# Create screenshots directory
SCREENSHOT_DIR="$EVIDENCE_BASE/08-evidence/screenshots"
mkdir -p "$SCREENSHOT_DIR"
```

## Scanning Phases

### Phase 1: Network Discovery & Port Scanning

#### 1.1 Host Discovery (Ping Sweep)
**Purpose**: Identify live hosts in target network
**Tool**: Nmap
**Command**:
```bash
nmap -sn [TARGET_NETWORK] -oA "$SCAN_DIR/network/nmap-host-discovery"
```

**Execute via Kali MCP**:
```
mcp__kali_mcp__nmap_scan(
  target="[TARGET]",
  scan_type="-sn",
  additional_args="-oA nmap-host-discovery"
)
```

**Evidence Collection**:
- [ ] Screenshot of command execution
- [ ] Screenshot of results showing live hosts
- [ ] Save output to: `$SCAN_DIR/network/nmap-host-discovery.txt`
- [ ] Document in: `08-evidence/commands-used.md`

---

#### 1.2 Quick Port Scan (Top 1000 TCP Ports)
**Purpose**: Rapid identification of common open ports
**Tool**: Nmap
**Command**:
```bash
nmap -T4 --top-ports 1000 [TARGET] -oA "$SCAN_DIR/network/nmap-quick-scan"
```

**Execute via Kali MCP**:
```
mcp__kali_mcp__nmap_scan(
  target="[TARGET]",
  scan_type="-T4",
  ports="--top-ports 1000",
  additional_args="-oA nmap-quick-scan"
)
```

**Evidence Collection**:
- [ ] Screenshot: `001-nmap-quick-scan-[TARGET]-[TIMESTAMP].png`
- [ ] Save XML output for parsing
- [ ] Document open ports in `03-scanning/network/open-ports-summary.md`

---

#### 1.3 Full TCP Port Scan (All 65535 Ports)
**Purpose**: Comprehensive TCP port discovery
**Tool**: Nmap
**Command**:
```bash
nmap -p- -T4 [TARGET] -oA "$SCAN_DIR/network/nmap-full-tcp"
```

**Execute via Kali MCP**:
```
mcp__kali_mcp__nmap_scan(
  target="[TARGET]",
  scan_type="-T4",
  ports="-p-",
  additional_args="-oA nmap-full-tcp"
)
```

**⚠️ Warning**: Full scan takes 20-60 minutes per host. Monitor for service impact.

**Evidence Collection**:
- [ ] Screenshot: `002-nmap-full-tcp-[TARGET]-[TIMESTAMP].png`
- [ ] Save all output formats (.nmap, .xml, .gnmap)
- [ ] Parse results for unusual high ports

---

#### 1.4 UDP Port Scan (Top 1000 UDP Ports)
**Purpose**: Discover UDP services (DNS, SNMP, NTP, etc.)
**Tool**: Nmap
**Command**:
```bash
nmap -sU --top-ports 1000 [TARGET] -oA "$SCAN_DIR/network/nmap-udp-scan"
```

**Execute via Kali MCP**:
```
mcp__kali_mcp__nmap_scan(
  target="[TARGET]",
  scan_type="-sU",
  ports="--top-ports 1000",
  additional_args="-oA nmap-udp-scan"
)
```

**Note**: UDP scans are slower and less reliable than TCP.

**Evidence Collection**:
- [ ] Screenshot: `003-nmap-udp-scan-[TARGET]-[TIMESTAMP].png`
- [ ] Document open UDP services
- [ ] Flag high-risk services (SNMP community strings, DNS zone transfers)

---

#### 1.5 Service Version Detection
**Purpose**: Identify exact service versions for vulnerability mapping
**Tool**: Nmap
**Command**:
```bash
nmap -sV -sC -p [OPEN_PORTS] [TARGET] -oA "$SCAN_DIR/network/nmap-version-detection"
```

**Execute via Kali MCP**:
```
mcp__kali_mcp__nmap_scan(
  target="[TARGET]",
  scan_type="-sV -sC",
  ports="[OPEN_PORTS]",
  additional_args="-oA nmap-version-detection"
)
```

**Evidence Collection**:
- [ ] Screenshot: `004-nmap-version-detection-[TARGET]-[TIMESTAMP].png`
- [ ] Extract banner information
- [ ] Cross-reference versions with CVE databases
- [ ] Document in: `03-scanning/network/service-versions.md`

---

#### 1.6 Nmap Vulnerability Scanning
**Purpose**: Check for known vulnerabilities using NSE scripts
**Tool**: Nmap NSE (Nmap Scripting Engine)
**Command**:
```bash
nmap --script vuln -p [OPEN_PORTS] [TARGET] -oA "$SCAN_DIR/network/nmap-vuln-scan"
```

**Execute via Kali MCP**:
```
mcp__kali_mcp__nmap_scan(
  target="[TARGET]",
  scan_type="--script vuln",
  ports="[OPEN_PORTS]",
  additional_args="-oA nmap-vuln-scan"
)
```

**⚠️ Warning**: Vulnerability scripts may trigger IDS/IPS alerts.

**Evidence Collection**:
- [ ] Screenshot: `005-nmap-vuln-scan-[TARGET]-[TIMESTAMP].png`
- [ ] Save detailed NSE script output
- [ ] Flag critical vulnerabilities (EternalBlue, BlueKeep, etc.)
- [ ] Document CVEs in: `05-vulnerability-analysis/vulnerability-summary.md`

---

### Phase 2: Web Application Scanning

**🆕 Modern Web App Detection:**
Before proceeding with traditional web scanning, determine application type:
- **Traditional Web App** (PHP, ASP.NET, JSP) → Use Nikto, Gobuster, Dirb
- **Modern SPA/PWA** (React, Vue, Angular) → Use `/scan-spa` command with Playwright
- **Hybrid** → Use both approaches for complete coverage

**Quick Detection:**
1. Navigate to target URL in browser
2. View page source:
   - If `<div id="root">` or `<div id="app">` with minimal HTML → **SPA (use Playwright)**
   - If full HTML content visible → **Traditional (continue below)**
3. Check Network tab:
   - API calls to `/api/*` or `/graphql` → **SPA (use Playwright)**
   - Full page loads → **Traditional (continue below)**

**If Modern SPA Detected:**
```
Recommend running: /scan-spa [TARGET_URL]
Then return here for additional traditional scanning
```

---

#### 2.1 Directory & File Brute-Forcing (Gobuster)
**Purpose**: Discover hidden directories, files, and endpoints
**Tool**: Gobuster
**Command**:
```bash
gobuster dir -u [TARGET_URL] -w /usr/share/wordlists/dirb/common.txt -o "$SCAN_DIR/web/gobuster-dirs.txt"
```

**Execute via Kali MCP**:
```
mcp__kali_mcp__gobuster_scan(
  url="[TARGET_URL]",
  mode="dir",
  wordlist="/usr/share/wordlists/dirb/common.txt",
  additional_args="-o gobuster-dirs.txt"
)
```

**Evidence Collection**:
- [ ] Screenshot: `010-gobuster-dir-scan-[TIMESTAMP].png`
- [ ] Save results: `$SCAN_DIR/web/gobuster-dirs.txt`
- [ ] Highlight sensitive findings (admin panels, config files, backups)
- [ ] Test discovered endpoints manually

**Common Wordlists**:
- `/usr/share/wordlists/dirb/common.txt` (4614 entries - fast)
- `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt` (220k entries - thorough)
- `/usr/share/wordlists/seclists/Discovery/Web-Content/` (SecLists collection)

---

#### 2.2 DNS Subdomain Enumeration (Gobuster)
**Purpose**: Discover subdomains of target domain
**Tool**: Gobuster (DNS mode)
**Command**:
```bash
gobuster dns -d [TARGET_DOMAIN] -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -o "$SCAN_DIR/web/gobuster-subdomains.txt"
```

**Execute via Kali MCP**:
```
mcp__kali_mcp__gobuster_scan(
  url="[TARGET_DOMAIN]",
  mode="dns",
  wordlist="/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
  additional_args="-o gobuster-subdomains.txt"
)
```

**Evidence Collection**:
- [ ] Screenshot: `011-gobuster-subdomain-enum-[TIMESTAMP].png`
- [ ] Document discovered subdomains
- [ ] Test each subdomain for accessibility
- [ ] Identify staging, dev, test environments (often less secure)

---

#### 2.3 Web Server Vulnerability Scanning (Nikto)
**Purpose**: Identify web server misconfigurations and vulnerabilities
**Tool**: Nikto
**Command**:
```bash
nikto -h [TARGET_URL] -output "$SCAN_DIR/web/nikto-scan.txt"
```

**Execute via Kali MCP**:
```
mcp__kali_mcp__nikto_scan(
  target="[TARGET_URL]",
  additional_args="-output nikto-scan.txt"
)
```

**⚠️ Warning**: Nikto is LOUD and generates significant traffic. Use during approved hours.

**Evidence Collection**:
- [ ] Screenshot: `012-nikto-scan-results-[TIMESTAMP].png`
- [ ] Save detailed report: `$SCAN_DIR/web/nikto-scan.txt`
- [ ] Prioritize findings (OSVDB references, CVEs)
- [ ] Validate findings manually to eliminate false positives

**Key Nikto Findings to Investigate**:
- Server version disclosure
- Default files and directories
- Insecure HTTP methods (PUT, DELETE, TRACE)
- Missing security headers
- Known vulnerabilities

---

#### 2.4 Directory Brute-Forcing (Dirb)
**Purpose**: Alternative directory discovery tool (recursive scanning)
**Tool**: Dirb
**Command**:
```bash
dirb [TARGET_URL] /usr/share/wordlists/dirb/common.txt -o "$SCAN_DIR/web/dirb-scan.txt"
```

**Execute via Kali MCP**:
```
mcp__kali_mcp__dirb_scan(
  url="[TARGET_URL]",
  wordlist="/usr/share/wordlists/dirb/common.txt",
  additional_args="-o dirb-scan.txt"
)
```

**Evidence Collection**:
- [ ] Screenshot: `013-dirb-scan-results-[TIMESTAMP].png`
- [ ] Save results: `$SCAN_DIR/web/dirb-scan.txt`
- [ ] Compare with Gobuster results for validation
- [ ] Document unique findings

---

#### 2.5 Playwright Browser Automation Testing (Modern Web Apps) 🆕

**Purpose**: Test JavaScript-heavy applications, SPAs, and authenticated workflows
**Tool**: Playwright MCP
**When to Use**: React/Vue/Angular apps, PWAs, complex authentication

**Quick Playwright Scan:**
```
# For comprehensive SPA testing, use dedicated command:
/scan-spa [TARGET_URL]

# Or integrate Playwright into current scan:
mcp__playwright__playwright_navigate("[TARGET_URL]")
mcp__playwright__playwright_screenshot("evidence/playwright-landing-page.png")
```

**Playwright Capabilities:**
- ✅ Full JavaScript rendering (sees complete SPA)
- ✅ Automated authentication workflows
- ✅ API endpoint discovery via network monitoring
- ✅ Client-side storage inspection (localStorage, cookies)
- ✅ XSS testing with automated payload injection
- ✅ CSRF token validation testing
- ✅ IDOR testing across user contexts
- ✅ Video recording of complex attack chains

**Evidence Collection:**
- [ ] Screenshot: `015-playwright-spa-analysis-[TIMESTAMP].png`
- [ ] Network logs (HAR): `evidence/logs/playwright-network.har`
- [ ] Storage dump: `evidence/artifacts/playwright-storage.json`
- [ ] Document findings in: `03-scanning/web/playwright-findings.md`

**For Complete SPA Testing:**
See `/scan-spa` command and `playbooks/playwright-web-testing.md`

---

#### 2.6 WordPress Vulnerability Scanning (WPScan)
**Purpose**: Identify WordPress-specific vulnerabilities
**Tool**: WPScan
**Command**:
```bash
wpscan --url [TARGET_URL] --enumerate u,p,t --output "$SCAN_DIR/web/wpscan-results.txt"
```

**Execute via Kali MCP**:
```
mcp__kali_mcp__wpscan_analyze(
  url="[TARGET_URL]",
  additional_args="--enumerate u,p,t --output wpscan-results.txt"
)
```

**Evidence Collection**:
- [ ] Screenshot: `014-wpscan-results-[TIMESTAMP].png`
- [ ] Document WordPress version
- [ ] List vulnerable plugins and themes
- [ ] Enumerate users for password attacks
- [ ] Save results: `$SCAN_DIR/web/wpscan-results.txt`

**Note**: Requires WPScan API token for vulnerability database access (free tier available).

---

### Phase 3: Service-Specific Enumeration

#### 3.1 SMB/Samba Enumeration (Enum4linux)
**Purpose**: Enumerate Windows/Samba shares, users, groups
**Tool**: Enum4linux
**Command**:
```bash
enum4linux -a [TARGET_IP] > "$SCAN_DIR/network/enum4linux-results.txt"
```

**Execute via Kali MCP**:
```
mcp__kali_mcp__enum4linux_scan(
  target="[TARGET_IP]",
  additional_args="-a"
)
```

**Evidence Collection**:
- [ ] Screenshot: `020-enum4linux-results-[TIMESTAMP].png`
- [ ] Document user accounts discovered
- [ ] List accessible SMB shares
- [ ] Check for null session access
- [ ] Identify domain information (SID, workgroup)

**Critical Findings to Flag**:
- Anonymous/null session access
- Writable shares
- User account enumeration
- Password policy information

---

#### 3.2 SQL Injection Testing (SQLmap)
**Purpose**: Detect and validate SQL injection vulnerabilities
**Tool**: SQLmap
**Command**:
```bash
sqlmap -u "[TARGET_URL]?param=value" --batch --risk=1 --level=1 --output-dir="$SCAN_DIR/web/sqlmap/"
```

**Execute via Kali MCP**:
```
mcp__kali_mcp__sqlmap_scan(
  url="[TARGET_URL]?param=value",
  additional_args="--batch --risk=1 --level=1"
)
```

**⚠️ CRITICAL SAFETY MEASURES**:
- Start with `--risk=1 --level=1` (safest)
- Use `--batch` to avoid interactive prompts
- **DO NOT use `--dump` or `--dump-all`** without explicit authorization
- **READ-ONLY testing** - validate vulnerability only
- Test on staging/dev environments when available

**Evidence Collection**:
- [ ] Screenshot: `021-sqlmap-injection-found-[TIMESTAMP].png`
- [ ] Document vulnerable parameters
- [ ] Note injection type (Union, Boolean, Time-based)
- [ ] **DO NOT extract data** - proof of vulnerability is sufficient
- [ ] Save SQLmap output: `$SCAN_DIR/web/sqlmap/`

**Proof of Concept (Safe)**:
```sql
-- Example: Demonstrate SQL injection without data exfiltration
-- Show database version only
sqlmap -u "URL" --batch --banner
```

---

#### 3.3 Password Attack Simulation (Hydra)
**Purpose**: Test for weak credentials (username/password)
**Tool**: Hydra

**⚠️ EXTREME CAUTION REQUIRED**:
- **Account lockout risk** - verify lockout policy first
- **Max 3-5 attempts per account** recommended
- **Coordinate with client** to avoid production account lockouts
- Test during approved maintenance windows
- Use small targeted wordlists

**Command**:
```bash
hydra -L users.txt -P passwords.txt [SERVICE]://[TARGET] -t 4 -V
```

**Execute via Kali MCP**:
```
mcp__kali_mcp__hydra_attack(
  target="[TARGET_IP]",
  service="ssh",  # or ftp, http-post-form, etc.
  username_file="users.txt",
  password_file="passwords.txt",
  additional_args="-t 4 -V"
)
```

**Recommended Approach**:
1. Test with known default credentials first
2. Use small custom wordlist (top 10-20 common passwords)
3. Monitor for account lockouts
4. Stop immediately if lockouts occur

**Evidence Collection**:
- [ ] Screenshot: `022-hydra-weak-credentials-[TIMESTAMP].png`
- [ ] Document compromised accounts
- [ ] **Immediately notify client** of weak credentials
- [ ] Save results: `$SCAN_DIR/network/hydra-results.txt`

**Common Services to Test**:
- SSH (port 22)
- FTP (port 21)
- HTTP/HTTPS (web login forms)
- RDP (port 3389)
- SMB (port 445)

---

### Phase 4: Wireless Network Assessment

**Note**: Only if wireless testing is authorized in scope.

#### 4.1 Wireless Access Point Discovery
**Tool**: airodump-ng, iwlist
**Purpose**: Identify wireless networks and access points

**Evidence Collection**:
- [ ] Document SSIDs, BSSIDs, channels
- [ ] Note encryption types (WEP, WPA, WPA2, WPA3)
- [ ] Identify rogue access points
- [ ] Screenshot: `030-wireless-discovery-[TIMESTAMP].png`

**⚠️ Legal Warning**: Wireless testing must be explicitly authorized. Do not attack client guest networks without approval.

---

## Post-Scan Activities

### 1. Evidence Organization
Organize all scan results into structured format:
```
03-scanning/
├── network/
│   ├── nmap-host-discovery.{nmap,xml,gnmap}
│   ├── nmap-full-tcp.{nmap,xml,gnmap}
│   ├── nmap-version-detection.{nmap,xml,gnmap}
│   ├── nmap-vuln-scan.{nmap,xml,gnmap}
│   ├── service-versions.md (parsed summary)
│   └── open-ports-summary.md
├── web/
│   ├── gobuster-dirs.txt
│   ├── gobuster-subdomains.txt
│   ├── nikto-scan.txt
│   ├── dirb-scan.txt
│   ├── wpscan-results.txt
│   └── sqlmap/ (directory with SQLmap outputs)
└── logs/
    ├── all-commands-executed.log
    └── timestamps.log
```

### 2. Screenshot Archive
Verify all screenshots are saved with proper naming:
```
08-evidence/screenshots/
├── 001-nmap-quick-scan-[TARGET]-[TIMESTAMP].png
├── 002-nmap-full-tcp-[TARGET]-[TIMESTAMP].png
├── 003-nmap-udp-scan-[TARGET]-[TIMESTAMP].png
├── 004-nmap-version-detection-[TARGET]-[TIMESTAMP].png
├── 005-nmap-vuln-scan-[TARGET]-[TIMESTAMP].png
├── 010-gobuster-dir-scan-[TIMESTAMP].png
├── 011-gobuster-subdomain-enum-[TIMESTAMP].png
├── 012-nikto-scan-results-[TIMESTAMP].png
├── 013-dirb-scan-results-[TIMESTAMP].png
├── 014-wpscan-results-[TIMESTAMP].png
├── 020-enum4linux-results-[TIMESTAMP].png
├── 021-sqlmap-injection-found-[TIMESTAMP].png
├── 022-hydra-weak-credentials-[TIMESTAMP].png
└── 030-wireless-discovery-[TIMESTAMP].png
```

### 3. Commands Documentation
Update `08-evidence/commands-used.md` with ALL executed commands:
```markdown
# Commands Executed - Scanning Phase

## Network Scanning
### [TIMESTAMP]
```bash
nmap -sn 203.0.113.0/24 -oA nmap-host-discovery
```
**Purpose**: Host discovery
**Results**: 15 live hosts identified
**Screenshot**: 001-nmap-quick-scan-[TARGET]-[TIMESTAMP].png

### [TIMESTAMP]
```bash
nmap -p- -T4 203.0.113.45 -oA nmap-full-tcp
```
**Purpose**: Full TCP port scan
**Results**: 8 open ports found
**Screenshot**: 002-nmap-full-tcp-[TARGET]-[TIMESTAMP].png

[Continue for all commands...]
```

### 4. Findings Summary
Create preliminary findings summary in `03-scanning/scan-summary.md`:
```markdown
# Scanning Phase Summary

## Scan Date: [DATE]
## Target: [TARGET]
## Pentester: [NAME]

### Network Scan Results
- **Total Hosts Scanned**: X
- **Live Hosts**: Y
- **Total Open Ports**: Z
- **High-Risk Services**: [List]

### Web Application Scan Results
- **URLs Scanned**: X
- **Hidden Directories Found**: Y
- **Subdomains Discovered**: Z
- **Critical Findings**: [Count]

### Preliminary Vulnerabilities Identified
| Severity | Count | Examples |
|----------|-------|----------|
| Critical | X | EternalBlue, SQL Injection |
| High | Y | Weak credentials, XSS |
| Medium | Z | Missing headers, info disclosure |
| Low | N | Version disclosure, default pages |

### Next Steps
- [ ] Validate all findings manually
- [ ] Eliminate false positives
- [ ] Perform deep enumeration on discovered services
- [ ] Proceed to vulnerability analysis phase
```

### 5. Client Notification
If critical findings discovered during scanning:
- [ ] **Immediately notify client** per communication protocol
- [ ] Provide preliminary details without complete analysis
- [ ] Recommend immediate containment if active exploitation suspected
- [ ] Document notification in engagement timeline

---

## Scanning Checklist

### Pre-Scan
- [ ] Authorization verified
- [ ] Target confirmed in-scope
- [ ] Storage location prepared
- [ ] Evidence directories created
- [ ] Screenshot tool ready
- [ ] Kali MCP connection verified

### Network Scanning
- [ ] Host discovery completed
- [ ] Quick port scan completed
- [ ] Full TCP scan completed
- [ ] UDP scan completed
- [ ] Service version detection completed
- [ ] Vulnerability scanning completed
- [ ] All results saved and backed up

### Web Application Scanning
- [ ] Directory brute-forcing completed (Gobuster)
- [ ] Subdomain enumeration completed
- [ ] Web vulnerability scanning completed (Nikto)
- [ ] Alternative directory scan completed (Dirb)
- [ ] WordPress scanning completed (if applicable)
- [ ] SQL injection testing completed (if applicable)

### Service Enumeration
- [ ] SMB enumeration completed (if applicable)
- [ ] SNMP enumeration completed (if applicable)
- [ ] LDAP enumeration completed (if applicable)
- [ ] Password testing completed (with caution)

### Evidence Collection
- [ ] All commands logged in `commands-used.md`
- [ ] All screenshots captured and named properly
- [ ] Scan outputs saved in organized structure
- [ ] Findings summary document created
- [ ] Critical findings flagged for immediate review

---

## Rate Limiting & Stealth Considerations

### Scanning Intensity Levels

**Loud (Fastest - High Detection Risk)**
- Nmap timing: `-T5` (Insane)
- Threads: 50-100
- No delays between requests
- Use when: Client doesn't care about stealth, no IDS/IPS

**Moderate (Balanced - Medium Detection Risk)**
- Nmap timing: `-T4` (Aggressive)
- Threads: 10-20
- Minimal delays
- Use when: Standard pentest with client awareness

**Stealthy (Slowest - Low Detection Risk)**
- Nmap timing: `-T2` (Polite) or `-T1` (Sneaky)
- Threads: 1-5
- Significant delays (--scan-delay, --max-rate)
- Use when: Red team engagement, avoid detection

### Client System Health Monitoring
During scanning, periodically check:
- [ ] Target system response times
- [ ] Service availability
- [ ] Network bandwidth utilization
- [ ] Client reports no service degradation

**If any service impact detected**:
1. STOP scanning immediately
2. Notify client
3. Adjust rate limiting or reschedule
4. Document incident

---

## Tool Version Documentation
Document tool versions for report appendix:
```bash
nmap --version > "$SCAN_DIR/logs/tool-versions.txt"
gobuster version >> "$SCAN_DIR/logs/tool-versions.txt"
nikto -Version >> "$SCAN_DIR/logs/tool-versions.txt"
wpscan --version >> "$SCAN_DIR/logs/tool-versions.txt"
sqlmap --version >> "$SCAN_DIR/logs/tool-versions.txt"
hydra -h | head -n 3 >> "$SCAN_DIR/logs/tool-versions.txt"
```

---

## Next Commands in Pentest Workflow

### Immediate Next Steps:
- **`/enumerate`** - Deep enumeration of discovered services
- **`/vuln-assess`** - Analyze and prioritize discovered vulnerabilities
- **`/validate`** - Non-destructively validate exploitability

### Typical Workflow After Scanning:
1. `/scan` → Active reconnaissance and scanning (YOU ARE HERE)
2. `/enumerate` → Service and application enumeration
3. `/vuln-assess` → Vulnerability analysis and risk assessment
4. `/validate` → Proof-of-concept validation (non-destructive)
5. `/evidence` → Evidence compilation
6. `/report` → Final report generation

---

**Scan Status**: COMPLETED
**Scan Date**: [Auto-populate timestamp]
**Pentester**: [Your name]
**Target**: $ARGUMENTS
**Storage Location**: [User-specified evidence path]
**Findings Count**: [To be populated]
**Critical Findings**: [YES/NO]

---

## Safety Reminders

🟢 **AUTHORIZED TESTING** - Verify target is in-scope before scanning
🟡 **RATE LIMITING** - Avoid denial of service through excessive scanning
🟠 **MONITOR IMPACT** - Watch for service degradation during scans
🔴 **STOP IF HARM** - Halt immediately if systems are negatively affected
📸 **EVIDENCE EVERYTHING** - Screenshot every scan and finding
💾 **SAVE ALL OUTPUTS** - Preserve raw scan data for analysis and reporting
📞 **CLIENT CONTACT** - Have emergency contact ready during scanning
