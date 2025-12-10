# Compile Penetration Test Evidence

Compile and organize penetration test evidence for: **$ARGUMENTS**

## Evidence Management Protocol

### Purpose
Systematically organize all testing evidence for final report delivery and client presentation.

### Evidence Types
1. **Screenshots** - Visual proof of findings
2. **Logs** - Raw tool outputs and command logs
3. **Artifacts** - Captured files, requests, responses
4. **Videos** - Screen recordings of exploitation chains
5. **Commands** - Complete command history with timestamps
6. **Reports** - Generated scan reports and analysis

---

## User Confirmation Required

**Before compiling evidence, ask the user:**
1. **Engagement name**: Which engagement/client is this for?
2. **Evidence location**: Where is evidence currently stored?
3. **Output format**: How should evidence be packaged?
   - Option A: Encrypted archive (ZIP/7z with password)
   - Option B: Organized folders on external drive
   - Option C: Both archive + organized folders
4. **Delivery method**: How will evidence be delivered to client?
   - Client portal upload
   - Encrypted email
   - Physical media (USB drive)
   - Secure file transfer

---

## Evidence Collection Checklist

### 1. Screenshot Inventory
Verify all screenshots are collected and properly named:

**Network Scanning Evidence**:
- [ ] Nmap host discovery results
- [ ] Full TCP port scan results
- [ ] UDP port scan results
- [ ] Service version detection
- [ ] Nmap vulnerability scan results

**Web Application Evidence**:
- [ ] Gobuster directory enumeration
- [ ] Subdomain discovery
- [ ] Nikto vulnerability scan
- [ ] WPScan results (if applicable)
- [ ] Dirb scan results

**Vulnerability Validation Evidence**:
- [ ] SQL injection proof-of-concept
- [ ] XSS demonstration
- [ ] RCE command execution
- [ ] Authentication bypass
- [ ] File upload vulnerability
- [ ] Privilege escalation path
- [ ] Other critical findings

**Run Screenshot Audit**:
```bash
# Navigate to evidence directory
cd "$EVIDENCE_DIR/08-evidence/screenshots"

# Count screenshots by category
echo "Network Scan Screenshots:"
ls -1 | grep -i "nmap\|scan" | wc -l

echo "Web App Screenshots:"
ls -1 | grep -i "gobuster\|nikto\|dirb\|wpscan" | wc -l

echo "Vulnerability Screenshots:"
ls -1 | grep -i "sqli\|xss\|rce\|auth\|upload" | wc -l

echo "Total Screenshots:"
ls -1 | wc -l
```

### 2. Log File Inventory
Verify all tool outputs are saved:

**Network Scanning Logs**:
- [ ] Nmap outputs (.nmap, .xml, .gnmap)
- [ ] Service enumeration logs
- [ ] Vulnerability scan logs

**Web Application Logs**:
- [ ] Gobuster output files
- [ ] Nikto scan reports
- [ ] Dirb results
- [ ] WPScan logs
- [ ] SQLmap logs
- [ ] Burp Suite project files (if used)

**Command History**:
- [ ] All commands executed documented in `commands-used.md`
- [ ] Timestamps for all activities
- [ ] Tool versions documented

**Run Log Audit**:
```bash
# Navigate to engagement directory
cd "$ENGAGEMENT_DIR"

# Find all log files
echo "Scanning Logs:"
find 03-scanning -type f -name "*.txt" -o -name "*.xml" -o -name "*.log"

echo "Enumeration Logs:"
find 04-enumeration -type f -name "*.txt" -o -name "*.log"

echo "Validation Logs:"
find 06-exploitation/validated-vulns -type f -name "*.txt" -o -name "*.log"
```

### 3. Artifacts Inventory
Verify captured artifacts:

**HTTP Requests/Responses**:
- [ ] Vulnerable requests (SQL injection, XSS, etc.)
- [ ] Server responses showing vulnerabilities
- [ ] Session tokens or cookies (if relevant)

**Configuration Files**:
- [ ] Exposed configuration files
- [ ] .git directories (if found)
- [ ] Backup files (.bak, .old, .swp)
- [ ] Source code files (if disclosed)

**Captured Files**:
- [ ] Uploaded test files (phpinfo, test.txt)
- [ ] Downloaded files (zone.identifier evidence)
- [ ] Any other artifacts collected

### 4. Video Recordings
If screen recordings were made:
- [ ] RCE exploitation chain
- [ ] SQL injection demonstration
- [ ] Multi-step attack paths
- [ ] Authentication bypass walkthrough
- [ ] Any complex exploitation requiring video proof

**Video Naming Convention**:
```
[VULN-ID]-[DESCRIPTION]-[DATE].mp4

Examples:
VULN-001-SQL-Injection-POC-20250106.mp4
VULN-003-RCE-Exploitation-Chain-20250106.mp4
```

### 5. Commands Documentation
Verify `08-evidence/commands-used.md` is complete:

**Required Documentation**:
- [ ] Every command executed during engagement
- [ ] Timestamps for all commands
- [ ] Purpose/objective of each command
- [ ] Results/findings from each command
- [ ] Screenshot references

**Example Format**:
```markdown
# Commands Executed - [CLIENT] Penetration Test

## Network Scanning Phase
### 2025-01-06 09:30:00 EST
```bash
nmap -sn 203.0.113.0/24 -oA nmap-host-discovery
```
**Purpose**: Discover live hosts in target network
**Results**: 15 live hosts identified
**Screenshot**: 001-nmap-host-discovery-20250106-093000.png
**Output File**: 03-scanning/network/nmap-host-discovery.nmap

---

### 2025-01-06 10:15:00 EST
```bash
nmap -p- -T4 203.0.113.45 -oA nmap-full-tcp
```
**Purpose**: Full TCP port scan on web server
**Results**: 8 open ports found (22, 80, 443, 3306, 8080, 8443, 9000, 9090)
**Screenshot**: 002-nmap-full-tcp-20250106-101500.png
**Output File**: 03-scanning/network/nmap-full-tcp.xml

[Continue for all commands...]
```

### 6. Vulnerability Documentation
Verify all validated vulnerabilities are documented:

**For each finding**:
- [ ] Unique vulnerability ID (VULN-001, VULN-002, etc.)
- [ ] Severity rating (Critical/High/Medium/Low)
- [ ] CVSS score calculated
- [ ] Detailed technical writeup
- [ ] Proof of concept steps
- [ ] Evidence (screenshots, logs)
- [ ] Impact assessment
- [ ] Remediation recommendations
- [ ] Client reproduction steps

**Check vulnerability writeups**:
```bash
# List all vulnerability writeups
find 06-exploitation/validated-vulns -name "*writeup.md"

# Verify each has required sections
for file in 06-exploitation/validated-vulns/*/writeup.md; do
  echo "Checking: $file"
  grep -q "## Summary" "$file" && echo "✓ Summary"
  grep -q "## Proof of Concept" "$file" && echo "✓ POC"
  grep -q "## Evidence" "$file" && echo "✓ Evidence"
  grep -q "## Remediation" "$file" && echo "✓ Remediation"
done
```

---

## Evidence Organization Structure

### Verify Complete Engagement Folder
```
[CLIENT]_YYYY-MM-DD_[TYPE]/
├── 01-planning/
│   ├── authorization.pdf ✓
│   ├── scope.md ✓
│   ├── rules-of-engagement.md ✓
│   └── contact-sheet.md ✓
│
├── 02-reconnaissance/
│   ├── osint/ ✓
│   └── [reconnaissance outputs] ✓
│
├── 03-scanning/
│   ├── network/ ✓
│   │   ├── nmap-*.{nmap,xml,gnmap} ✓
│   │   └── service-versions.md ✓
│   └── web/ ✓
│       ├── gobuster-*.txt ✓
│       ├── nikto-*.txt ✓
│       └── [other web scan results] ✓
│
├── 04-enumeration/
│   └── [enumeration results] ✓
│
├── 05-vulnerability-analysis/
│   ├── findings/ ✓
│   │   ├── VULN-001-*.md ✓
│   │   ├── VULN-002-*.md ✓
│   │   └── ...
│   └── vulnerability-summary.md ✓
│
├── 06-exploitation/
│   ├── validated-vulns/ ✓
│   │   ├── VULN-001-SQL-Injection/ ✓
│   │   │   ├── screenshots/ ✓
│   │   │   ├── logs/ ✓
│   │   │   └── writeup.md ✓
│   │   └── ...
│   └── validation-summary.md ✓
│
├── 08-evidence/
│   ├── screenshots/ ✓ [COUNT: XX files]
│   ├── logs/ ✓ [COUNT: XX files]
│   ├── artifacts/ ✓ [COUNT: XX files]
│   ├── videos/ ✓ [COUNT: XX files]
│   ├── commands-used.md ✓
│   └── evidence-manifest.md ✓
│
├── 09-reporting/
│   ├── executive-summary.md
│   ├── technical-report.md
│   ├── remediation-roadmap.md
│   └── appendices/
│
└── README.md ✓
```

---

## Evidence Manifest Creation

Create `08-evidence/evidence-manifest.md` documenting all evidence:

```markdown
# Evidence Manifest - [CLIENT] Penetration Test

## Engagement Information
- **Client**: [Client Name]
- **Engagement Type**: [External/Internal/Web App]
- **Testing Dates**: [Start Date] to [End Date]
- **Lead Pentester**: [Name]
- **Evidence Compiled**: [Date/Time]
- **Storage Location**: [Path to evidence]

## Evidence Summary
- **Total Screenshots**: [COUNT]
- **Total Log Files**: [COUNT]
- **Total Artifacts**: [COUNT]
- **Total Videos**: [COUNT]
- **Total Findings**: [COUNT]
  - Critical: [COUNT]
  - High: [COUNT]
  - Medium: [COUNT]
  - Low: [COUNT]
  - Informational: [COUNT]

## Screenshots Inventory

### Network Scanning (001-009)
| Filename | Description | Timestamp | Related Finding |
|----------|-------------|-----------|-----------------|
| 001-nmap-host-discovery-*.png | Host discovery scan | 2025-01-06 09:30 | N/A |
| 002-nmap-full-tcp-*.png | Full TCP port scan | 2025-01-06 10:15 | N/A |
| 003-nmap-version-detection-*.png | Service version detection | 2025-01-06 11:00 | VULN-005 |
| ... | ... | ... | ... |

### Web Application Scanning (010-019)
| Filename | Description | Timestamp | Related Finding |
|----------|-------------|-----------|-----------------|
| 010-gobuster-dirs-*.png | Directory enumeration | 2025-01-06 13:00 | VULN-008 |
| 011-nikto-scan-*.png | Web vulnerability scan | 2025-01-06 14:00 | VULN-009 |
| ... | ... | ... | ... |

### Vulnerability Validation (020-099)
| Filename | Description | Timestamp | Related Finding |
|----------|-------------|-----------|-----------------|
| 020-sql-injection-poc-*.png | SQL injection proof of concept | 2025-01-06 15:30 | VULN-001 |
| 021-xss-reflected-*.png | XSS vulnerability demo | 2025-01-06 16:00 | VULN-002 |
| 022-rce-whoami-*.png | RCE command execution | 2025-01-06 16:30 | VULN-003 |
| ... | ... | ... | ... |

## Log Files Inventory

### Scanning Logs
| Filename | Tool | Size | Description |
|----------|------|------|-------------|
| nmap-host-discovery.nmap | Nmap | 2.4 KB | Host discovery output |
| nmap-full-tcp.xml | Nmap | 45 KB | Full TCP scan XML |
| gobuster-dirs.txt | Gobuster | 12 KB | Directory brute-force results |
| nikto-scan.txt | Nikto | 78 KB | Web vulnerability scan |
| ... | ... | ... | ... |

### Validation Logs
| Filename | Tool | Size | Related Finding |
|----------|------|------|-----------------|
| sqlmap-output.txt | SQLmap | 156 KB | VULN-001 |
| burp-suite-requests.xml | Burp Suite | 245 KB | Multiple findings |
| ... | ... | ... | ... |

## Artifacts Inventory
| Filename | Type | Description | Related Finding |
|----------|------|-------------|-----------------|
| vulnerable-request.txt | HTTP Request | SQL injection request | VULN-001 |
| xss-payload.txt | Payload | XSS payloads tested | VULN-002 |
| phpinfo-test.php | Uploaded File | File upload POC | VULN-007 |
| ... | ... | ... | ... |

## Video Recordings
| Filename | Duration | Description | Related Finding |
|----------|----------|-------------|-----------------|
| VULN-001-SQL-Injection-POC.mp4 | 3:24 | SQL injection exploitation | VULN-001 |
| VULN-003-RCE-Chain.mp4 | 5:12 | RCE exploitation chain | VULN-003 |
| ... | ... | ... | ... |

## Commands Log
**Complete command history**: `08-evidence/commands-used.md`
- Total commands executed: [COUNT]
- Date range: [START] to [END]
- All commands timestamped with results

## Findings Summary
| Vuln ID | Severity | Type | Status | Evidence Count |
|---------|----------|------|--------|----------------|
| VULN-001 | Critical | SQL Injection | Validated | 4 screenshots, 2 logs |
| VULN-002 | High | XSS | Validated | 3 screenshots, 1 log |
| VULN-003 | Critical | RCE | Validated | 5 screenshots, 1 video, 2 logs |
| ... | ... | ... | ... | ... |

## Chain of Custody
- **Evidence Collected By**: [Pentester Name]
- **Evidence Storage**: [External Drive SN / NAS Path / Local Path]
- **Storage Encryption**: [Yes/No - Method]
- **Hash of Evidence Archive**: [SHA256 hash if archived]
- **Evidence Transferred To**: [Client POC]
- **Transfer Date**: [Date]
- **Transfer Method**: [Secure portal / Encrypted email / Physical media]

## Verification
I certify that all evidence listed in this manifest was collected during authorized penetration testing activities conducted between [START DATE] and [END DATE] for [CLIENT NAME].

**Pentester Signature**: ___________________
**Date**: ___________________
```

---

## Evidence Packaging

### Create Encrypted Archive
If delivering evidence via encrypted archive:

```bash
# Navigate to engagement directory
cd /path/to/engagement

# Create password-protected 7-Zip archive (recommended)
7z a -p -mhe=on -t7z "[CLIENT]_Pentest_Evidence_[DATE].7z" .

# OR create password-protected ZIP (more compatible)
zip -er "[CLIENT]_Pentest_Evidence_[DATE].zip" .

# Generate SHA256 hash of archive
sha256sum "[CLIENT]_Pentest_Evidence_[DATE].7z" > evidence-archive-hash.txt
```

**Archive Password Guidelines**:
- Minimum 16 characters
- Mix of uppercase, lowercase, numbers, symbols
- Generate random password (don't use common phrases)
- Communicate password via separate secure channel (not same email as archive)

**Password Delivery Methods**:
1. Phone call to client POC
2. Separate encrypted email
3. Password manager secure share
4. In-person during debrief
5. **Never in same email as archive**

### Verify Archive Integrity
```bash
# Test archive can be extracted
7z t "[CLIENT]_Pentest_Evidence_[DATE].7z"

# Verify hash
sha256sum -c evidence-archive-hash.txt
```

### Evidence Delivery Checklist
- [ ] All evidence organized in standard folder structure
- [ ] Evidence manifest created and reviewed
- [ ] Encrypted archive created with strong password
- [ ] Archive integrity verified (test extraction)
- [ ] SHA256 hash generated
- [ ] Password communicated via secure channel
- [ ] Archive uploaded to client portal / sent via secure method
- [ ] Client confirmation of receipt received
- [ ] Backup copy retained per retention policy

---

## Evidence Quality Control

### Screenshot Quality Checks
For each screenshot, verify:
- [ ] **Clarity**: Image is clear and readable
- [ ] **Context**: URL bar, terminal prompt, or application visible
- [ ] **Timestamp**: System time visible (if relevant)
- [ ] **Full Screen**: No cropping of important information
- [ ] **Annotation**: Key areas highlighted or annotated (if needed)
- [ ] **File Size**: Not excessively large (compress if >5MB)

**Automated Quality Check**:
```bash
# Check screenshot resolution and file size
for img in 08-evidence/screenshots/*.png; do
  echo "File: $img"
  file "$img" | grep -oP '\d+\sx\s\d+'
  du -h "$img"
done

# Flag screenshots over 10MB
find 08-evidence/screenshots -name "*.png" -size +10M
```

### Log File Completeness
For each log file, verify:
- [ ] **Not Truncated**: Complete output captured
- [ ] **Readable Format**: Plain text or parseable (XML, JSON)
- [ ] **Tool Version**: Tool version documented
- [ ] **Timestamp**: Execution time documented
- [ ] **Error-Free**: No errors during tool execution (or errors explained)

### Artifact Validation
For each artifact, verify:
- [ ] **Relevance**: Directly related to a finding
- [ ] **Sanitized**: No client secrets or sensitive data exposed unnecessarily
- [ ] **Documented**: Purpose and source explained
- [ ] **Safe**: No actual malware or malicious code

---

## Evidence Sanitization

### Remove Pentester Sensitive Data
Before delivering evidence to client, sanitize:
- [ ] **Internal IP Addresses**: Remove testing system IPs (if not relevant)
- [ ] **Pentester Credentials**: Remove any personal credentials or API keys
- [ ] **Company Proprietary Info**: Remove internal tool configurations
- [ ] **Unrelated Findings**: Remove any out-of-scope discoveries (with client permission)
- [ ] **False Positives**: Remove validated false positives (document separately)

### Redact Client Secrets
If evidence contains client sensitive data:
- [ ] **Passwords**: Redact or blur actual passwords (show pattern only)
- [ ] **API Keys**: Redact actual keys (show format only)
- [ ] **Session Tokens**: Redact or partially redact
- [ ] **Personal Data**: Blur PII if captured in screenshots (GDPR/privacy compliance)
- [ ] **Database Content**: If any actual data captured, redact before delivery

**Screenshot Redaction Tools**:
- ImageMagick (command-line blurring)
- GIMP (manual editing)
- macOS Preview (annotation and redaction)
- Windows Paint/Snip & Sketch

**Example Redaction**:
```bash
# Blur sensitive area of screenshot using ImageMagick
convert screenshot.png -region 200x50+100+150 -blur 0x10 screenshot-redacted.png
```

---

## Evidence Retention

### Retention Policy
Document evidence retention per engagement agreement:
- [ ] **Client Copy**: Full evidence delivered to client
- [ ] **Pentester Backup**: Encrypted backup retained by testing team
- [ ] **Retention Duration**: [30 days / 90 days / 1 year / Per contract]
- [ ] **Secure Deletion**: Process for secure deletion after retention period
- [ ] **Legal Hold**: Process if evidence required for legal proceedings

### Backup Storage
- [ ] **Encrypted External Drive**: Labeled with engagement ID and date
- [ ] **Secure NAS**: Network storage with access controls
- [ ] **Offsite Backup**: Cloud storage with encryption (if permitted)
- [ ] **Access Log**: Document who has access to backup evidence

### Secure Deletion After Retention
When retention period expires:
```bash
# Secure file deletion (Linux/macOS)
shred -vfz -n 3 /path/to/evidence/*

# OR use secure erase tool
srm -r /path/to/evidence/

# Verify deletion
ls -la /path/to/evidence/
```

For encrypted external drives:
1. Securely wipe drive with multiple passes
2. Physically destroy drive if required by policy
3. Document destruction in evidence log

---

## Evidence Compilation Checklist

### Pre-Compilation
- [ ] All testing activities completed
- [ ] All findings validated and documented
- [ ] Screenshots organized and named properly
- [ ] Logs saved and complete
- [ ] Commands documented with timestamps
- [ ] Videos captured and edited (if applicable)

### Compilation Process
- [ ] Evidence folder structure verified
- [ ] Screenshot inventory completed
- [ ] Log file inventory completed
- [ ] Artifacts inventory completed
- [ ] Evidence manifest created
- [ ] Quality control checks performed
- [ ] Sanitization completed (pentester data removed)
- [ ] Redaction completed (client sensitive data)

### Packaging & Delivery
- [ ] Encrypted archive created
- [ ] Archive integrity verified
- [ ] SHA256 hash generated
- [ ] Password generated and documented
- [ ] Backup copy created
- [ ] Archive uploaded/delivered to client
- [ ] Password communicated separately
- [ ] Client confirmation received

### Retention
- [ ] Backup evidence stored securely
- [ ] Access controls configured
- [ ] Retention duration documented
- [ ] Deletion date scheduled

---

## Next Commands in Pentest Workflow

### Immediate Next Steps:
- **`/report`** - Generate professional penetration test report
- **`/remediate`** - Create detailed remediation roadmap

### Typical Workflow After Evidence Compilation:
1. `/evidence` → Evidence compilation and packaging (YOU ARE HERE)
2. `/report` → Technical and executive report generation
3. `/remediate` → Remediation guidance and roadmap
4. Client debrief and presentation
5. `/retest` → Post-remediation validation (future)

---

**Evidence Compilation Status**: COMPLETED
**Engagement**: $ARGUMENTS
**Compiled By**: [Pentester Name]
**Compilation Date**: [Auto-populate timestamp]
**Total Evidence Items**: [COUNT]
**Archive Created**: [YES/NO]
**Client Delivered**: [YES/NO]
**Backup Secured**: [YES/NO]

---

## CRITICAL REMINDERS

📸 **COMPLETE DOCUMENTATION** - Every finding must have evidence
🔒 **ENCRYPT EVERYTHING** - All evidence must be encrypted at rest and in transit
🧹 **SANITIZE DATA** - Remove pentester sensitive info before delivery
🔍 **QUALITY CONTROL** - Review all evidence for clarity and completeness
📋 **EVIDENCE MANIFEST** - Comprehensive inventory required
💾 **BACKUP SECURELY** - Maintain encrypted backup per retention policy
🔑 **SECURE PASSWORD** - Strong password, separate communication channel
✅ **CLIENT CONFIRMATION** - Verify client received evidence successfully
⏰ **RETENTION POLICY** - Document and follow evidence retention requirements
🗑️ **SECURE DELETION** - Properly destroy evidence after retention period

**Professional evidence management ensures report defensibility and client trust.**
