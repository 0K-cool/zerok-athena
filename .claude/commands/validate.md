# Validate Vulnerability (Non-Destructive POC)

Non-destructively validate vulnerability: **$ARGUMENTS**

## 🤖 Multi-Agent Architecture Integration

**This command dispatches the Exploitation Agent** (PTES Phase 5) - The most safety-critical agent.

**What the Exploitation Agent does:**
- ✅ Requests HITL (Human-in-the-Loop) approval BEFORE exploitation
- ✅ Non-destructive proof-of-concept validation only
- ✅ Safe exploitation techniques by vulnerability type
- ✅ Complete evidence collection (before/during/after/cleanup)
- ✅ Immediate cleanup protocols
- ✅ Logs all approval decisions to database

**Critical Safety Constraints:**
- ❌ NO data exfiltration
- ❌ NO file modification/creation/deletion
- ❌ NO backdoors or persistence
- ❌ NO privilege escalation beyond POC
- ❌ NO destructive commands

**See**: `.claude/agents/exploitation-agent.md` for complete safety protocols

## 🔌 Real-Time Monitoring Integration

**IMPORTANT**: This command logs HITL checkpoints and validation results to the Pentest Monitor dashboard.

**Claude MUST:**
1. **Request HITL approval BEFORE validation** (NEVER skip):
```python
# Use AskUserQuestion to get approval
approval = AskUserQuestion(
    questions=[{
        "question": "Approve validation for [VULNERABILITY]?",
        "header": "Validation",
        "options": [
            {
                "label": "Approve (Safe method: [DESCRIBE])",
                "description": "Execute non-destructive validation"
            },
            {
                "label": "Deny",
                "description": "Skip this validation"
            }
        ]
    }]
)
```

2. **Log HITL decision to database**:
```python
db.record_hitl_approval(
    engagement=engagement_name,
    checkpoint_type="Vulnerability Validation",
    description=f"Validation approval for: {vulnerability_title}",
    approved=user_approved,
    approver="Kelvin",
    notes=f"Method: {validation_method}"
)
```

3. **Log validation command** (only if approved):
```python
if user_approved:
    db.record_command(
        engagement=engagement_name,
        phase="Validation",
        command=validation_command,
        tool=tool_name,
        target=target,
        output=validation_result
    )

    # Update finding status to validated
    # (Dashboard will show "Validated ✅" badge)
```

**Dashboard access:** http://localhost:8080/engagement/{engagement_name} → HITL Approvals tab

---

## CRITICAL: Non-Destructive Testing Protocol

### Validation Philosophy
**OBJECTIVE**: Prove vulnerability exists WITHOUT causing harm, data loss, or service disruption.

**APPROVED METHODS**:
- ✅ Read-only database queries (SELECT statements only)
- ✅ Viewing sensitive files/directories (no modification)
- ✅ Demonstrating authentication bypass (log out immediately)
- ✅ Showing XSS with alert box (no malicious payload)
- ✅ Confirming RCE with `whoami` or `id` command (no system changes)
- ✅ Testing path traversal with read-only file access
- ✅ Proof of SSRF with internal IP disclosure
- ✅ Demonstrating IDOR by accessing own account with different ID

**PROHIBITED ACTIONS**:
- ❌ Data exfiltration or downloading sensitive information
- ❌ Creating/modifying/deleting files or database records
- ❌ Adding backdoors or persistent access mechanisms
- ❌ Privilege escalation beyond proof-of-concept
- ❌ Lateral movement to other systems
- ❌ Denial of service attacks
- ❌ Social engineering actual users
- ❌ Executing exploit code that modifies system state

### Pre-Validation Checklist
- [ ] **Authorization confirmed** for exploitation/validation testing
- [ ] **Vulnerability documented** in findings database
- [ ] **Client approval** for proof-of-concept demonstration
- [ ] **Backup/rollback plan** (if any system interaction required)
- [ ] **Emergency contact available** during validation
- [ ] **Evidence capture ready** (screenshots, video recording)
- [ ] **Test environment preferred** over production (if available)

**⚠️ STOP**: If any checklist item is not satisfied, DO NOT PROCEED.

---

## User Confirmation Required

**Before validation, ask the user:**
1. **Confirm vulnerability details**: Is this the correct vulnerability to validate?
2. **Client authorization**: Has client approved exploitation/validation testing?
3. **Environment**: Production or test/staging environment?
4. **Evidence storage**: Where should screenshots and proof be saved?
5. **Risk assessment**: Any concerns about system impact?
6. **Rollback plan**: Is there a way to undo actions if something goes wrong?

**After receiving user approval, log HITL checkpoint:**
```python
db.record_hitl_approval(
    engagement=engagement_name,
    checkpoint_type="Vulnerability Validation",
    description=f"User approved validation: {vulnerability_details}",
    approved=True,
    approver="Kelvin",
    notes=f"Environment: {environment}, Method: {validation_method}, Risk: {risk_level}"
)
```

---

## Validation Methodology by Vulnerability Type

### 1. SQL Injection (SQLi) - Non-Destructive Validation

#### Safe Validation Approach
**Goal**: Confirm SQL injection without extracting sensitive data.

**Step 1: Confirm Injection Point**
```sql
# Boolean-based blind SQLi test
' OR '1'='1' --
' OR '1'='2' --

# Expected: Different responses confirm SQL injection
```

**Step 2: Database Fingerprinting (Safe)**
```sql
# MySQL version
' UNION SELECT @@version--

# PostgreSQL version
' UNION SELECT version()--

# Microsoft SQL Server version
' UNION SELECT @@version--
```

**Step 3: Proof of Concept (Read-Only)**
```bash
# Use SQLmap with safe flags
sqlmap -u "URL" --batch --banner --current-user --current-db --risk=1 --level=1

# DO NOT USE: --dump, --dump-all, --passwords, --tables
```

**Evidence to Collect**:
- [ ] Screenshot: SQL injection confirmation (error message or diff response)
- [ ] Screenshot: Database version disclosure
- [ ] Screenshot: Current database user and database name
- [ ] **DO NOT screenshot actual data** from tables
- [ ] Document vulnerable parameter and payload used
- [ ] Save SQLmap log (with safe flags only)

**Proof of Impact (Safe)**:
- Demonstrate ability to retrieve database metadata (version, user, database name)
- Show union-based injection with SELECT statement returning known values
- **Stop before extracting any actual data**

**Documentation for Client**:
```markdown
## Vulnerability: SQL Injection in [PARAMETER]

**Severity**: Critical
**CVSS Score**: 9.8

### Proof of Concept (Non-Destructive)
1. Navigate to: [URL]
2. Enter payload: `' OR '1'='1'--`
3. Observe authentication bypass or different response
4. Confirmed database type: [MySQL/PostgreSQL/MSSQL]
5. Database user: [username from @@user]
6. Current database: [database name from current_db()]

### Impact
- Attacker can read entire database
- Potential for data exfiltration
- Authentication bypass possible
- Database modification possible (not tested)

### Remediation
- Use parameterized queries/prepared statements
- Implement input validation and sanitization
- Apply least privilege to database user
- Deploy web application firewall (WAF)

### Evidence
- Screenshot 1: Vulnerable parameter with injection payload
- Screenshot 2: Database version disclosure
- Screenshot 3: SQLmap output confirming injection

### Reproduction Steps
[Exact steps for client to reproduce]
```

---

### 2. Cross-Site Scripting (XSS) - Non-Destructive Validation

#### Safe Validation Approach
**Goal**: Demonstrate XSS without malicious impact.

**Step 1: Basic XSS Proof of Concept**
```html
<!-- Reflected XSS -->
<script>alert('XSS-POC')</script>

<!-- Stored XSS (use unique identifier) -->
<script>alert('XSS-Stored-Pentest-[YOUR_NAME]-[DATE]')</script>

<!-- DOM-based XSS -->
<img src=x onerror="alert('XSS-DOM')">
```

**Step 2: Safe Impact Demonstration**
```javascript
// Show cookie access (without exfiltration)
<script>alert(document.cookie)</script>

// Show DOM manipulation (harmless)
<script>document.body.innerHTML = "XSS Proof of Concept by [Pentester Name]"</script>

// Show session token access (display only, no exfiltration)
<script>alert('Session Token: ' + document.cookie)</script>
```

**PROHIBITED XSS Payloads**:
- ❌ Cookie stealing with remote exfiltration
- ❌ BeEF framework hooking
- ❌ Keylogging scripts
- ❌ Redirects to phishing pages
- ❌ Crypto mining scripts

**Evidence to Collect**:
- [ ] Screenshot: XSS alert box with proof-of-concept message
- [ ] Screenshot: Reflected XSS in URL with payload visible
- [ ] Screenshot: Stored XSS triggering on page load
- [ ] Screenshot: Document.cookie or session data displayed (not exfiltrated)
- [ ] Document vulnerable parameter/input field
- [ ] Provide exact reproduction steps

**Documentation**:
```markdown
## Vulnerability: Cross-Site Scripting (XSS) in [LOCATION]

**Severity**: High
**CVSS Score**: 7.2
**Type**: [Reflected / Stored / DOM-based]

### Proof of Concept
1. Navigate to: [URL]
2. Enter payload: `<script>alert('XSS-POC')</script>`
3. Observe JavaScript execution (alert box)
4. Confirmed access to: document.cookie

### Impact
- Session hijacking possible
- Account takeover risk
- Phishing attacks via trusted domain
- Malware distribution potential

### Remediation
- Implement output encoding (HTML entity encoding)
- Use Content Security Policy (CSP)
- Sanitize user input
- HTTPOnly flag on cookies
- X-XSS-Protection header

### Evidence
- Screenshot: Alert box displaying XSS execution
- Screenshot: Browser developer console showing executed script
```

---

### 3. Remote Code Execution (RCE) - EXTREME CAUTION

#### Safe Validation Approach
**Goal**: Prove command execution without system modification.

**Step 1: Safe Command Execution**
```bash
# Safe commands that don't modify system
whoami          # Show current user
id              # Show user ID and groups
pwd             # Show current directory
hostname        # Show system hostname
uname -a        # Show OS information (Linux)
ver             # Show OS version (Windows)
ipconfig        # Show network configuration (Windows)
ifconfig        # Show network configuration (Linux)
```

**Step 2: Read-Only File Access**
```bash
# Linux - Read non-sensitive files
cat /etc/passwd      # User accounts (no password hashes in modern systems)
cat /etc/os-release  # OS version information

# Windows - Read non-sensitive files
type C:\Windows\System32\drivers\etc\hosts
systeminfo
```

**PROHIBITED RCE Commands**:
- ❌ Creating files (touch, echo >, wget)
- ❌ Modifying files (rm, del, chmod, chown)
- ❌ Adding users or changing permissions
- ❌ Installing backdoors or malware
- ❌ Downloading/executing scripts
- ❌ Stopping/starting services
- ❌ Network scanning from compromised host

**Evidence to Collect**:
- [ ] Screenshot: Command injection payload in vulnerable parameter
- [ ] Screenshot: Command output showing `whoami` or `id`
- [ ] Screenshot: System information disclosure (hostname, OS version)
- [ ] Video recording: Complete exploit chain from injection to execution
- [ ] Document exact payload and injection point
- [ ] HTTP request/response showing command execution

**Documentation**:
```markdown
## Vulnerability: Remote Code Execution (RCE) in [LOCATION]

**Severity**: Critical
**CVSS Score**: 10.0

### Proof of Concept (Non-Destructive)
1. Navigate to: [URL]
2. Inject payload: `; whoami ;`
3. Observe command output in response
4. Confirmed OS: [Linux/Windows]
5. Current user: [username from whoami output]
6. Hostname: [hostname]

### Impact
- Complete system compromise possible
- Data exfiltration risk
- Lateral movement to other systems
- Installation of persistent backdoors
- Privilege escalation opportunities

### Remediation
- Input validation and sanitization
- Avoid system command execution with user input
- Use parameterized commands or safe APIs
- Implement least privilege principle
- Deploy application whitelisting
- Network segmentation

### Evidence
- Screenshot: RCE payload in vulnerable parameter
- Screenshot: Output of `whoami` command execution
- Screenshot: System information disclosure
- Video: Complete exploitation chain
```

---

### 4. Authentication Bypass - Safe Validation

#### Safe Validation Approach
**Goal**: Demonstrate authentication bypass without persistent access.

**Step 1: Bypass Authentication**
```sql
# SQL injection authentication bypass
Username: admin' OR '1'='1'--
Password: [anything]

# Logic flaw bypass
# Access admin panel directly: /admin without authentication check
```

**Step 2: Demonstrate Access (Briefly)**
- [ ] Take screenshot of successful login
- [ ] Screenshot administrative interface/dashboard
- [ ] **Log out immediately**
- [ ] **Do not modify any settings or data**
- [ ] Do not create accounts or change passwords

**Evidence to Collect**:
- [ ] Screenshot: Login page with bypass payload
- [ ] Screenshot: Successful authentication (admin dashboard)
- [ ] Screenshot: Proof of elevated privileges (admin menu)
- [ ] Screenshot: Session cookie or token (if relevant)
- [ ] Log out confirmation
- [ ] Document exact bypass method

---

### 5. File Upload Vulnerability - Non-Destructive Testing

#### Safe Validation Approach
**Goal**: Prove file upload vulnerability without uploading malicious code.

**Step 1: Test File Type Bypass**
```bash
# Upload benign test files
test.txt → test.php (rename to bypass extension check)
image.jpg with PHP code in EXIF (polyglot file)
test.php.jpg (double extension)
```

**Step 2: Safe Proof of Concept**
```php
<?php
// Safe PHP file for testing (no system commands)
phpinfo();  // Displays PHP configuration
?>

# OR even safer:
<?php
echo "File upload successful - Pentest POC by [YOUR_NAME]";
?>
```

**Step 3: Verify Upload and Access**
- Upload test file
- Access uploaded file via web browser
- Screenshot successful execution
- **Delete uploaded file immediately** if possible
- Document upload path and filename

**PROHIBITED Upload Actions**:
- ❌ Web shells with command execution
- ❌ Backdoors or persistent access tools
- ❌ Malware or exploit payloads
- ❌ Scripts that modify server files
- ❌ Exfiltration scripts

**Evidence to Collect**:
- [ ] Screenshot: File upload interface with test file
- [ ] Screenshot: Successful upload confirmation
- [ ] Screenshot: Accessing uploaded file via URL
- [ ] Screenshot: phpinfo() or safe script execution
- [ ] Screenshot: File deletion (if possible)
- [ ] Document upload path and restrictions bypassed

---

### 6. Privilege Escalation - Safe Validation

#### Safe Validation Approach
**Goal**: Demonstrate privilege escalation path without actually escalating.

**Step 1: Identify Privilege Escalation Vector**
- Misconfigured sudo permissions
- SUID binaries
- Kernel vulnerabilities
- Insecure file permissions
- Windows UAC bypass

**Step 2: Document Without Exploiting**
```bash
# Check sudo permissions (safe)
sudo -l

# List SUID binaries (safe)
find / -perm -4000 -type f 2>/dev/null

# Check kernel version (safe)
uname -r
```

**Step 3: Prove Exploitability (Without Execution)**
- Show vulnerable sudo configuration
- Demonstrate SUID binary with known exploit
- Reference CVE for kernel vulnerability
- **Do not actually escalate privileges**
- Provide POC code or reference exploit

**Evidence to Collect**:
- [ ] Screenshot: `sudo -l` output showing misconfiguration
- [ ] Screenshot: SUID binary with known vulnerability
- [ ] Screenshot: Kernel version with known exploit
- [ ] Reference to public exploit code
- [ ] Explanation of exploitation path
- [ ] **No screenshot of actual root/admin access**

---

## Evidence Organization

### Validation Evidence Folder Structure
```
06-exploitation/validated-vulns/
├── VULN-001-SQL-Injection/
│   ├── screenshots/
│   │   ├── 01-injection-point.png
│   │   ├── 02-sqlmap-confirmation.png
│   │   ├── 03-database-version.png
│   │   └── 04-current-user.png
│   ├── logs/
│   │   ├── sqlmap-output.txt
│   │   └── http-requests.txt
│   ├── payloads/
│   │   └── sql-injection-payloads.txt
│   └── VULN-001-writeup.md
│
├── VULN-002-XSS/
│   ├── screenshots/
│   │   ├── 01-xss-payload.png
│   │   ├── 02-alert-box.png
│   │   └── 03-cookie-access.png
│   ├── payloads/
│   │   └── xss-payloads.txt
│   └── VULN-002-writeup.md
│
└── validation-summary.md
```

### Screenshot Naming Convention
```
[VULN-ID]-[STEP]-[DESCRIPTION]-[TIMESTAMP].png

Examples:
VULN-001-01-sql-injection-point-20250106-153022.png
VULN-001-02-sqlmap-detection-20250106-153145.png
VULN-002-01-xss-reflected-payload-20250106-154301.png
VULN-003-01-rce-whoami-output-20250106-155512.png
```

---

## Post-Validation Activities

### 1. Document Findings
For each validated vulnerability, create detailed writeup:
```markdown
# Vulnerability Writeup: [VULN-ID] - [Vulnerability Name]

## Summary
- **Vulnerability**: [Name]
- **Severity**: [Critical/High/Medium/Low]
- **CVSS Score**: [Score]
- **Location**: [URL/IP/Service]
- **Validation Date**: [Date]
- **Validated By**: [Pentester Name]

## Technical Details
[Detailed technical explanation]

## Proof of Concept (Non-Destructive)
### Steps to Reproduce:
1. [Step 1]
2. [Step 2]
3. [Step 3]

### Payload Used:
```
[Exact payload]
```

### Expected Result:
[What should happen]

### Actual Result:
[What happened]

## Evidence
- Screenshot 1: [Description]
- Screenshot 2: [Description]
- Log file: [Filename]

## Impact Analysis
- **Confidentiality**: [Impact]
- **Integrity**: [Impact]
- **Availability**: [Impact]

## Business Impact
[Explain in business terms]

## Remediation
### Immediate Actions:
- [Quick fixes]

### Long-term Solutions:
- [Permanent fixes]

### Verification:
[How to verify fix]

## References
- CVE: [CVE-ID if applicable]
- CWE: [CWE-ID]
- OWASP: [OWASP reference]
- External resources: [Links]
```

### 2. Update Vulnerability Database
Update `05-vulnerability-analysis/vulnerability-summary.md`:
```markdown
| Vuln ID | Severity | Type | Location | Validated | Status |
|---------|----------|------|----------|-----------|--------|
| VULN-001 | Critical | SQL Injection | login.php | ✅ Yes | Open |
| VULN-002 | High | XSS | comment.php | ✅ Yes | Open |
| VULN-003 | Critical | RCE | upload.php | ✅ Yes | Open |
```

### 3. Client Notification for Critical Findings
If critical vulnerability validated:
- [ ] **Immediately notify client** per communication protocol
- [ ] Provide writeup with proof of concept
- [ ] Recommend immediate containment actions
- [ ] Offer guidance on interim mitigations
- [ ] Schedule emergency briefing if needed

---

## Validation Checklist

### Pre-Validation
- [ ] Authorization confirmed for exploitation testing
- [ ] Vulnerability details reviewed and understood
- [ ] Non-destructive approach planned
- [ ] Evidence capture ready (screenshots, screen recording)
- [ ] Emergency contact available
- [ ] Backup/rollback plan in place (if applicable)

### During Validation
- [ ] Payload tested in safe manner
- [ ] System impact monitored
- [ ] Evidence captured (screenshots, logs)
- [ ] Commands and payloads documented
- [ ] Read-only operations only (no modifications)
- [ ] **Stop immediately if any harm occurs**

### Post-Validation
- [ ] Evidence organized in structured folders
- [ ] Vulnerability writeup completed
- [ ] Client reproduction steps documented
- [ ] Remediation guidance provided
- [ ] Vulnerability database updated
- [ ] Critical findings reported to client immediately
- [ ] All uploaded files cleaned up (if applicable)
- [ ] Access logged out (if authentication bypass)

---

## Risk Assessment Matrix

| Validation Type | Risk Level | Client Approval Required | Safeguards |
|----------------|-----------|-------------------------|------------|
| SQL Injection (read-only) | Low | Standard authorization | Read-only queries, no --dump |
| XSS (alert box) | Low | Standard authorization | No exfiltration, benign payload |
| RCE (whoami) | Medium | Explicit approval | Safe commands only, no modifications |
| Auth Bypass (view only) | Medium | Explicit approval | Log out immediately, no changes |
| File Upload (phpinfo) | Medium | Explicit approval | Delete file after, no web shells |
| Privilege Escalation (identify only) | Low | Standard authorization | Document only, no actual escalation |
| Password Cracking | High | Explicit approval | Offline only, limited attempts |
| Denial of Service | HIGH | Executive approval | **GENERALLY PROHIBITED** |

---

## Next Commands in Pentest Workflow

### Immediate Next Steps:
- **`/evidence`** - Compile all validation evidence for reporting
- **`/report`** - Generate technical report with validated findings
- **`/remediate`** - Create remediation roadmap for client

### Typical Workflow After Validation:
1. `/validate` → Non-destructive vulnerability validation (YOU ARE HERE)
2. `/evidence` → Evidence compilation and organization
3. `/report` → Technical and executive report generation
4. `/remediate` → Remediation guidance and roadmap
5. `/retest` → Post-fix validation

---

**Validation Status**: COMPLETED
**Vulnerability**: $ARGUMENTS
**Validation Date**: [Auto-populate timestamp]
**Pentester**: [Your name]
**Method**: Non-Destructive POC
**Evidence Saved**: [Path]
**Client Notified**: [YES/NO]

---

## CRITICAL SAFETY REMINDERS

🔴 **NON-DESTRUCTIVE ONLY** - Validate without causing harm
🟠 **READ-ONLY OPERATIONS** - No data modification or deletion
🟡 **IMMEDIATE LOGOUT** - Don't maintain unauthorized access
🟢 **DOCUMENT EVERYTHING** - Screenshot and log all validation steps
📸 **VIDEO RECORD** - Consider recording entire validation process
💾 **SAVE EVIDENCE** - Preserve all proof-of-concept artifacts
📞 **CLIENT CONTACT** - Notify client of critical findings immediately
🧹 **CLEAN UP** - Remove test files, log out, restore state
⚠️ **STOP IF HARM** - Halt immediately if system impacted
✅ **REPEATABLE** - Client must be able to reproduce findings

**Remember: The goal is to prove vulnerability exists, not to demonstrate full exploitation.**
