# Non-Destructive POC Validation Skill

## Purpose
Enforce non-destructive testing policies during penetration testing engagements. Provides safe proof-of-concept validation procedures, payload libraries, and safety guardrails to ensure Rules of Engagement (RoE) compliance while demonstrating exploitability without causing harm.

## When to Use
- Before executing any exploitation technique
- When validating discovered vulnerabilities
- During POC demonstration for client
- When assessing exploitability of findings
- For training/educational purposes

## Instructions

### 1. Pre-Exploitation Safety Check

Before attempting any exploitation, ALWAYS verify:

1. **Authorization Status:**
   - Is target in-scope per RoE?
   - Do we have written authorization?
   - Are we within authorized testing window?
   - Is this activity explicitly permitted?

2. **Impact Assessment:**
   - Could this cause service disruption?
   - Could this corrupt or modify data?
   - Could this trigger security controls (IPS/WAF)?
   - Is there a safer alternative approach?

3. **Backup/Rollback Plan:**
   - Can we undo this action if needed?
   - Have we documented pre-test state?
   - Do we have emergency contact available?

**RED FLAGS - STOP IMMEDIATELY:**
- 🚫 Target is production system with no dev/staging alternative
- 🚫 No clear rollback procedure available
- 🚫 Service appears unstable or degraded
- 🚫 Client emergency contact unavailable
- 🚫 Authorization unclear or expired

### 2. SQL Injection - Non-Destructive Validation

#### Safe SQLi Payloads (Read-Only)

**Basic Detection:**
```sql
' OR '1'='1
" OR "1"="1
' OR 1=1--
" OR 1=1--
' OR 1=1#
```

**Version Disclosure (MySQL):**
```sql
' UNION SELECT @@version--
' UNION SELECT version()--
' UNION SELECT user()--
' UNION SELECT database()--
```

**Version Disclosure (PostgreSQL):**
```sql
' UNION SELECT version()--
' UNION SELECT current_database()--
' UNION SELECT current_user--
```

**Version Disclosure (MSSQL):**
```sql
' UNION SELECT @@version--
' UNION SELECT DB_NAME()--
' UNION SELECT SYSTEM_USER--
```

**Version Disclosure (Oracle):**
```sql
' UNION SELECT banner FROM v$version--
' UNION SELECT user FROM dual--
```

**PROHIBITED SQLi Actions:**
- ❌ DROP, DELETE, UPDATE, INSERT statements
- ❌ Exfiltrating actual user data (passwords, PII, PHI)
- ❌ Creating new accounts or privileges
- ❌ Modifying database structure
- ❌ Executing stored procedures that write data
- ❌ `xp_cmdshell` or OS command execution

**Safe Alternative:**
- Use SQLmap with `--level 1 --risk 1` flags
- Use `--dbs` to list databases (no data extraction)
- Use `--tables` to list table names only
- Stop at version disclosure or database name
- Screenshot proof is sufficient

### 3. Cross-Site Scripting (XSS) - Non-Destructive Validation

#### Safe XSS Payloads

**Basic Alert Box (Reflected/Stored):**
```javascript
<script>alert('XSS-PENTEST-2025')</script>
<script>alert(document.domain)</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
```

**DOM-Based XSS:**
```javascript
#<script>alert('DOM-XSS')</script>
javascript:alert('XSS')
<iframe src="javascript:alert('XSS')">
```

**Proof of Impact (Safe):**
```javascript
<script>alert('Cookie: ' + document.cookie)</script>
<script>alert('Session: ' + sessionStorage.getItem('token'))</script>
```

**PROHIBITED XSS Actions:**
- ❌ Actual cookie theft/exfiltration to external server
- ❌ Session hijacking beyond demonstration
- ❌ Keylogging or credential capture
- ❌ Defacement or page modification that persists
- ❌ Phishing overlays or fake login forms
- ❌ Crypto-mining scripts
- ❌ Browser exploitation frameworks (BeEF)

**Safe Alternative:**
- Use alert boxes with unique identifiers
- Use `console.log()` instead of `alert()` for less disruption
- Screenshot the alert box as proof
- Immediately clear stored XSS payloads after testing
- Use test accounts for stored XSS validation

### 4. Remote Code Execution (RCE) - Non-Destructive Validation

#### Safe RCE Commands

**Information Disclosure Only:**

**Linux/Unix:**
```bash
whoami
id
hostname
uname -a
pwd
cat /etc/os-release
```

**Windows:**
```cmd
whoami
hostname
systeminfo
ver
echo %USERNAME%
```

**PROHIBITED RCE Actions:**
- ❌ Reverse shells or bind shells
- ❌ File creation/modification/deletion
- ❌ Privilege escalation beyond demonstration
- ❌ Lateral movement to other systems
- ❌ Installing backdoors or persistence
- ❌ Downloading/uploading malicious files
- ❌ Executing destructive commands (`rm -rf`, `del`, etc.)
- ❌ Network scanning from compromised host

**Safe Alternative:**
- Execute safe information disclosure commands only
- Screenshot command output as proof
- Log out immediately after demonstration
- Document exact command sequence
- Report finding to client immediately

### 5. Authentication Bypass - Non-Destructive Validation

#### Safe Auth Bypass Procedures

**SQL Injection Auth Bypass:**
```sql
admin' OR '1'='1'--
admin'--
' OR 1=1--
```

**Default Credentials Testing:**
- Test common defaults: admin/admin, admin/password, root/root
- Limit to 3-5 attempts per account (avoid lockout)
- Document successful credentials immediately
- Log out immediately after access gained

**Session Management Issues:**
- Test session fixation (use test session IDs)
- Test for session timeout (read-only validation)
- Test CSRF protection (use safe POC requests)

**PROHIBITED Auth Bypass Actions:**
- ❌ Brute-forcing passwords beyond 3-5 attempts
- ❌ Account enumeration that triggers lockouts
- ❌ Maintaining unauthorized access
- ❌ Accessing other users' accounts
- ❌ Modifying account privileges
- ❌ Creating backdoor accounts

**Safe Alternative:**
- Demonstrate bypass once, log out immediately
- Screenshot proof of successful login
- Report credential immediately for client reset
- Use test accounts when possible
- Stop at proof of access demonstration

### 6. File Upload Vulnerabilities - Non-Destructive Validation

#### Safe File Upload Payloads

**PHP Info Test:**
```php
<?php phpinfo(); ?>
```

**Benign Test Files:**
- `test.txt` with "PENTEST-2025" content
- Empty `.php` file with comment only
- Image file with EXIF metadata test

**Web Shell Detection (NO EXECUTION):**
```php
<?php
// PENTEST WEB SHELL DETECTION TEST
// DO NOT EXECUTE - FOR DETECTION ONLY
echo "Web shell would execute here";
?>
```

**PROHIBITED File Upload Actions:**
- ❌ Uploading actual web shells (c99, r57, WSO)
- ❌ Executing uploaded malicious files
- ❌ Uploading files that create persistence
- ❌ Uploading malware or backdoors
- ❌ Leaving uploaded files on server

**Safe Alternative:**
- Upload phpinfo() file, access once, delete immediately
- Upload test.txt, verify access, delete immediately
- Document file upload path and access method
- Use test accounts and non-production systems
- Always clean up uploaded files after testing

### 7. Command Injection - Non-Destructive Validation

#### Safe Command Injection Payloads

**Detection Payloads:**
```bash
; whoami
| whoami
` whoami `
$( whoami )
& whoami
&& whoami
```

**Time-Based Blind Detection:**
```bash
; sleep 5
| ping -c 5 127.0.0.1
```

**PROHIBITED Command Injection Actions:**
- ❌ Reverse shells: `nc -e /bin/bash`, `bash -i`, etc.
- ❌ File manipulation: `rm`, `mv`, `chmod`, etc.
- ❌ Network scanning from compromised host
- ❌ Privilege escalation commands
- ❌ Persistence mechanisms (cron jobs, startup scripts)

**Safe Alternative:**
- Use information disclosure commands only
- Time-based detection for blind injection
- Screenshot command output
- Document injection point and method
- Report immediately to client

### 8. Directory Traversal / Path Traversal - Non-Destructive Validation

#### Safe Path Traversal Payloads

**Linux:**
```
../../../etc/passwd
....//....//....//etc/passwd
..%2f..%2f..%2fetc%2fpasswd
```

**Windows:**
```
..\..\..\windows\win.ini
....\\....\\....\\windows\\win.ini
..%5c..%5c..%5cwindows%5cwin.ini
```

**Target Safe Files:**
- `/etc/passwd` (user enumeration, no password hashes)
- `/etc/os-release` (OS version)
- `C:\windows\win.ini` (benign config file)
- Application config files (read-only)

**PROHIBITED Path Traversal Actions:**
- ❌ Reading sensitive files: `/etc/shadow`, `/root/.ssh/id_rsa`
- ❌ Reading application secrets: database passwords, API keys
- ❌ Reading user private data
- ❌ Downloading entire directory structures
- ❌ Modifying files via PUT/POST methods

**Safe Alternative:**
- Read benign system files for proof
- Screenshot file contents
- Document traversal path and method
- Stop at proof of access
- Report vulnerability severity accurately

### 9. XML External Entity (XXE) - Non-Destructive Validation

#### Safe XXE Payloads

**File Disclosure (Benign Files):**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<root>
  <data>&xxe;</data>
</root>
```

**Out-of-Band Detection (Safe):**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://your-collab-server.com/xxe-test">
]>
<root>
  <data>&xxe;</data>
</root>
```

**PROHIBITED XXE Actions:**
- ❌ Reading sensitive files: `/etc/shadow`, private keys
- ❌ SSRF to internal services
- ❌ Denial of service (billion laughs attack)
- ❌ Exfiltrating actual data

**Safe Alternative:**
- Read benign files: `/etc/hostname`, `/etc/os-release`
- Use Burp Collaborator for out-of-band detection
- Document XXE vulnerability with safe proof
- Report immediately (XXE is often CRITICAL severity)

### 10. Server-Side Request Forgery (SSRF) - Non-Destructive Validation

#### Safe SSRF Payloads

**Internal Service Detection:**
```
http://127.0.0.1:80
http://localhost:8080
http://169.254.169.254/latest/meta-data/
```

**PROHIBITED SSRF Actions:**
- ❌ Accessing sensitive internal APIs
- ❌ Cloud metadata exfiltration (AWS/Azure/GCP secrets)
- ❌ Port scanning internal network
- ❌ Attacking internal services
- ❌ Reading sensitive internal data

**Safe Alternative:**
- Test for SSRF with HTTP response timing
- Use Burp Collaborator for out-of-band detection
- Test for cloud metadata access but don't exfiltrate
- Document SSRF capability with safe proof
- Report immediately (SSRF can be CRITICAL)

## Safety Guardrails

### Automated Safety Checks

Before ANY exploitation attempt, Claude MUST:

1. **Verify Authorization:**
   - Check engagement README.md for scope
   - Verify target is in authorized IP range/domain
   - Confirm testing window is active

2. **Assess Risk Level:**
   ```
   LOW RISK: Version disclosure, read-only queries
   MEDIUM RISK: Auth bypass, file upload (benign)
   HIGH RISK: RCE (info commands), SSRF detection
   CRITICAL RISK: Any action that could disrupt service
   ```

3. **Require Human Approval:**
   - MEDIUM risk: Inform user before proceeding
   - HIGH risk: Ask user for explicit confirmation
   - CRITICAL risk: Refuse and ask user to perform manually

4. **Document Everything:**
   - Trigger `evidence-collection` skill automatically
   - Log command in `commands-used.md`
   - Screenshot proof immediately
   - Update evidence manifest

### Emergency Stop Procedures

**If service disruption detected:**
1. STOP all testing immediately
2. Document exactly what was executed (last 5 commands)
3. Alert user to contact client emergency POC
4. Preserve evidence of testing state
5. Log incident in engagement folder
6. Do not resume testing until cleared by client

### Payload Library

Maintain safe payload libraries at:
- `skills/non-destructive-poc/payloads/sqli-safe.txt`
- `skills/non-destructive-poc/payloads/xss-safe.txt`
- `skills/non-destructive-poc/payloads/rce-safe.txt`
- `skills/non-destructive-poc/payloads/lfi-safe.txt`

## Procedures

### Standard POC Workflow

1. **Discovery Phase:**
   - Vulnerability identified from scan or manual testing
   - Initial severity assessment (CVSS estimation)

2. **Safety Check Phase:**
   - Verify target in scope
   - Assess risk level of validation
   - Select safe payload from library
   - Plan rollback procedure

3. **Validation Phase:**
   - Execute safe POC payload
   - Capture screenshot evidence
   - Document exact steps for repeatability
   - Assess actual impact (may differ from initial estimate)

4. **Cleanup Phase:**
   - Remove any uploaded files
   - Log out of compromised accounts
   - Clear test payloads from application
   - Verify no persistence left behind

5. **Documentation Phase:**
   - Update evidence manifest
   - Log commands used
   - Create finding template
   - Calculate CVSS score
   - Report to client if CRITICAL/HIGH

### Client Demonstration

When demonstrating findings to client:
1. Use the same safe payloads from testing
2. Narrate each step clearly
3. Show immediate impact (but not actual exploitation)
4. Demonstrate on test accounts when possible
5. Clean up immediately after demonstration

## Checklists

### Pre-Exploitation Checklist
```markdown
- [ ] Target verified in-scope per RoE
- [ ] Written authorization confirmed
- [ ] Testing window active
- [ ] Emergency contact available
- [ ] Backup/rollback plan documented
- [ ] Safe payload selected from library
- [ ] Screenshot tool ready
- [ ] Risk level assessed (LOW/MEDIUM/HIGH/CRITICAL)
- [ ] Human approval obtained (if MEDIUM/HIGH/CRITICAL)
```

### Post-Exploitation Checklist
```markdown
- [ ] Evidence captured (screenshots)
- [ ] Commands logged in commands-used.md
- [ ] Uploaded files deleted
- [ ] Compromised accounts logged out
- [ ] Test payloads cleared from application
- [ ] Evidence manifest updated
- [ ] Finding document created
- [ ] CVSS score calculated
- [ ] Client notified (if CRITICAL/HIGH)
- [ ] No persistence mechanisms left behind
```

## Integration with Other Skills

### Automatic Skill Triggering

**When vulnerability validated:**
1. `evidence-collection` - Capture screenshot and log command
2. `cvss-scoring` - Calculate severity score
3. `non-destructive-poc` (this skill) - Ensure safe validation
4. `report-generation` - Add to findings list

### Skill Chaining Example

```
User: "Found SQL injection on login page"

Claude (multi-skill workflow):
1. [non-destructive-poc] - Select safe SQLi payload: ' UNION SELECT @@version--
2. [evidence-collection] - Generate filename: 001-CRITICAL-SQLI-login-bypass-20251020-143022.png
3. [kali-tool-parser] - Run SQLmap with safe flags: --level 1 --risk 1 --dbs
4. [evidence-collection] - Log SQLmap command in commands-used.md
5. [cvss-scoring] - Calculate CVSS: 9.8 (CRITICAL)
6. [evidence-collection] - Create finding document: VULN-001
7. [client-communication] - Draft immediate notification to client POC
```

## Examples

### Example 1: SQL Injection Validation

```
User: "I found SQL injection on https://target.com/login.php in the username field"

Claude (using non-destructive-poc skill):

**SAFETY CHECK:**
✅ Target https://target.com is in-scope per RoE (verified in README.md)
✅ Testing window active: October 20-24, 2025
✅ Risk level: MEDIUM (read-only query)
✅ Safe payload selected: ' UNION SELECT @@version--

**VALIDATION:**
I'll test this with a safe read-only payload to confirm exploitability:

Payload: admin' UNION SELECT @@version--

[Execute SQLmap with safe flags]
```bash
sqlmap -u "https://target.com/login.php" --data "username=admin&password=test" --level 1 --risk 1 --dbs --batch
```

**RESULT:**
Database version disclosed: MySQL 5.7.33
Available databases: information_schema, mysql, webapp_db

**IMPACT:** Confirms SQL injection vulnerability allowing database enumeration

**EVIDENCE:** Screenshot captured as 001-CRITICAL-SQLI-login-bypass-20251020-143022.png

**NEXT STEPS:**
- Stop testing here (no data exfiltration)
- Document finding with CVSS score
- Report immediately to client (CRITICAL severity)
```

### Example 2: XSS Validation (Reflected)

```
User: "Comment field might be vulnerable to XSS"

Claude (using non-destructive-poc skill):

**SAFETY CHECK:**
✅ Target in-scope
✅ Risk level: LOW (alert box only)
✅ Safe payload: <script>alert('XSS-PENTEST-2025')</script>

**VALIDATION:**
Testing with benign alert payload:

Comment: <script>alert('XSS-PENTEST-2025')</script>

[Submit comment and observe browser]

**RESULT:**
Alert box executed with message "XSS-PENTEST-2025"
Confirms reflected XSS vulnerability

**IMPACT:** Attacker could execute arbitrary JavaScript (session hijacking, phishing)

**EVIDENCE:** Screenshot captured as 002-HIGH-XSS-reflected-comment-20251020-143401.png

**CLEANUP:**
- Alert dismissed
- Test comment deleted
- No persistence

**NEXT STEPS:**
- Document finding with CVSS score (likely 6.1 MEDIUM)
- Test for stored XSS variant
- Check for CSP headers
```

### Example 3: RCE Validation (REFUSED - Too Risky)

```
User: "I think I can get RCE on this production web server via file upload"

Claude (using non-destructive-poc skill):

**SAFETY CHECK:**
⚠️ Target is PRODUCTION system
⚠️ No dev/staging alternative available
⚠️ Risk level: HIGH (RCE on production)
⚠️ Service disruption possible

**RECOMMENDATION:**
I cannot safely validate RCE on a production system without significant risk.

**SAFER ALTERNATIVES:**
1. Test file upload with phpinfo() file only
2. Upload test.txt and verify access
3. Document upload path and file type bypass
4. Request client provide staging environment for RCE testing
5. Rate as "Potential RCE" in report with caveat about validation risk

Would you like me to proceed with the safer phpinfo() validation instead?
```

## Resources

### Payload Libraries
- `payloads/sqli-safe.txt` - Safe SQL injection payloads
- `payloads/xss-safe.txt` - Benign XSS payloads
- `payloads/rce-safe.txt` - Information disclosure commands
- `payloads/lfi-safe.txt` - Safe path traversal targets
- `payloads/xxe-safe.txt` - Benign XXE payloads

### Procedures
- `procedures/sqli-validation.md` - Step-by-step SQL injection testing
- `procedures/xss-validation.md` - XSS testing procedures
- `procedures/rce-validation.md` - RCE safe validation
- `procedures/file-upload-validation.md` - File upload testing

### Checklists
- `checklists/pre-exploitation.md` - Safety checks before exploitation
- `checklists/post-exploitation.md` - Cleanup verification
- `checklists/client-demo.md` - Live demonstration safety

### References
- OWASP Testing Guide v4.2
- PTES Technical Guidelines
- NIST SP 800-115 Section 7 (Exploitation)
- PCI DSS Penetration Testing Guidance

## Safety Considerations

### Legal Protection
- ALWAYS verify written authorization before exploitation
- Document authorization in engagement folder
- Stop immediately if authorization questioned
- Have "get-out-of-jail letter" accessible during testing
- Maintain professional liability insurance

### Ethical Boundaries
- Non-destructive testing is NOT optional
- Client trust depends on safe validation
- Err on side of caution when uncertain
- When in doubt, ask client for guidance
- Refuse requests that violate RoE

### Technical Safety
- Test on staging/dev when available
- Use rate limiting to avoid service impact
- Monitor for service degradation
- Have rollback plan for every action
- Document pre-test state for restoration

## Skill Metadata

**Version:** 1.0
**Created:** 2025-10-20
**Author:** Kelvin Lomboy / Cooperton
**Engagement:** SSESL Internal/External Pentest
**Status:** Active
**Risk Level:** HIGH (Controls dangerous actions)
**Priority:** CRITICAL (Safety guardrail)
