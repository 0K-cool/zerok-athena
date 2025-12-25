# Kali Tool Parser Skill

## Purpose
Automate parsing and analysis of Kali Linux tool outputs (Nmap, Gobuster, Nikto, SQLmap, Hydra, etc.) to identify vulnerabilities, prioritize findings, and generate actionable intelligence. Eliminates manual scan review, accelerates vulnerability identification, and ensures no critical findings are missed.

## When to Use
- After completing Nmap port scans
- After web application scanning (Nikto, Gobuster, Dirb)
- After vulnerability validation (SQLmap, Hydra)
- When processing multiple scan outputs simultaneously
- During evidence compilation phase
- For automated vulnerability prioritization

## Instructions

### 1. Nmap Scan Parser

#### Supported Nmap Output Formats
- XML format (`.xml`) - PREFERRED for programmatic parsing
- Normal format (`.nmap`) - Human-readable output
- Grepable format (`.gnmap`) - Line-based parsing

#### What to Extract from Nmap Scans

**Port and Service Information:**
- Open ports (state: open)
- Service name and version
- OS detection results
- Script scan results (NSE)

**Vulnerability Indicators:**
- Outdated service versions with known CVEs
- Default credentials detected (FTP anonymous, SMB null sessions)
- SSL/TLS vulnerabilities (Heartbleed, POODLE, etc.)
- SMB signing disabled
- Dangerous services (Telnet, FTP, TFTP on port 69)

**High-Value Targets:**
- Database ports: 3306 (MySQL), 5432 (PostgreSQL), 1433 (MSSQL), 27017 (MongoDB)
- Remote access: 22 (SSH), 3389 (RDP), 5900 (VNC)
- Web services: 80 (HTTP), 443 (HTTPS), 8080, 8443
- File sharing: 445 (SMB), 139 (NetBIOS), 21 (FTP), 2049 (NFS)
- Directory services: 389 (LDAP), 636 (LDAPS), 88 (Kerberos)

#### Nmap Parser Output Format

```markdown
## Nmap Scan Analysis: [Target]

**Scan Date:** [Timestamp]
**Scan Command:** [Exact nmap command]
**Target:** [IP/Hostname]

### Summary
- **Total Hosts Up:** X
- **Total Open Ports:** X
- **Critical Services Detected:** X
- **Potential Vulnerabilities:** X

### Open Ports & Services

| Port | Protocol | State | Service | Version | Notes |
|------|----------|-------|---------|---------|-------|
| 22 | TCP | open | ssh | OpenSSH 7.4 | Outdated (CVE-2018-15473) |
| 80 | TCP | open | http | Apache 2.4.6 | Web server (enumerate further) |
| 3306 | TCP | open | mysql | MySQL 5.5.60 | Database exposed (HIGH RISK) |

### Vulnerability Findings

**CRITICAL:**
- MySQL database exposed on 3306 (no authentication required)
- SMB signing disabled (relay attack possible)

**HIGH:**
- OpenSSH 7.4 user enumeration vulnerability (CVE-2018-15473)
- Apache 2.4.6 multiple vulnerabilities (CVE-2017-15715, CVE-2017-15710)

**MEDIUM:**
- SSL/TLS supports TLSv1.0 (deprecated protocol)
- HTTP methods PUT/DELETE enabled (potential upload)

**LOW:**
- SSH banner disclosure (OS version)
- HTTP server banner disclosure

### Recommended Next Steps
1. **Immediate:** Test MySQL anonymous access (no password)
2. **High Priority:** Enumerate HTTP with Gobuster/Nikto
3. **Medium Priority:** Test SSH user enumeration
4. **Low Priority:** Banner grab all services for version confirmation

### Evidence Files
- Nmap XML: `03-scanning/nmap/target-scan-20251020-143022.xml`
- Nmap Output: `03-scanning/nmap/target-scan-20251020-143022.nmap`
- Screenshot: `001-INFO-RECON-nmap-scan-results-20251020-143022.png`
```

### 2. Gobuster/Dirb Parser

#### What to Extract from Gobuster Scans

**Discovered Paths:**
- HTTP status codes (200, 301, 302, 403, 401)
- Path names (especially sensitive: /admin, /backup, /config, /.git)
- Response sizes (identify interesting files)

**High-Value Targets:**
- Admin panels: `/admin`, `/administrator`, `/wp-admin`, `/phpmyadmin`
- Backup files: `/backup`, `/old`, `/.git`, `/.svn`, `/db_backup.sql`
- Config files: `/config`, `/configuration.php`, `/.env`, `/web.config`
- Upload directories: `/uploads`, `/images`, `/files`, `/media`
- API endpoints: `/api`, `/v1`, `/graphql`, `/swagger`

**Potential Vulnerabilities:**
- Directory listing enabled (301/200 on directories)
- Exposed backup files (SQL dumps, zip files)
- Source control exposed (.git, .svn)
- Information disclosure (phpinfo.php, readme.html)

#### Gobuster Parser Output Format

```markdown
## Gobuster Scan Analysis: [Target URL]

**Scan Date:** [Timestamp]
**Scan Command:** [Exact gobuster command]
**Target:** [Base URL]
**Wordlist:** [Wordlist used]

### Summary
- **Total Paths Discovered:** X
- **Status 200 (OK):** X
- **Status 403 (Forbidden):** X
- **Status 301/302 (Redirects):** X
- **High-Value Targets:** X

### Discovered Paths (Prioritized)

**CRITICAL - Immediate Investigation:**
- `/admin` (Status: 200) - Admin panel accessible
- `/backup.sql` (Status: 200) - Database backup exposed
- `/.git/config` (Status: 200) - Git repository exposed

**HIGH - Test for Vulnerabilities:**
- `/uploads` (Status: 301) - File upload directory (test for unrestricted upload)
- `/api/v1` (Status: 200) - API endpoint (test for authentication)
- `/config.php.bak` (Status: 200) - Backup config file (credentials?)

**MEDIUM - Enumerate Further:**
- `/images` (Status: 301) - Image directory (directory listing?)
- `/js` (Status: 301) - JavaScript directory (source code review)
- `/includes` (Status: 403) - Include files (forced browsing?)

**LOW - Informational:**
- `/robots.txt` (Status: 200) - Disallowed paths
- `/sitemap.xml` (Status: 200) - Site structure
- `/favicon.ico` (Status: 200) - Standard resource

### Potential Vulnerabilities Identified
1. **Exposed Admin Panel** - `/admin` accessible without authentication redirect
2. **Database Backup Disclosure** - `/backup.sql` downloadable (CRITICAL)
3. **Git Repository Exposed** - `/.git/` accessible (source code disclosure)
4. **Unrestricted Upload Directory** - `/uploads` may allow arbitrary file upload

### Recommended Next Steps
1. **CRITICAL:** Download /backup.sql and analyze for credentials (NON-DESTRUCTIVE: read only)
2. **CRITICAL:** Use git-dumper to extract /.git repository contents
3. **HIGH:** Test /admin for default credentials or SQL injection
4. **HIGH:** Test /uploads for arbitrary file upload vulnerability
5. **MEDIUM:** Review /config.php.bak for hardcoded credentials

### Evidence Files
- Gobuster Output: `03-scanning/gobuster/target-dir-scan-20251020-143022.txt`
- Screenshot: `002-HIGH-MISCONFIG-exposed-admin-panel-20251020-143022.png`
```

### 3. Nikto Parser

#### What to Extract from Nikto Scans

**Server Information:**
- Web server type and version
- Detected technologies (PHP, ASP.NET, etc.)
- HTTP headers analysis

**Vulnerability Findings:**
- Outdated software versions
- Missing security headers (X-Frame-Options, CSP, etc.)
- Default files and directories
- Potential vulnerabilities (XSS, SQLi indicators)

**Security Issues:**
- Clickjacking vulnerabilities
- HTTP methods enabled (PUT, DELETE, TRACE)
- SSL/TLS misconfigurations
- Information disclosure

#### Nikto Parser Output Format

```markdown
## Nikto Scan Analysis: [Target URL]

**Scan Date:** [Timestamp]
**Scan Command:** [Exact nikto command]
**Target:** [Base URL]

### Summary
- **Total Findings:** X
- **OSVDB Vulnerabilities:** X
- **Missing Headers:** X
- **Potentially Dangerous Files:** X

### Server Information
- **Web Server:** Apache/2.4.6 (CentOS)
- **Technologies:** PHP/5.4.16, OpenSSL/1.0.2k
- **IP Address:** 192.168.1.100
- **HTTPS:** Yes (Certificate expires: 2026-01-01)

### Critical Findings

**CRITICAL:**
- OSVDB-3092: `/admin/` directory browsable (administrative interface exposed)
- OSVDB-3233: `/phpinfo.php` accessible (PHP configuration disclosure)

**HIGH:**
- Server version disclosure in HTTP headers
- Missing X-Frame-Options header (clickjacking possible)
- HTTP TRACE method enabled (XST attack possible)

**MEDIUM:**
- Missing Content-Security-Policy header
- Missing X-Content-Type-Options header
- `/backup/` directory exists (potential sensitive files)

**LOW:**
- Server allows HTTP 1.0 protocol
- Verbose error messages enabled

### Missing Security Headers
- `X-Frame-Options` - Clickjacking protection
- `Content-Security-Policy` - XSS protection
- `X-Content-Type-Options` - MIME sniffing protection
- `Strict-Transport-Security` - HTTPS enforcement

### Recommended Next Steps
1. **CRITICAL:** Enumerate `/admin/` directory with Gobuster
2. **CRITICAL:** Review `/phpinfo.php` for sensitive configuration
3. **HIGH:** Test for clickjacking on login forms
4. **HIGH:** Enumerate `/backup/` for exposed backup files
5. **MEDIUM:** Recommend security headers implementation

### Evidence Files
- Nikto Output: `03-scanning/nikto/target-scan-20251020-143022.txt`
- Screenshot: `003-CRITICAL-INFO-phpinfo-disclosure-20251020-143022.png`
```

### 4. SQLmap Parser

#### What to Extract from SQLmap Scans

**Injection Points:**
- Parameter name and injection type
- Database type and version
- Injection technique used

**Exploitation Results:**
- Database names enumerated
- Table names discovered
- Columns identified
- Data extracted (if any - SHOULD BE NONE in non-destructive testing)

**Risk Assessment:**
- Injection exploitability
- Backend DBMS type
- Potential impact

#### SQLmap Parser Output Format

```markdown
## SQLmap Analysis: [Target URL]

**Scan Date:** [Timestamp]
**Scan Command:** [Exact sqlmap command]
**Target URL:** [Full URL]
**Injection Point:** [Parameter name]

### Summary
- **Vulnerable:** YES
- **Database Type:** MySQL 5.7.33
- **Injection Type:** Error-based, UNION query-based
- **Exploitability:** HIGH

### Vulnerability Details

**Injection Parameter:** `id`
**Injection Type:** GET parameter
**Payload Example:** `id=1' UNION SELECT @@version--`

**Backend DBMS:** MySQL 5.7.33-log
**Web Application Technology:** PHP 7.4.3, Apache 2.4.41

### Enumeration Results

**Databases Discovered:**
- information_schema
- mysql
- webapp_db ⚠️ (application database)
- customer_portal ⚠️ (potentially sensitive)

**Tables in `webapp_db`:**
- users ⚠️ (likely contains credentials)
- products
- orders ⚠️ (potentially contains PII)
- sessions

**IMPORTANT:** Stopped enumeration here per non-destructive policy. Did NOT extract actual user data.

### Risk Assessment

**Severity:** CRITICAL (CVSS 9.8)

**Impact:**
- **Confidentiality:** HIGH - Full database read access possible
- **Integrity:** HIGH - UPDATE/DELETE queries possible
- **Availability:** MEDIUM - Database could be dropped

**Exploitability:** Easy (no authentication required, simple payload)

### Proof of Concept (Non-Destructive)

**Safe Payload:**
```sql
https://target.com/product.php?id=1' UNION SELECT @@version,database(),user()--
```

**Result:**
```
5.7.33-log | webapp_db | webapp_user@localhost
```

This demonstrates full SQL injection without extracting actual data.

### Recommended Remediation
1. **Immediate:** Use parameterized queries (prepared statements)
2. **Short-term:** Implement input validation and sanitization
3. **Long-term:** Web Application Firewall (WAF) deployment
4. **Best Practice:** Principle of least privilege for database user

### Evidence Files
- SQLmap Output: `06-exploitation/sqlmap/target-sqli-20251020-143022.txt`
- Screenshot: `004-CRITICAL-SQLI-product-id-parameter-20251020-143022.png`

### Next Steps
1. Document finding in vulnerability report
2. Calculate CVSS score (estimated 9.8 CRITICAL)
3. Notify client immediately per RoE
4. Prepare remediation guidance
```

### 5. Hydra Parser

#### What to Extract from Hydra Scans

**Brute Force Results:**
- Successful credentials discovered
- Number of attempts made
- Services tested (SSH, FTP, HTTP, etc.)

**Risk Assessment:**
- Weak password policy
- Account lockout failures
- Default credentials

#### Hydra Parser Output Format

```markdown
## Hydra Password Attack Analysis: [Target]

**Scan Date:** [Timestamp]
**Scan Command:** [Exact hydra command]
**Target:** [IP/Hostname]
**Service:** [SSH/FTP/HTTP/etc.]

### Summary
- **Successful Logins:** X
- **Attempts Made:** X
- **Attack Duration:** X minutes
- **Risk Level:** HIGH

### Discovered Credentials

**CRITICAL - Valid Credentials Found:**

| Service | Port | Username | Password | Notes |
|---------|------|----------|----------|-------|
| SSH | 22 | admin | admin123 | Default credentials |
| FTP | 21 | backup | Password1 | Weak password |

### Risk Assessment

**Severity:** HIGH (CVSS 8.8)

**Impact:**
- Unauthorized access to system/application
- Weak password policy enforcement
- No account lockout mechanism detected (tested 50+ attempts)

**Exploitability:** Easy (simple brute force successful)

### Recommended Remediation
1. **Immediate:** Reset compromised credentials
2. **Immediate:** Implement account lockout policy (3-5 failed attempts)
3. **Short-term:** Enforce strong password policy (length, complexity)
4. **Medium-term:** Implement multi-factor authentication (MFA)
5. **Long-term:** Monitor for brute force attempts (fail2ban, IDS/IPS)

### Evidence Files
- Hydra Output: `06-exploitation/hydra/target-ssh-bruteforce-20251020-143022.txt`
- Screenshot: `005-HIGH-AUTHBYPASS-weak-credentials-20251020-143022.png`

### Client Notification
**IMMEDIATE NOTIFICATION REQUIRED:**
These credentials have been compromised and must be reset immediately. Client POCs notified: [Timestamp]

### Next Steps
1. Report credentials to client for immediate reset
2. Test discovered credentials for privilege level
3. Document in vulnerability report
4. Calculate CVSS score
```

## Automation Scripts

### Parser Architecture

All parsers follow a standard structure:

```python
#!/usr/bin/env python3
"""
[Tool] Output Parser
Extracts vulnerability findings from [Tool] scan results
"""

import sys
import json
from datetime import datetime

class ToolParser:
    def __init__(self, scan_file):
        self.scan_file = scan_file
        self.findings = []
        self.summary = {}

    def parse(self):
        """Main parsing logic"""
        pass

    def extract_vulnerabilities(self):
        """Extract vulnerability indicators"""
        pass

    def prioritize_findings(self):
        """Sort findings by severity"""
        pass

    def generate_markdown_report(self):
        """Generate markdown output"""
        pass

    def generate_evidence_manifest_entries(self):
        """Generate evidence manifest entries"""
        pass

if __name__ == "__main__":
    parser = ToolParser(sys.argv[1])
    parser.parse()
    print(parser.generate_markdown_report())
```

### Parser Scripts Location

- `parsers/nmap_parser.py` - Nmap XML/text parser
- `parsers/gobuster_parser.py` - Gobuster output parser
- `parsers/nikto_parser.py` - Nikto scan parser
- `parsers/sqlmap_parser.py` - SQLmap output parser
- `parsers/hydra_parser.py` - Hydra credentials parser
- `parsers/enum4linux_parser.py` - Enum4linux SMB enumeration parser

## Vulnerability Mapping

### CVE Mapping

When service versions are detected, automatically map to known CVEs:

**Common Vulnerable Services:**
- Apache 2.4.6 → CVE-2017-15715, CVE-2017-15710
- OpenSSH 7.4 → CVE-2018-15473
- MySQL 5.5.x → CVE-2016-6662, CVE-2016-6663
- ProFTPD 1.3.5 → CVE-2015-3306
- PHP 5.4.x → CVE-2015-8617, CVE-2016-3074

### MITRE ATT&CK Mapping

Map findings to MITRE ATT&CK techniques:

**Reconnaissance:**
- T1046 - Network Service Scanning (Nmap)
- T1595 - Active Scanning (Gobuster, Nikto)

**Initial Access:**
- T1190 - Exploit Public-Facing Application (SQL injection, XSS)
- T1078 - Valid Accounts (Hydra credential discovery)

**Persistence:**
- T1505.003 - Web Shell (File upload vulnerabilities)

**Credential Access:**
- T1110 - Brute Force (Hydra attacks)
- T1552.001 - Credentials in Files (Exposed backup files)

### OWASP Top 10 Mapping

Map web vulnerabilities to OWASP Top 10:

- **A01:2021 - Broken Access Control** - Exposed admin panels, directory listing
- **A02:2021 - Cryptographic Failures** - Weak SSL/TLS, exposed backups
- **A03:2021 - Injection** - SQL injection, command injection
- **A04:2021 - Insecure Design** - Missing security headers
- **A05:2021 - Security Misconfiguration** - Default credentials, verbose errors
- **A06:2021 - Vulnerable Components** - Outdated software versions
- **A07:2021 - Authentication Failures** - Weak passwords, no lockout
- **A08:2021 - Software and Data Integrity** - Exposed .git repositories
- **A09:2021 - Logging Failures** - (Depends on further testing)
- **A10:2021 - SSRF** - (Depends on vulnerability discovery)

## Template Outputs

### Vulnerability Summary Template

```markdown
## Scan Summary Report

**Engagement:** [Client Name]
**Scan Date:** [Date Range]
**Assessor:** [Name]

### Executive Summary
- **Total Hosts Scanned:** X
- **Total Vulnerabilities:** X
- **Critical Findings:** X
- **High Findings:** X
- **Medium Findings:** X
- **Low/Info Findings:** X

### Critical Vulnerabilities Requiring Immediate Action
1. [VULN-001] SQL Injection on login page (CVSS 9.8)
2. [VULN-002] MySQL database exposed without authentication (CVSS 9.1)
3. [VULN-003] Default credentials on SSH (CVSS 8.8)

### Scan Coverage
- **Nmap scans completed:** X hosts
- **Gobuster scans completed:** X web applications
- **Nikto scans completed:** X web servers
- **SQLmap tests completed:** X injection points
- **Hydra attacks completed:** X services

### Recommended Immediate Actions
1. Reset all default/weak credentials discovered
2. Restrict MySQL access to authorized IPs only
3. Patch SQL injection vulnerability on login page
4. Implement Web Application Firewall (WAF)
5. Enable account lockout policies
```

## Integration with Other Skills

### Skill Chaining

**Automated Workflow:**

1. **Tool Execution** → `kali-tool-parser` → Extract findings
2. `kali-tool-parser` → `evidence-collection` → Screenshot & log results
3. `kali-tool-parser` → `non-destructive-poc` → Select safe validation payloads
4. `kali-tool-parser` → `cvss-scoring` → Calculate severity scores
5. `kali-tool-parser` → `client-communication` → Draft urgent notifications (if CRITICAL)

### Example Multi-Skill Workflow

```
User: "Run Nmap scan on 192.168.1.0/24 network"

Claude (multi-skill execution):

1. [kali-mcp] Execute: nmap -sV -sC -oA scan-results 192.168.1.0/24

2. [kali-tool-parser] Parse Nmap XML output:
   - 15 hosts discovered
   - 47 open ports total
   - 3 critical services: MySQL (3306), RDP (3389), Telnet (23)
   - 5 high-value targets identified

3. [evidence-collection] Generate:
   - Screenshot: 006-INFO-RECON-nmap-network-scan-20251020-143022.png
   - Log command in commands-used.md
   - Save scan XML to 03-scanning/nmap/

4. [kali-tool-parser] Generate vulnerability report:
   - CRITICAL: MySQL exposed on 192.168.1.50 (no auth)
   - CRITICAL: Telnet service on 192.168.1.100 (cleartext protocol)
   - HIGH: Outdated OpenSSH on 5 hosts

5. [cvss-scoring] Calculate scores:
   - MySQL exposure: CVSS 9.1 CRITICAL
   - Telnet service: CVSS 7.5 HIGH
   - OpenSSH CVE-2018-15473: CVSS 5.3 MEDIUM

6. [non-destructive-poc] Recommend next steps:
   - Test MySQL anonymous access (safe command: mysql -h 192.168.1.50 -e "SELECT version()")
   - Enumerate OpenSSH users (safe script: ssh_enum.py)

7. [client-communication] Draft notification:
   "URGENT: Critical findings discovered during network scan requiring immediate attention..."
```

## Examples

### Example 1: Nmap Scan Auto-Analysis

```
User: "Parse this Nmap scan: /path/to/scan.xml"

Claude (using kali-tool-parser):

I'll analyze the Nmap scan results and extract actionable intelligence.

[Parse Nmap XML]

**SCAN ANALYSIS COMPLETE**

**Summary:**
- 1 host up (192.168.1.100)
- 8 open ports discovered
- 2 CRITICAL vulnerabilities identified
- 3 HIGH risk services

**CRITICAL FINDINGS:**

1. **MySQL Database Exposed (Port 3306)**
   - Version: MySQL 5.5.60
   - Risk: Unauthenticated access possible
   - CVSS: 9.1 CRITICAL
   - Action: Test anonymous access immediately

2. **SMB Signing Disabled (Port 445)**
   - Risk: SMB relay attacks possible
   - CVSS: 7.5 HIGH
   - Action: Attempt SMB relay attack simulation

**HIGH RISK SERVICES:**

1. **SSH (Port 22)** - OpenSSH 7.4 (CVE-2018-15473 user enumeration)
2. **HTTP (Port 80)** - Apache 2.4.6 (multiple CVEs)
3. **RDP (Port 3389)** - Remote Desktop exposed

**RECOMMENDED NEXT STEPS:**

Priority 1 (IMMEDIATE):
1. Test MySQL anonymous access
2. Run Gobuster on HTTP (port 80)
3. Test SMB null session access

Priority 2 (HIGH):
4. Test SSH user enumeration
5. Run Nikto on web server
6. Enumerate SMB shares

Would you like me to proceed with Priority 1 testing using non-destructive methods?

**Evidence captured:**
- Screenshot: 007-INFO-RECON-nmap-analysis-20251020-143022.png
- Scan saved: 03-scanning/nmap/target-192.168.1.100-20251020-143022.xml
```

### Example 2: Gobuster Results Auto-Triage

```
User: "Parse Gobuster results: /path/to/gobuster-output.txt"

Claude (using kali-tool-parser):

I'll analyze the Gobuster directory brute-force results and prioritize findings.

[Parse Gobuster output]

**DIRECTORY ENUMERATION ANALYSIS COMPLETE**

**Summary:**
- 42 paths discovered
- 3 CRITICAL exposures
- 5 HIGH priority targets
- 12 MEDIUM interest paths

**CRITICAL EXPOSURES (Immediate Investigation):**

1. **/.git/config (Status: 200)**
   - Risk: Full source code disclosure via Git repository
   - CVSS: 7.5 HIGH (Information Disclosure)
   - Action: Extract repository with git-dumper tool

2. **/backup.sql (Status: 200, Size: 2.1MB)**
   - Risk: Database backup exposed (likely contains credentials)
   - CVSS: 9.1 CRITICAL (Credential Disclosure)
   - Action: Download and analyze (non-destructive: read only)

3. **/admin (Status: 200)**
   - Risk: Administrative interface accessible
   - CVSS: 8.8 HIGH (Unauthorized Access)
   - Action: Test for authentication bypass or default credentials

**HIGH PRIORITY TARGETS:**

1. **/uploads (Status: 301)** - Potential arbitrary file upload
2. **/api/v1 (Status: 200)** - API endpoints (test for auth)
3. **/config.php.bak (Status: 200)** - Backup config file
4. **/phpinfo.php (Status: 200)** - PHP configuration disclosure
5. **/db_backup (Status: 301)** - Backup directory

**RECOMMENDED ACTIONS:**

**IMMEDIATE (CRITICAL):**
1. Download /backup.sql for analysis
2. Extract /.git/ repository
3. Test /admin for vulnerabilities

**HIGH PRIORITY:**
4. Test /uploads for unrestricted file upload
5. Enumerate /api/v1 endpoints
6. Review /config.php.bak for hardcoded credentials

Would you like me to proceed with downloading /backup.sql using non-destructive methods (read-only)?

**Evidence captured:**
- Screenshot: 008-CRITICAL-MISCONFIG-exposed-backup-sql-20251020-143022.png
- Gobuster output: 03-scanning/gobuster/target-dir-scan-20251020-143022.txt
```

## Resources

### Parser Scripts
- `parsers/nmap_parser.py` - Nmap XML/text parser (Python)
- `parsers/gobuster_parser.py` - Gobuster output parser (Python)
- `parsers/nikto_parser.py` - Nikto scan parser (Python)
- `parsers/sqlmap_parser.py` - SQLmap output parser (Python)
- `parsers/hydra_parser.py` - Hydra credentials parser (Python)

### Mapping Databases
- `mappings/cve-database.json` - Service versions to CVE mappings
- `mappings/mitre-attack.json` - Vulnerability to ATT&CK technique mappings
- `mappings/owasp-top10.json` - Web vulnerability to OWASP mappings
- `mappings/cvss-calculator.json` - Vulnerability type to base CVSS scores

### Templates
- `templates/scan-summary.md` - Overall scan summary report
- `templates/nmap-report.md` - Nmap-specific report
- `templates/web-scan-report.md` - Web application scan report
- `templates/vulnerability-entry.md` - Individual vulnerability template

## Safety Considerations

### Parser Safety
- Never execute code found in scan outputs
- Sanitize all output before displaying to user
- Validate file paths before reading
- Handle malformed scan outputs gracefully
- Limit memory usage for large scan files

### Privacy Protection
- Redact actual passwords/credentials in parser output (show as [REDACTED])
- Sanitize PII before logging
- Encrypt scan outputs at rest
- Securely delete temporary parsing files

### Rate Limiting
- Parse scan files asynchronously to avoid blocking
- Limit concurrent parser executions
- Throttle evidence file generation

## Skill Metadata

**Version:** 1.0
**Created:** 2025-10-20
**Author:** Kelvin Lomboy / Cooperton
**Engagement:** SSESL Internal/External Pentest
**Status:** Active
**Dependencies:** Python 3.x, xmltodict, json
**Integration:** Works with evidence-collection, non-destructive-poc, cvss-scoring
