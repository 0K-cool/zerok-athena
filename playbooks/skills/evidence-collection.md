# Evidence Collection Skill

## Purpose
Automate evidence collection, documentation, and chain of custody tracking for penetration testing engagements. Ensures 100% compliance with naming conventions, maintains evidence integrity, and provides real-time tracking of all findings.

## When to Use
- When documenting any penetration testing finding
- After capturing screenshots of vulnerabilities
- When logging commands and tool outputs
- During evidence compilation and manifest generation
- For chain of custody documentation

## Instructions

### 1. Screenshot Documentation
When the user provides a screenshot or mentions capturing evidence:

1. **Generate Standardized Filename:**
   Format: `[NUM]-[SEVERITY]-[CATEGORY]-[DESCRIPTION]-YYYYMMDD-HHMMSS.png`

   - NUM: Zero-padded 3-digit sequential number (001, 002, 003...)
   - SEVERITY: CRITICAL, HIGH, MEDIUM, LOW, INFO
   - CATEGORY: SQLI, XSS, RCE, AUTHBYPASS, FILEUPLOAD, MISCONFIG, INFO, etc.
   - DESCRIPTION: Brief hyphenated description (login-bypass, reflected-xss, etc.)
   - YYYYMMDD-HHMMSS: Current timestamp

   **Examples:**
   - `001-CRITICAL-SQLI-login-bypass-20251020-143022.png`
   - `002-HIGH-XSS-reflected-comment-20251020-143401.png`
   - `003-CRITICAL-RCE-command-execution-20251020-144512.png`

2. **Update Evidence Manifest:**
   Add entry to `08-evidence/evidence-manifest.md` with:
   - Finding number
   - Screenshot filename
   - Date/time captured
   - Assessor name
   - Brief description
   - Associated vulnerability ID

3. **Log in Commands Used:**
   Update `08-evidence/commands-used.md` with:
   - Exact command executed
   - Timestamp
   - Purpose/objective
   - Results/findings
   - Screenshot reference

### 2. Finding Documentation
Create a structured finding template in `05-vulnerability-analysis/` with:

```markdown
# VULN-[NUM]: [Vulnerability Title]

**Severity:** [CRITICAL/HIGH/MEDIUM/LOW]
**CVSS Score:** [Calculate or TBD]
**Discovery Date:** [YYYY-MM-DD HH:MM]
**Assessor:** [Name]

## Location
- System/URL: [Target system]
- Port/Service: [If applicable]
- Network Segment: [Internal/External]

## Description
[Technical description of the vulnerability]

## Proof of Concept
### Steps to Reproduce:
1. [Step 1]
2. [Step 2]
3. [...]

### Commands Executed:
```bash
[Command 1]
[Command 2]
```

## Evidence
- Screenshot(s): `[filename(s)]`
- Log files: `[log filenames]`
- Additional artifacts: `[artifact filenames]`

## Impact
**Confidentiality:** [High/Medium/Low/None]
**Integrity:** [High/Medium/Low/None]
**Availability:** [High/Medium/Low/None]

[Detailed impact description]

## Remediation
### Immediate Actions:
1. [Action 1]
2. [Action 2]

### Long-term Fixes:
1. [Fix 1]
2. [Fix 2]

## References
- CVE: [If applicable]
- CWE: [If applicable]
- OWASP: [If applicable]
- MITRE ATT&CK: [Technique ID]

## Testing Notes
[Any additional notes about the testing process]
```

### 3. Chain of Custody Tracking
Maintain evidence integrity documentation:

1. **Evidence Collected By:** [Assessor name]
2. **Collection Date/Time:** [Timestamp]
3. **Evidence Type:** [Screenshot, log file, artifact, etc.]
4. **Storage Location:** [Engagement folder path]
5. **Hash (if applicable):** [SHA256]
6. **Transferred To:** [Client POC]
7. **Transfer Date:** [Upon delivery]

### 4. Evidence Manifest Format

Create or update `08-evidence/evidence-manifest.md`:

```markdown
# Evidence Manifest - [Engagement Name]

**Engagement:** [Client Name]
**Assessment Period:** [Start Date] - [End Date]
**Lead Assessor:** [Name]
**Evidence Storage:** [Path]

## Evidence Index

| # | Vuln ID | Severity | Category | Filename | Date Captured | Assessor | Description |
|---|---------|----------|----------|----------|---------------|----------|-------------|
| 001 | VULN-001 | CRITICAL | SQLI | 001-CRITICAL-SQLI-login-bypass-20251020-143022.png | 2025-10-20 14:30 | K. Lomboy | SQL injection in login form |
| 002 | VULN-002 | HIGH | XSS | 002-HIGH-XSS-reflected-comment-20251020-143401.png | 2025-10-20 14:34 | K. Lomboy | Reflected XSS in comment field |
| ... | ... | ... | ... | ... | ... | ... | ... |

## Evidence Storage Structure
```
08-evidence/
├── screenshots/
│   ├── 001-CRITICAL-SQLI-login-bypass-20251020-143022.png
│   ├── 002-HIGH-XSS-reflected-comment-20251020-143401.png
│   └── ...
├── logs/
│   ├── nmap-scan-20251020.xml
│   ├── nikto-output-20251020.txt
│   └── ...
└── artifacts/
    ├── captured-request-001.txt
    ├── database-schema-002.sql
    └── ...
```

## Chain of Custody

| Evidence ID | Collected By | Date | Transferred To | Transfer Date | Notes |
|-------------|--------------|------|----------------|---------------|-------|
| 001 | K. Lomboy | 2025-10-20 | [Pending] | [TBD] | SQL injection proof |
| ... | ... | ... | ... | ... | ... |

## Evidence Integrity

All evidence stored on encrypted volume: [Path]
Evidence archive created: [Archive filename]
Archive hash (SHA256): [Hash value]
```

### 5. Command Logging Format

Update `08-evidence/commands-used.md`:

```markdown
### Date: [YYYY-MM-DD]

#### Time: [HH:MM TZ] - [Brief Description]

**Command:**
```bash
[Exact command as executed]
```

**Purpose:** [What you were trying to accomplish]

**Results:** [What happened / what was discovered]

**Screenshot Reference:** [Filename if applicable]

**Tool Version:** [Tool name and version]

**Follow-up Actions:** [Next steps based on results]

---
```

## Resources

### Templates
- `templates/finding-template.md` - Structured vulnerability documentation
- `templates/evidence-manifest.md` - Evidence tracking spreadsheet
- `templates/screenshot-metadata.json` - Metadata for screenshots

### Scripts
- `scripts/screenshot-namer.py` - Automated filename generation
- `scripts/evidence-tracker.py` - Evidence manifest updater
- `scripts/chain-of-custody.py` - Custody documentation generator

## Examples

### Example 1: SQL Injection Finding
```
User: "I found SQL injection on the login page. Captured screenshot."

Claude (using evidence-collection skill):
1. Filename: 001-CRITICAL-SQLI-login-bypass-20251020-143022.png
2. Updated evidence manifest with entry #001
3. Logged command: sqlmap -u "https://target.com/login.php" --dbs
4. Created VULN-001 finding document in 05-vulnerability-analysis/
5. Prompt: "Would you like me to calculate the CVSS score?" (trigger cvss-scoring skill)
```

### Example 2: XSS Discovery
```
User: "Found reflected XSS in comment field"

Claude (using evidence-collection skill):
1. Filename: 002-HIGH-XSS-reflected-comment-20251020-143401.png
2. Updated evidence manifest
3. Created finding template with:
   - Payload: <script>alert('XSS')</script>
   - Location: https://target.com/comments.php?id=123
   - Impact: Session hijacking possible
4. Added remediation: Input validation + output encoding
```

### Example 3: Bulk Evidence Processing
```
User: "Process all screenshots from today's testing"

Claude (using evidence-collection skill):
1. Scan 08-evidence/screenshots/ for new files
2. Generate standardized filenames for any non-compliant files
3. Update evidence manifest with all entries
4. Cross-reference with commands-used.md
5. Generate summary report of findings collected today
```

## Safety Considerations

- **Never modify original evidence files** - only rename/organize copies
- **Maintain chain of custody** - document every evidence transfer
- **Encrypt evidence storage** - protect client confidential data
- **Hash critical files** - ensure integrity verification
- **Timestamp everything** - accurate timeline reconstruction

## Integration with Other Skills

This skill works seamlessly with:
- **non-destructive-poc** - Captures POC evidence automatically
- **cvss-scoring** - Triggers CVSS calculation for new findings
- **kali-tool-parser** - Links parsed scan results to evidence
- **report-generation** - Pulls evidence for final deliverable

## Skill Metadata

**Version:** 1.0
**Created:** 2025-10-20
**Author:** Kelvin Lomboy / Cooperton
**Engagement:** SSESL Internal/External Pentest
**Status:** Active
