# ATHENA Monitor Integration Guide

## Overview

This guide shows how to integrate the NiceGUI ATHENA Monitor with your existing VERSANT Pentest commands (`/engage`, `/scan`, `/validate`) for automated activity tracking.

## Architecture

```
┌─────────────────────────────────────┐
│   VERSANT Pentest Commands          │
│   (/engage, /scan, /validate)       │
└────────────┬────────────────────────┘
             │
             ├─ record_command()
             ├─ create_finding()
             ├─ record_hitl_approval()
             ├─ update_scan_progress()
             │
             ▼
┌─────────────────────────────────────┐
│   AthenaDatabase (SQLite)          │
│   (athena_tracker.db)              │
└────────────┬────────────────────────┘
             │
             ▼
┌─────────────────────────────────────┐
│   NiceGUI Dashboard (Real-time)     │
│   http://localhost:8080             │
└─────────────────────────────────────┘
```

## Quick Start (For Tomorrow's Engagement)

### 1. Launch Dashboard (Before Starting Pentest)

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-monitor

# Activate virtual environment (if not already)
source venv/bin/activate

# Launch dashboard
python athena_monitor.py
```

Dashboard opens at: **http://localhost:8080**

### 2. Initialize Database Connection

At the start of your engagement, Claude will initialize the database connection:

```python
from athena_monitor import AthenaDatabase

# Initialize database
db = AthenaDatabase(
    db_path="/Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-monitor/athena_tracker.db"
)
```

### 3. Use Slash Commands Normally

All your existing commands now automatically log to the dashboard:
- `/engage [CLIENT_NAME] External Penetration Test` → Logs engagement creation
- `/scan [TARGET]` → Logs commands, tracks progress
- `/validate [VULNERABILITY]` → Logs findings, HITL approvals

---

## Integration with `/engage` Command

### When: Engagement Initialization

The `/engage` command creates the engagement folder structure and verifies authorization. Database logging happens automatically:

**What Gets Logged:**
1. Engagement creation with authorization status
2. HITL checkpoint: Authorization verification
3. Initial command: Folder structure creation

**Example Flow:**
```
User: /engage TestCorp External Penetration Test

Claude executes:
1. Verify authorization (HITL checkpoint)
2. Create engagement folder structure
3. Log to database:

db.create_engagement(
    name="TestCorp_2025-12-16_External",
    client="TestCorp Inc.",
    engagement_type="External",
    scope="192.168.1.0/24, testcorp.com",
    authorization_verified=True  # After user confirms
)

db.record_hitl_approval(
    engagement="TestCorp_2025-12-16_External",
    checkpoint_type="Authorization",
    description="Pre-engagement authorization verification",
    approved=True,
    approver="Kelvin",
    notes="Signed authorization letter confirmed"
)
```

**Dashboard Shows:**
- New engagement in "Active Engagements"
- Authorization checkpoint logged
- Ready for scanning phase

---

## Integration with `/scan` Command

### When: Active Scanning (Network, Web, Services)

The `/scan` command performs comprehensive security scanning. Every command executed gets logged to prevent redundant work.

**What Gets Logged:**
1. Each scan command with tool, target, output
2. Scan progress updates (for long-running scans)
3. Preliminary findings (vulnerabilities discovered)
4. HITL checkpoint: Scope confirmation before scanning

**Example Flow:**

#### Before Executing Scan
```python
# Check if target already scanned
previous_scans = db.search_commands(
    engagement="TestCorp_2025-12-16_External",
    tool="nmap",
    target="192.168.1.10"
)

if previous_scans:
    print(f"Target already scanned at {previous_scans[0]['timestamp']}")
    # Show previous results instead of re-scanning
```

#### During Scan Execution
```python
# Record command before execution
command_id = db.record_command(
    engagement="TestCorp_2025-12-16_External",
    phase="Network Scanning",
    command="nmap -p- -T4 -sV 192.168.1.10",
    tool="nmap",
    target="192.168.1.10"
)

# Execute scan via Kali MCP
result = mcp__kali_mcp__nmap_scan(
    target="192.168.1.10",
    scan_type="-p- -T4 -sV",
    additional_args="-oA nmap-full-tcp"
)

# Update command with output and duration
# (In production, track start/end time and update record)

# Update scan progress (for real-time monitoring)
db.update_scan_progress(
    engagement="TestCorp_2025-12-16_External",
    phase="Network Scanning",
    target="192.168.1.10",
    progress=0.25,  # 25% complete
    scanned_hosts=1,
    total_hosts=4
)
```

#### After Scan Completion
```python
# Record any findings discovered
if vulnerability_detected:
    db.create_finding(
        engagement="TestCorp_2025-12-16_External",
        severity="HIGH",
        category="Outdated Software",
        title="OpenSSH 7.4 - Multiple Vulnerabilities",
        description="Outdated SSH version with known CVEs",
        target="192.168.1.10:22",
        cvss_score=7.8,
        cve_id="CVE-2024-XXXXX"
    )
```

**Dashboard Shows:**
- Real-time command history
- Scan progress bar (upcoming feature)
- Findings as they're discovered
- Prevents duplicate scanning

---

## Integration with `/validate` Command

### When: Vulnerability Validation (Non-Destructive POC)

The `/validate` command performs non-destructive proof-of-concept validation. This is the most critical phase for HITL checkpoints.

**What Gets Logged:**
1. HITL checkpoint: User approval BEFORE validation
2. Validation command and safe payload
3. Validation result (success/failure)
4. Updated finding status (validated)
5. Evidence path (screenshot locations)

**Example Flow:**

#### HITL Checkpoint (REQUIRED Before Validation)
```python
# HITL: User must approve each vulnerability validation
approval = AskUserQuestion(
    questions=[{
        "question": "Approve validation for SQL Injection in /login.php?",
        "header": "Validation",
        "options": [
            {
                "label": "Approve (Safe payload: SELECT @@version)",
                "description": "Execute read-only SQL query to confirm injection"
            },
            {
                "label": "Deny (Skip validation)",
                "description": "Do not validate this vulnerability"
            }
        ]
    }]
)

# Log HITL decision
db.record_hitl_approval(
    engagement="TestCorp_2025-12-16_External",
    checkpoint_type="Vulnerability Validation",
    description="SQL Injection in /login.php - Validation approval",
    approved=user_approved,
    approver="Kelvin",
    notes="Non-destructive validation: SELECT @@version only"
)
```

#### Validation Execution (Only If Approved)
```python
if user_approved:
    # Record validation attempt
    db.record_command(
        engagement="TestCorp_2025-12-16_External",
        phase="Validation",
        command="sqlmap -u 'https://testcorp.com/login.php' --batch --banner",
        tool="sqlmap",
        target="https://testcorp.com/login.php",
        output="MySQL 5.7.32 detected - SQL injection confirmed"
    )

    # Update finding as validated
    # (In production, would update finding record with validated=True)

    # Log evidence location
    db.create_finding(
        engagement="TestCorp_2025-12-16_External",
        severity="CRITICAL",
        category="SQL Injection",
        title="SQL Injection in /login.php (VALIDATED)",
        description="Confirmed exploitable SQL injection - MySQL 5.7.32",
        target="https://testcorp.com/login.php",
        evidence_path="08-evidence/screenshots/VULN-001-sqlmap-validation.png",
        cvss_score=9.8
    )
```

**Dashboard Shows:**
- HITL approval log (audit trail)
- Validated findings marked with green badge
- Evidence paths for each validation
- Complete command history for client reproduction

---

## Complete Workflow Example (Tomorrow's Engagement)

### Phase 1: Engagement Start (5 minutes)
```bash
# Terminal 1: Launch dashboard
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-monitor
python athena_monitor.py

# Terminal 2: Start pentest
cd /Users/kelvinlomboy/VERSANT/Projects/Pentest
/engage TestCorp External Penetration Test
```

**Claude automatically:**
- Creates engagement in database
- Logs authorization HITL checkpoint
- Creates folder structure

**Dashboard shows:**
- New engagement "TestCorp_2025-12-16_External"
- Status: Active
- Authorization: Verified ✅

---

### Phase 2: Reconnaissance & Scanning (2-4 hours)
```bash
/scan 192.168.1.0/24
```

**Claude automatically:**
- Checks if targets already scanned (search_commands)
- Records each command before execution
- Updates scan progress in real-time
- Logs preliminary findings as discovered
- Records HITL checkpoint for scope confirmation

**Dashboard shows (real-time):**
- Command history updating live
- Scan progress: "25% complete (1/4 hosts)"
- Findings appearing as discovered
- Duplicate scan prevention working

---

### Phase 3: Vulnerability Validation (1-2 hours)
```bash
/validate SQL Injection in login.php
```

**Claude automatically:**
- Requests HITL approval before validation
- Logs approval decision
- Records validation command
- Updates finding status to "validated"
- Logs evidence screenshot paths

**Dashboard shows:**
- HITL approval log entry
- Finding updated with "Validated ✅" badge
- Complete validation command history
- Evidence paths for client reproduction

---

## Advanced Features

### 1. Prevent Redundant Scanning

Before executing any scan, Claude checks if it was already done:

```python
# Check command history
previous = db.search_commands(
    engagement="TestCorp_2025-12-16_External",
    tool="nmap",
    target="192.168.1.10"
)

if previous:
    print(f"""
    🔍 Target already scanned!

    Previous scan: {previous[0]['timestamp']}
    Command: {previous[0]['command']}
    Output: {previous[0]['output']}

    Showing previous results instead of re-scanning.
    """)
    # Use previous results
else:
    # Execute new scan
    pass
```

### 2. Session Resumption After Interruption

If your pentest session is interrupted (context loss, system restart):

```python
# Resume from database
engagement_name = "TestCorp_2025-12-16_External"

# Get all previous commands
commands = db.search_commands(engagement=engagement_name, limit=100)

# Get all findings
findings = db.list_findings(engagement=engagement_name)

# Show summary
print(f"""
📊 Resuming Engagement: {engagement_name}

Commands executed: {len(commands)}
Findings discovered: {len(findings)}
Critical findings: {len([f for f in findings if f['severity'] == 'CRITICAL'])}

Last activity: {commands[0]['timestamp']}
Last command: {commands[0]['command']}

Continuing from where we left off...
""")
```

### 3. Real-Time Dashboard Monitoring

While Claude executes commands, you can watch the dashboard in your browser:

- **Main Dashboard** (`http://localhost:8080`) - Overview of all engagements
- **Engagement Details** (`http://localhost:8080/engagement/TestCorp_2025-12-16_External`) - Live findings and commands
- **Auto-refresh** - Updates every 5 seconds automatically

---

## Database Schema Reference

### Tables

**commands** - All executed commands
```sql
- id, timestamp, engagement, phase, command
- tool, target, output, status, duration_seconds
```

**findings** - Vulnerability findings
```sql
- id, timestamp, engagement, severity, category, title
- description, target, evidence_path, cvss_score, cve_id
- status, validated
```

**scan_progress** - Real-time progress tracking
```sql
- id, engagement, phase, target, progress
- status, started_at, completed_at
- total_hosts, scanned_hosts
```

**hitl_approvals** - HITL checkpoint audit log
```sql
- id, timestamp, engagement, checkpoint_type
- description, approved, approver, notes
```

**engagements** - Multi-engagement support
```sql
- id, name, client, engagement_type
- started_at, status, scope, authorization_verified
```

---

## Troubleshooting

### Dashboard Not Updating

**Problem:** Dashboard shows stale data
**Solution:**
- Refresh page manually (F5)
- Check auto-refresh is enabled (should update every 5-10 seconds)
- Verify database file path is correct

### Commands Not Logging

**Problem:** Dashboard doesn't show executed commands
**Solution:**
- Verify AthenaDatabase initialized with correct db_path
- Check database file exists: `ls -la athena_tracker.db`
- Confirm permissions: Database file must be writable

### Database File Location

**Default:** `/Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-monitor/athena_tracker.db`

**To change location:**
```python
db = AthenaDatabase(db_path="/path/to/custom/location/athena_tracker.db")
```

---

## Production Recommendations

### For Tomorrow's Engagement

1. **Launch dashboard first** - Start `athena_monitor.py` before beginning pentest
2. **Keep dashboard visible** - Monitor in separate window/screen
3. **Database backups** - Database is portable SQLite file, easy to backup
4. **Evidence storage** - Dashboard tracks evidence paths, not files themselves
5. **Client deliverable** - Database provides complete audit trail for report

### Future Enhancements (Roadmap)

See `README.md` Phase 2-4 for planned features:
- Real-time scan progress bars
- Click-to-approve HITL interface
- Evidence browser (inline screenshots)
- PDF report export
- Slack/email notifications

---

## Security Considerations

### Database Security

- **Sensitive data:** Database contains engagement details, findings, commands
- **Storage location:** Encrypted drive recommended
- **Access control:** Database file should have restricted permissions
- **Client data:** Follow VERSANT data retention policies

### Deployment

- **Local only:** Dashboard runs on localhost:8080 (not exposed to network)
- **No authentication:** Current version has no login (add if needed)
- **Secure networks:** Only run on trusted networks
- **Data residency:** Database is local SQLite file (no cloud)

---

## Support

**Documentation:**
- Main README: `tools/athena-monitor/README.md`
- This guide: `tools/athena-monitor/INTEGRATION-GUIDE.md`
- Tomorrow's workflow: `TOMORROW-QUICK-START.md`

**Automation Roadmap:**
- Long-term strategy: `AUTOMATION-ROADMAP.md`

**Questions:**
- Ask Claude (Vex) during session
- Reference NiceGUI docs: https://nicegui.io

---

**You're ready for tomorrow's engagement! 🦖⚡**

**Launch dashboard → Run `/engage` → Monitor real-time → Complete pentest with full audit trail**
