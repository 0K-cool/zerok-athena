# ATHENA Monitor - Quick Start (Tomorrow's Engagement)

## 🚀 5-Minute Setup

### Step 1: Install Dependencies (One-Time Setup)

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-monitor

# Create virtual environment (if not exists)
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

**Expected output:**
```
✅ Successfully installed nicegui-1.4.x
```

---

### Step 2: Launch Dashboard (Before Starting Pentest)

```bash
# Activate virtual environment
source venv/bin/activate

# Launch dashboard (opens browser automatically)
python athena_monitor.py
```

**Dashboard URL:** http://localhost:8080

**Keep this terminal running!** Dashboard updates in real-time as you work.

---

### Step 3: Start Your Pentest (New Terminal)

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/Pentest

# Start engagement (Claude will auto-log to dashboard)
/engage TestCorp External Penetration Test
```

**What happens automatically:**
- ✅ Engagement created in database
- ✅ Authorization checkpoint logged
- ✅ Dashboard shows new engagement

---

### Step 4: Execute Scanning (Dashboard Updates Live)

```bash
# Run scans (Claude checks for duplicates, logs all commands)
/scan 192.168.1.0/24
```

**Dashboard shows in real-time:**
- Command history as scans execute
- Findings as vulnerabilities discovered
- Prevents duplicate scanning (checks database first)

---

### Step 5: Validate Findings (HITL Checkpoints Logged)

```bash
# Validate vulnerabilities (Claude requests approval, logs decision)
/validate SQL Injection in login.php
```

**What happens:**
1. Claude requests your approval (HITL checkpoint)
2. Your approval/denial logged to database
3. Validation executed (if approved)
4. Finding marked as "Validated ✅" in dashboard

---

## Dashboard Features

### Main Dashboard (http://localhost:8080)
- Overview of all active engagements
- Quick stats (Critical findings, High findings, Total)
- Click engagement to view details

### Engagement Details (http://localhost:8080/engagement/[NAME])
- **Findings Tab** - All vulnerabilities with severity badges
- **Commands Tab** - Complete command history
- **Progress Tab** - Real-time scan progress (coming soon)
- **HITL Tab** - Approval checkpoint log

### Auto-Refresh
- Main dashboard: Every 10 seconds
- Engagement details: Every 5 seconds
- Manual refresh: Click "Refresh" button

---

## How Integration Works

### Automatic Logging

When you use slash commands, Claude automatically:

**`/engage` command:**
```python
✅ Creates engagement in database
✅ Logs authorization HITL checkpoint
✅ Records engagement setup
```

**`/scan` command:**
```python
✅ Checks if target already scanned (prevents duplicates)
✅ Logs each scan command before execution
✅ Updates scan progress in real-time
✅ Logs findings as discovered
```

**`/validate` command:**
```python
✅ Requests HITL approval BEFORE validation
✅ Logs approval decision to database
✅ Records validation command and result
✅ Marks finding as validated
```

---

## Troubleshooting

### Dashboard Not Opening

**Problem:** `python athena_monitor.py` fails
**Solution:**
```bash
# Verify virtual environment active
which python
# Should show: .../athena-monitor/venv/bin/python

# If not, activate:
source venv/bin/activate

# Reinstall dependencies if needed:
pip install -r requirements.txt
```

### Database Not Updating

**Problem:** Commands executed but dashboard doesn't show them
**Solution:**
- Click "Refresh" button on dashboard
- Check database file exists:
  ```bash
  ls -la athena_tracker.db
  ```
- Verify auto-refresh enabled (should update every 5-10 seconds)

### Port Already in Use

**Problem:** `Address already in use: 8080`
**Solution:**
```bash
# Kill existing process
lsof -ti:8080 | xargs kill -9

# Or change port in athena_monitor.py (line 614):
ui.run(port=8081, ...)
```

---

## File Locations

**Dashboard script:**
```
/Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-monitor/athena_monitor.py
```

**Database file:**
```
/Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-monitor/athena_tracker.db
```

**Virtual environment:**
```
/Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-monitor/venv/
```

---

## What to Watch During Engagement

### Real-Time Indicators

**Dashboard shows:**
- ✅ Live command history (updates as Claude executes scans)
- ✅ Findings discovered (appears immediately when vulnerability found)
- ✅ HITL checkpoints (logs every time you approve/deny action)
- ✅ Duplicate prevention (Claude checks database before re-scanning)

**What to monitor:**
1. **Commands Tab** - Verify scans executing correctly
2. **Findings Tab** - Track vulnerabilities as discovered
3. **HITL Tab** - Audit trail of all approvals

---

## After Engagement Complete

### Database is Portable

```bash
# Copy database for backup/archive
cp athena_tracker.db ~/backups/TestCorp_2025-12-16_athena_tracker.db

# Database contains complete audit trail:
- All commands executed
- All findings discovered
- All HITL approvals
- Complete engagement history
```

### Use for Reporting

Database provides:
- Command history for "Methodology" section
- Finding details for "Technical Findings" section
- HITL log for "Audit Trail" appendix
- Timeline reconstruction if needed

---

## Quick Commands Reference

### Dashboard Operations
```bash
# Launch dashboard
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-monitor
source venv/bin/activate
python athena_monitor.py

# Generate test data (for testing)
# Navigate to: http://localhost:8080/test
```

### Pentest Operations (Claude Auto-Logs)
```bash
# All standard commands work normally
/engage [CLIENT] [TYPE]
/scan [TARGET]
/validate [VULNERABILITY]

# Claude handles database logging automatically
```

---

## Key Benefits for Tomorrow

1. **No Duplicate Work** - Dashboard tracks what's been scanned
2. **Real-Time Visibility** - See progress as it happens
3. **Complete Audit Trail** - Every command, finding, approval logged
4. **Session Resumption** - If interrupted, resume from database
5. **Client Deliverable** - Database shows complete methodology

---

## Test Before Engagement (Recommended)

```bash
# 1. Launch dashboard
python athena_monitor.py

# 2. Generate test data
# Navigate to: http://localhost:8080/test
# Click "Create Engagement"
# Click "Add Test Findings"
# Click "Add Test Commands"

# 3. Verify dashboard shows test data
# Navigate to: http://localhost:8080
# Click on "TestCorp_2025-12-16_External"

# 4. If everything looks good, you're ready!
```

---

**You're ready for tomorrow! Launch dashboard → Start engagement → Monitor real-time → Complete pentest with full audit trail** 🦖⚡

**Questions?** Ask Claude (Vex) during your session.

**Full Documentation:**
- `README.md` - Complete feature documentation
- `INTEGRATION-GUIDE.md` - Detailed integration instructions
- `TOMORROW-QUICK-START.md` - Tomorrow's engagement workflow
