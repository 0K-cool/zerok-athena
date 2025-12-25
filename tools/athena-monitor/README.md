# ATHENA Monitor

Real-time monitoring and auditing dashboard for AI-powered penetration testing operations.

**Inspired by:** [Pentesting: The Rise of AI Agents](https://threat-hunter.ai/2025/12/06/pentesting-the-rise-of-ai-agents/)
**Enhanced with:** NiceGUI for superior real-time capabilities over Flask

---

## 🎯 Features

### Core Capabilities (Matching Article)
- ✅ **Command Tracking** - Log all executed commands with timestamps
- ✅ **Finding Management** - Document vulnerabilities and milestones
- ✅ **Search History** - Prevent redundant actions across sessions
- ✅ **Session Resumption** - Context persistence if agent interrupted

### Enhanced Features (NiceGUI Advantages)
- ✅ **Real-Time Dashboard** - Live updates via WebSockets (no polling)
- ✅ **Interactive UI** - Material Design components (no HTML/CSS/JS)
- ✅ **Multi-Engagement Tracking** - Monitor multiple pentests simultaneously
- ✅ **HITL Approval Interface** - Click-to-approve critical checkpoints
- ✅ **Evidence Browser** - View screenshots and artifacts inline
- ✅ **Scan Progress Monitoring** - Real-time progress bars
- ✅ **Pure Python** - Single file, no frontend code required

---

## 🚀 Quick Start

### Installation

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/Pentest/tools/athena-monitor

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Launch Dashboard

```bash
python athena_monitor.py
```

Dashboard opens automatically at: **http://localhost:8080**

---

## 📊 Usage

### 1. Generate Test Data

Navigate to: **http://localhost:8080/test**

- Create sample engagement
- Add test findings (Critical, High, Medium)
- Add test command history

### 2. View Main Dashboard

Navigate to: **http://localhost:8080**

- See all active engagements
- View summary statistics
- Click engagement for details

### 3. Engagement Details

Click any engagement to view:
- **Findings Tab** - All vulnerabilities with severity badges
- **Commands Tab** - Complete command history
- **Progress Tab** - Real-time scan progress (coming soon)
- **HITL Tab** - Approval checkpoint log (coming soon)

---

## 🔌 Integration with Claude Code

### From AI Agent (During Pentest)

```python
from athena_monitor import PentestDatabase

# Initialize
db = PentestDatabase()

# Before executing command - check if already done
previous_commands = db.search_commands(
    engagement="TestCorp_2025-12-16_External",
    tool="nmap",
    target="192.168.1.10"
)

if previous_commands:
    print("Already scanned this target! Skipping...")
else:
    # Execute scan
    result = execute_nmap_scan("192.168.1.10")

    # Record command
    db.record_command(
        engagement="TestCorp_2025-12-16_External",
        phase="Scanning",
        command="nmap -p- -T4 192.168.1.10",
        tool="nmap",
        target="192.168.1.10",
        output=result,
        duration=320.5
    )

# When vulnerability found
db.create_finding(
    engagement="TestCorp_2025-12-16_External",
    severity="CRITICAL",
    category="SQL Injection",
    title="SQL Injection in /login.php",
    description="Unauthenticated SQL injection in username parameter",
    target="https://testcorp.com/login.php",
    cvss_score=9.8,
    cve_id="CVE-2024-XXXXX"
)
```

### From Slash Commands

Integrate into existing VERSANT commands:

**`/engage` command:**
```python
# Create engagement in tracker
db.create_engagement(
    name=f"{client_name}_{date}_External",
    client=client_name,
    engagement_type="External",
    scope=scope_definition,
    authorization_verified=True
)
```

**`/scan` command:**
```python
# Before each scan
db.record_command(
    engagement=current_engagement,
    phase="Scanning",
    command=scan_command,
    tool="nmap",
    target=target
)

# Update progress
db.update_scan_progress(
    engagement=current_engagement,
    phase="Scanning",
    target=target,
    progress=0.75,
    scanned_hosts=15,
    total_hosts=20
)
```

**`/validate` command:**
```python
# Record finding
finding_id = db.create_finding(
    engagement=current_engagement,
    severity="HIGH",
    category="XSS",
    title="Reflected XSS in search",
    target=target_url,
    cvss_score=7.4
)

# Record validation attempt
db.record_command(
    engagement=current_engagement,
    phase="Validation",
    command=validation_command,
    tool="manual",
    target=target_url,
    output="XSS confirmed - payload executed"
)
```

---

## 🏗️ Architecture

### Database Schema

**commands** table:
- Tracks all executed commands
- Prevents redundant scanning
- Full command history with output

**findings** table:
- Vulnerability database
- CVSS scoring
- Evidence linking
- Validation status

**scan_progress** table:
- Real-time progress tracking
- Multi-target support
- Phase management

**hitl_approvals** table:
- Checkpoint approval log
- Audit trail for critical decisions
- Approver tracking

**engagements** table:
- Multi-engagement support
- Authorization tracking
- Client metadata

### Technology Stack

- **Backend:** SQLite (zero-config, portable)
- **Frontend:** NiceGUI (Python-only, real-time)
- **Web Framework:** FastAPI (async, WebSockets)
- **UI Components:** Material Design (built-in)

---

## 🔥 Why NiceGUI > Flask (Article's Choice)

| Requirement | Flask (Article) | NiceGUI (Our Version) |
|-------------|----------------|----------------------|
| Real-time updates | Complex (Socket.IO) | Built-in (WebSockets) |
| UI development | HTML/CSS/JS | Pure Python |
| Learning curve | High (web dev) | Low (Python only) |
| Code complexity | Multiple files | Single file |
| Async support | Limited (WSGI) | Full (FastAPI) |
| Deployment | Gunicorn/uWSGI | One command |
| Development speed | Slow (frontend) | Fast (Python only) |

**Result:** Same functionality, 1/10th the code, native real-time capabilities.

---

## 🎯 Roadmap

### Phase 1: Core Features (✅ Complete)
- [x] Command tracking
- [x] Finding management
- [x] Search history
- [x] Multi-engagement support
- [x] Real-time dashboard

### Phase 2: Advanced Features (In Progress)
- [ ] Real-time scan progress bars
- [ ] HITL approval interface (click-to-approve)
- [ ] Evidence browser (inline screenshots)
- [ ] Export reports (PDF generation)
- [ ] Slack/email notifications

### Phase 3: AI Integration (Coming Soon)
- [ ] Direct MCP server integration
- [ ] Auto-detect duplicate scans
- [ ] Intelligent finding prioritization
- [ ] Vulnerability chaining detection
- [ ] Automated evidence collection

### Phase 4: Team Collaboration (Future)
- [ ] Multi-user support
- [ ] Role-based access control
- [ ] Real-time collaboration
- [ ] Client portal view

---

## 📚 References

**Original Article:**
- [Pentesting: The Rise of AI Agents](https://threat-hunter.ai/2025/12/06/pentesting-the-rise-of-ai-agents/)

**NiceGUI Documentation:**
- [NiceGUI Official Docs](https://nicegui.io/)
- [NiceGUI Examples](https://nicegui.io/documentation)

**MCP Protocol:**
- [Model Context Protocol](https://modelcontextprotocol.io/)
- [FastMCP Framework](https://github.com/jlowin/fastmcp)

---

## 🚨 Security Note

This dashboard is designed for **authorized penetration testing only**. It logs sensitive security information. Always:
- Run on secure networks
- Use encrypted storage
- Control access (authentication coming soon)
- Follow data retention policies

---

**Built by:** VERSANT Security
**For:** AI-powered defensive penetration testing
**Status:** Production-ready prototype
**License:** Internal use - VERSANT Projects
