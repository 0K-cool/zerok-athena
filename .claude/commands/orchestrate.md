# Execute Full Penetration Test (Automated Multi-Agent)

Execute complete automated penetration testing workflow for: **$ARGUMENTS**

## 🤖 Master Orchestrator Agent

**This command dispatches the Orchestrator Agent** - The "brain" of the multi-agent pentesting system.

**What the Orchestrator does:**
- 🎯 **Coordinates all 7 specialized subagents** following PTES methodology
- 🔐 **Enforces authorization** at every phase (no testing without validation)
- ⚡ **Parallel execution** for maximum speed and efficiency
- 🛡️ **HITL checkpoints** before exploitation (human approval required)
- 📊 **Data aggregation** from all agents into unified intelligence
- 🚨 **Emergency stop** capability if service impact detected
- 📝 **Complete audit trail** in Pentest Monitor database

**See**: `.claude/agents/orchestrator-agent.md` for complete architecture

---

## Automated PTES Workflow

The Orchestrator executes all 7 PTES phases automatically:

```
┌─────────────────────────────────────────────────────────────┐
│              ORCHESTRATOR AGENT (Master)                    │
│  Coordinates: Planning → OSINT → Active Recon → Vuln Scan  │
│                  → Exploitation → Post-Exploit → Reporting │
└─────────────────────────────────────────────────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
        ▼                   ▼                   ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Planning   │     │ Passive     │     │   Active    │
│   Agent     │     │   OSINT     │     │    Recon    │
│ (Phase 1)   │     │ (Phase 2a)  │     │ (Phase 2b)  │
└─────────────┘     └─────────────┘     └─────────────┘
        │                   │                   │
        └───────────────────┼───────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
        ▼                   ▼                   ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│    Web      │     │ Exploitation│     │    Post-    │
│   Vuln      │     │   Agent     │     │    Exploit  │
│  Scanner    │     │ (Phase 5)   │     │  (Phase 6)  │
│ (Phase 4)   │     │             │     │             │
└─────────────┘     └─────────────┘     └─────────────┘
        │                   │                   │
        └───────────────────┼───────────────────┘
                            │
                            ▼
                    ┌─────────────┐
                    │  Reporting  │
                    │    Agent    │
                    │  (Phase 7)  │
                    └─────────────┘
```

---

## Execution Flow

### Phase 1: Planning (Gatekeeper)
**Agent**: Planning Agent
**Duration**: ~15 minutes
**Actions**:
- ✅ Validates authorization documentation
- ✅ Defines scope (in-scope vs out-of-scope)
- ✅ Extracts Rules of Engagement
- ✅ Creates engagement folder structure
- ✅ Initializes Pentest Monitor database
- 🚨 **BLOCKS all testing until authorization confirmed**

**User Interaction**: Must confirm authorization before proceeding

---

### Phase 2a: Passive OSINT (Zero Target Contact)
**Agent**: Passive OSINT Agent
**Duration**: ~30 minutes
**Actions**:
- Certificate Transparency log mining
- Passive Amass subdomain enumeration
- Email harvesting
- Shodan organization search
- GitHub secret scanning
- Google dorking

**Parallel Execution**: Runs in background while user reviews planning results

**Output**:
- Subdomains discovered: ~25-50
- Email addresses: ~15-30
- Technology stack identified
- Exposed secrets flagged

---

### Phase 2b: Active Reconnaissance
**Agent**: Active Recon Agent
**Duration**: ~45 minutes
**Actions**:
- DNS enumeration (uses OSINT subdomains)
- Multi-stage port scanning (Top 1000 → Full TCP)
- Service version detection
- Operating system fingerprinting
- Technology stack validation

**Parallel Execution**: Scans multiple targets simultaneously

**Output**:
- Asset inventory (all discovered systems)
- Open ports and services
- Vulnerable service versions (CVE cross-reference)

---

### Phase 3: Threat Modeling (Orchestrator Analysis)
**Agent**: Orchestrator (internal analysis)
**Duration**: ~10 minutes
**Actions**:
- Attack surface analysis
- Asset prioritization (web apps, databases, admin panels)
- Entry point identification
- Attack path planning

**Output**:
- High-value targets identified
- Attack scenarios modeled
- Testing strategy optimized

---

### Phase 4: Vulnerability Analysis
**Agent**: Web Vuln Scanner Agent
**Duration**: ~3 hours (parallel scanning)
**Actions**:
- Technology detection (Traditional vs SPA)
- Nikto web server vulnerability scanning
- Gobuster directory brute-forcing
- Playwright deep-dive (for SPAs)
- OWASP Top 10 coverage
- WordPress scanning (if detected)

**Parallel Execution**: All web apps scanned simultaneously

**Output**:
- All vulnerabilities identified and scored (CVSS)
- False positives eliminated
- Findings sorted by severity (Critical → Low)

---

### Phase 5: Exploitation (HITL Approval Required)
**Agent**: Exploitation Agent
**Duration**: ~2 hours
**Actions**:
- 🚨 **Request user approval** before ANY exploitation
- Non-destructive proof-of-concept validation
- Safe techniques only (read-only operations)
- Complete evidence collection
- Immediate cleanup after validation

**User Interaction**:
```
HITL Checkpoint:
┌────────────────────────────────────────────────┐
│ Approve validation for 2 CRITICAL and 5 HIGH? │
│                                                │
│ [Approve All]  [CRITICAL Only]  [Skip]        │
└────────────────────────────────────────────────┘
```

**Output**:
- Validated vulnerabilities (confirmed exploitable)
- Evidence package (screenshots, logs, POC)
- Impact assessment (business consequences)

---

### Phase 6: Post-Exploitation (Simulation Only)
**Agent**: Post-Exploitation Agent
**Duration**: ~1 hour
**Actions**:
- Privilege escalation path analysis (document only)
- Lateral movement simulation
- Attack scenario modeling
- Business impact assessment

**CRITICAL**: This is SIMULATION only - NO actual post-exploitation

**Output**:
- Attack scenarios (e.g., ransomware path)
- Business impact quantified ($2-5M estimated loss)
- Defensive recommendations

---

### Phase 7: Reporting
**Agent**: Reporting Agent
**Duration**: ~45 minutes
**Actions**:
- Executive Summary generation
- Technical Report creation
- Remediation Roadmap
- Evidence Package compilation
- Presentation Deck

**Output**:
- Complete professional deliverable package
- Ready for client delivery

---

## Performance Optimization

**Speed Enhancements**:
- ⚡ **Parallel agent execution** (OSINT + Active Recon simultaneously)
- ⚡ **Multi-target scanning** (all web apps scanned at once)
- ⚡ **Model selection** (Haiku for fast tasks, Opus for strategy)
- ⚡ **Database caching** (prevents redundant scans)

**Estimated Timeline**:
- Traditional manual pentest: **7-10 days**
- Orchestrated multi-agent: **~12 hours** (with HITL approvals)

**Speed Gain**: 5-10x faster than manual testing

---

## Safety Protocols

**Authorization Enforcement**:
```python
if not authorization_validated:
    STOP("Cannot proceed without valid authorization")

if target not in authorized_scope:
    STOP(f"Target {target} is OUT OF SCOPE")

if action in prohibited_actions:
    STOP(f"Action {action} prohibited by RoE")
```

**HITL Approval Checkpoints**:
1. **Before exploitation** - User must approve validation
2. **Before post-exploitation** - User must approve simulation
3. **Emergency stop** - User can halt at any time

**Monitoring**:
- Continuous service health monitoring
- Automatic stop if service degradation detected
- Client emergency contact on standby

---

## Integration with Pentest Monitor

**Real-Time Dashboard Updates**:
```
Engagement: ACME_2025-12-16_External
Status: Running

Phase Progress:
✅ Planning (100%)
✅ Passive OSINT (100%)
✅ Active Recon (100%)
✅ Threat Modeling (100%)
🔄 Vulnerability Analysis (65% - Scanning web.acme.com)
⏳ Exploitation (Pending HITL approval)
⏳ Post-Exploitation (Queued)
⏳ Reporting (Queued)

Findings: 18 total (2 CRITICAL, 4 HIGH, 8 MEDIUM, 4 LOW)
Commands Executed: 142
Duration: 8 hours 23 minutes
```

**Dashboard Access**: http://localhost:8080/engagement/ACME_2025-12-16_External

---

## Usage Examples

### Full Automated Workflow
```bash
/orchestrate ACME Corporation - External Pentest
```

**What happens**:
1. Validates authorization (user confirms)
2. Executes all 7 PTES phases automatically
3. Requests HITL approval before exploitation
4. Generates complete deliverable package
5. Ready for client delivery

### Resume Interrupted Engagement
```bash
/orchestrate ACME_2025-12-16_External --resume
```

**What happens**:
- Loads engagement from database
- Identifies last completed phase
- Resumes from next phase
- Preserves all previous results

### Custom Phase Selection
```bash
/orchestrate ACME_2025-12-16_External --phases "recon,scan,validate"
```

**What happens**:
- Skips planning (assumes already done)
- Runs only specified phases
- Useful for focused testing

---

## Command Line Options

```
/orchestrate [CLIENT_NAME] [OPTIONS]

OPTIONS:
  --resume              Resume interrupted engagement
  --phases PHASES       Execute only specified phases (comma-separated)
  --mode MODE           Execution mode (full_auto, hitl_checkpoints, manual_approval)
  --speed SPEED         Scan speed (stealth, moderate, aggressive)
  --skip-osint          Skip passive OSINT phase
  --skip-exploitation   Skip exploitation phase (vulnerability analysis only)
  --report-only         Generate report from existing data
```

---

## Output

The Orchestrator returns complete engagement summary:

```json
{
  "engagement_id": "ACME_2025-12-16_External",
  "status": "COMPLETE",
  "duration": "12 hours 15 minutes",
  "phases_completed": [
    "Planning",
    "Passive OSINT",
    "Active Reconnaissance",
    "Threat Modeling",
    "Vulnerability Analysis",
    "Exploitation",
    "Post-Exploitation",
    "Reporting"
  ],
  "statistics": {
    "assets_discovered": 35,
    "subdomains_found": 28,
    "findings_total": 21,
    "findings_validated": 7,
    "critical_findings": 2,
    "high_findings": 5
  },
  "deliverables": {
    "executive_summary": "Executive_Summary_ACME_2025-12-16.pdf",
    "technical_report": "Technical_Report_ACME_2025-12-16.pdf",
    "evidence_package": "Evidence_ACME_2025-12-16.zip.enc"
  }
}
```

---

## Success Criteria

- ✅ All PTES phases executed in correct order
- ✅ Authorization validated before testing
- ✅ All subagents completed successfully
- ✅ HITL approvals obtained and logged
- ✅ Complete audit trail in database
- ✅ Professional report delivered
- ✅ No unauthorized actions performed
- ✅ No service degradation caused
- ✅ Client can reproduce all findings

---

## Emergency Stop

**If anything goes wrong**:
```
🚨 EMERGENCY STOP ACTIVATED

Reason: Service degradation detected on target.acme.com
Action: All testing halted immediately
Notification: Client emergency contact called
Status: Awaiting instructions
```

**User can trigger manual stop**:
- Press Ctrl+C in terminal
- Use `/stop` command
- Dashboard "Emergency Stop" button

---

## Next Steps

After orchestrated pentest completion:
1. **Review deliverables** - Executive Summary, Technical Report
2. **Schedule client debrief** - Present findings
3. **Remediation support** - Help prioritize fixes
4. **Retest scheduling** - Use `/retest` after fixes applied
5. **Archive engagement** - Backup database and evidence

---

**Orchestration Status**: READY TO EXECUTE
**Target**: $ARGUMENTS
**Estimated Duration**: 8-12 hours (with HITL approvals)
**Phases**: All 7 PTES phases
**Agent Model**: Opus (strategic planning and coordination)
**Subagent Models**: Haiku (fast tasks), Sonnet (complex analysis)
**Safety Level**: MAXIMUM (Authorization + HITL + Emergency Stop)

---

## Professional Penetration Testing - Automated

This is professional-grade penetration testing following industry standards:
- ✅ PTES (Penetration Testing Execution Standard)
- ✅ OWASP Testing Guide methodology
- ✅ NIST SP 800-115 compliance
- ✅ CVSS v3.1 vulnerability scoring
- ✅ MITRE ATT&CK framework mapping
- ✅ Complete audit trail and evidence
- ✅ Client-repeatable methodology

**Powered by**: Multi-Agent AI Architecture
**Designed by**: Following Chinese Nation-State TTPs (defensive use)
**Speed**: 5-10x faster than manual testing
**Quality**: Professional deliverables suitable for compliance audits
**Safety**: Multiple checkpoints and human oversight

**Remember**: This is AUTHORIZED penetration testing only. Unauthorized hacking is illegal.
