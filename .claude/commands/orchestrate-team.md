# Execute Full Penetration Test (Agent Teams Mode)

Execute a complete automated penetration testing workflow using **Claude Code Agent Teams** for: **$ARGUMENTS**

## Agent Teams Orchestration

This command uses Claude Code's Agent Teams feature for **peer-to-peer multi-agent coordination** — a significant upgrade over the hub-and-spoke subagent model used by `/orchestrate`.

**Key advantages over `/orchestrate`:**
- Agents communicate directly with each other (not just through orchestrator)
- True parallel execution across independent sessions
- Shared task list with dependency tracking
- Split-pane visibility into all agent activity

---

## Step 1: Initialize Team

Create the ATHENA pentest team:

```
TeamCreate:
  team_name: "athena-pentest"
  description: "ATHENA Penetration Test - $ARGUMENTS"
  agent_type: "orchestrator"
```

---

## Step 2: Create PTES Task List

Create all tasks with proper dependencies. The team lead creates these, teammates claim and complete them.

### Core PTES Pipeline Tasks

**TASK: Validate authorization and create engagement structure**
- Owner: planner
- Description: PTES Phase 1. Verify signed authorization letter, define scope (in-scope vs out-of-scope), extract Rules of Engagement, create engagement folder structure, verify tool connectivity. BLOCKS all other testing.
- ActiveForm: Validating authorization and setting up engagement

**TASK: Execute passive OSINT reconnaissance**
- Owner: recon-passive
- Blocked by: authorization task
- Description: PTES Phase 2a. ZERO target contact. Certificate Transparency mining, passive Amass, Shodan org search, email harvesting, GitHub secret scanning, Google dorking. Use GAU for passive URL discovery. Report discovered subdomains, emails, tech stack to recon-active via SendMessage.
- ActiveForm: Gathering passive intelligence

**TASK: Execute active reconnaissance**
- Owner: recon-active
- Blocked by: passive OSINT task
- Description: PTES Phase 2b. Multi-stage scanning using Naabu (fast port discovery) → Nmap -sV (service versions) → Httpx (web probing) → Katana (crawl SPAs). Build complete asset inventory. Send discovered services to vuln-scanner and cve-researcher via SendMessage.
- ActiveForm: Scanning and enumerating targets

**TASK: Research CVEs for discovered service versions**
- Owner: cve-researcher
- Blocked by: active recon task
- Description: Cross-phase CVE research. For each service version discovered by recon-active, research known CVEs, available exploits, and CVSS scores. Check exploit-db, NVD, GitHub advisories. Send CVE findings to vuln-scanner and exploiter via SendMessage.
- ActiveForm: Researching CVEs and exploits

**TASK: Scan for web application vulnerabilities**
- Owner: vuln-scanner
- Blocked by: active recon task
- Description: PTES Phase 4. For each web service discovered, run Nikto, Gobuster/Dirb, Nuclei (with CVE + DAST templates). Test OWASP Top 10. If SPA detected, use Playwright. Cross-reference with CVE researcher findings. Assign CVSS scores. Send validated findings to exploiter via SendMessage.
- ActiveForm: Scanning for vulnerabilities

**TASK: Validate critical and high findings (HITL required)**
- Owner: exploiter
- Blocked by: vuln scan task
- Description: PTES Phase 5. NON-DESTRUCTIVE ONLY. Before ANY exploitation, request HITL approval from operator via team-lead. Safe POC techniques only — SQLi with SELECT @@version, XSS with alert(), RCE with whoami. Screenshot all evidence. Immediate cleanup. Send validated findings to post-exploit and reporter via SendMessage.
- ActiveForm: Validating vulnerabilities (non-destructive)

**TASK: Simulate post-exploitation attack paths**
- Owner: post-exploit
- Blocked by: exploitation task
- Description: PTES Phase 6. SIMULATION ONLY — do NOT execute. Document privilege escalation paths, lateral movement opportunities, data access scope, persistence mechanisms. Assess business impact. Send attack path analysis to reporter via SendMessage.
- ActiveForm: Simulating post-exploitation paths

**TASK: Generate final penetration test report**
- Owner: reporter
- Blocked by: post-exploitation task
- Description: PTES Phase 7. Compile all findings from all agents. Generate executive summary (non-technical), technical report (detailed findings with CVSS), remediation roadmap (prioritized), evidence package, and appendices (methodology, tools, references). Save to engagement 09-reporting/ folder.
- ActiveForm: Generating penetration test report

---

## Step 3: Spawn All Teammates

Spawn each teammate with their specialized prompt. Use split-pane display mode. Each agent reads its full prompt from `.claude/agents/[name]-agent.md`.

### Teammate Spawn Configuration

| Name | Model | SubagentType | Mode | Agent File |
|------|-------|-------------|------|------------|
| planner | sonnet | general-purpose | default | planning-agent.md |
| recon-passive | haiku | general-purpose | default | passive-osint-agent.md |
| recon-active | haiku | general-purpose | default | active-recon-agent.md |
| vuln-scanner | sonnet | general-purpose | default | web-vuln-scanner-agent.md |
| exploiter | sonnet | general-purpose | plan | exploitation-agent.md |
| post-exploit | sonnet | general-purpose | default | post-exploitation-agent.md |
| cve-researcher | sonnet | general-purpose | default | cve-researcher.md |
| reporter | sonnet | general-purpose | default | reporting-agent.md |

**IMPORTANT**: The `exploiter` agent MUST use `mode: "plan"` so its exploitation plans are reviewed before execution (HITL enforcement).

### Teammate Prompt Template

Each teammate's prompt should include:
1. The full content of their agent file from `.claude/agents/`
2. The team awareness instructions (below)
3. The specific engagement parameters ($ARGUMENTS)

### Team Awareness Instructions (Include in ALL teammate prompts)

```
## Team Coordination Protocol

You are a teammate in the ATHENA pentest team. Follow these rules:

### Task Management
- Check TaskList when you start and after completing each task
- Claim your assigned task with TaskUpdate (set status to in_progress)
- Mark tasks completed with TaskUpdate when done
- If blocked, message team-lead explaining the blocker

### Peer Communication (SendMessage)
- Message teammates DIRECTLY when sharing findings relevant to their work
- Always message team-lead for: HITL requests, critical findings, blockers, phase completions
- Include structured data in messages (target, port, service, finding, severity)
- Keep messages concise and actionable

### Communication Matrix
| From | To | When |
|------|----|------|
| recon-passive | recon-active | Discovered subdomains and IPs |
| recon-active | vuln-scanner | Discovered web services and ports |
| recon-active | cve-researcher | Service versions for CVE lookup |
| cve-researcher | vuln-scanner | CVE matches for discovered services |
| cve-researcher | exploiter | Exploitable CVEs with POC info |
| vuln-scanner | exploiter | Validated vulnerabilities for POC |
| exploiter | post-exploit | Successfully validated findings |
| exploiter | reporter | Evidence and reproduction steps |
| post-exploit | reporter | Attack path analysis |
| ALL agents | team-lead | Phase completion, critical findings, blockers |

### Safety Rules (NON-NEGOTIABLE)
- NEVER test targets outside authorized scope
- NEVER perform destructive actions
- ALWAYS request HITL approval before exploitation
- ALWAYS collect evidence (screenshots, logs, commands)
- STOP immediately if service impact detected

### Kali Backend Selection
- External pentests: Use kali_external tools (mcp__kali_external__*)
- Internal pentests: Use kali_internal tools (mcp__kali_internal__*)
- Both backends available — choose based on engagement type

### Engagement Context
- Client: [FROM $ARGUMENTS]
- Engagement folder: engagements/[CLIENT]_[DATE]_[TYPE]/
- Evidence goes to: 08-evidence/
- Use ToolSearch to load Kali MCP tools before first use
```

---

## Step 4: Team Lead Responsibilities

As team lead (orchestrator), you:

1. **Create the team** with TeamCreate
2. **Create all tasks** with dependencies using TaskCreate
3. **Spawn all teammates** with their prompts
4. **Assign initial tasks** — planner gets first task
5. **Monitor progress** via TaskList
6. **Handle HITL requests** — when exploiter needs approval, present to operator via AskUserQuestion
7. **Aggregate findings** — track critical/high findings across all agents
8. **Manage phase transitions** — ensure phases complete before dependents start
9. **Emergency stop** — if any agent reports service impact, broadcast stop to all
10. **Shutdown team** when engagement complete — SendMessage shutdown_request to all

### HITL Approval Flow

```
exploiter → SendMessage to team-lead: "Request approval to validate VULN-001 (Critical SQLi on target:443)"
team-lead → AskUserQuestion to operator: "Approve validation? [Approve/Skip]"
operator → Approves
team-lead → SendMessage to exploiter: "APPROVED — proceed with safe POC"
exploiter → Executes safe POC, collects evidence
exploiter → SendMessage to team-lead: "VULN-001 validated. Evidence at 08-evidence/001-CRITICAL-SQLI-*.png"
```

### Emergency Stop Protocol

```
ANY agent → SendMessage to team-lead: "SERVICE IMPACT DETECTED on [target]"
team-lead → broadcast: "EMERGENCY STOP — All testing halted. Do not execute any more commands."
team-lead → AskUserQuestion: "Service impact reported. Contact client emergency POC?"
```

---

## Step 5: Engagement Completion

When all tasks are completed:
1. Verify all tasks show status: completed
2. Review reporter's deliverables
3. Send shutdown_request to all teammates
4. TeamDelete to clean up
5. Present final summary to operator

### Final Summary Format

```
ATHENA ENGAGEMENT COMPLETE
==========================
Client: [NAME]
Type: [External/Internal/Web App]
Duration: [X hours]
Agents Deployed: 8 (+ team lead)

FINDINGS SUMMARY
  Critical: X
  High: X
  Medium: X
  Low: X
  Validated: X of Y

DELIVERABLES
  Executive Summary: 09-reporting/executive-summary.md
  Technical Report: 09-reporting/technical-report.md
  Remediation Roadmap: 09-reporting/remediation-roadmap.md
  Evidence Package: 08-evidence/

PTES PHASES COMPLETED
  [x] Phase 1: Pre-Engagement (Planning)
  [x] Phase 2: Intelligence Gathering (Passive + Active)
  [x] Phase 3: Threat Modeling
  [x] Phase 4: Vulnerability Analysis
  [x] Phase 5: Exploitation (Non-Destructive)
  [x] Phase 6: Post-Exploitation (Simulation)
  [x] Phase 7: Reporting
```

---

## Comparison: /orchestrate vs /orchestrate-team

| Feature | /orchestrate (Subagents) | /orchestrate-team (Agent Teams) |
|---------|------------------------|--------------------------------|
| Communication | Hub-and-spoke | Peer-to-peer + team lead |
| Parallelism | Background tasks | True independent sessions |
| Visibility | Inline results | Split-pane per agent |
| CVE research | Sequential after scan | Parallel with scanning |
| Coordination | Orchestrator manages all | Shared task list |
| HITL | Direct AskUserQuestion | Via team lead |
| Cost | Lower (shared context) | Higher (per-agent context) |
| Resilience | Single point of failure | Independent agents continue |

---

## Fallback

If Agent Teams encounters issues, fall back to `/orchestrate` which uses the proven subagent dispatch model.

---

**Target**: $ARGUMENTS
**Mode**: Agent Teams (split-pane)
**Agents**: 9 (8 teammates + team lead)
**Safety**: HITL + Authorization + Emergency Stop
**Methodology**: PTES Compliant
