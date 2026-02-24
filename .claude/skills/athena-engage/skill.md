---
name: athena-engage
category: pentesting
description: Launch a real AI pentesting engagement using Claude Code Agent Teams. Spawns 5 AI agents (recon, vuln, exploit, post-exploit, report) that reason about pentesting decisions and coordinate via Neo4j blackboard pattern. Dashboard visualizes progress in real-time.
---

# ATHENA AI Engagement — Claude Code Agent Teams

Launch a penetration testing engagement powered by real Claude Code AI agents.

## Usage

```
/athena-engage <target_scope>
```

**Examples:**
```
/athena-engage 10.1.1.20
/athena-engage 10.1.1.0/24
/athena-engage https://juiceshop.example.com
/athena-engage 10.1.1.20,10.1.1.21,10.1.1.22
```

## What This Does

Unlike Automation Mode (Python sequences), AI Mode spawns **5 real Claude Code agents** that:
- **Reason** about what to scan, what to exploit, what to report
- **Decide** tool selection based on findings (not hardcoded sequences)
- **Communicate** via Neo4j blackboard pattern (shared state)
- **Require HITL approval** for all exploitation attempts
- **Update the dashboard** in real-time via REST API

## Pre-Requisites

Before running, ensure:
1. **Dashboard is running:** `cd tools/athena-dashboard && ./start.sh` → http://localhost:8080
2. **Kali backend is reachable:** At least one of kali_external or kali_internal
3. **Neo4j is reachable:** athena-neo4j MCP connected
4. **Target is authorized:** You have explicit authorization to test the target

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  Team Lead (Vex)                                     │
│  Creates engagement, spawns agents, relays HITL      │
├──────────┬──────────┬──────────┬──────────┬─────────┤
│  Recon   │  Vuln    │  Exploit │  Post-   │  Report │
│  Agent   │  Agent   │  Agent   │  Exploit │  Agent  │
│  (PO/AR/ │  (CV/WV/ │  (EC/EX/ │  Agent   │  (RP/   │
│   JS)    │   AP)    │   VF)    │  (PE/LM) │   DV)   │
├──────────┴──────────┴──────────┴──────────┴─────────┤
│  Neo4j Blackboard (shared state)                     │
├─────────────────────────────────────────────────────┤
│  Dashboard REST API (http://localhost:8080)           │
├─────────────────────────────────────────────────────┤
│  Kali MCP Backends (external + internal)             │
└─────────────────────────────────────────────────────┘
```

## Orchestration Steps

When this skill is invoked, follow these steps exactly:

### Step 1: Validate Prerequisites

Check that the dashboard is running:
```bash
curl -sf http://localhost:8080/health
```
If it fails, tell the user to start the dashboard first.

Check Neo4j connectivity:
```
Tool: mcp__athena_neo4j__query_graph
Query: RETURN 1 AS ok
```

### Step 2: Create Engagement in Neo4j

```
Tool: mcp__athena_neo4j__run_cypher
Query:
CREATE (e:Engagement {
  id: $eid,
  name: $name,
  target: $target,
  scope: $scope,
  status: 'active',
  mode: 'ai',
  started_at: timestamp(),
  authorization: 'documented'
})
RETURN e.id AS id
```

Generate engagement ID as `eng-` + 6 random hex chars.
Set `name` to "AI Engagement — {target}" and `scope` to the target scope provided.

### Step 3: Create Engagement in Dashboard

```bash
curl -s -X POST http://localhost:8080/api/engagements \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "AI Engagement — TARGET",
    "target": "TARGET",
    "scope": "TARGET",
    "authorization": "documented",
    "backend": "external"
  }'
```

### Step 4: Notify Dashboard — AI Mode Active

```bash
curl -s -X POST http://localhost:8080/api/events \
  -H 'Content-Type: application/json' \
  -d '{"type":"system","agent":"OR","content":"AI Mode activated. 5 Claude Code agents will execute PTES phases 1-7. HITL approval required for exploitation."}'
```

### Step 5: Create Agent Team

```
Tool: TeamCreate
team_name: athena-engagement
description: "ATHENA AI pentesting engagement against {target}"
```

### Step 6: Create Tasks with Dependencies

Create 5 tasks representing PTES phases:

**Task 1: Reconnaissance**
- No dependencies
- Assign to athena-recon agent

**Task 2: Vulnerability Analysis**
- Blocked by Task 1
- Assign to athena-vuln agent

**Task 3: Exploitation**
- Blocked by Task 2
- Assign to athena-exploit agent

**Task 4: Post-Exploitation**
- Blocked by Task 3
- Assign to athena-postexploit agent

**Task 5: Reporting**
- Blocked by Task 4
- Assign to athena-report agent

### Step 7: Spawn Agents

Spawn all 5 agents. They will self-manage based on task dependencies (blocked agents wait until their dependencies are met).

For each agent, the prompt MUST include:
- **Engagement ID** (`$eid`)
- **Target scope** (what they're authorized to test)
- **Dashboard URL** (`http://localhost:8080`)
- **Backend preference** (`external` or `internal` or `both`)

**Spawn recon agent immediately** (no dependencies):
```
Tool: Task
subagent_type: athena-recon
team_name: athena-engagement
name: recon
prompt: |
  You are the reconnaissance agent for ATHENA engagement {eid}.
  Target scope: {target}
  Dashboard: http://localhost:8080
  Engagement ID: {eid}
  Backend: Use kali_external for internet-facing targets, kali_internal for internal.

  Execute your full reconnaissance methodology. Start by setting your dashboard
  LEDs to running (PO, AR, JS), then run passive and active recon, persist
  everything to Neo4j, and mark complete when done.

  When finished, send a message to the team lead summarizing your findings.
```

**Spawn remaining agents** — they will check TaskList and wait for their blockers to clear:
Each subsequent agent gets a similar prompt with their specific engagement ID and scope.

### Step 8: Monitor Progress

As team lead, you:
1. Receive messages from agents as they complete phases
2. Relay HITL approval decisions when the exploit agent requests them
3. Track overall engagement progress via TaskList
4. Handle any agent errors or stuck states

### Step 9: Shutdown Team

When the report agent completes:
1. Send shutdown requests to all agents
2. Delete the team (`TeamDelete`)
3. Tell the user where to find the report
4. Provide a summary of the engagement results

## HITL Approval Relay

When the exploit or post-exploit agent requests HITL approval:

1. The agent POSTs to `/api/approvals` — the dashboard shows a modal to the operator
2. The operator clicks Approve/Reject in the dashboard
3. The agent polls `/api/approvals/{id}` and gets the decision
4. **No relay needed from team lead** — agents handle HITL directly with the dashboard

The team lead only intervenes if an agent gets stuck or encounters an error.

## Comparison: Automation Mode vs AI Mode

| Aspect | Automation Mode | AI Mode |
|--------|----------------|---------|
| Trigger | Dashboard "Engage" button | `/athena-engage` CLI command |
| Engine | Python orchestrator.py | Claude Code Agent Teams |
| Agents | 19 Python sequences | 5 AI agents with reasoning |
| Decisions | Hardcoded tool order | Context-aware tool selection |
| Thinking | Static strings | Real AI reasoning (visible in timeline) |
| Cost | $0 (Python only) | Included in Claude Code subscription |
| Speed | 5-15 minutes | 15-45 minutes (more thorough) |
| Dashboard | Same UI | Same UI (identical events) |

## Error Handling

- **Agent crashes:** Team lead receives error notification. Can re-spawn the agent.
- **Tool failure:** Agents handle tool errors gracefully — retry or skip.
- **Neo4j down:** Agents fall back to dashboard-only reporting (POST findings directly).
- **Dashboard down:** Agents continue working but dashboard updates are lost.
- **HITL timeout:** Exploit agent polls indefinitely. Operator must eventually decide.
