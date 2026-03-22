# Command Router Agent — Dedicated Operator Command Handler

**Created:** 2026-03-22
**Status:** Feature request
**Priority:** HIGH — operator commands take 2-4 minutes to process via ST

## Problem

Operator commands (typed into the AI drawer) go to ST's command queue. ST processes them only after finishing its current SDK turn (up to 15 tool calls, 1-2 minutes each). This means:

- Simple commands like "target is back up" take 2-4 minutes to process
- Operator has no immediate feedback that the command was received
- ST is doing strategy work AND command handling — conflicting responsibilities
- Time-critical commands (pause, redirect, status check) are delayed

## Current Flow

```
Operator types command
  → queued in ST's _command_queue
    → ST finishes current SDK turn (1-2 min)
      → ST picks up command from queue
        → ST processes and responds (30s-1min)
          → Total: 2-4 minutes
```

## Proposed Architecture: Command Router Agent (CR)

A lightweight, always-responsive agent that:
1. Receives ALL operator commands immediately
2. Routes them to the appropriate agent or takes action directly
3. Provides instant acknowledgment to the operator
4. Does NOT run long SDK queries — keeps its event loop fast

### Design Options

#### Option A: Non-LLM Router (fastest, simplest)
- Python handler, no Claude API call
- Pattern-matches commands: "pause" → call pause API, "status" → query agents, "resume" → call resume API
- For complex commands: forwards to ST's queue AND acknowledges immediately
- Response time: <1 second
- Limitation: can't understand nuanced/creative commands

#### Option B: Lightweight LLM Router (balanced)
- Haiku model for fast classification
- Classifies command type: ACTION (pause/stop/resume), QUERY (status/info), DIRECTIVE (strategy change)
- ACTIONs executed immediately
- QUERYs answered from API/Neo4j data
- DIRECTIVEs forwarded to ST with acknowledgment
- Response time: 2-5 seconds

#### Option C: Dedicated ST Command Turn (simplest code change)
- Reduce `max_turns_per_chunk` from 15 to 5 for ST only
- ST checks command queue every ~30s instead of ~2min
- Trade-off: more SDK session resume overhead, higher API cost
- NOT recommended: band-aid, doesn't solve the architectural problem

### Recommended: Option B

Option B gives instant feedback on actions + fast answers for status queries + proper routing for strategy changes. Haiku is cheap ($0.25/MTok) and fast (<1s response).

### Implementation Notes

- CR would be a permanent agent that starts with every engagement
- CR does NOT count toward agent budget (it's infrastructure, not a pentest agent)
- CR is INVISIBLE in the UI — no chip in AI Agent Status grid, no budget badge, no PTES phase
- CR does NOT emit timeline events — operator only sees the response to their command
- CR works behind the scenes like WebSocket relay or KPI polling — essential plumbing
- CR's event callback emits directly to the dashboard (operator sees response immediately)
- CR has access to all APIs but NO Kali tools (it's a coordinator, not a scanner)
- Operator commands currently go to `session.send_command()` on ST — change to route to CR instead
- CR can also handle: help commands, engagement info queries, agent status, cost tracking

### What Changes

| Current | New |
|---------|-----|
| Operator → ST queue (2-4 min) | Operator → CR (instant) → routes to ST if needed |
| Pause button → API (works) | Pause button → CR → API (same, but CR acknowledges) |
| "What's the status?" → ST processes | "What's the status?" → CR answers from API directly |
| "Focus on SQLi" → ST queue | "Focus on SQLi" → CR forwards to ST + acknowledges |

### Files Involved

- `agent_session_manager.py` — route operator commands to CR instead of ST
- `agent_configs.py` — new CR agent config (Haiku, no Kali, no budget limit)
- `server.py` — CR command input endpoint
- `index.html` — command input routes to CR
