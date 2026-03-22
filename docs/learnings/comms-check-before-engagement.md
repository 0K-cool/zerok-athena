# Comms Check Before Engagement Start

**Created:** 2026-03-22
**Status:** Feature request
**Priority:** HIGH — prevents silent agent failures

## Concept

Like a military radio check before an operation, ST should verify all spawned agents are responsive before starting the pentest. This catches broken event callbacks, stale sessions, and failed spawns immediately — not 20 minutes into the engagement.

## Flow

```
ST: "COMMS CHECK — all agents report in"
  → AR: "AR ready, 21 tools available"          ← 1s
  → WV: "WV ready, Nuclei + Nikto loaded"       ← 1s
  → EX: (no response)                           ← timeout 5s
  → ST: "WARNING: EX did not respond — re-spawning"
  → EX (re-spawned): "EX ready, Metasploit available"  ← 2s
ST: "All agents confirmed. Commencing engagement."
```

## What It Catches

- VF silent session bug (broken event callback)
- Failed spawns (KeyError crashes)
- Agents stuck in initialization
- Kali backend connectivity issues (agent can't reach tools)

## Implementation Options

### Option A: Server-side health ping (recommended)
After `_spawn_agent()` succeeds, emit a test event and verify it reaches the dashboard WebSocket within 3 seconds. If not, log error and re-spawn.

### Option B: ST prompt instruction
Add to ST's prompt: "After spawning each agent, verify it's responsive by checking /api/agents/status. If running=false or tool_calls=0 after 10 seconds, re-spawn."

### Option C: Agent self-check
Each agent's first action on spawn is to POST a "ready" event. If the manager doesn't receive the ready event within 5 seconds, mark the agent as failed.

### Recommendation
Option A + C: Server verifies spawn success (A), and each agent confirms readiness with a self-check (C). Belt and suspenders.

## Military Analogy

This is exactly what team leaders do:
- **Before patrol:** Radio check with every element
- **After insertion:** Accountability check — every operator confirms position
- **During operation:** Regular status checks — "SITREP"

ATHENA should operate the same way. ST is the team leader. Agents are operators.
