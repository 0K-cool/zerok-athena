# ST Should Know About Pause/Resume

**Created:** 2026-03-22
**Status:** Feature request
**Priority:** MEDIUM — improves resume continuity

## Problem

When the operator pauses, ST's subprocess gets SIGTERM'd. On resume, ST is re-spawned with a generic "Continue the engagement" prompt. ST has no awareness that a pause happened — it doesn't know:
- How long the engagement was paused
- Why the operator paused (maybe to redirect strategy?)
- What the last active operation was before pause

## Current Flow

```
Pause: SIGTERM → ST dies (no pre-pause notification)
Resume: ST re-spawned → "Continue the engagement from where you left off"
        → ST queries Neo4j → figures out state → continues
```

## Proposed Flow

```
Pause: SIGTERM → ST dies
Resume: ST re-spawned with enriched context:
  "This engagement was PAUSED by the operator at [time] for [duration].
   Review Neo4j state and continue from where the team left off.
   Last active agents: AR (6 tool calls), ST (5 tool calls)
   Findings so far: [count] | Exploits: [count]
   Resume your strategy — reassess priorities based on current state."
```

## Implementation

In `agent_session_manager.py` `resume()`, when re-spawning ST:
1. Include pause duration in the prior_context
2. Include last-known agent states
3. Include finding/exploit summary from Neo4j
4. If the operator typed a command during pause (e.g., "focus on port 445"), include that as a directive

## Pre-Pause Notification (Future)

If we switch from SIGTERM to graceful pause (SDK supports it), we could:
1. Send ST: "Operator is pausing. Summarize current strategy state."
2. ST responds with a summary
3. Save summary to engagement metadata
4. On resume, include that summary in the context
