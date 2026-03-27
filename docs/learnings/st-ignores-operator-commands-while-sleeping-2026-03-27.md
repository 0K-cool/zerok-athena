# BUG: ST Ignores Operator Commands While Sleeping — Operator is the Boss

**Date:** March 27, 2026
**Severity:** CRITICAL — Operator loses control of the engagement
**Status:** DOCUMENTED — Not yet fixed

## Problem

ST runs `sleep 300` (5 minutes) to wait for RP. During this time, operator commands are queued but NOT processed. The operator typed "Team leader, why you still running?" and "why still up?" — both got "Suggestion queued" responses instead of immediate action.

The operator (pentester) is ST's boss. When the boss gives a command, ST must respond IMMEDIATELY — not after a 5-minute nap.

## Impact

- Operator loses control of the engagement for 5+ minutes
- Cannot redirect, stop, or query ST during sleep
- Cannot issue critical commands (e.g., "stop exploiting target X — it's out of scope")
- In a client engagement, this could mean violating scope or missing an urgent change

## Root Cause

Claude Agent SDK processes tool calls sequentially. When ST runs `sleep 300` via Bash, the SDK is blocked waiting for the tool call to complete. Operator commands are queued as "suggestions" that ST reads at the next turn boundary — which is after the sleep.

## Proposed Fixes

### Option A: Ban long sleep in ST (prompt fix)
"NEVER use sleep for more than 10 seconds. To wait for an agent, poll its status every 30 seconds using GET /api/agents/status instead of sleeping."

### Option B: Server-side command interrupt (RECOMMENDED)
When an operator sends a command while ST is in a long-running tool call:
1. Server cancels ST's current tool call (send SIGINT to the subprocess)
2. Inject the operator's command as the next prompt
3. ST processes the command immediately
4. If ST was sleeping, the sleep is killed — no data loss

### Option C: Separate operator command channel
Run a lightweight "Command Router" (CR) agent that ALWAYS listens for operator commands, even when ST is busy. CR can:
1. Forward commands to ST's pending queue with HIGH priority
2. Execute simple commands directly (stop, pause, status)
3. Kill ST's current operation if the command is urgent

NOTE: CR agent already exists in the codebase (agent_configs.py _CR_PROMPT) but has a 60s idle timeout bug (BUG-003) and is rarely spawned.

### Option D: Never block the operator
Server-side rule: if an operator command arrives and ST has a tool call running for >30 seconds, auto-cancel the tool call and deliver the command.

## Principle

The operator is ALWAYS in control. No agent should ever be unresponsive to operator commands. This is a safety and scope compliance requirement, not just a UX issue.

## Files to Modify

- `agent_configs.py` — Ban long sleep in ST prompt (Option A)
- `sdk_agent.py` — Add tool call interrupt mechanism (Option B)
- `server.py` — Auto-cancel long tool calls on operator command (Option D)
- `agent_session_manager.py` — Operator priority command injection
