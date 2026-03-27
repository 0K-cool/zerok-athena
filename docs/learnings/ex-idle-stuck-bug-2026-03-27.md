# BUG: EX Agent Idle-Stuck After First Exploit — 5/150 Tool Calls

**Date:** March 27, 2026
**Severity:** HIGH — EX wastes a concurrent agent slot doing nothing
**Status:** DOCUMENTED — Not yet fixed

## Problem

EX agent gets first shell (vsftpd backdoor, uid=0) within 5 tool calls, then goes completely idle for the rest of the engagement. It stays in "Running" state at 5/150 tool calls, consuming a concurrent agent slot but doing no work. Other services (MySQL, PostgreSQL, Tomcat, SSH, telnet, distccd) are never exploited by EX.

## Evidence

- Cycle 2 (4m): EX at 5/150
- Cycle 3 (7m): EX at 5/150
- Cycle 4 (14m): EX at 5/150
- No new tool calls for 10+ minutes

## Root Cause

EX's prompt has conflicting instructions:
1. Speed rules say "first shell as fast as possible" (Sprint-oriented)
2. Autonomous mode should exploit ALL exploitable services, not just the first one
3. After getting vsftpd shell, EX has no explicit instruction to continue exploiting other services
4. EX doesn't proactively query Neo4j for unexploited findings — it waits for bilateral messages from DA

## Impact

- Only 1 exploit confirmed by EX (vsftpd) when 8-10 are possible
- VF has to discover and verify exploits independently (slower, more expensive)
- Wasted agent slot — PE or RP could use it
- TTFS never set because EX doesn't call /first-shell
- Engagement takes longer because exploitation phase is underutilized

## Proposed Fix

1. **EX prompt (autonomous mode):** After getting first shell, explicitly continue:
   "After each successful exploit, query Neo4j for remaining unexploited findings:
   GET /api/engagements/{eid}/findings?status=discovered
   Exploit the next highest-severity finding. Continue until all HIGH/CRITICAL
   findings have been attempted or your budget is exhausted."

2. **EX self-direction:** EX should proactively query Neo4j for targets instead of
   waiting for bilateral messages from DA. DA feeds are supplementary, not primary.

3. **Idle detection:** If EX makes no tool calls for 120 seconds in autonomous mode,
   ST should send a redirect message: "EX, check Neo4j for unexploited findings
   and continue exploitation."

4. **First-shell registration:** After ANY successful exploit (not just in sprint),
   EX should call POST /api/engagements/{eid}/first-shell to register TTFS.

## Files to Modify

- `agent_configs.py` — _EX_PROMPT: Add autonomous continuation instructions
- `agent_configs.py` — ST prompt: Add EX idle detection and redirect logic
- `server.py` — Consider adding an idle agent detection endpoint
