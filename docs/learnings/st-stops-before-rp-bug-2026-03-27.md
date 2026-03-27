# BUG: ST Stops Engagement Before RP Finishes Report Generation

**Date:** March 27, 2026
**Severity:** HIGH — Client deliverable (report) not generated
**Status:** DOCUMENTED — Not yet fixed

## Problem

ST declared the engagement complete and stopped all agents while RP was still running and generating reports. The report is the client deliverable — without it, the engagement has no formal output.

## Expected Behavior

ST should enforce a completion gate:
1. All exploitation phases complete (AR → DA → EX → VF → PE)
2. ST requests RP to generate reports
3. **ST waits for RP to signal completion** before declaring engagement done
4. Only then does ST stop the engagement

## Current Behavior

ST monitors agent completion but doesn't have a hard gate on RP. When most agents finish, ST declares engagement complete, killing RP mid-generation.

## Impact

- No technical report generated
- No executive summary generated
- Client gets raw findings but no formatted deliverable
- PTES Phase 7 (Reporting) incomplete

## Proposed Fix

1. **ST prompt:** Add explicit gate — "Do NOT stop the engagement until RP has completed ALL reports. Wait for RP's completion message before declaring engagement done."
2. **Server-side gate:** Before processing engagement stop from ST, check if RP is still running. If yes, delay the stop until RP completes or hits a timeout (5 minutes max).
3. **RP completion signal:** RP should post a bilateral message to ST: `{"msg_type": "report_complete", "content": "All reports generated"}` — ST waits for this before stopping.

## Files to Modify

- `agent_configs.py` — ST prompt: add RP completion gate
- `server.py` — Optional: server-side RP gate before engagement stop
- `agent_configs.py` — RP prompt: send completion signal to ST when done
