# Beta Test Bugs — March 28, 2026

## BUG: Empty SYSTEM Event Cards in Timeline

**Severity:** LOW — Cosmetic, no data loss
**Status:** DOCUMENTED

### Problem
PE SYSTEM notification card at 10:31:55 rendered with empty content — just the red icon, "PE SYSTEM" label, and timestamp, but no text body. The event content exists in the API (verified via events endpoint) but the timeline card didn't render it.

### Likely Root Cause
The timeline card renderer may be truncating or failing to display `system` type events that contain long content or special characters (PE's content included filesystem paths with `/` and command output with newlines).

### Where to Look
- `index.html` — timeline card rendering for `system` type events
- Check if content is being HTML-escaped or truncated to empty
- Check if card has a max-height that clips content to invisible

### Also Observed
- 3 empty SYSTEM cards at 10:22:17 (same pattern, unknown agent)
- May be the same root cause

### Root Cause Found
The empty card at 10:31:55 is a `tool_complete` event containing a JSON API response (`{"ok": true, "finding_id": "d522097e", ...}`). The timeline card renderer shows `tool_complete` events as SYSTEM cards but doesn't render JSON content in the body — only human-readable text.

**Fix:** Either skip rendering `tool_complete` events that contain JSON responses, or format the JSON into readable text (e.g., "Finding d522097e created (deduplicated, confirmed)").

## BUG: Total Exploitable KPI Inflated by VF Confirmations

**Severity:** MEDIUM — KPI semantics wrong
**Status:** DOCUMENTED

### Problem
"Total Exploitable" KPI increases when VF confirms exploits. At 22 min: Total Exploitable = 28, but it should represent discovered vulnerabilities with exploit potential (stable number), not confirmations. VF confirmations should increment the Confirmed Exploit Rate gauge, not Total Exploitable.

### Expected Behavior
- **Total Exploitable:** Count of findings marked as exploitable by AR/DA/EX (stable after discovery phase)
- **Confirmed Exploit Rate:** `VF_confirmed / Total_Exploitable` (increases as VF works)

### Actual Behavior
- **Total Exploitable:** Increases with every VF confirmation (tracks confirmations, not potential)
- **Confirmed Exploit Rate:** 20 confirmed / 77 total = 26% (denominator is total findings, not exploitable)

### Fix
Check how "Total Exploitable" is computed in the exploit-stats endpoint — it should count findings with `severity in (critical, high)` or `exploit_available=true`, NOT findings where `verified=true`.

### Files to Modify
- `server.py` — exploit-stats endpoint, separate exploitable count from confirmed count

### Root Cause: Total Exploitable KPI
Pre-existing issue (BUG-050). The `kpi-criticals` element shows `total_exploited` (confirmed + likely), not total exploitable vulnerabilities. Line 12699 in index.html:
```javascript
const totalExploited = es.total_exploited !== undefined ? es.total_exploited : es.confirmed_exploits;
```
Our Bug #7 gate fix made it more visible by returning data earlier. Fix: `kpi-criticals` should show count of HIGH/CRITICAL findings (exploitable potential), not `total_exploited`.

## BUG: Duplicate Screenshots — Server + VF Both Capture

**Severity:** MEDIUM — Wastes storage, clutters Evidence Gallery
**Status:** DOCUMENTED

### Problem
8 out of 13 findings with screenshots have 2 copies — one from server auto-capture (`agent=server`) and one from VF taking its own screenshot. Both fire on the same confirmation event.

### Fix
In `_trigger_auto_screenshot`, check if a screenshot already exists for this finding before capturing:
```python
# Skip if screenshot already exists for this finding
existing = [a for a in state.artifacts if a.finding_id == finding_id and a.type == 'screenshot']
if existing:
    return  # VF already captured one
```

## BUG: Agents Verify Duplicate Findings (Same CVE, Multiple Entries)

**Severity:** HIGH — Wastes agent budget, inflates confirmed count
**Status:** DOCUMENTED — Related to Dedup V2

### Problem
50 confirmed findings but only 43 unique vulnerabilities. VF verifies each finding individually without checking if the same CVE has already been verified. EX exploits the same vuln reported by different agents.

Examples:
- CVE-2012-1823: 3 separate confirmed findings (bus + DA + DA)
- CVE-2011-2523: 2 separate confirmed findings (bus + DA)
- TWiki RCE: 2 identical DA findings

### Root Cause
1. Dedup V2 (cross-path) not implemented yet — bus and /api/findings create parallel nodes
2. DA posts the same finding twice with slightly different titles
3. VF/EX don't check "has this CVE already been confirmed?" before working on it

### Fix
Part of Dedup V2 (Monday):
- Unified finding creation path prevents parallel nodes
- VF prompt: "Before verifying, check if this CVE has already been verified: GET /api/findings?cve=CVE-XXXX&status=confirmed"
- Server-side: when VF confirms a finding, auto-mark all findings with same fingerprint as confirmed

## BUG: RP Budget Exhaustion → Infinite Respawn Loop

**Severity:** HIGH — Wastes budget, RP never completes reports
**Status:** DOCUMENTED

### Problem
RP (Reporting) spawns with $12.00 budget on Opus model. With 50+ findings, report generation exhausts the budget before completing all 3 reports. ST detects RP stopped, interprets it as "stuck," and respawns with a fresh $12 budget. RP burns through again. Loop repeats.

### Evidence (eng-eb2adc, March 28, 2026)
- RP spawned 3 times
- Each time: "Early-stopping RP due to budget exhaustion"
- ST respawns after each exhaustion

### Root Causes
1. **$12 RP budget too low** for Opus with 50+ findings (3 reports × heavy Neo4j queries × long-form markdown)
2. **ST doesn't distinguish budget exhaustion from idle/stuck** — treats both as "respawn"
3. **RP uses Opus** ($25/MTok) when Sonnet ($15/MTok) is sufficient for report writing

### Proposed Fixes
1. **Increase RP budget** — $20-25 for standard, or scale dynamically: `base_budget + (finding_count * $0.15)`
2. **ST prompt: don't respawn budget-exhausted agents** — "If an agent stopped due to budget exhaustion, do NOT respawn. Report to operator that RP needs more budget."
3. **RP model: Sonnet** — report writing is text generation, Opus reasoning is overkill. 40% cost reduction.
4. **Server-side: cap respawn count** — max 2 respawns per agent per engagement. After that, alert operator.

### Files to Modify
- `agent_configs.py` — RP budget, RP model selection, ST respawn logic
- `agent_session_manager.py` — respawn counter, budget-exhaustion detection

## BUG: Auto-Screenshots Capture Wrong Content (Web Page Instead of Exploit Evidence)

**Severity:** HIGH — Evidence useless for client reports
**Status:** DOCUMENTED

### Problem
All 21 auto-screenshots capture `http://10.1.1.25` (Apache default page) regardless of what exploit was confirmed. A web screenshot of the homepage proves nothing about a vsftpd backdoor, Samba RCE, or PostgreSQL default creds. Additionally, many screenshots are 0 bytes (possibly failing silently).

### What We Capture vs What Client Needs

| Exploit | What We Screenshot | What Client Needs |
|---|---|---|
| vsftpd backdoor (port 21) | http://10.1.1.25 (web page) | Terminal: `nc 10.1.1.25 6200` → `uid=0(root)` |
| Samba RCE (port 445) | http://10.1.1.25 (web page) | Terminal: msfconsole exploit output |
| PostgreSQL default creds | http://10.1.1.25 (web page) | Terminal: `psql -U postgres` → connected |
| Tomcat manager (port 8180) | http://10.1.1.25 (homepage) | http://10.1.1.25:8180/manager/ (the actual vuln page) |

### Root Cause
`_trigger_auto_screenshot` constructs `http://{target_ip}` and calls Kali's web screenshot endpoint. This:
1. Always hits port 80 regardless of which service was exploited
2. Captures a web page when most exploits are terminal-based
3. Doesn't know WHAT was exploited — just knows the target IP

### Proposed Fix

**Option A: Agent-driven evidence (BEST)**
Agents (EX/VF) capture their own evidence — they know what they just did. 
- EX: After exploit, call `screenshot_terminal` with the command + output
- VF: After verification, capture the terminal proving independent confirmation
- Server auto-capture becomes a fallback, not the primary method

**Option B: Smart screenshot routing**
In `_trigger_auto_screenshot`, check the finding's service/port:
- Web finding (port 80, 443, 8080, 8180) → `screenshot_web` with correct port/path
- Terminal finding (SSH, FTP, netcat) → `screenshot_terminal` with exploit command
- Requires finding metadata to include service/port info

**Option C: Command output AS evidence (already working)**
The 63 `command_output` artifacts from EX/VF are the REAL evidence. They contain actual exploit commands and results. Prioritize these in reports over screenshots.

### Recommendation
Option A + C. Agent-driven terminal screenshots + command_output as primary evidence. Server auto-capture web screenshots only for web vulnerabilities.

### Files to Modify
- `server.py` — `_trigger_auto_screenshot` routing logic
- `agent_configs.py` — EX/VF prompts to mandate `screenshot_terminal` after every exploit
- Report templates — prioritize command_output evidence over web screenshots

## BUG: PTES Reporting Phase Shows Covered Despite RP Failure

**Severity:** MEDIUM — PTES accuracy
**Status:** DOCUMENTED

### Problem
PTES Methodology Coverage shows Reporting phase as partial/covered (orange), but RP:
- Ran out of budget 3 times
- Session ended with "0 tool calls, $0.0000 cost"
- COMMS CHECK FAILED
- Never completed a single report

### Root Cause
The PTES restore logic (our Bug #9 fix) marks phases covered when the agent shows `completed` or `running` status. RP briefly had `running` status before dying, which set the PTES cell. When RP died, the cell was never cleared back to "No Coverage."

### Fix
PTES coverage for RP should check:
1. Did RP actually produce reports? (Reports count > 0)
2. OR: Only mark RP phase if RP status is `completed` AND `tool_calls > 0`
3. Agent death/budget exhaustion should clear the phase back to "No Coverage"

## MINOR: Agent Field Overwrite on Fingerprint-Shared Findings

**Severity:** LOW — Cosmetic, doesn't affect KPIs
**Status:** DOCUMENTED — Follow-up

### Problem
When DA posts a finding that matches an existing EX-confirmed fingerprint, the merge branch correctly preserves the `status=confirmed` from EX (Bug A fix working). However, the merge still updates `f.agent = payload.agent` — overwriting `EX` with `DA`. The finding then shows `agent=DA, status=confirmed` even though EX was the one who confirmed it.

### Evidence (eng-8899fe)
- EX confirmed vsftpd CVE-2011-2523 → `bus-554af2fdf733, agent=EX, status=confirmed`
- DA posted same CVE → fingerprint match → merge preserved confirmed status
- But `f.agent` overwritten to DA → `find-a8a4ce8c, agent=DA, status=confirmed`
- Result: 1 DA finding showing as confirmed (down from 9 before the fix)

### Fix
In the merge `_update_existing` Cypher, don't overwrite `f.agent` when the existing finding is already confirmed and the new agent is non-confirm:

```cypher
SET f.agent = CASE WHEN f.status = 'confirmed' AND $agent IN ['DA','AR','WV','PR','PX']
                   THEN f.agent ELSE $agent END
```

Or use `contributing_agents` list (already tracked) and keep the original confirming agent as `f.agent`.

### Impact
Cosmetic only — the confirmed count, exploit rate, TTFS, and unverified count all work correctly. Only the "by agent" breakdown in detailed reports would show DA as the confirming agent instead of EX.

## BUG: RP Stalls on Technical Report — Executive Summary Only

**Severity:** HIGH — Client deliverable incomplete
**Status:** DOCUMENTED
**Evidence:** eng-8899fe, March 28, 2026

### What Happened
- RP spawned 3 times, stalled each time on technical report generation
- Only delivered executive summary (7.9KB)
- 73 findings too large for RP to process in single context window
- Executive summary was generated successfully (covers all findings at high level)
- Technical report (per-finding detail) never completed

### Why RP Stalls on Technical Report
1. RP queries each of 73 findings individually from Neo4j (N+1 pattern)
2. Each finding query = 1 tool call + response fills context
3. After ~30-40 findings, context window full
4. RP either exhausts budget or exceeds max_turns_per_chunk
5. Respawn starts fresh but hits same wall

### Fix Required
- **Chunked technical report:** Generate per-host or per-severity sections independently
- **Pre-aggregated report data:** Single `/api/report-data` endpoint returns all findings formatted for report, not N+1 queries
- **Template-based generation:** RP fills a template with data, not free-form report writing
- Part of the multi-target scalability architecture

## BUG: /api/scope Returns Empty After Server Restart

**Severity:** LOW — Pentest runs fine, scope data available in Neo4j
**Status:** DOCUMENTED

### Problem
`GET /api/scope` returns `raw_scope: ""` and `targets: []` after server restart, even though the engagement has `target: "10.1.1.25, 10.1.1.31"` in Neo4j. The `/api/engagements` list endpoint (reads from Neo4j) shows the correct scope, but `/api/scope` reads from in-memory `state.engagements` where the `target` field isn't populated on restart.

### Root Cause
When the server restarts, in-memory `Engagement` objects are recreated from Neo4j but the `target`/`scope` fields may not be hydrated from the Neo4j node properties into the Pydantic model. The `Engagement` class (line 224) has `target: str` but the reconstruction from Neo4j may skip it.

### Fix
In the server startup or engagement load path, ensure `target` and `scope` are read from Neo4j and populated on the in-memory Engagement object. Or: have `/api/scope` fall back to Neo4j query when in-memory target is empty.

### Impact
ST still receives the scope in its startup context (passed from Neo4j engagement data at start_ai time). Agents work correctly. Only the `/api/scope` REST endpoint returns stale data after restart.

## BUG: Empty Timeline Cards STILL Appearing (F2 Partial Fix)

**Severity:** LOW — Cosmetic
**Status:** PARTIALLY FIXED — with-tool_id path still renders empty

### What Was Fixed
- tool_complete events WITHOUT tool_id + JSON content → now filtered (our fix at line 9256)

### What's Still Broken
- tool_complete events WITH tool_id but JSON content → `handleToolComplete` fallback still renders empty cards
- PE SYSTEM at 19:56:04 — empty card (tool_complete with tool_id, JSON response)
- Exploitation SYSTEM at 19:58:02 — 2 empty cards (same pattern)

### Fix Needed
In `handleToolComplete` (index.html), the fallback `else` branch that calls `renderCompletedToolCard(msg)` — our fix added a JSON guard but only for the no-tool_id path. The with-tool_id path has a SECOND fallback when `runningTools[toolId]` is undefined (tool_start was dropped). That path also needs the JSON guard:

```javascript
// In handleToolComplete, the else branch at ~line 9799:
// Our current fix filters JSON here — GOOD
// But there's ANOTHER fallback inside the if(runningTools[toolId]) path
// where renderCompletedToolCard is called when tool output is JSON
```

Find ALL calls to `renderCompletedToolCard` in `handleToolComplete` and add the JSON guard before each one.

## BUG: Kali Attack Box IP (10.1.1.13) Counted as Discovered Host

**Severity:** MEDIUM — Inflates host count, pollutes per-host stats
**Status:** DOCUMENTED

### Problem
"Hosts Discovered" KPI shows 3 but only 2 are actual targets. The third (10.1.1.13) is the Kali attack box IP. 2 findings were attributed to this IP — likely from scan output or finding titles that mentioned the scanner's own address.

### Root Cause
No exclusion list for known infrastructure IPs (Kali backends, ATHENA server, DNS servers). Any IP that appears in finding data gets counted as a discovered host.

### Fix
Add a `_KALI_BACKEND_IPS` exclusion set (already exists in server.py for other purposes — search for it). When computing host stats or creating Host nodes, skip IPs in the exclusion set.

Also: the Hosts Discovered KPI card should match the Attack Graph host count. Both should read from the same source of truth.

## BUG: PTES Vuln Analysis Shows No Coverage Despite WV Running

**Severity:** MEDIUM — PTES accuracy
**Status:** DOCUMENTED

### Evidence (eng-beb01b)
- WV running at 10/100 tool calls
- 96 findings including A06 (45), A03 (25), A07 (17) vulnerability categories
- PTES shows Vuln Analysis as "No Coverage" (dark)
- All other phases show partial or covered

### Likely Root Cause
The PTES restore block maps WV agent status to Vuln Analysis phase. WV is `running` but the PTES cell doesn't show partial. Either:
1. The live WebSocket `updatePtesFromAgent('WV', 'running')` isn't firing
2. WV's events don't trigger the PTES update in the WebSocket handler
3. The restore block's `/api/agents` doesn't return WV status correctly

### Fix
Check the WebSocket handler for agent_status events — does it call `updatePtesFromAgent` for WV? Also check if WV is in the agent status response from `/api/agents`.

## BUG: Executive Summary Report Missing TYPE Badge Color

**Severity:** LOW — Cosmetic
**Status:** DOCUMENTED

### Problem
Reports page shows 3 reports. Technical has green TYPE badge, Remediation has red TYPE badge, but Executive Summary has no colored badge — just plain text "EXECUTIVE-SUMMARY".

### Root Cause
The badge color logic in index.html likely uses a map like:
```javascript
{"technical": "green", "remediation": "red"}
```
But "executive-summary" isn't in the map, so it renders as plain text without a badge.

### Fix
Add "executive-summary" to the report type badge color map — probably blue or teal to distinguish from the others.

## BUG: AI Cost Badge Shows Estimated Cost, Not Actual API Cost

**Severity:** MEDIUM — Misleading billing data
**Status:** DOCUMENTED

### Problem
Dashboard cost badge showed $10.28 but actual Claude API cost was ~$5.35. The badge uses estimated cost ($0.12/tool call average) instead of actual API cost reported by sdk_agent._report_actual_cost.

### Evidence (eng-beb01b)
- Budget API estimated: ~$44 total across all agents
- Dashboard badge: $10.28
- Actual costs from session-end logs: ~$5.35

### Root Cause
The cost tracking has two paths:
1. **Estimated cost** — calculated per tool call at budget endpoint (`estimated_cost += $0.12`)
2. **Actual cost** — reported by Claude SDK via `_report_actual_cost` after each API call

The dashboard badge and budget API use the ESTIMATED path. The actual cost is logged but not surfaced to the dashboard.

### Fix
The budget endpoint should prefer actual cost when available. `_report_actual_cost` writes to `budget["actual_cost"]` — the dashboard should read this instead of `budget["estimated_cost"]`. If actual is 0 (not yet reported), fall back to estimated.

### Files to Modify
- `server.py` — cost_update WebSocket broadcast should include actual_cost
- `index.html` — cost badge should prefer actual_cost over estimated_cost

## BUG: Kill Chain Lateral Move Lit Without Actual Lateral Movement

**Severity:** HIGH — Misleading security assessment, client-facing indicator
**Status:** DOCUMENTED

### Problem
Kill Chain Depth visualization shows "Lateral Move" as lit (active) but there were 0 LATERAL_MOVE edges in Neo4j and 0 credential reuse findings. An agent title claimed "Lateral movement confirmed: root on both hosts via port 1524" — but this was parallel exploitation of the same bindshell on two hosts, NOT an actual pivot (creds from Host A used on Host B).

### Root Cause
Kill Chain phases are triggered by keyword matching in finding titles/events — not by verified graph relationships. If any finding title contains "lateral movement", the Kill Chain lights up that phase. No verification against actual Neo4j LATERAL_MOVE edges or cross-host credential reuse evidence.

### Impact
- Client report would claim "Lateral Movement achieved" when it wasn't
- Misleading risk assessment — lateral movement implies network-wide compromise
- Pentester reviewing dashboard would assume pivot happened

### Fix
Kill Chain phases should only light up based on VERIFIED evidence:
- **Lateral Move:** Only lit when LATERAL_MOVE edges exist in Neo4j graph, OR when a credential harvested from Host A is confirmed working on Host B
- **NOT from:** keyword matching in finding titles or agent claims
- Server-side: add `/api/kill-chain` endpoint that checks actual graph relationships, not text matching
