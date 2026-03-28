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
