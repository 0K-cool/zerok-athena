# Beta Test Bugs — March 23, 2026 (01:00 AM AST Session)

**Engagement:** 0din Server (eng-6d06ef), Target: 10.1.1.25/32
**Server version:** Post athena-config.yaml + RAG Settings commits

---

## BUG-001: Confirmed Exploit Rate gauge not updating [HIGH]

**Page:** Dashboard
**API data:** `confirmed_exploits: 1`, `success_rate: 12.5%`, `discovered_vulns: 16`
**Expected:** Confirmed Exploit Rate gauge shows 12.5% (1 confirmed / 16 discovered)
**Actual:** Gauge stays at 0%
**Root cause:** Likely the dashboard JS that reads exploit-stats and updates the gauge SVG isn't firing or is reading the wrong field.

**Check:** `index.html` — search for `exploit-rate` or `scan-coverage-arc` or the gauge update function. Verify it reads from `/api/engagements/{eid}/exploit-stats` and maps `success_rate` to the gauge.

---

## BUG-002: Mean Time to Exploit (MTTE) not displaying [HIGH]

**Page:** Dashboard — MTTE KPI card in top bar
**API data:** `mtte_seconds: 325`, `mtte_display: "5m 25s"`
**Expected:** MTTE KPI shows "5m 25s"
**Actual:** MTTE shows blank/dash
**Root cause:** Similar to BUG-001 — the KPI update function isn't reading from exploit-stats or isn't being called when exploit data changes.

**Check:** `index.html` — search for `kpi-mtte` or `mtte` and verify the update path.

---

## BUG-003: Command Router (CR) times out after 60 seconds [HIGH]

**Page:** AI Drawer / Operator Command input
**Steps to reproduce:**
1. Start engagement — CR spawns alongside ST
2. Wait 60 seconds without sending operator commands
3. CR session ends ("No operator commands for 60 seconds")
4. Send operator message — no response (CR offline, ST busy)

**Expected:** CR stays alive for the entire engagement duration, always ready to route operator commands instantly.
**Actual:** CR exits after 60s of inactivity. Operator messages go unprocessed until ST finishes its current tool chain.

**Fix options:**
1. Remove the 60s timeout from CR — keep it alive until engagement stops
2. Increase timeout significantly (e.g., engagement duration)
3. Auto-respawn CR when an operator message is received and CR is offline

---

## BUG-004: Stale RAG search event persists across engagement deletion [MEDIUM]

**Page:** AI Drawer
**Steps to reproduce:**
1. Run a RAG search during an engagement (or via curl test)
2. Delete the engagement
3. Create a new engagement
4. Open AI Drawer — stale RAG search event from old engagement still visible

**Root cause:** RAG events were stored without `engagement_id` in metadata, so the engagement deletion filter didn't catch them. FIXED in commit 85ff1d8 — events now include `engagement_id` and orphan cleanup works.

**Status:** FIXED

---

## BUG-005: DA/PX/WV blocked for external engagements [MEDIUM]

**Page:** AI Drawer — ST tool calls
**Steps to reproduce:**
1. Start an external engagement
2. ST requests DA agent
3. Server returns 400: "Agent DA not allowed for engagement type(s) ['external']"

**Root cause:** `_AGENTS_BY_TYPE["external"]` didn't include DA, PX, or WV. ST should decide strategy, not a hardcoded gate.

**Status:** FIXED in commit 24967cd — all agents allowed for all engagement types.

---

## BUG-006: RAG search event shows "AGENT" instead of agent code [LOW]

**Page:** AI Drawer
**Steps to reproduce:**
1. An agent hits `/api/knowledge/search` without the `?agent=XX` parameter
2. Event renders as "AGENT RAG SEARCH" instead of "AR RAG SEARCH"

**Expected:** Agent code should be identified from the request context or default to the requesting agent.
**Fix:** Agents should include `&agent=AR` in their RAG search URLs. Update agent prompts to include the agent parameter.

---

## BUG-007: RAG search error shows Python code snippet [LOW]

**Page:** AI Drawer
**Steps to reproduce:**
1. RAG search fails (vex-rag subprocess error)
2. Error message shows raw Python: `(import sys, os; sys.path.insert(0, '/Users/kelvinlomboy/tools/vex-rag'); from mc`

**Root cause:** Error sanitization strips tracebacks but the `error` field in metadata still contains the raw subprocess stderr. The restore path renders `metadata.error` directly.
**Partial fix:** Commit 9ac5581 sanitizes new events. Old events in Neo4j still have raw errors.

---

## BUG-008: Stop button appears to work then re-engages [CRITICAL]

**Page:** Dashboard — Engage AI / Stop controls
**Steps to reproduce:**
1. Engagement is running with multiple agents active
2. Click Stop button
3. UI briefly shows "Stopping..." / idle state
4. Engagement restarts — agents re-engage automatically

**Expected:** Stop kills all agents, engagement goes idle, stays idle.
**Actual:** Stop fires but engagement re-engages moments later. Likely a WebSocket state sync or agent respawn issue.

**Root cause candidates:**
1. `window._stopRequested` flag gets cleared too early, WebSocket `session_state` handler reverts to running
2. An agent's pending tool call completes after stop, triggering a respawn
3. ST's `sleep 30 && curl` polling command fires after stop and re-activates the engagement
4. The agent session manager's stop doesn't cancel all `_agent_tasks` — a surviving task restarts

**Priority:** CRITICAL — operator cannot reliably stop an engagement

---

## BUG-009: PTES Methodology Coverage matrix all phases showing Covered [HIGH]

**Page:** Dashboard — Methodology Coverage widget
**Steps to reproduce:**
1. Start engagement with 0din Server
2. AR runs recon, EX starts exploitation
3. All PTES phases show as "Covered" (red) even though only Pre-Engagement and Intel Gathering have activity
4. Tool lists overflow cell boundaries — long MCP tool names (mcp__athena-neo4j__create_host etc.) break the layout

**Expected:** Only phases with actual agent activity show as Covered/Partial. Tool lists should be truncated or hidden to fit cells.
**Actual:** All phases red, tool names overflow cells, columns cut off ("THREAT MO...")

**Root cause:** The dynamic PTES matrix (`updatePtesToolList`) is likely mapping ALL tool calls to phases regardless of which agent ran them, or the phase-to-agent mapping is too broad.

**Check:** `index.html` — search for `updatePtesToolList` and `_agentToolsUsed`. Verify the phase mapping only marks a phase as covered when the correct agent type runs tools (e.g., Exploitation only covered when EX runs exploit tools, not when AR runs nmap).

---

## Feature Requests

### FR-001: CR should acknowledge operator messages immediately [MEDIUM]
When operator sends a message, CR should respond instantly with "Message received, forwarding to ST" — even if ST is busy mid-tool-chain. Currently CR routes the message but there's no feedback to the operator, creating a silent gap that feels like the message was lost.

### FR-002: ST should have full real-time cost visibility [HIGH]
ST's SITREP reports "$1.16 of $18 (6.5% used)" while dashboard KPI shows $3.40. ST is self-estimating costs instead of querying the actual cost API. ST should query `/api/budget` for:
- **Total actual cost** (all agents combined)
- **Per-agent cost breakdown** (AR: $X, EX: $Y, VF: $Z)
- **Budget cap remaining** (runway left before engagement cap)
This enables ST to make cost-aware decisions: deprioritize low-value targets when budget is tight, trigger RP for final report at 80% budget, etc. ST is team leader — full visibility is mandatory.

### FR-003: Evidence architecture — EX + VF both capture, tagged differently [HIGH]
**Current state:** 50 artifacts exist but all `command_output` type with empty content fields. Agents create artifact records but don't populate them with actual output.

**Evidence architecture:**
- **EX** captures `evidence_type: "exploitation"` — shell output, command results, proof of access. Raw immediate proof. Used in report Attack Methodology section.
- **VF** captures `evidence_type: "verification"` — independent reproduction using different tools. Screenshots of confirmed access. Court-admissible proof. Used in report Findings/Proof section.
- **RP** consumes both — EX evidence for the attack narrative, VF evidence for the proof section.

**Bugs to fix:**
1. Artifacts have empty `content` — `_capture_exploitation_evidence()` in sdk_agent.py POSTs to `/api/artifacts/text` but content not flowing through
2. No `evidence_type` field on artifacts — need to tag as "exploitation" vs "verification"
3. No screenshots captured — VF should take screenshots on confirmed exploits via Kali Playwright endpoint
4. Evidence not linked to findings — artifacts exist as orphan nodes, not connected via HAS_ARTIFACT

### FR-004: Credential Tracker shows 0 despite agents finding creds [HIGH]
**Was working previously.** Agents found tomcat:tomcat, MySQL no-password root, VNC password "password", bindshell no-auth — but Credential Tracker shows 0. Agents are reporting creds as regular findings instead of using `msg_type: "credential"`. DA tried `msg_type: "debrief"` and got rejected (debrief not in valid types). The `credential` type exists in valid message types — agents just aren't using it. Investigate: did recent prompt changes break the credential posting flow? Check agent_configs.py for credential-specific instructions.

### FR-005: CR should show "Message forwarded to ST" in AI drawer [LOW]
A visible event card when CR forwards a message to ST, so the operator can see the routing pipeline working.

### SYSTEMIC: Page loading failure during active engagement [CRITICAL]
Multiple pages show 0 data and "Loading..." while engagement is active, despite sidebar badges showing correct counts. Affects: Engagements, Findings, Vulnerabilities, Attack Graph, Reports. Dashboard KPI cards work fine. Likely Neo4j query contention (agent writes vs page reads) or currentEngagementId being lost on navigation. **#1 priority for next session.**

### BUG-NEW-001: Reports can't be downloaded from dashboard [HIGH]
Reports page shows 3 reports (Technical, Executive Summary, Remediation Roadmap) but download fails. Files exist on disk at `engagements/active/eng-6d06ef/09-reporting/*.md`. The download button/link either hits the wrong path, the serve endpoint fails, or report content is only in filesystem not accessible via API. Investigate the report download handler in server.py and the click handler in index.html.

### BUG-NEW-002: Findings Over Time chart — single data point [MEDIUM]
Chart shows all findings as one flat line at a single timestamp instead of accumulating over time. Both "By Client" and "All Engagements" views affected. Was working previously. Likely finding timestamps not distributing correctly or chart bucketing logic broken.

### BUG-NEW-002: Empty System CONTROL card [LOW]
Saw a System CONTROL card with no content — just red icon and timestamp (02:55:07). Event emitted with empty/null content.

### BUG-NEW-003: Attack Graph slow to load [MEDIUM]
Attack Graph shows "Loading attack graph..." for extended time during active engagement. Eventually loads after engagement activity slows. Badge shows 107 items but page stays blank. Related to systemic loading issue.

---

## Late Session Bugs (05:00 AM round)

### BUG-LATE-001: Exploit Rate gauge shows 100% with 0 confirmed [HIGH]
Gauge shows 100% but text reads "0 confirmed + 1 unverified / 1". The calculation uses `(confirmed + unverified) / total` instead of `confirmed / total`. The gauge numerator is wrong — unverified should not count as confirmed.

### BUG-LATE-002: Stop button blocked by Attack Chains widget [MEDIUM]
The `attack-chains-body` widget overlaps the Stop button area (z-index issue). Physical clicks hit the widget, not the button. Only JS `.click()` bypasses it. Fix: increase z-index on the control bar or set `pointer-events: none` on the empty attack chains widget body.

### BUG-LATE-003: Findings page stuck on "Loading..." [HIGH — recurring]
Badge shows correct count but table never loads. The dropdown recovery fix didn't fully resolve this — may be a separate rendering or API response parsing issue. Needs deeper investigation of `loadFindings()` data flow.

### BUG-LATE-004: Vulnerabilities page empty despite badge count [HIGH — recurring]
Same pattern as Findings — badge shows 1 but page shows "No vulnerability data yet." Dropdown recovery applied but not resolving.

### BUG-LATE-005: MTTE never populates despite confirmed exploits [MEDIUM — recurring]
Despite 100% exploit rate shown, MTTE KPI stays at "--" throughout entire engagement lifecycle. The `es` scoping fix was applied but MTTE still not updating. May need the exploit-stats endpoint to be called more frequently or the MTTE display logic has a second issue.

### BUG-LATE-006: Coverage jumps to 100% on stop [LOW]
Scan coverage was 44% during running engagement, jumped to 100% immediately after stop. Artificial — doesn't reflect actual scan progress. Likely the stop/reset flow sets coverage to 100% instead of preserving the last real value.

### BUG-LATE-007: /api/events fetch unresponsive from browser context [LOW]
The events API doesn't respond to fetch calls from the Playwright browser context (timeouts). May be CORS or routing issue. Dashboard's own JS can access it but external fetch fails.

---

## Session 2 Bugs (5:45 PM round)

### BUG-S2-001: MTTE filter too broad — includes high/critical severity, not just confirmed exploits [MEDIUM]
MTTE exploit filter includes findings with high/critical severity, not just VF-confirmed exploits. This inflates MTTE with findings that were never actually exploited.

**Fix:** MTTE = time from engagement start to **first successful EX exploit** (first finding where EX agent confirmed shell/RCE/access). Not average across all exploits, not VF-confirmed, not severity-based. Just: engagement started → EX got first shell → that delta is MTTE. Simple, clean, client-meaningful: "an attacker could compromise your system in 25 seconds."

Filter: first finding where `agent = "EX"` AND (`evidence IS NOT NULL` OR has HAS_ARTIFACT relationship OR title contains exploit indicators like "root shell", "RCE confirmed", "backdoor").

### BUG-S2-002: Attack Graph missing Harvested Creds purple dotted lines [MEDIUM]
4 credentials exist (PostgreSQL, MySQL root, rlogin, Tomcat) and show in selection panel, but no HARVESTED_FROM edges connect them to hosts/services in the graph visualization. Legend shows "Harvested Creds" with purple dotted lines but none rendered.

### BUG-S2-003: Evidence capture only from EX/VF — need PE and DA too [HIGH]
PE harvests credentials and DA discovers services/vulnerabilities but neither captures evidence artifacts. Only EX (exploitation) and VF (verification) trigger _capture_exploitation_evidence. PE should capture credential evidence, DA should capture analysis evidence. Add evidence capture for all active agents, with evidence_type tags: "exploitation" (EX), "verification" (VF), "post_exploitation" (PE), "analysis" (DA).

---

## Notes

- L4 injection scanner false-positives on ATHENA's own CVE findings ("unauthenticated root access" etc.) — expected for pentest platform, not a real injection
- Beta tester agent running in parallel — additional bugs may be reported
