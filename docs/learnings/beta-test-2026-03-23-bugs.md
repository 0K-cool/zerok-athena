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

### FR-S2-001: Add /docs/ as explicit RAG fallback in agent prompts [HIGH]
RAG KB can return empty or fail entirely. Agents should have a local fallback: read playbooks and knowledge docs directly from `/docs/playbooks/` and `/docs/knowledge/` directories. Add to the shared agent prompt fallback chain:

1. RAG KB (MCP tool `mcp__athena_knowledge_base__search_kb`)
2. If empty → `searchsploit` (Kali local Exploit-DB)
3. If empty → **NEW: Read local docs** — `ls docs/playbooks/ docs/knowledge/` then `cat docs/playbooks/<relevant-file>.md`
4. If still empty → Online sources (AttackerKB, NVD, PacketStorm, GitHub PoCs, CISA KEV)

This ensures agents always have access to methodology playbooks even when RAG MCP server is down or returns no results. The 16 playbooks in `docs/playbooks/` cover: AD attacks, scanning, C2, cloud, credentials, LOTL/privesc, network, web app, CVE research, evidence collection, SQL injection, etc.

### FR-S2-002: Agent speed optimization — parallel verification + batch scanning [HIGH]
Improve agent speed without compromising verification integrity or creating bottlenecks on ATHENA or Kali:

**VF optimization:**
1. Parallel verification batches — verify 2-3 services simultaneously
2. Prioritize EX-confirmed exploits at front of queue
3. Batch nmap scans — `nmap -p 21,445,6667 --script <relevant-scripts>` instead of one port at a time
4. Skip redundant verifications (dedup across EX + DA findings for same service)

**Apply same analysis to ALL agents:**
- AR: batch port scans (already doing naabu + nmap batching)
- EX: prioritize highest-CVSS targets first
- DA: batch searchsploit queries instead of one-at-a-time
- PE: start post-exploitation as soon as first shell is obtained, don't wait for all exploits

**Key constraint:** No bottlenecks on ATHENA server or Kali backends. Parallel tool calls should use asyncio.gather where possible.

**Dynamic resource check (adaptive speed):**
Agents should adapt speed based on host resources and architecture:
1. **Kali backend latency probe** — at engagement start, measure tool response time. <2s = aggressive batching. >10s = conservative sequential.
2. **Target resilience check** — monitor for connection resets, timeouts, OOM signals. If target is fragile (like Juice Shop), reduce scan intensity automatically.
3. **ATHENA server load** — if event loop latency >500ms or CPU >80%, throttle agent tool call frequency.
4. **Kali concurrent capacity** — test with 2-3 parallel requests at start. If all succeed <5s, allow parallel. If timeouts, fall back to sequential.
5. **Architecture-aware** — ARM/embedded targets need gentler scanning than full Linux servers. Detect from OS fingerprint.

**Operator host (where agents run) — most important factor:**
Claude SDK agent sessions run locally. The host machine dictates how many parallel agents are sustainable:
- M1 Air (8 cores, 16GB) — max 4-5 concurrent agents before degradation
- M1/M2 Pro (10-12 cores, 32GB) — 6-8 concurrent agents
- M4 Max (16 cores, 128GB) — 10+ concurrent agents
- Cloud VM — scale by vCPU count

At engagement start, ST should check local resources:
- `sysctl -n hw.ncpu` — core count
- `sysctl -n hw.memsize` — total RAM
- `uptime` — current load average
- If load > 0.7 × cores, reduce concurrent agents (pause lowest priority)
- If available RAM < 2GB, defer DA/PE until AR/EX complete

ST should query these metrics during SITREP cycles and adjust agent aggressiveness dynamically:
- `GET /api/kali/health` — backend response times
- `GET /api/status` — ATHENA server load + host resource metrics
- Target response patterns from AR scan results
- Local host: load average, memory pressure, swap usage

**Future: Cloud-hosted agents**
Agents don't need to run on operator's laptop. Architecture already supports remote:
- Agents communicate via HTTP/WebSocket (not local IPC)
- Cloud VM: check vCPU/RAM via metadata API (AWS IMDSv2, GCP metadata)
- Container: read cgroup limits
- Kubernetes: pod resource requests/limits
- Serverless: function memory allocation
- Enables: parallel pentests, unlimited agent scaling, operator on thin client
- Dashboard + Neo4j + Kali backends stay where they are — only agent runtime moves

### BUG-S2-004: Exploit count inflated — duplicate findings not deduped [HIGH]
Shows 20 confirmed exploits but only ~8 are truly unique. Multiple agents (EX, DA, ST) post findings for the same CVE with slightly different titles, bypassing the fingerprint-based MERGE dedup:
- "CVE-2011-2523: vsftpd 2.3.4 Backdoor" (EX) vs "CVE(s) detected: CVE-2011-2523, CVE-2010-2075..." (DA)
- "6 CRITICAL CVEs confirmed..." is a batch summary, not an individual exploit
- "31 open TCP ports" counted as exploitable but isn't an exploit

**Fix:** Improve finding deduplication — extract CVE IDs from titles and dedup on CVE + host + port combination. Batch CVE findings should be split into individual findings or excluded from exploit count. Port discovery findings should not count as exploitable.

### BUG-S2-005: Open Ports KPI shows 27 but 31 ports discovered [MEDIUM]
KPI label says "Open Ports" but value reads from `services` count (27) not actual open ports (31). Naabu found 31 open ports, nmap identified services on 27. The 4 unidentified ports are still open but not counted.

**Fix:** Either change the KPI to read actual open port count from naabu/scan results, or rename the label to "Services" to match what it displays.

### FR-S2-003: ST needs override authority as Red Team leader [HIGH]
ST is the team leader but can't override system gates:
- RP blocked because workers still running — ST should force-stop workers and deploy RP
- ST says "engagement at saturation" but system ignores the decision
- Workers consuming budget unnecessarily after ST declares completion

**Fix:** Give ST explicit override commands:
1. `POST /api/agents/stop-all-workers` — ST can stop AR, EX, DA, PE, VF in one call
2. `POST /api/agents/force-spawn` — bypass "workers still running" gate for RP
3. Phase transition: when ST declares phase change (e.g., "Reporting"), automatically stop workers not needed for that phase
4. Budget authority: ST can freeze agent budgets to prevent further spending

ST is the Red Team leader. The system should execute ST's decisions, not block them.

### Evidence Pipeline Improvements (from Session 2 audit)

**Current state (50 artifacts, eng-aadee9):**
- Content: 50/50 (100%) ✅
- Tagged: 17/50 (34%) — 33 untagged (mostly AR scans)
- Finding-linked: 23/50 but only 4 unique finding IDs
- Proof quality: 4 root shells, 17 Metasploit sessions, 5 credential proofs ✅

**Fixes needed:**

**FIX-EV-001: 33 untagged artifacts [MEDIUM]**
AR (19) and auto-captured artifacts have no evidence_type. Add `evidence_type="reconnaissance"` for AR outputs. Auto-captured nmap/httpx outputs should be tagged based on the capturing agent.

**FIX-EV-002: Evidence clusters on 1 finding — only 4 unique finding IDs [HIGH]**
23 artifacts link to findings but most point to the same finding (find-11ecfe0a). `_last_finding_id` stays stale too long. Fix: after each evidence capture, check if a NEW finding was created since last capture and update `_last_finding_id` proactively. Or: match evidence to findings by CVE/service/port correlation, not just last-created order.

**FIX-EV-003: PE evidence too thin — 1/3 tagged [MEDIUM]**
`_is_post_exploitation_result` indicators are too narrow. PE outputs contain SUID binary lists, /etc/shadow dumps, network mapping — but only 1 matched. Widen indicators: add "sbin", "/usr/bin", "ifconfig", "netstat", "arp", "route", "cat /etc", "whoami", "id".

**FIX-EV-004: All evidence is command_output — no variety [LOW]**
No screenshots, HTTP request/response pairs, or response diffs despite UI filter options existing. Future: VF should capture HTTP pairs for web vulns, EX should capture Metasploit session logs as separate type.

**FIX-EV-005: Evidence titles generic — "Exploitation evidence — mcp_k..." [MEDIUM]**
All titles say "Exploitation evidence — mcp__kali_external__execute_command". Should be descriptive: "Root shell via vsftpd backdoor (CVE-2011-2523)" based on the finding title or tool context.

**FIX-EV-006: Evidence Gallery shows 0 then loads after delay [LOW]**
First screenshot showed "No evidence yet" then second showed 40 artifacts. Same engagement filter / loading race as other pages.

**FIX-EV-007: ALL evidence must be registered and viewable on dashboard [HIGH — NON-NEGOTIABLE]**
Every piece of evidence captured by any agent MUST:
1. Be registered as an artifact via the `/api/artifacts/text` or `/api/artifacts` endpoint
2. Be viewable in the Evidence Gallery on the ATHENA dashboard
3. Be linked to the finding it proves
4. Be downloadable/exportable for client delivery
5. Include: the command run, the output received, the agent that captured it, timestamp

No hidden evidence in log files or agent memory. If it's not on the dashboard, it doesn't exist for the client. The Evidence Gallery is the single source of truth for all pentest proof. Clients and auditors must be able to browse, filter, and download all evidence from the dashboard without touching the filesystem.

### BUG-S2-006: KPI values flicker between two counts [HIGH]
Total Findings flickers between 134 and 119. Drawer stats alternate between "0 vulns" and "125 vulns". Two data sources fight: KPI poll (loadDashboardFromAPI every 5s) vs WebSocket real-time events. Each overwrites the other.

**One source of truth rule:** The API poll should be authoritative. WebSocket events should only INCREMENT counts, never decrease them. If WS says 119 but last API poll said 134, keep 134. Apply Math.max() on all KPI updates to prevent downward flicker.

**Fix:** In every KPI update path (both API poll and WS handler), use:
```javascript
kpiEl.textContent = Math.max(parseInt(kpiEl.textContent || '0'), newValue);
```

### BUG-S2-007: Attack Graph — credential nodes visible but no HARVESTED_FROM edges [HIGH]
Purple triangle credential nodes appear (cred-077a7841, cred-ec06145a, cred-c6858327) but no purple dotted lines connect them to hosts. The Neo4j HARVESTED_FROM edge fix (commit ddc773f) was deployed but the server wasn't restarted — credentials were posted via the old in-memory path, not through Neo4j. Next engagement after restart should create the edges. Verify the graph query at GET /api/attack-graph includes HARVESTED_FROM in its relationship types.

### BUG-S2-008: Attack Graph Refresh button doesn't work [MEDIUM]
Clicking Refresh does nothing visible. The graph stays the same. May need to re-fetch data from API and redraw the vis.js network.

### BUG-S2-009: Attack Graph Reset View very slow [MEDIUM]
Reset View works but takes a long time (5-10 seconds) on a dense graph with 167 nodes. The vis.js physics simulation recalculates all node positions. Consider: disable physics after initial layout stabilizes, or use a simpler layout (hierarchical) for large graphs.

### BUG-S2-010: Attack Graph too dense/cluttered at 100+ nodes [LOW]
With 100 findings, 27 services, 21 attack paths, the graph is unreadable — labels overlap, edges are tangled. Consider: cluster nodes by service/CVE, collapse credentials into a single node with count badge, or add zoom/filter controls.

---

## Notes

- L4 injection scanner false-positives on ATHENA's own CVE findings ("unauthenticated root access" etc.) — expected for pentest platform, not a real injection
- Beta tester agent running in parallel — additional bugs may be reported
