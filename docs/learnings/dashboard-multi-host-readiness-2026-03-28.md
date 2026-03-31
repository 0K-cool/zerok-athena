# Dashboard Multi-Host Readiness Audit — March 28, 2026

## Architecture Decision: Per-Engagement Host Selector (Phase 1) + Cross-Engagement Portfolio View (Phase 2)

### Decision

**Phase 1 (Next session):** Per-engagement host selector in the **left sidebar**, nested under the selected engagement. Scopes all KPIs and charts to a selected host.

```
ENGAGEMENTS (left sidebar)
  ★ Acme Corp Network        ← selected engagement
      All Hosts (3)           ← default, shows aggregate (current behavior)
      10.1.1.25               ← click to filter dashboard to this host
      10.1.1.31
  • Odin Server #4
  • Odin Server #3
```

**UX decision (Kelvin, Mar 28):** Option A — sidebar nesting. No new UI on the main dashboard area. Hosts expand under the selected engagement. Fits existing sidebar pattern.

**Phase 2 (Future):** Cross-engagement comparison view — separate dashboard page for ongoing client relationships (e.g., "Q1 vs Q2 posture improvement").

### Rationale

1. **Hosts don't persist across engagements** — 10.1.1.25 in eng-001 might be a different machine than 10.1.1.25 in eng-002
2. **Scope changes** — one engagement targets 5 hosts, the next targets 50
3. **Client isolation** — different engagements = different clients, mixing is dangerous
4. **Simpler queries** — Neo4j already scopes everything by engagement ID
5. **Backend ready** — 7 API endpoints already support `?host_ip=` filtering but the frontend never calls them

### Phase 2 Value Proposition

Cross-engagement comparison is a premium differentiator:
- "Here's how your security posture improved between Q1 and Q2 pentests"
- Retest validation: "These 12 CVEs were confirmed last quarter — 9 are now remediated"
- Trend tracking for ongoing client relationships

---

## Audit Summary

**21 issues found.** Backend is ahead of frontend — 7 API endpoints already support host filtering but the frontend never calls them.

### Backend APIs That Already Support Multi-Host (Unused by Frontend)

| API Endpoint | Host Support | Frontend Usage |
|---|---|---|
| `GET /api/engagements/{eid}/hosts` | Per-host list with finding/confirmed counts | **Never called** |
| `GET /api/engagements/{eid}/exploit-stats?host_ip=X` | Scoped exploit stats per host | **Never called** |
| `GET /api/engagements/{eid}/exploit-stats/by-host` | Grouped exploit stats for all hosts | **Never called** |
| `GET /api/engagements/{eid}/findings?host_ip=X` | Findings filtered by host | **Never called** |
| `GET /api/engagements/{eid}/report-data` | `findings_by_host` grouped structure | Only used by RP agent |
| `GET /api/engagements/{eid}/credentials` | `hosts_accessed` per-host breakdown | Ignores `hosts_accessed`, uses totals only |
| `GET /api/engagements/{eid}/services-summary` | `host_count` per service | Ignores `host_count`, counts array length only |

### Backend APIs That Need `host_ip` Filter Added

| API Endpoint | What's Missing |
|---|---|
| `GET /api/engagements/{eid}/vuln-severity` | No `host_ip` filter parameter |
| `GET /api/kpi/mtte` | Computes engagement-wide only, no per-host |
| `GET /api/engagements/{eid}/summary` | Aggregate counts only, no per-host breakdown |
| `GET /api/findings/trends` | No host dimension in trend data |
| First shell / TTFS endpoint | No per-host TTFS — only engagement-level |
| Scan coverage | No per-host scan progress tracking |

---

## All Issues (Prioritized)

### P0 — Reported Bug

#### Issue 1: Remediation Priority Chart Y-axis Always Shows "1"

**Widget:** Remediation Priority bubble chart (CVSS × Hosts)
**Lines:** index.html:12565-12591 (data mapping), 8570-8600 (chart init)
**Root Cause:** Line 12570:
```javascript
y: Array.isArray(f.affected_hosts) ? f.affected_hosts.length : (f.affected_hosts || 1)
```
Each finding represents ONE host, so `affected_hosts` is either null/undefined (defaults to 1) or a single-element array (length=1). Findings are never grouped by CVE across hosts.
**Fix:** Group findings by CVE/fingerprint before charting. A single bubble for "CVE-2007-2447" should show Y=2 if it affects both 10.1.1.25 and 10.1.1.31. Server-side grouping via new endpoint or client-side aggregation.

---

### P1 — Critical for Multi-Host

#### Issue 2: No Global Host Selector/Filter (Architectural Gap)

**Impact:** Zero way to scope any widget to a specific host. Every widget shows engagement-wide aggregates.
**Fix:** Add a host dropdown populated from `/api/engagements/{eid}/hosts` (already exists). When a host is selected, pass `host_ip` to all API calls. "All Hosts" shows aggregate (current behavior).
**Scope:** index.html — new dropdown component + wiring to every `loadDashboardFromAPI()` call.

---

### P2 — High Value (Backend Ready, Frontend-Only Work)

#### Issue 3: Hosts Discovered KPI — Flat Count, No Drill-down

**Lines:** index.html:6305-6310 (HTML), 13234-13248 (JS update)
**Current:** Single integer. No click handler, no host list.
**Fix:** Click opens host list panel from `/api/engagements/{eid}/hosts`. Show IP, OS, finding count, confirmed count, compromise status.

#### Issue 4: Total Exploitable KPI — No Per-Host Breakdown

**Lines:** index.html:6329-6336 (HTML), 12716-12724 (JS)
**Backend:** `/exploit-stats?host_ip=` and `/exploit-stats/by-host` already exist.
**Fix:** When host selected, call with `?host_ip=`. When "All Hosts", show aggregate.

#### Issue 5: Exploit Gauge — Engagement-Wide Only

**Lines:** index.html:9541-9600 (updateExploitGauge)
**Backend:** `/exploit-stats/by-host` exists.
**Fix:** Scope to selected host. Show "8/47 hosts fully compromised" in aggregate mode.

#### Issue 6: Credential Tracker — Ignores `hosts_accessed` Field

**Lines:** index.html:6671-6695 (HTML), 10363-10376 (updateCredentialTracker)
**Current:** Only uses `total`, `default_weak`, `unique_accounts`. Ignores per-host breakdown.
**Fix:** Show per-host credential access when host is selected.

#### Issue 7: Findings Table — No Host Filter Column

**Lines:** index.html:14201-14261 (loadFindings)
**Backend:** `?host_ip=` param exists on findings endpoint.
**Fix:** Add host dropdown filter to Findings view. Pass `host_ip` to API.

#### Issue 8: Services KPI — Ignores `host_count` Per Service

**Lines:** index.html:12761-12775
**Backend:** `/services-summary` already returns `host_count` per service.
**Fix:** Show "SSH (22): 47 hosts, HTTP (80): 32 hosts" in service drill-down.

---

### P3 — Moderate Effort (Backend + Frontend)

#### Issue 9: TTFS — Single Engagement-Wide Metric

**Lines:** index.html:6337-6345, 12733-12739. server.py: TTFS query.
**Fix:** Add per-host TTFS. Show "Host Compromise Timeline" — when each host fell.

#### Issue 10: MTTE — Aggregated Across All Hosts

**Lines:** index.html:6346-6355, 12741-12759. server.py: MTTE calc.
**Fix:** Add per-host MTTE. Show median + range for multi-host.

#### Issue 11: Severity Bar Chart — No Host Filter

**Lines:** index.html:6417-6463, 10665-10713 (updateSeverityChart)
**Fix:** Add `host_ip` param to vuln-severity endpoint. Scope chart to selected host.

#### Issue 12: Vulnerability Status Donut — Global Only

**Lines:** index.html:10716-10732. server.py: vuln-severity (no host_ip filter).
**Fix:** Same as severity chart — add host_ip filter to backend + frontend.

#### Issue 13: Total Findings KPI — No Host Distribution

**Lines:** index.html:6321-6328, 12482-12486
**Fix:** Show "87 findings across 12 hosts" or scope to selected host.

#### Issue 14: Findings Over Time Trend Chart — No Host Dimension

**Lines:** server.py:5828-5954 (trends endpoint). index.html:12532-12533.
**Fix:** Add host_ip grouping to trends. Show per-host trend lines or stacked area.

---

### P4 — Enhancement (UX Design Required)

#### Issue 15: Kill Chain Stepper — No Per-Host Progression

**Lines:** index.html:10305-10361 (updateKillChain)
**Current:** Keyword-matches ALL findings globally. If ANY finding matches "lateral movement", that stage lights up.
**Fix:** Per-host kill chain depth or host-level maximum display.

#### Issue 16: Attack Surface Radar — Global Category Distribution

**Lines:** index.html:12543-12563
**Fix:** Filterable per host or aggregate with host-count overlays.

#### Issue 17: Recent Findings Widget — No Host Column

**Lines:** index.html:12507-12521, 10213-10260 (createFindingEntry)
**Fix:** Add host IP column/tag to each finding entry.

#### Issue 18: PTES Progress Matrix — Global, Not Per-Host

**Lines:** index.html:6726-6810, 11100-11111, 12847-12927
**Fix:** Per-host PTES coverage or "45/47 hosts at Exploitation, 2 at Recon".

#### Issue 19: AI Timeline — No Host Tagging

**Lines:** index.html:12929-12940
**Fix:** Tag events with target host IP (many events carry `metadata.target`).

#### Issue 20: Attack Graph — Multi-Host Aware but Isolated

**Current:** Actually the most multi-host-aware widget — shows Host/Service/Finding nodes.
**Gap:** No interaction with main dashboard. Clicking a host in the graph doesn't filter KPIs.

#### Issue 21: Scan Coverage Ring — Global Only

**Lines:** index.html:6466-6479, 9509-9538
**Fix:** Per-host scan progress tracking ("X% of hosts fully scanned").

---

## Implementation Plan (Estimated)

| Phase | Work | Effort | Dependencies |
|---|---|---|---|
| **Phase 1a** | Fix Remediation chart bug (P0) | 1-2 hours | None |
| **Phase 1b** | Build global host selector dropdown (P1) | 3-4 hours | None |
| **Phase 1c** | Wire P2 widgets to host selector (6 widgets) | 4-6 hours | Phase 1b |
| **Phase 2** | Add host_ip to P3 backend endpoints + wire | 6-8 hours | Phase 1b |
| **Phase 3** | P4 UX enhancements | 8-12 hours | Phase 2 |
| **Phase 4** | Cross-engagement portfolio view | 12-16 hours | Phase 3 |

**Total estimated: ~35-48 hours across multiple sessions**
