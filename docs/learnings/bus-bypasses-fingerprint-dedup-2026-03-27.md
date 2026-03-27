# BUG: Bus Pipeline Bypasses Fingerprint Dedup — 97/97 Findings Have No Fingerprint

**Date:** March 27, 2026
**Severity:** CRITICAL — Root cause of all remaining duplicate findings
**Status:** DOCUMENTED — Not yet fixed

## Problem

97 out of 97 findings have no `fingerprint` field. All findings come through `/api/bus/publish` (bus pipeline) with `bus-*` IDs, NOT through `/api/findings` (fingerprint pipeline). The production-grade 5-tier fingerprint dedup we built only applies to `POST /api/findings` — which agents rarely use.

## Architecture Gap

```
Agent finding → POST /api/bus/publish → finding_pipeline.py → bus-* ID → NO fingerprint, NO MERGE
                                                                          ↑ ALL findings go here

Agent finding → POST /api/findings → _compute_finding_fingerprint() → MERGE on fingerprint
                                                                       ↑ NOTHING goes here
```

We built production-grade dedup on the wrong code path.

## Evidence

- `eng-eb2adc`: 97 findings, 0 fingerprints, 0 MERGE operations
- All finding IDs start with `bus-` (e.g., `bus-c18998c71b33f6f6`)
- The `/api/findings` endpoint has full MERGE/dedup logic but agents don't use it
- `finding_pipeline.py` has its own `dedup_key` (SHA256) but it's NOT the same as `_compute_finding_fingerprint`

## Root Cause

Agents post findings via bilateral bus messages (`POST /api/bus/publish`), which flow through `finding_pipeline.py`. This pipeline validates and broadcasts findings but creates Finding nodes WITHOUT the fingerprint-based MERGE that prevents duplicates.

## Proposed Fix

Apply the 5-tier fingerprint dedup to `finding_pipeline.py` — the bus path:

1. **finding_pipeline.py:** When creating a Finding from a bus message, compute `_compute_finding_fingerprint()` and store it on the Finding node
2. **finding_pipeline.py:** Use Neo4j MERGE on `{fingerprint, engagement_id}` instead of CREATE
3. **finding_pipeline.py:** Apply the same evidence merging, severity upgrade, and VF auto-confirmation logic that exists in `/api/findings`
4. **OR:** Redirect bus findings through `/api/findings` endpoint internally so all findings go through ONE dedup pipeline

Option 4 is cleaner — single source of truth for finding creation.

## Impact

- ALL duplicate findings in every engagement since the bus pipeline was introduced
- The fingerprint dedup we built is effectively dead code (nothing triggers it)
- Finding counts inflated by 2-3x across all engagements
- Confirmed exploit counts unreliable

## Files to Modify

- `finding_pipeline.py` — Add fingerprint computation + MERGE logic
- OR `server.py` — Route bus findings through `/api/findings` endpoint internally
