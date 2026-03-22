# MTTE Still Shows "—" — 6th Confirmation Path Missing confirmed_at

**Created:** 2026-03-22
**Status:** Pending fix
**Priority:** HIGH — MTTE KPI broken despite confirmed exploit

## Problem

1 confirmed exploit exists. `exploit-stats` returns `mtte_display: "6m 37s"` (in-memory calculation). But `/api/kpi/mtte` returns null because `confirmed_at` is NOT set on the Finding node in Neo4j.

We fixed 5 confirmation paths in the prior session. There's a 6th path that sets finding status to confirmed without writing `confirmed_at` to Neo4j.

## Evidence

- `GET /api/engagements/eng-da7592/exploit-stats` → `mtte_seconds: 397, mtte_display: "6m 37s"` ✅
- `GET /api/kpi/mtte?engagement=eng-da7592` → `mtte_seconds: null` ❌
- Dashboard MTTE KPI card shows "—"

## Investigation

Find the 6th confirmation path — likely one of:
1. EX agent posting a finding with "CONFIRMED" in the title directly via `/api/findings`
2. The finding dedup MERGE path setting status but not confirmed_at
3. A bus message path that updates finding status without Neo4j write
4. ST or EX calling a different API endpoint that sets exploit status

Check: query Neo4j directly for the confirmed finding and see if `confirmed_at` is null:
```cypher
MATCH (f:Finding {engagement_id: "eng-da7592"})
WHERE f.verification_status = "confirmed" OR f.status = "confirmed"
RETURN f.id, f.title, f.status, f.confirmed_at, f.discovered_at
```

## Workaround

The dashboard could fall back to `exploit-stats` MTTE when `/api/kpi/mtte` returns null. But the proper fix is finding and patching the 6th path.
