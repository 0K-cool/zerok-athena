# MTTE Shows "—" Despite Confirmed Exploits

**Created:** 2026-03-21
**Status:** Pending fix
**Priority:** HIGH — KPI data integrity

## Problem

MTTE KPI shows "—" when 1+ exploits are confirmed. The `/api/kpi/mtte` endpoint returns null because Finding nodes in Neo4j don't have `confirmed_at` set, even though verification confirms them.

## Evidence

| Endpoint | MTTE | Notes |
|----------|------|-------|
| `/api/engagements/{id}/exploit-stats` | 12m 47s | Works — uses in-memory timestamp spread |
| `/api/kpi/mtte?engagement={id}` | null / "—" | Broken — Neo4j `confirmed_at` is NULL |

Dashboard uses `/api/kpi/mtte` (Bug A fix from prior session).

## Root Cause Investigation Needed

The code at `server.py:2601-2633` DOES set `confirmed_at` on the Finding node when `result.status == "confirmed"`. But the MTTE endpoint at `server.py:2160` queries for findings where BOTH `discovered_at IS NOT NULL AND confirmed_at IS NOT NULL` and gets zero results.

Possible causes:
1. The verification result path (`POST /api/verify/{id}/result`) isn't being reached for this engagement
2. VF's silent session bug means VF confirms via bilateral message to ST, but doesn't call the verification result API
3. The finding status is set to `confirmed` somewhere else (e.g., finding creation with CONFIRMED title) without setting `confirmed_at`
4. `discovered_at` might not be set on findings created through certain paths
5. The `confirmed_at` Cypher SET clause is conditional (`if confirmed_at_val is not None`) and may not fire

## Fix Approach

Trace ALL paths where a finding's status becomes "confirmed" and ensure each one sets `confirmed_at`:
1. VF verification result endpoint (`server.py:2601`)
2. Finding merge during dedup (`server.py:1908-1911`)
3. Finding creation with "CONFIRMED" prefix in title (`server.py:~1896`)
4. Any other path that sets `f.status = 'confirmed'`

Also ensure `discovered_at` is set on ALL finding creation paths.
