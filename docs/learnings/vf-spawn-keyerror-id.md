# VF Spawn Crash — KeyError: 'id'

**Created:** 2026-03-22
**Status:** Pending fix
**Priority:** HIGH — VF never starts, blocks verification + screenshots

## Problem

ST correctly calls `POST /api/agents/request` for VF (returns `ok: true`), the request enters the session manager queue, but `_spawn_agent("VF")` crashes with `KeyError: 'id'`. Dashboard shows `Session manager error: 'id'`. VF stays idle.

## Evidence

```
[OR:system] ST requested VF agent: Verify CRITICAL finding...
[ST:tool_start] Calling Bash: curl -s -X POST http://localhost:8080/api/agents/request...
[ST:tool_complete] {"ok": true, "agent": "VF", ...}
[OR:system] Session manager error: 'id'
```

VF session: `{}` (empty — never created)

## Root Cause (Hypothesis)

`_spawn_agent()` calls `_build_context_from_neo4j()` which queries Neo4j for findings, hosts, services, etc. One of these queries returns a record where a field accessed via `record['id']` doesn't exist. The `dict(r)` conversion at line ~1708 works, but a subsequent access like `f['id']` on a record without that field crashes.

Alternatively, it could be in:
- `_fetch_experience_brief()` — accessing prior engagement data
- `_build_knowledge_brief()` — reading from knowledge base
- Workspace creation — file operations

## Investigation Plan

1. Add try/except with full traceback in `_spawn_agent()` around lines 1406-1470
2. Run engagement and check logs for the full stack trace
3. The error `'id'` is a KeyError — search for all `['id']` accesses in `_spawn_agent()` and called functions
4. Likely needs a `.get('id', '')` instead of `['id']` somewhere

## Impact

- VF never starts → no verification → no green CONFIRMED cards
- No screenshots captured
- MTTE not calculated (no confirmed_at set)
- ST thinks VF is running but it's not
