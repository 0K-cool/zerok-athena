# agent:None Findings — Persistent Issue (v2)

**Date:** March 25, 2026
**Engagement:** eng-bacf26 (0din Server #4, restarted)
**Priority:** HIGH — blocks MTTE and confirmed exploit count

---

## Status After Fixes

3 fixes were applied:
1. ✅ FIX 1: FindingPayload optional fields (prevents 422)
2. ✅ FIX 2: Auto-detect agent from title keywords in create_finding()
3. ✅ FIX 3: exploit-stats includes agent:None with exploit keywords
4. ✅ FIX 4: Explicit /api/findings curl in EX/PE prompts with "agent":"EX"

## Remaining Issue

12 findings still have agent:None in eng-bacf26 restart. Possible causes:

1. **Race condition:** Findings created by agents BEFORE server restart picked up the auto-detect fix. Agents were spawned with old prompts and continued running after restart.

2. **Third creation path:** There may be a finding creation path that doesn't go through create_finding() at all — possibly the _sdk_event_to_dashboard bridge or a direct Neo4j write in sdk_agent.py.

3. **Bus path timing:** The _bus_to_neo4j handler sets f.agent = msg.from_agent, but if from_agent is None/empty for certain message types, the finding gets agent:None.

## The agent:None Findings

All have: `discovery_source=None, bus_type=None, timestamp=None, evidence=None, category=None`

This means they were NOT created by:
- _bus_to_neo4j (would have discovery_source='bus', bus_type, timestamp)
- create_finding() REST API (would have timestamp, category from auto-detect)

They were likely created by a DIRECT Neo4j MERGE that only sets `id`, `title`, `engagement_id`, `severity` — no agent, no timestamp, no category.

## Next Steps

1. Search ALL code for `MERGE (f:Finding` — find every Neo4j write path
2. The orphan path creates findings with minimal fields (id, title, severity, engagement_id only)
3. Add agent auto-detect to EVERY finding creation path
4. Consider: single canonical `_ensure_finding()` function that ALL paths call, guaranteeing agent is always set

## Workaround (immediate)

FIX 3 (exploit-stats OR branch for agent:None + title keywords) partially works but also requires evidence or confirmed_at, which these findings lack. The workaround is to relax the MTTE filter to accept title keywords ALONE for agent:None findings (without requiring evidence).
