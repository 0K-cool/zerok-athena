# VF Silent Session Bug — Zero Events Emitted to Dashboard

**Created:** 2026-03-21
**Status:** P0 — Pending investigation
**Priority:** CRITICAL — VF runs but is invisible to operator, no screenshots captured

## Problem

VF agent runs tool calls and confirms exploits, but emits **zero events** to the dashboard WebSocket. All VF results only appear via ST's strategy cards (ST relays VF's bilateral messages). The operator has no visibility into VF's actual work.

## Evidence

| Agent | Events | Tool Calls | Cost |
|-------|--------|------------|------|
| ST | 22 | 15 | $0.117 |
| WV | 13 | 52 | $1.581 |
| EX | 5 | 16 | $0.535 |
| **VF** | **0** | **14** | **$0.000** |

- VF: 14 tool calls but $0.000 cost → `ResultMessage` with `total_cost_usd` never fired
- VF: 0 events but confirmed 1 exploit → results only visible via ST relay
- VF: `running=false` after completion → session ended but no completion event emitted

## Impact

1. **No screenshots captured** — VF's prompt has screenshot instructions but if events aren't emitting, the screenshot tool calls may not be executing either, or their results are lost
2. **Operator blind** — VF's thinking, tool calls, and confirmations invisible in AI drawer
3. **No VF cards** — no thinking cards, no tool call cards, no confirmation cards for VF
4. **Cost tracking broken** — VF shows $0.000 despite 14 tool calls

## What Changed

Our changes in this session that could affect VF:

1. **Verification routing through ST** (`server.py`): Changed `_auto_queue_verification()` to send notifications to ST instead of VF directly. VF is now spawned via ST's `request_agent("VF", ...)` call through the `/api/agents/request` endpoint → `_spawn_agent()` in `agent_session_manager.py`

2. **VF dedup guard** (`server.py`): Added confirmed-finding check before creating verification records

3. **Bug D fix — skip system emit for ST** (`sdk_agent.py`): Added `if agent_code != "ST"` guard on ResultMessage emit. This should NOT affect VF since VF's `agent_code` is "VF", not "ST". But worth double-checking.

## What Was Working Before

In the Gym website engagement (before our routing change), VF events DID appear in the AI drawer:
- VF thinking cards visible
- VF tool call cards visible (httpx, curl, Nuclei)
- VF confirmation cards with CONFIRMED badges
- VF cost was non-zero

The key difference: **before our change**, VF was spawned directly by the server via `vf_session.send_command()` or `request_agent("VF", ...)`. **After our change**, VF is spawned by ST calling `POST /api/agents/request` with `agent: "VF"`.

But looking at `_spawn_agent()` (agent_session_manager.py:1376), both paths end up calling the same function, so the spawn mechanism should be identical.

## Investigation Plan

1. **Compare VF spawn path**: Was VF spawned via `_spawn_agent()` in both cases? Check if the old direct-VF path (`vf_session.send_command`) bypassed `_spawn_agent()` and used an already-running VF session, while the new path creates a fresh session that has an event callback issue.

2. **Check event callback wiring**: `_spawn_agent()` at line 1444 does `session.set_event_callback(self._event_callback)`. Verify the callback is actually set on VF's session after spawn.

3. **Check if VF's query actually runs**: VF shows 14 tool_calls — are those real SDK tool calls, or budget-system artifacts? If `cost_usd = 0.0`, the SDK query may not have run (tool calls counted differently).

4. **Check `_suppress_engagement_ended`**: Line 1451 sets this flag on every spawned agent. Verify it's not also suppressing other events.

5. **Check if VF's `_emit()` is calling the callback**: Add a log line in `_emit()` when `agent_code == "VF"` to see if it fires.

6. **Diff working vs broken**: Compare git commits before/after the verification routing change. The old code had `vf_session.send_command(verify_prompt)` which re-used an existing VF session. If VF was already running from a prior spawn, it would have the event callback from that spawn. Our change routes through ST, which calls `request_agent("VF")` → `_spawn_agent("VF")` → creates a NEW session. If the old VF session was still referenced somewhere...

## Quick Test

Revert the verification routing change (Bug A fix) temporarily and run an engagement to see if VF events return. If they do, the routing change introduced the regression. If they don't, it's a pre-existing issue we didn't notice.

## Related

- Intelligence badge flicker (same session)
- Settings Refresh button not working
- Screenshot evidence not captured (direct consequence of VF being silent)
