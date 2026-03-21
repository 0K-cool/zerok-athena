# Engagement Running Clock

**Created:** 2026-03-21
**Status:** Feature request
**Priority:** MEDIUM — operational awareness

## Problem

No way to see how long the current pentest has been running, or how long a completed engagement took. Operators can't gauge pace, compare engagement durations, or estimate time remaining.

## Proposed Feature

### Live Clock (during engagement)
- Display running timer next to "Pentest Running" badge in header
- Format: `⏱ 12m 34s` (updates every second)
- Starts on `engagement_started` event
- Pauses on `engagement_paused` (shows paused state)
- Stops on `engagement_ended` / `engagement_stopped`

### Completion Time (after engagement)
- Replace running timer with final duration: `⏱ 23m 15s (completed)`
- Persist in engagement metadata for reports

### Per-Agent Duration (optional, in Agent Status grid)
- Show elapsed time per agent tile: `ST: 2m 30s`, `WV: 8m 12s`
- Helps identify slow agents and optimize strategy

## Implementation Notes

### Data Source
- `engagement_started` timestamp already exists in the engagement record
- `engagement_ended` timestamp set on completion
- Per-agent: `session.start_time` → `session.end_time` in `agent_session_manager.py`

### Frontend (index.html)
1. Add clock element in header bar (next to "Pentest Running" badge)
2. Start `setInterval(1000)` timer on `engagement_started` WS event
3. Clear interval on `engagement_ended`
4. Format as `Xm Ys` (or `Xh Ym Zs` for long engagements)

### Where to Display
Option A: **Header bar** — next to "Pentest Running" badge (most visible)
Option B: **KPI row** — replace or augment the Active Engagements card
Option C: **AI Drawer** — next to Phase indicator

Recommendation: **Option A** — always visible, doesn't take KPI space.

### Backend
- Already stored: engagement `started_at` field
- Add: `completed_at` field on engagement end
- API: include `duration_seconds` in `/api/engagements/{id}/summary`

### Report Integration
- RP should include total engagement duration in reports
- "Engagement completed in 23 minutes, 15 seconds"
- Per-agent breakdown in methodology section
