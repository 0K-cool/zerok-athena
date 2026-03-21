# Intelligence Badge Flickering

**Created:** 2026-03-21
**Status:** Pending fix
**Priority:** MEDIUM — visual noise, data race

## Problem

The Intelligence nav badge flickers between two values (observed: 13 → 4 → 13). Two data sources are fighting to set the badge:

1. **WebSocket handler** — increments badge on each new intel event (accumulates correctly)
2. **API polling** — fetches count from server which may return a different number (e.g., deduplicated count, engagement-scoped count)

## Root Cause (Hypothesis)

Same class of bug as the agent cost-decreasing issue (BUG-007, fixed with `Math.max` guard). The badge value should be monotonically increasing during an engagement — use `Math.max(current, incoming)` pattern.

## Fix Approach

Apply the same `Math.max` guard pattern used for cost badges:
1. Find the Intelligence badge update code (both WS handler and API polling paths)
2. Add `Math.max(currentCount, newCount)` before setting textContent
3. Or: single source of truth — only update from one source (WS for real-time, API for page load)

## Related

- BUG-007 (agent costs decreasing) — same pattern, fixed with `max()` guard
- Reports badge (BUG-010) — fixed by adding synchronous WS increment
- One Source of Truth principle — badge should have ONE authoritative updater during live engagement
