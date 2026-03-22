# Attack Chains Widget Flickering — Disappearing and Re-appearing

**Created:** 2026-03-22
**Status:** Pending investigation
**Priority:** MEDIUM — visual instability

## Problem

The Attack Chains widget on the dashboard disappears and re-appears during active engagements. Chains show briefly then vanish, then come back.

## Likely Cause

Same class as intelligence badge flicker — two data sources (WebSocket updates + API polling) fighting to set the chains widget content. One source returns chains, the other returns empty, they alternate.

## Investigation

1. Check how Attack Chains widget gets populated — WebSocket vs API polling
2. Check if `loadDashboardFromAPI()` overwrites chains that the WebSocket handler just set
3. Apply same Math.max / single-source-of-truth pattern used for other KPIs
