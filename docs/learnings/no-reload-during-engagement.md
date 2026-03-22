# Don't Reload Dashboard During Active Engagement

**Created:** 2026-03-21
**Status:** Known limitation
**Priority:** LOW — operational awareness

## Problem

Reloading the ATHENA dashboard during an active engagement with multiple agents running causes the page to hang/load very slowly. The server is under heavy load (SDK queries, WebSocket broadcasts, Kali tool calls, Neo4j writes) and serving the large index.html + reconnecting WebSocket adds significant overhead.

## Workaround

- Don't reload during active engagements
- If you need to see CSS/JS changes, wait until engagement stops
- The engagement continues running server-side regardless of browser state

## Potential Fix (Future)

- Lazy-load dashboard sections (don't render all views at once)
- Split index.html into separate JS/CSS bundles
- Add a lightweight loading skeleton that renders before full JS executes
- WebSocket reconnection should be deferred until DOM is ready
