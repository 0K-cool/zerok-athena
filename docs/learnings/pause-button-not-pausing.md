# Pause Button Not Actually Pausing Engagement

**Created:** 2026-03-21
**Status:** Pending investigation
**Priority:** MEDIUM

## Problem

Clicking Pause on the dashboard doesn't actually pause the engagement — agents continue running. User expected all agents to pause but they kept executing.

## Investigate

- Check if `pauseEngage()` calls the correct API endpoint
- Check if the server-side pause handler actually pauses SDK sessions
- Check if individual agent sessions respect the pause signal
- Compare with Stop (which does work via API)
