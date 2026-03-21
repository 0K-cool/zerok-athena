# Settings Page — Refresh Button Not Working

**Created:** 2026-03-21
**Status:** Pending fix
**Priority:** LOW

## Problem

The "Refresh" button on the Settings & Configuration page does nothing when clicked. Users expect it to re-fetch `/api/config/features` and update all displayed values.

## Observed

- Button is wired to `onclick="loadSettingsView()"` (line 7422)
- `loadSettingsView()` should fetch and re-render all settings data
- Clicking the button has no visible effect — data stays stale

## Possible Causes

1. `loadSettingsView()` may be throwing a silent error (check console)
2. The function may be defined but not executing the fetch properly
3. The response may be cached (unlikely for fetch API)

## Related

- Kali Backend shows "0 tools" even after server-side fix to include `tools` field in `/api/config/features` response — likely because the Refresh button doesn't work, so the page shows stale data from initial load (before server restart)

## Fix Approach

1. Check if `loadSettingsView()` actually runs when button is clicked
2. If it runs but doesn't update: check if the DOM update is conditional on data changes
3. If it doesn't run: check for JS errors blocking execution
