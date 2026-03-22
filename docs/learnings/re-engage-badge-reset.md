# Re-Engage Badge Reset Incomplete

**Created:** 2026-03-21
**Status:** Pending fix
**Priority:** MEDIUM — stale data displayed after re-engage

## Problem

When re-engaging (Clear & Re-engage), some nav badges don't reset to 0:
- Scans badge: shows 18 (stale from previous run)
- Findings badge: shows 19 (stale)
- Intelligence badge: shows 5 (stale)

Other badges (Vulnerabilities, Evidence, Attack Graph, Reports) correctly show no badge (0).

## Root Cause

`resetDashboardFindingWidgets()` resets KPI cards and charts but doesn't reset ALL nav badges. The badges that persist are likely set by WebSocket handlers that increment but never reset, or by API polling that hasn't re-fetched yet.

## Fix

In `resetDashboardFindingWidgets()` or `selectEngagement()`, reset ALL nav badges to 0:
```js
['scans', 'findings', 'vulnerabilities', 'evidence', 'attack-graph', 'reports', 'intelligence'].forEach(function(name) {
    var badge = document.getElementById('nav-badge-' + name);
    if (badge) { badge.textContent = '0'; badge.style.display = 'none'; }
});
```
