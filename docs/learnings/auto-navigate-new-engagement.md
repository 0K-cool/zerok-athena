# Auto-Navigate to New Engagement After Creation

**Created:** 2026-03-21
**Status:** Feature request
**Priority:** MEDIUM — UX improvement

## Problem

When a user creates a new engagement (via "New Engagement" button or modal), the dashboard stays on the current view. The user must manually click on the new engagement in the sidebar to switch to it. This is an extra step that feels unnecessary — if you just created an engagement, you obviously want to work with it.

## Expected Behavior

After creating a new engagement:
1. Auto-select the new engagement in the sidebar (highlight it)
2. Switch the AI drawer's engagement dropdown to the new engagement
3. Navigate to the Dashboard view (or Engagements view) showing the new engagement's empty state
4. Update all KPIs and widgets for the new engagement context

## Implementation Notes

- The engagement creation API (`POST /api/engagements`) returns the new `engagement_id`
- After successful creation, call `selectEngagement(newEngagementId)` which already handles:
  - Sidebar active state
  - Drawer engagement dropdown
  - KPI refresh via `loadDashboardFromAPI()`
  - Nav badge updates
- If on the Engagements list page, also refresh the table to show the new entry
- Show a toast: "Engagement created — {name}" (already exists)

## Where to Implement

- `index.html` — Find the engagement creation success handler (the `.then()` after `POST /api/engagements`)
- Add `selectEngagement(data.engagement_id)` after the success toast
- Optionally switch to Dashboard view: `showView('dashboard')`

## Edge Cases

- If creation fails, don't navigate (stay on current view, show error toast)
- If user is mid-engagement on another target, confirm before switching? (probably not — creating a new engagement implies intent to switch)
