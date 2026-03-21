# Stop Button UX Issues

**Created:** 2026-03-21
**Status:** Pending fix
**Priority:** MEDIUM — UX confusion during engagement stop

## Problems

1. **No immediate feedback** — After clicking Stop, nothing visually changes immediately. User doesn't know if the command was received.

2. **Multiple clicks** — User clicks Stop repeatedly thinking it didn't work, potentially sending multiple stop signals.

3. **Clear + Engage AI buttons don't appear** — After stopping, the control buttons (Clear, Engage AI) don't show up until the UI detects all agents have stopped, which can take 10-30 seconds.

4. **Slow stop** — Active SDK sessions need to cancel gracefully (mid-tool-call). This is expected behavior but not communicated to the user.

## Fix Approach

1. **Immediate visual feedback on first click:**
   - Disable Stop button after click
   - Change button text to "Stopping..." with a spinner
   - Show toast: "Stop command sent — waiting for agents to finish current operations"

2. **Prevent multiple clicks:**
   - `onclick` handler sets `disabled=true` immediately
   - Re-enable only if stop fails

3. **Show transitional state:**
   - After stop command sent, show "Stopping..." state on agent chips
   - Show Clear + Engage AI buttons in disabled state (greyed) as preview

4. **Progressive agent shutdown:**
   - As each agent confirms stopped, update its chip
   - When ALL agents stopped, enable Clear + Engage AI buttons
