# VF Inconsistent Confirmation — Green Cards Missing for Some Confirmed Findings

**Created:** 2026-03-21
**Status:** Pending fix
**Priority:** MEDIUM — visual inconsistency, missing green CONFIRMED cards

## Problem

VF confirms findings through two different paths:

1. **Informal** — VF runs curl commands, gets results, posts a `system` message saying "CONFIRMED". No green card appears in the AI drawer. Finding status updated in Neo4j but `verification_result` event never emitted.

2. **Formal** — VF calls `POST /api/verify/{id}/result` with structured data. Server emits `verification_result` WebSocket event. Dashboard renders the green CONFIRMED card with confidence percentage and badge.

VF is inconsistent — some findings get green cards, some don't.

## Root Cause

VF's prompt instructs it to call `/api/verify/{id}/result` but it doesn't always follow that instruction. When VF does ad-hoc testing (curl commands inline), it confirms the finding in its reasoning/system messages but skips the formal verification result API call.

## Impact

- Missing green CONFIRMED cards for informally verified findings
- Inconsistent visual representation — operator can't tell which findings are formally verified vs informally confirmed
- `verification_result` event not emitted → dashboard confirmation tracking incomplete

## Fix Options

### Option A: Strengthen VF prompt (prompt engineering)
Add explicit instruction: "After EVERY confirmation, you MUST call POST /api/verify/{id}/result. A finding is NOT considered confirmed until the API is called. System messages alone are insufficient."

### Option B: Server-side detection (code fix)
In `_sdk_event_to_dashboard()`, detect VF `system` events containing "confirmed" and auto-trigger a `verification_result` event if one hasn't been emitted for that finding.

### Option C: Client-side fallback (UI fix)
In `index.html`, detect VF system messages with "CONFIRMED" and render a green card from the client side.

### Recommendation
**Option A** first (low risk, prompt change). Option B as defense-in-depth if VF still skips the formal path.
