# VF Not Calling Screenshot Tools Despite Prompt Instructions

**Created:** 2026-03-21
**Status:** Pending fix
**Priority:** HIGH — evidence chain incomplete, no visual proof in reports

## Problem

VF has screenshot tools approved (`screenshot_web`, `screenshot_terminal` in `_KALI_TOOL_NAMES`), Kali endpoints are verified working (both return PNG screenshots), and VF's prompt says "REQUIRED for every confirmed finding." But VF never calls the screenshot tools — all artifacts are `command_output` only.

## Evidence

- VF: 30+ tool calls, all `execute_command` (curl), zero `screenshot_web`/`screenshot_terminal`
- Kali endpoints verified: `POST /api/tools/screenshot` returns base64 PNG on both backends
- Prompt instruction at step 3e says "Capture Visual Evidence (REQUIRED for every confirmed finding)"

## Root Cause

Prompt compliance issue. VF treats the screenshot instruction as optional. The instruction is placed AFTER the verification result submission step — by the time VF reaches it, it has already moved on to the next finding.

## Fix Options

### Option A: Reorder prompt steps (prompt engineering)
Move screenshot capture BEFORE verification result submission:
```
3d. Capture Visual Evidence (MUST do before submitting result)
3e. Submit verification result via POST /api/verify/{id}/result
```
Add: "DO NOT submit verification result until at least one screenshot is captured."

### Option B: Server-side enforcement (code fix)
In `/api/verify/{id}/result` endpoint, check if at least one `screenshot` artifact is linked to the finding. If not, return a warning (not rejection — don't block VF).

### Option C: Automatic screenshot capture (code fix)
In `_sdk_event_to_dashboard()`, when VF's `verification_result` event fires with status=confirmed, automatically trigger a screenshot capture on the Kali backend for the finding's target URL and upload as artifact.

### Recommendation
**Option A + C**: Reorder prompt AND add automatic server-side screenshot capture as fallback. Option A makes VF try first; Option C catches anything VF misses.
