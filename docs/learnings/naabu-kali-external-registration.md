# Naabu Not Registered for Kali External

**Created:** 2026-03-22
**Status:** Pending investigation
**Priority:** LOW — AR self-corrected, naabu works despite listing discrepancy

## Problem

During the 0din Server engagement, AR noted that naabu is listed as "internal only" in the tool availability matrix, but `mcp__kali_external__naabu_scan` IS available and works on the external backend. AR self-corrected and proceeded, but the tool registry may have an incorrect `backends` config.

## Investigation

Check `tool-registry.json` for naabu:
- What `backends` array does it have? (should be `["external", "internal"]`)
- If it only lists `["internal"]`, update to include `"external"` since it works there
- Also check the Kali external health endpoint — naabu shows as available in the tools list

## Impact

Minor — AR works around it. But the discrepancy between the tool registry and actual availability could confuse agents or cause unnecessary fallback logic.
