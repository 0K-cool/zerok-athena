# BUG: Evidence Screenshots Incomplete — Only 3 out of 57 Artifacts Are Screenshots

**Date:** March 27, 2026
**Severity:** HIGH — Client deliverable quality
**Status:** DOCUMENTED — Not yet fixed

## Problem

Evidence Gallery shows 57 artifacts but only 3 are actual screenshots. The rest (54) are command_output text. 40.5% coverage means 72 out of 121 findings have no evidence at all.

For client reports, every confirmed exploit MUST have:
1. A screenshot showing the exploit succeeded (visual proof)
2. Command output showing the exact command and result
3. Both linked to the specific finding

## Current State

- 57 artifacts: 54 command_output (text), 3 screenshots (images)
- 40.5% coverage (49/121 findings have evidence)
- VF captures some command output but rarely takes screenshots
- EX captures exploitation evidence but inconsistently

## Expected State

Every confirmed exploit should have:
- Screenshot of the shell/access obtained
- Command output with exact commands used
- Linked to the specific Finding node in Neo4j
- Coverage should be 80%+ for confirmed exploits, 50%+ for all findings

## Root Cause

1. **EX/VF prompts don't strongly enforce screenshots** — agents take screenshots optionally
2. **Screenshot tool may not be available** — if Playwright/screenshot MCP tool isn't loaded, agents can't capture visual evidence
3. **Auto-capture triggers only on certain events** — not all exploit confirmations trigger evidence capture

## Proposed Fix

1. **Agent prompts:** Make screenshot MANDATORY after every confirmed exploit: "After confirming an exploit, you MUST take a screenshot using the screenshot tool. This is NON-NEGOTIABLE for client deliverables."
2. **Server-side auto-capture:** When a finding's status changes to "confirmed", auto-trigger a screenshot capture if the agent session is still active
3. **Evidence validation:** Flag findings with "confirmed" status but no screenshot as incomplete in the Evidence Gallery
4. **Coverage target:** Display "evidence completeness" percentage in the engagement summary

## Key Insight: Prompt Compliance Fails — Need Server-Side Enforcement

Changed screenshot prompt from "use them AFTER confirming" to "MANDATORY — NON-NEGOTIABLE for client deliverables." Result: still only 1 screenshot. Same pattern as EX speed prompts and RAG KB queries — agents deprioritize instructions in long prompts.

**The proper fix is server-side auto-capture:**
1. When a finding's status changes to "confirmed" via PATCH, server auto-triggers screenshot request to Kali backend
2. Server calls Kali screenshot endpoint with target URL/command
3. Server uploads the artifact automatically — no agent action needed
4. Deterministic: every confirmed exploit gets a screenshot, period

This pattern applies broadly: anything that MUST happen should be server-enforced, not agent-requested.

## Impact on Client Work

Without visual evidence:
- Reports lack proof of exploitation
- Clients may dispute findings
- Compliance audits (PCI, HIPAA) require evidence documentation
- Competitive disadvantage vs tools that auto-capture everything
