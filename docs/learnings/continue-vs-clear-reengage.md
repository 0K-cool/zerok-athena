# Continue vs Clear Re-engage Options

**Created:** 2026-03-22
**Status:** Feature request
**Priority:** MEDIUM

## Problem

Currently, re-engaging clears all data (findings, evidence, scans). If the operator paused a pentest and comes back later, they lose all progress.

## Proposed UX

Two buttons on the re-engage UI:

1. **Continue Engagement** — Keep all existing findings, evidence, scans. ST gets prior context and picks up where it left off.
2. **Clear & Re-engage** — Wipe everything, start fresh (current behavior).

## Implementation

### Continue:
- Don't clear Neo4j data
- Pass existing findings as prior_context to ST
- ST reviews what was done and decides next steps
- Agents resume from current phase

### Clear & Re-engage:
- Current behavior — clear Neo4j, reset badges, start fresh

### UI:
- Two buttons in the engagement action area (or a modal with both options)
- Default: Continue (less destructive)
