# Persist Engagement Duration

**Created:** 2026-03-22
**Status:** Feature request
**Priority:** LOW — internal tracking only

## Problem

The engagement clock runs in the browser only. Total engagement duration is not persisted server-side. When the browser closes or refreshes after completion, the duration is lost.

## Proposed Fix

1. **Server-side:** Set `completed_at` timestamp on engagement record in Neo4j when engagement stops/completes
2. **API:** Include `duration_seconds` in `/api/engagements/{id}/summary` (computed from `started_at` - `completed_at`)
3. **Dashboard:** Show duration in the Engagements table (e.g., "23m 15s" column)
4. **Engagements page:** Show duration for completed engagements

## NOT in reports

Duration is for INTERNAL use only — do NOT include in pentest reports (Executive Summary, Technical Report, Remediation Roadmap). Engagement timing is operational metadata, not client-facing.

## What Exists

- `started_at` — already stored on engagement creation
- `completed_at` — NOT stored yet (needs to be set on stop/complete)
- Browser clock — works but ephemeral
