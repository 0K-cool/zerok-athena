# Hardcoded localhost:8080 in Agent Prompts

**Created:** 2026-03-21
**Status:** Pending fix
**Priority:** MEDIUM — breaks if port changes

## Problem

All agent prompts (_ST_PROMPT, _VF_PROMPT, _EX_PROMPT, etc.) hardcode `http://localhost:8080` for API calls. If the dashboard port changes, every agent prompt breaks silently — agents will POST to the wrong URL.

## Current State

Prompts use literal strings like:
- `POST http://localhost:8080/api/agents/request`
- `POST http://localhost:8080/api/events`
- `POST http://localhost:8080/api/verify`
- `GET http://localhost:8080/api/engagements/{eid}/summary`

## Fix

### Step 1: Add `{dashboard_url}` placeholder to all prompts
Replace all `http://localhost:8080` with `{dashboard_url}` in:
- `_ST_PROMPT`
- `_VF_PROMPT`
- `_EX_PROMPT`
- `_DA_PROMPT`
- `_PE_PROMPT`
- `_PX_PROMPT`
- `_RP_PROMPT`
- `_AR_PROMPT`
- `_WV_PROMPT`
- `_PR_PROMPT`
- All base prompts and shared sections

### Step 2: Update `format_prompt()` to inject `dashboard_url`
Add `dashboard_url` parameter alongside existing `eid`, `target`, `backend`, `prior_context`.
Source: from server config or environment variable `ATHENA_DASHBOARD_URL`.

### Step 3: Add to Settings page
Add a "Dashboard URL" field in the Settings > Configuration section.
Default: `http://localhost:8080`
Stored in `.env` or server config.

### Step 4: Update `agent_session_manager.py`
Pass `dashboard_url` to `format_prompt()` during agent spawn.

## Scope

This is a find-and-replace across `agent_configs.py` + plumbing in `format_prompt()` and `agent_session_manager.py`. Low risk but many files touched.
