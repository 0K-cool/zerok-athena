# Screenshot Evidence Deployment Plan

**Created:** 2026-03-20
**Status:** Pending implementation
**Priority:** HIGH — Evidence chain is code-complete but screenshots aren't captured because endpoints aren't deployed

## Problem

The evidence screenshot infrastructure is fully built:
- `kali-screenshot-endpoints.py` — Playwright-based web + terminal screenshot endpoints
- `tool-registry.json` — `screenshot_web` and `screenshot_terminal` tool definitions
- `agent_configs.py` — VF/EX agents have approval + prompt instructions to capture screenshots
- `server.py` — Artifact upload + Neo4j storage + thumbnail generation ready

But screenshots aren't being captured because:
1. The screenshot endpoints run on **Kali backends**, not the ATHENA dashboard server
2. `kali-screenshot-endpoints.py` hasn't been deployed to the Kali boxes
3. Kali boxes need Playwright + Chromium installed

## Implementation Plan

### Option A: Deploy to Kali Backends (Primary — attacker vantage point)

1. SSH to both Kali boxes (external + internal)
2. Install Playwright + Chromium:
   ```bash
   pip3 install playwright
   playwright install chromium
   ```
3. Deploy `kali-screenshot-endpoints.py` to each Kali box's tool server
4. Register the `/api/tools/screenshot` and `/api/tools/screenshot_terminal` routes
5. Verify: `curl -X POST http://kali-external:port/api/tools/screenshot -d '{"url":"https://example.com"}'`

**Pros:** Screenshots from the pentester's network vantage point (correct for evidence)
**Cons:** Requires Kali box access + Playwright install (large dependency)

### Option B: Add Screenshot Endpoints to ATHENA Server (Fallback)

1. Add Playwright-based screenshot routes directly to `server.py`
2. When agents call `screenshot_web`/`screenshot_terminal`, the ATHENA server handles it locally
3. This is a fallback — images are from the dashboard server's perspective, not the Kali box

**Pros:** No Kali deployment needed, works immediately
**Cons:** Screenshots from wrong network vantage point, adds Playwright dependency to dashboard server

### Recommended: Both

- **Option A** as primary path — agents call Kali tools via MCP
- **Option B** as fallback — if Kali endpoint returns error, ATHENA server captures locally
- Tool registry already supports `backends: ["external", "internal"]` — add `"dashboard"` as fallback

## What's Already Working

- Text evidence (`command_output`) — 16+ artifacts captured per engagement
- `auto_link_latest_finding` — artifacts auto-linked to most recent finding
- `/api/artifacts/text` JSON endpoint — text evidence without multipart complexity
- Finding dedup via fingerprint MERGE — no more duplicate CVE entries
- VF/EX prompt instructions — agents know to call screenshot tools (will work once endpoints deploy)

## Files Involved

| File | Location | Purpose |
|------|----------|---------|
| `kali-screenshot-endpoints.py` | Dashboard dir | Screenshot endpoint code (deploy to Kali) |
| `tool-registry.json` | Dashboard dir | Tool definitions (ready) |
| `agent_configs.py` | Dashboard dir | Agent approval + prompts (ready) |
| `server.py` | Dashboard dir | Artifact storage (ready) |
| `sdk_agent.py` | Dashboard dir | Evidence capture flow (ready) |

## Testing Checklist

- [ ] Deploy screenshot endpoints to Kali external
- [ ] Deploy screenshot endpoints to Kali internal
- [ ] Verify Playwright + Chromium on both Kali boxes
- [ ] Run engagement — confirm `screenshot` type artifacts appear in Evidence Gallery
- [ ] Verify screenshots linked to findings via `finding_id`
- [ ] Verify thumbnails generated for screenshot artifacts
- [ ] Test "Package for Client" with screenshots included
- [ ] Add fallback screenshot route to ATHENA server (Option B)
