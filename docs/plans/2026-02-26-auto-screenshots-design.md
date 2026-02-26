# Automated Evidence Screenshots — Design Document

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Date:** February 26, 2026
**Status:** Approved
**Depends on:** Evidence Capture System (Phase 1, committed `50877a2`)
**Phase:** Phase 2 (Evidence Screenshots)
**Next:** Phase G (Verify Agent with Agent Teams)

---

## 1. Problem Statement

ATHENA agents confirm vulnerabilities and capture text output automatically, but there are no visual screenshots. Clients expect pentest reports with real tool output — terminal windows showing Metasploit sessions, SQLMap dumps, nmap scans — the same evidence a human pentester would screenshot. Currently, screenshots require manual upload.

**Clients need:** Visual proof that looks like a human ran the tools. Before/after comparisons for web vulnerabilities. Terminal output that's report-ready without reformatting.

---

## 2. Goals

1. **Automated screenshot capture** — Every confirmed finding gets visual evidence without human intervention
2. **Baseline + exploit pairs** — Before/after comparison for web-targetable findings
3. **Two screenshot modes** — Browser screenshots for web exploits, terminal-rendered screenshots for CLI tool output
4. **Zero-wiring extensibility** — New tools added to the registry get screenshots automatically via `run_tool()` + `report_finding()` hooks
5. **Report-ready evidence** — Screenshots embedded inline per finding in the pentest report with auto-numbered figures
6. **Gallery navigation** — Browse evidence sequentially without closing the viewer

## 3. Non-Goals (Out of Scope)

- Video recording of exploitation steps
- Real-time screenshot streaming via WebSocket
- Screenshot annotation/markup tools
- Verify Agent (deferred to Phase G with Agent Teams)
- EyeWitness mass recon screenshots (separate feature)

---

## 4. Architecture

### 4.1 Overview

Screenshots are captured inline during the orchestrator's exploit pipeline. Two universal hook points ensure every tool and every finding gets evidence automatically:

- **`run_tool()`** — Stashes full tool context (name, command, full stdout) after every tool execution
- **`report_finding()`** — Triggers screenshot capture using stashed context when a finding is confirmed

```
Orchestrator
    │
    ├─ run_tool("sqlmap_scan", params)
    │     ├─ Kali executes tool (existing)
    │     └─ Stashes: _last_tool_name, _last_tool_command, _last_tool_output
    │
    └─ report_finding(title, severity, ..., evidence)
          │
          ├─ Create Finding in Neo4j (existing)
          │
          └─ capture_evidence_screenshot()  ← NEW
                │
                ├─ HTTP target? → screenshot_web (baseline + exploit)
                │     └─ Kali Playwright → navigates URL → PNG
                │
                └─ Always → screenshot_terminal (evidence)
                      └─ Kali Playwright → renders HTML terminal → PNG

                ├─ Dashboard receives base64 PNG
                ├─ Saves to 08-evidence/screenshots/
                ├─ Generates thumbnail (300px, JPEG 75%)
                └─ Creates Artifact node in Neo4j, links to Finding
```

### 4.2 Key Design Decision: Hook into Universal Methods

Rather than wiring screenshots into each individual exploit method (`_exploit_with_metasploit`, `_exploit_with_sqlmap`, etc.), the system hooks into `run_tool()` and `report_finding()`. This means:

- **Existing exploit methods are untouched** — no code changes to the 5 current methods
- **New tools get screenshots automatically** — any future exploit method that calls `run_tool()` and `report_finding()` inherits evidence capture
- **Tool registry extensibility** — optional `evidence_capture` field lets tool authors customize behavior per tool

### 4.3 Dual Screenshot Modes

**Web screenshots (`screenshot_web`):**
Playwright navigates to the target URL in headless Chromium on the Kali box, waits for page load, captures viewport as PNG. Used for:
- SQL injection error pages
- Admin panels / broken access control
- XSS demonstrations
- Default credential login pages
- Any finding with an HTTP/HTTPS target

**Terminal screenshots (`screenshot_terminal`):**
Playwright renders a styled HTML terminal template on the Kali box and screenshots the result. Used for:
- Metasploit session output
- SQLMap database dumps
- Nmap scan results
- Nuclei findings
- Any CLI tool output that clients want to see as "real terminal"

The terminal template renders a dark terminal window with:
- Title bar: tool name + timestamp (looks like a real terminal tab)
- Command line: `$ <command>` at the top
- Output: monospace text, ANSI colors converted to HTML spans
- ATHENA watermark in corner (branding for reports)
- Truncated at 200 lines with `[... N more lines truncated]`

---

## 5. Kali-Side Components

### 5.1 New Flask Endpoints

**`POST /api/tools/screenshot`** — Browser screenshot of a URL

```json
Request: {
  "url": "http://10.1.1.25/login.php",
  "viewport": "1280x900",
  "wait_ms": 2000,
  "full_page": false
}
Response: {
  "success": true,
  "image_b64": "<base64 PNG>",
  "file_size": 184320,
  "viewport": "1280x900"
}
```

**`POST /api/tools/screenshot_terminal`** — Terminal-rendered screenshot

```json
Request: {
  "command": "sqlmap -u 'http://10.1.1.25/login.php?id=1' --batch",
  "output": "<full tool stdout>",
  "tool_name": "SQLMap",
  "timestamp": "2026-02-26 03:45:00 AST",
  "max_lines": 200
}
Response: {
  "success": true,
  "image_b64": "<base64 PNG>",
  "file_size": 245760,
  "viewport": "1280x900"
}
```

### 5.2 Tool Registry Entries

```json
"screenshot_web": {
  "display_name": "Web Screenshot",
  "endpoint": "/api/tools/screenshot",
  "timeout": 30,
  "backends": ["external", "internal"],
  "category": "evidence",
  "params": {
    "url": {"type": "string", "required": true, "description": "Target URL to screenshot"},
    "viewport": {"type": "string", "required": false, "default": "1280x900", "description": "Viewport WxH"},
    "wait_ms": {"type": "integer", "required": false, "default": 2000, "description": "Wait for page load (ms)"},
    "full_page": {"type": "boolean", "required": false, "default": false, "description": "Full page or viewport only"}
  }
},
"screenshot_terminal": {
  "display_name": "Terminal Screenshot",
  "endpoint": "/api/tools/screenshot_terminal",
  "timeout": 15,
  "backends": ["external", "internal"],
  "category": "evidence",
  "params": {
    "command": {"type": "string", "required": true, "description": "Command that was executed"},
    "output": {"type": "string", "required": true, "description": "Full command stdout"},
    "tool_name": {"type": "string", "required": false, "default": "Terminal", "description": "Tool name for title bar"},
    "timestamp": {"type": "string", "required": false, "description": "Execution timestamp"},
    "max_lines": {"type": "integer", "required": false, "default": 200, "description": "Max lines to render"}
  }
}
```

### 5.3 Tool Registry Extensibility

Existing and new tools can optionally declare screenshot preferences:

```json
"sqlmap_scan": {
  "display_name": "SQLMap SQL Injection Scanner",
  "evidence_capture": {
    "screenshot_mode": "terminal",
    "baseline": true
  }
}
```

| Field | Values | Default |
|-------|--------|---------|
| `screenshot_mode` | `"web"`, `"terminal"`, `"both"` | `"terminal"` for CLI tools, auto-detect from target |
| `baseline` | `true`, `false` | `true` if HTTP target |

If `evidence_capture` is not present, defaults apply: terminal screenshot for evidence, web baseline if HTTP target.

### 5.4 Kali Prerequisites

Both Kali boxes (external Antsle + internal mini-PC):

```bash
pip install playwright
playwright install chromium
```

Chromium runs headless — no X11/xvfb needed with modern Playwright `--headless` mode.

### 5.5 Terminal HTML Template

File: `terminal-template.html` on both Kali boxes.

Dark terminal window with:
- Title bar: `{tool_name} — {timestamp}` with minimize/maximize/close dots
- Font: system monospace (Fira Code, SF Mono, Menlo fallback)
- Background: `#1a1a2e` (dark navy, Kali-inspired)
- Text: `#e0e0e0` (light gray)
- Command: `#00ff41` (green, `$ command` prefix)
- ANSI color support: red, green, yellow, blue, magenta, cyan mapped to HTML spans
- ATHENA watermark: bottom-right corner, subtle
- Max viewport: 1280x900

---

## 6. Orchestrator Integration

### 6.1 `run_tool()` Modification

Stash tool context after every execution:

```python
async def run_tool(self, tool_name, params, display=""):
    self._last_tool_name = tool_name
    self._last_tool_command = display or tool_name
    result = await self.kali.run_tool(tool_name, params, ...)
    self._last_tool_output = result.stdout  # Full output, not truncated
    return result
```

### 6.2 `report_finding()` Modification

Trigger screenshot capture after finding creation:

```python
async def report_finding(self, title, severity, category, target,
                          description, cvss=0.0, cve="", evidence="",
                          write_neo4j=True):
    # ... existing dedup/create/Neo4j logic (unchanged) ...

    # NEW: Auto-capture evidence screenshots
    if evidence and finding_id:
        tool_name = self._last_tool_name or self.agent
        command = self._last_tool_command or ""
        full_output = self._last_tool_output or evidence

        # Terminal screenshot of tool output (always)
        await self.capture_evidence_screenshot(
            finding_id=finding_id, target=target,
            tool_name=tool_name, tool_output=full_output,
            command=command, capture_type="exploit",
        )

        # Web baseline screenshot (only if HTTP target)
        if target.startswith(("http://", "https://")):
            await self.capture_evidence_screenshot(
                finding_id=finding_id, target=target,
                tool_name=tool_name, tool_output="",
                capture_type="baseline",
            )
```

### 6.3 `capture_evidence_screenshot()` Helper

New method on `AgentRunner`:

```python
async def capture_evidence_screenshot(
    self,
    finding_id: str,
    target: str,
    tool_name: str,
    tool_output: str,
    command: str = "",
    capture_type: str = "exploit",
) -> str | None:
    """Capture screenshot and save as Artifact. Returns artifact_id or None."""

    try:
        if capture_type == "baseline" and target.startswith(("http://", "https://")):
            result = await self.kali.run_tool("screenshot_web", {
                "url": target, "viewport": "1280x900", "wait_ms": 2000
            })
        elif tool_output:
            result = await self.kali.run_tool("screenshot_terminal", {
                "command": command, "output": tool_output,
                "tool_name": tool_name, "max_lines": 200
            })
        else:
            return None

        if not result.success:
            logger.warning(f"Screenshot failed for {finding_id}: {result.error}")
            return None

        # Decode base64, save to evidence dir, create thumbnail,
        # create Neo4j Artifact node, link to Finding
        artifact_id = await self._save_screenshot(
            finding_id=finding_id,
            image_b64=result.stdout,  # base64 PNG in response
            capture_type=capture_type,
            screenshot_mode="web" if capture_type == "baseline" else "terminal",
            tool_name=tool_name,
        )
        return artifact_id

    except Exception as e:
        logger.warning(f"Evidence screenshot error: {e}")
        return None  # Never fail the engagement
```

### 6.4 Screenshot Mode per Exploit Method

No per-method wiring needed. Automatic behavior:

| Finding Target | Baseline | Evidence |
|----------------|----------|----------|
| `http://...` or `https://...` | `screenshot_web` (browser view of page) | `screenshot_terminal` (tool output) |
| Non-HTTP (IP, SMB, FTP, etc.) | Skipped | `screenshot_terminal` (tool output) |

Override via `evidence_capture` in tool-registry.json if needed (e.g., `"screenshot_mode": "both"` for a web scanner that should capture both browser view AND terminal output as evidence).

---

## 7. Storage & Neo4j

### 7.1 File Structure

```
engagements/active/{eid}/08-evidence/
├── screenshots/
│   ├── 001-CRITICAL-A03-sqli-login-baseline-20260226-034500.png
│   ├── 002-CRITICAL-A03-sqli-login-exploit-20260226-034505.png
│   ├── 003-HIGH-A01-broken-access-admin-panel-exploit-20260226-034530.png
│   └── thumbnails/
│       ├── 001-CRITICAL-A03-sqli-login-baseline-20260226-034500.jpg
│       └── ...
├── command-output/    (existing, Phase 1)
├── http-pairs/
├── tool-logs/
└── response-diffs/
```

**File naming:** `{seq}-{SEVERITY}-{OWASP}-{short-title}-{baseline|exploit}-{timestamp}.png`

Sequence auto-increments by counting existing files in `screenshots/`.

### 7.2 File Constraints

- Max 2MB per screenshot (auto-compress PNG → JPEG 85% if exceeded)
- Thumbnails: 300px wide, JPEG 75% quality (Pillow, same as Phase 1)
- SHA-256 computed on write for chain of custody

### 7.3 Neo4j Artifact Node

```cypher
CREATE (a:Artifact {
    id: $aid,
    engagement_id: $eid,
    type: 'screenshot',
    file_path: $rel_path,
    file_hash: $sha256,
    file_size: $size,
    mime_type: 'image/png',
    caption: $caption,
    agent: $agent,
    backend: $backend,
    capture_mode: $mode,          // 'baseline' or 'exploit'
    screenshot_mode: $ss_mode,    // 'web' or 'terminal'
    thumbnail_path: $thumb_path,
    timestamp: datetime()
})
```

### 7.4 Relationships

```cypher
// Link to Engagement (always)
MATCH (e:Engagement {id: $eid})
MERGE (e)-[:HAS_EVIDENCE]->(a)

// Link to Finding (always for screenshots)
MATCH (f:Finding {id: $finding_id})
MERGE (f)-[:HAS_ARTIFACT]->(a)
```

### 7.5 Caption Auto-Generation

| Type | Pattern | Example |
|------|---------|---------|
| Web baseline | `"Baseline: {page title or URL path}"` | `"Baseline: login page before SQL injection"` |
| Terminal exploit | `"Evidence: {tool_name} — {finding title short}"` | `"Evidence: SQLMap — confirmed SQL injection on parameter 'id'"` |
| Web exploit | `"Evidence: {URL path} after {finding title short}"` | `"Evidence: /admin panel accessible without authentication"` |

### 7.6 Baseline-to-Exploit Pairing Query

```cypher
MATCH (f:Finding)-[:HAS_ARTIFACT]->(a:Artifact {type: 'screenshot'})
WHERE f.id = $finding_id
RETURN a ORDER BY a.capture_mode  // baseline first, exploit second
```

---

## 8. Report Integration

The Report Agent (RP) queries Artifacts per Finding and embeds screenshots inline:

```markdown
### Finding 3.1 — SQL Injection in Login Form [CRITICAL]

**Evidence:**

![Figure 3.1a — Login page baseline](screenshots/001-CRITICAL-A03-sqli-login-baseline-20260226-034500.png)
*Baseline: Login page before injection attempt*
*SHA-256: a7f3e2d9...*

![Figure 3.1b — SQLMap confirmed injection](screenshots/002-CRITICAL-A03-sqli-login-exploit-20260226-034505.png)
*Evidence: SQLMap confirmed SQL injection on parameter 'id'*
*SHA-256: b8c4f3e1...*
```

**Report query:**

```cypher
MATCH (f:Finding)-[:HAS_ARTIFACT]->(a:Artifact)
WHERE f.engagement_id = $eid
RETURN f.id, f.title, f.severity,
       collect(a {.id, .type, .file_path, .caption, .capture_mode, .file_hash}) AS artifacts
ORDER BY f.severity DESC, f.timestamp
```

**Auto-numbering:** Figures numbered as `{finding_section}.{artifact_index}` (e.g., Figure 3.1a, 3.1b for baseline/exploit pair).

---

## 9. Gallery Navigation (UI Enhancement)

**Current behavior:** Click artifact → fullscreen overlay → click overlay or ESC to close.

**New behavior:** Click artifact → fullscreen overlay with prev/next navigation.

### 9.1 Navigation Controls

```
┌─────────────────────────────────────────────────┐
│  ◄                                          ►   │
│                                                  │
│           [Screenshot or Text Viewer]            │
│                                                  │
│                                                  │
│  ┌─────────────────────────────────────────┐    │
│  │ 3 / 22  │  CRITICAL  │  screenshot      │    │
│  │ SQLMap — confirmed SQL injection         │    │
│  └─────────────────────────────────────────┘    │
└─────────────────────────────────────────────────┘
```

**Controls:**
- **Left/Right arrows** (on-screen): Navigate to previous/next artifact
- **Left/Right arrow keys**: Keyboard navigation
- **Bottom bar**: Shows position (`3 / 22`), severity badge, type, caption
- **ESC or click backdrop**: Close viewer
- **Swipe** (future/touch): Swipe left/right to navigate (nice-to-have, not required)

### 9.2 Implementation

The `showArtifactFullsize()` function receives the full artifact list and current index:

```javascript
async function showArtifactFullsize(artifacts, currentIndex) {
    // Render current artifact (screenshot as img, text as pre — existing logic)
    // Add left/right arrow buttons
    // Add bottom info bar with position, severity, type, caption
    // Keyboard listener for arrow keys + ESC
    // Arrow click/keypress updates currentIndex and re-renders content
}
```

**Gallery grid passes the full list:** When rendering the Evidence Gallery grid, each card's `onclick` passes the artifacts array and its index instead of just the artifact ID.

### 9.3 Navigation Scope

Navigation cycles through ALL artifacts in the current view:
- If viewing from a Finding detail panel → navigate through that finding's artifacts only
- If viewing from the Evidence Gallery page → navigate through all engagement artifacts

---

## 10. Error Handling

### 10.1 Core Principle

**Never block the engagement pipeline.** Screenshots are best-effort enhancement. If capture fails, the exploit still succeeded and text evidence is still saved.

### 10.2 Failure Matrix

| Scenario | Behavior |
|----------|----------|
| Chromium not installed on Kali | `run_tool` returns error → log warning, skip, continue |
| Target URL unreachable | Playwright timeout (30s) → log, skip |
| Target requires auth (login wall) | Baseline shows login page — valid evidence |
| Non-HTTP target (SMB, FTP, raw IP) | Baseline skipped, terminal screenshot only |
| Kali backend offline | Existing backend failover handles this |
| Screenshot >2MB | Compress PNG → JPEG 85% before saving |
| Tool output empty | Skip terminal screenshot, web baseline if HTTP |
| Rapid consecutive findings | Sequential per finding, ~5-8s overhead each |

### 10.3 Timeouts

| Tool | Timeout | Reason |
|------|---------|--------|
| `screenshot_web` | 30s | Page load + render |
| `screenshot_terminal` | 15s | Local HTML render, no network |

### 10.4 No Retry Policy

If a screenshot fails, don't retry. Move on. Target state may have changed. One shot, best effort.

### 10.5 Graceful Degradation

If Playwright/Chromium is not installed on a Kali box, the entire screenshot system is a no-op. Text evidence auto-capture (Phase 1) continues as fallback.

---

## 11. Files Changed

### New Files

| File | Location | Description |
|------|----------|-------------|
| `terminal-template.html` | Both Kali boxes | Dark terminal HTML template for CLI screenshots |

### Modified Files

| File | Change | Scope |
|------|--------|-------|
| `tool-registry.json` | Add `screenshot_web`, `screenshot_terminal` entries + optional `evidence_capture` field | ~30 lines |
| `orchestrator.py` | Modify `run_tool()` to stash context. Modify `report_finding()` to trigger screenshots. Add `capture_evidence_screenshot()` and `_save_screenshot()` helpers. | ~100 lines |
| `server.py` | Add base64 decode path for screenshot artifacts received from orchestrator | ~20 lines |
| `index.html` | Refactor `showArtifactFullsize()` for gallery navigation (prev/next, keyboard, info bar) | ~80 lines |
| Kali Flask API | Add `/api/tools/screenshot` and `/api/tools/screenshot_terminal` endpoints | ~300 lines |

### Unchanged

- Individual exploit methods (`_exploit_with_*`) — untouched
- Neo4j schema — existing Artifact node, two new optional fields
- Evidence directory structure — `screenshots/` already exists
- Dashboard gallery grid — already renders screenshot artifacts

---

## 12. Success Metrics

| Metric | Target |
|--------|--------|
| Evidence coverage | 90%+ of confirmed findings have at least 1 screenshot |
| Capture latency | < 8 seconds per finding (baseline + exploit pair) |
| Gallery load time | < 2 seconds for 50 artifacts |
| Zero manual screenshots | Agents capture 100% of evidence automatically |
| Report integration | Every finding section has inline figures |
| New tool onboarding | Zero code changes — add to registry, get screenshots |

---

## 13. Future Work (Phase G)

- **Verify Agent:** Dedicated agent replays findings independently, captures evidence as a separate verification step. Uses Agent Teams for parallel verification.
- **Screenshot annotation:** Highlight vulnerable elements (red boxes around SQL errors, arrows pointing to admin panels)
- **Video capture:** Short clips of multi-step exploits
- **EyeWitness integration:** Mass recon screenshots across all discovered web services
