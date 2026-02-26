# Automated Evidence Screenshots — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add automated screenshot capture (web + terminal-rendered) to ATHENA's exploit pipeline so every confirmed finding gets visual evidence without human intervention.

**Architecture:** Hook into `run_tool()` (stash tool context) and `report_finding()` (trigger screenshot capture) in the orchestrator. Two new Kali Flask endpoints produce PNG screenshots. Dashboard saves screenshots, generates thumbnails, creates Neo4j Artifact nodes. Gallery UI gets prev/next navigation.

**Tech Stack:** Python (Playwright, Flask, Pillow), JavaScript (dashboard UI), HTML/CSS (terminal template)

**Design doc:** `docs/plans/2026-02-26-auto-screenshots-design.md`

---

### Task 1: Add screenshot tool entries to tool-registry.json

**Files:**
- Modify: `tools/athena-dashboard/tool-registry.json`

**Step 1: Add screenshot_web and screenshot_terminal entries**

Add these two entries right before the closing `}` of tool-registry.json (after the `evidence_package` entry at line 513):

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

**Step 2: Verify JSON is valid**

Run: `cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA && python3 -c "import json; json.load(open('tools/athena-dashboard/tool-registry.json')); print('Valid JSON')"`
Expected: `Valid JSON`

**Step 3: Commit**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA
git add tools/athena-dashboard/tool-registry.json
git commit -m "feat: Add screenshot_web and screenshot_terminal to tool registry"
```

---

### Task 2: Create terminal-template.html

**Files:**
- Create: `tools/athena-dashboard/terminal-template.html`

**Step 1: Create the terminal HTML template**

This is a self-contained HTML file that renders CLI output as a styled terminal window. Playwright on Kali will load this file (with query params or injected data) and screenshot it.

The template must:
- Accept data via a `<script>` block that Playwright will populate before screenshotting (the Kali endpoint will write a temp HTML file with the data injected)
- Render a dark terminal window at 1280x900 viewport
- Show title bar with tool name + timestamp + window dots (red/yellow/green)
- Show `$ command` in green on the first line
- Show output in light gray monospace below
- Convert ANSI color codes to HTML spans (basic 8-color support)
- Show ATHENA watermark in bottom-right corner
- Truncate at max_lines with `[... N more lines]` message
- Background: `#1a1a2e`, text: `#e0e0e0`, command: `#00ff41`
- Font: `"Fira Code", "SF Mono", "Cascadia Code", "Consolas", monospace`

**Step 2: Verify it renders in a browser**

Open the file locally in a browser and check:
- Title bar looks like a real terminal window tab
- Command line is green with `$` prefix
- Output is monospace, readable, scrollable
- Watermark visible but subtle

**Step 3: Commit**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA
git add tools/athena-dashboard/terminal-template.html
git commit -m "feat: Add terminal screenshot HTML template for CLI evidence rendering"
```

---

### Task 3: Add Kali Flask screenshot endpoints

**Files:**
- Create: `tools/athena-dashboard/kali-screenshot-endpoints.py`

**Context:** The Kali Flask API runs on the Kali boxes (not in this repo — it's deployed separately). This file contains the endpoint code to be added to the Kali Flask API. It will be deployed via SSH to both Kali boxes.

**Step 1: Write the endpoint code**

The file should contain two Flask route functions:

**`POST /api/tools/screenshot`** — Web screenshot:
1. Parse `url`, `viewport` (default "1280x900"), `wait_ms` (default 2000), `full_page` (default false)
2. Parse viewport string → width, height integers
3. Launch Playwright Chromium headless (or reuse a browser context)
4. Create page with viewport size
5. Navigate to URL with `wait_until="networkidle"`, timeout 20s
6. If `wait_ms` > 0, sleep that duration for JS rendering
7. Take screenshot (full_page option)
8. Close page
9. Return `{"success": true, "image_b64": base64.b64encode(png_bytes).decode(), "file_size": len(png_bytes), "viewport": viewport_str}`
10. On any error: return `{"success": false, "error": str(e)}`

**`POST /api/tools/screenshot_terminal`** — Terminal-rendered screenshot:
1. Parse `command`, `output`, `tool_name` (default "Terminal"), `timestamp` (default now), `max_lines` (default 200)
2. Truncate output to max_lines, add `[... N more lines truncated]` if needed
3. Convert basic ANSI color codes in output to HTML spans:
   - `\033[31m` → `<span style="color:#ff5555">` (red)
   - `\033[32m` → green, `\033[33m` → yellow, `\033[34m` → blue
   - `\033[35m` → magenta, `\033[36m` → cyan, `\033[1m` → bold
   - `\033[0m` → `</span>` (reset)
4. Read `terminal-template.html` from same directory
5. Inject tool_name, timestamp, command, and processed output into the template (replace placeholder markers)
6. Write to temp file
7. Launch Playwright, navigate to `file:///tmp/athena-terminal-{uuid}.html`
8. Set viewport 1280x900, screenshot
9. Delete temp file
10. Return same format as screenshot_web

**Important:** Both endpoints should handle Playwright not being installed gracefully — return `{"success": false, "error": "Playwright/Chromium not installed"}`.

**Step 2: Verify syntax**

Run: `python3 -c "import ast; ast.parse(open('tools/athena-dashboard/kali-screenshot-endpoints.py').read()); print('Valid Python')"`

**Step 3: Commit**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA
git add tools/athena-dashboard/kali-screenshot-endpoints.py
git commit -m "feat: Kali Flask screenshot endpoints for web and terminal captures"
```

---

### Task 4: Modify orchestrator.py — run_tool() context stashing

**Files:**
- Modify: `tools/athena-dashboard/orchestrator.py:178-304` (AgentRunner.run_tool method)

**Step 1: Add instance variables for tool context**

Find the `AgentRunner.__init__` method. After existing instance variable assignments, add:

```python
        # Evidence screenshot context (stashed by run_tool for report_finding)
        self._last_tool_name = ""
        self._last_tool_command = ""
        self._last_tool_output = ""
```

**Step 2: Stash context in run_tool()**

In `run_tool()`, right after `tool_display = display or f"Running {tool_name}..."` (line 194), add:

```python
        # Stash tool context for evidence screenshots (used by report_finding)
        self._last_tool_name = tool_name
        self._last_tool_command = tool_display
```

Then after the ANSI stripping block (after line 273 `result.stderr = _ANSI_RE.sub("", result.stderr)`), add:

```python
        # Stash full output for terminal screenshots (after ANSI stripping)
        self._last_tool_output = result.stdout or ""
```

**Step 3: Verify the orchestrator still loads**

Run: `cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA && python3 -c "import ast; ast.parse(open('tools/athena-dashboard/orchestrator.py').read()); print('Valid Python')"`

**Step 4: Commit**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA
git add tools/athena-dashboard/orchestrator.py
git commit -m "feat: Stash tool context in run_tool() for evidence screenshots"
```

---

### Task 5: Add capture_evidence_screenshot() and _save_screenshot() to orchestrator.py

**Files:**
- Modify: `tools/athena-dashboard/orchestrator.py` (AgentRunner class)

**Step 1: Add capture_evidence_screenshot() method**

Add this method to the `AgentRunner` class (after the `_upgrade_finding` method, around line 620):

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
        """Capture a screenshot and save as Artifact. Returns artifact_id or None.

        capture_type: 'baseline' (web page before exploit) or 'exploit' (terminal/web after)
        Never raises — screenshots are best-effort, never block the engagement.
        """
        try:
            if capture_type == "baseline" and target.startswith(("http://", "https://")):
                result = await self.kali.run_tool("screenshot_web", {
                    "url": target, "viewport": "1280x900", "wait_ms": 2000,
                }, backend=self.ctx.backend_override or "auto",
                   target_type=self.ctx.target_type)
                screenshot_mode = "web"
            elif tool_output:
                result = await self.kali.run_tool("screenshot_terminal", {
                    "command": command,
                    "output": tool_output[:50000],  # Cap at 50KB for terminal render
                    "tool_name": tool_name,
                    "max_lines": 200,
                }, backend=self.ctx.backend_override or "auto",
                   target_type=self.ctx.target_type)
                screenshot_mode = "terminal"
            else:
                return None

            if not result.success:
                logger.warning(f"[EVIDENCE] Screenshot failed ({capture_type}) for {finding_id}: {result.error}")
                return None

            # Extract base64 image from response
            # The Kali endpoint returns JSON with image_b64 field
            import json as _json
            try:
                resp_data = _json.loads(result.stdout)
                image_b64 = resp_data.get("image_b64", "")
            except (ValueError, AttributeError):
                image_b64 = result.stdout  # Fallback: raw base64

            if not image_b64:
                logger.warning(f"[EVIDENCE] Empty screenshot response for {finding_id}")
                return None

            artifact_id = await self._save_screenshot(
                finding_id=finding_id,
                image_b64=image_b64,
                capture_type=capture_type,
                screenshot_mode=screenshot_mode,
                tool_name=tool_name,
            )
            if artifact_id:
                logger.info(f"[EVIDENCE] Screenshot captured ({capture_type}/{screenshot_mode}): {artifact_id}")
            return artifact_id

        except Exception as e:
            logger.warning(f"[EVIDENCE] Screenshot error: {e}")
            return None
```

**Step 2: Add _save_screenshot() method**

Add this right after `capture_evidence_screenshot()`:

```python
    async def _save_screenshot(
        self,
        finding_id: str,
        image_b64: str,
        capture_type: str,
        screenshot_mode: str,
        tool_name: str,
    ) -> str | None:
        """Decode base64 PNG, save to disk, create thumbnail, create Neo4j Artifact node."""
        import base64
        import hashlib
        from server import ensure_evidence_dirs, neo4j_driver, neo4j_available
        from PIL import Image
        from io import BytesIO
        from pathlib import Path

        try:
            # Decode PNG
            png_bytes = base64.b64decode(image_b64)
            file_hash = hashlib.sha256(png_bytes).hexdigest()

            # Compress if >2MB
            if len(png_bytes) > 2 * 1024 * 1024:
                img = Image.open(BytesIO(png_bytes))
                buf = BytesIO()
                img.convert("RGB").save(buf, format="JPEG", quality=85)
                png_bytes = buf.getvalue()
                file_hash = hashlib.sha256(png_bytes).hexdigest()
                ext = ".jpg"
                mime_type = "image/jpeg"
            else:
                ext = ".png"
                mime_type = "image/png"

            # Build filename: {seq}-{SEVERITY}-{short_title}-{capture_type}-{timestamp}{ext}
            evidence_root = ensure_evidence_dirs(self.ctx.engagement_id)
            screenshots_dir = evidence_root / "screenshots"

            # Auto-increment sequence by counting existing files
            existing = list(screenshots_dir.glob(f"*{ext}")) + list(screenshots_dir.glob("*.png")) + list(screenshots_dir.glob("*.jpg"))
            # Filter out thumbnails directory files
            existing = [f for f in existing if "thumbnails" not in str(f)]
            seq = len(existing) + 1

            # Get finding severity from context
            severity = "unknown"
            for f in self.ctx.findings:
                if f.get("id") == finding_id:
                    severity = (f.get("severity") or "unknown").upper()
                    break

            timestamp_str = datetime.now().strftime("%Y%m%d-%H%M%S")
            safe_tool = re.sub(r'[^a-zA-Z0-9-]', '-', tool_name)[:20].strip('-').lower()
            filename = f"{seq:03d}-{severity}-{safe_tool}-{capture_type}-{timestamp_str}{ext}"
            filepath = screenshots_dir / filename
            filepath.write_bytes(png_bytes)

            # Compute relative path from ATHENA project root
            athena_dir = Path(__file__).parent.parent.parent
            try:
                rel_path = str(filepath.relative_to(athena_dir))
            except ValueError:
                rel_path = str(filepath)

            # Generate thumbnail (300px wide, JPEG 75%)
            thumbnail_rel = None
            try:
                img = Image.open(BytesIO(png_bytes))
                ratio = 300 / img.width
                new_h = int(img.height * ratio)
                thumb = img.resize((300, new_h), Image.LANCZOS)
                thumb_name = f"{seq:03d}-{capture_type}-thumb.jpg"
                thumb_path = screenshots_dir / "thumbnails" / thumb_name
                buf = BytesIO()
                thumb.convert("RGB").save(buf, format="JPEG", quality=75)
                thumb_path.write_bytes(buf.getvalue())
                try:
                    thumbnail_rel = str(thumb_path.relative_to(athena_dir))
                except ValueError:
                    thumbnail_rel = str(thumb_path)
            except Exception as e:
                logger.warning(f"[EVIDENCE] Thumbnail error: {e}")

            # Create Neo4j Artifact node and link to Finding + Engagement
            artifact_id = f"art-{uuid.uuid4().hex[:8]}"
            caption = f"{'Baseline' if capture_type == 'baseline' else 'Evidence'}: {tool_name}"

            if neo4j_available and neo4j_driver:
                with neo4j_driver.session() as sess:
                    sess.run("""
                        CREATE (a:Artifact {
                            id: $aid, engagement_id: $eid,
                            type: 'screenshot', file_path: $path,
                            file_hash: $hash, file_size: $size,
                            mime_type: $mime, caption: $caption,
                            agent: $agent, backend: $backend,
                            capture_mode: $capture_mode,
                            screenshot_mode: $ss_mode,
                            thumbnail_path: $thumb,
                            timestamp: datetime()
                        })
                        WITH a
                        MATCH (e:Engagement {id: $eid})
                        MERGE (e)-[:HAS_EVIDENCE]->(a)
                        WITH a
                        MATCH (f:Finding {id: $fid})
                        MERGE (f)-[:HAS_ARTIFACT]->(a)
                        RETURN a
                    """, {
                        "aid": artifact_id,
                        "eid": self.ctx.engagement_id,
                        "path": rel_path,
                        "hash": file_hash,
                        "size": len(png_bytes),
                        "mime": mime_type,
                        "caption": caption,
                        "agent": self.agent,
                        "backend": self.ctx.backend_override or "external",
                        "capture_mode": capture_type,
                        "ss_mode": screenshot_mode,
                        "thumb": thumbnail_rel,
                        "fid": finding_id,
                    })

                # Broadcast evidence update
                await self.state.broadcast({
                    "type": "stat_update",
                    "evidence_count": 1,
                    "timestamp": time.time(),
                })

            return artifact_id

        except Exception as e:
            logger.warning(f"[EVIDENCE] Save screenshot error: {e}")
            return None
```

**Step 3: Verify syntax**

Run: `cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA && python3 -c "import ast; ast.parse(open('tools/athena-dashboard/orchestrator.py').read()); print('Valid Python')"`

**Step 4: Commit**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA
git add tools/athena-dashboard/orchestrator.py
git commit -m "feat: Add capture_evidence_screenshot() and _save_screenshot() helpers"
```

---

### Task 6: Modify report_finding() to trigger screenshot capture

**Files:**
- Modify: `tools/athena-dashboard/orchestrator.py:486-577` (AgentRunner.report_finding method)

**Step 1: Add screenshot capture after finding creation**

In `report_finding()`, find the block at the end where stats are emitted (line 577: `await self._emit_stats()`). Right BEFORE that line, add the screenshot capture logic:

```python
        # Auto-capture evidence screenshots for this finding
        if evidence and finding_id:
            _tool = self._last_tool_name or self.agent
            _cmd = self._last_tool_command or ""
            _full_output = self._last_tool_output or evidence

            # Terminal screenshot of tool output (always when there's output)
            await self.capture_evidence_screenshot(
                finding_id=finding_id, target=target,
                tool_name=_tool, tool_output=_full_output,
                command=_cmd, capture_type="exploit",
            )

            # Web baseline screenshot (only if HTTP target)
            if target.startswith(("http://", "https://")):
                await self.capture_evidence_screenshot(
                    finding_id=finding_id, target=target,
                    tool_name=_tool, tool_output="",
                    capture_type="baseline",
                )
```

**Important:** This must also be added to the `_upgrade_finding()` method (around line 579-620) in the same position — right before stats emission. When a finding is upgraded (e.g., from discovery to confirmed exploit), we want screenshots of the confirmation.

**Step 2: Verify syntax**

Run: `cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA && python3 -c "import ast; ast.parse(open('tools/athena-dashboard/orchestrator.py').read()); print('Valid Python')"`

**Step 3: Commit**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA
git add tools/athena-dashboard/orchestrator.py
git commit -m "feat: Trigger screenshot capture in report_finding() and _upgrade_finding()"
```

---

### Task 7: Add server.py internal screenshot save endpoint

**Files:**
- Modify: `tools/athena-dashboard/server.py`

**Step 1: Add internal endpoint for orchestrator to save screenshots**

The orchestrator's `_save_screenshot()` imports `ensure_evidence_dirs` and `neo4j_driver` directly from server.py, so no new REST endpoint is needed — it calls the server module directly.

However, we need to verify that the imports in `_save_screenshot()` work correctly. The orchestrator already imports from server.py (line 500: `from server import Finding, Severity`).

Check that these are already exported from server.py:
- `ensure_evidence_dirs` (line 227)
- `neo4j_driver` (module-level variable)
- `neo4j_available` (module-level variable)

If not already importable, add them to any `__all__` list or verify they're module-level.

**Step 2: Verify imports work**

Run: `cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-dashboard && python3 -c "from server import ensure_evidence_dirs, neo4j_driver, neo4j_available; print('Imports OK')"`

Note: This may fail if the server has dependencies not available outside FastAPI. If so, the `_save_screenshot()` method will need to call the evidence directory logic inline rather than importing.

**Step 3: Commit (if changes needed)**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA
git add tools/athena-dashboard/server.py
git commit -m "fix: Ensure evidence helpers are importable from orchestrator"
```

---

### Task 8: Refactor showArtifactFullsize() for gallery navigation

**Files:**
- Modify: `tools/athena-dashboard/index.html:10323-10368` (showArtifactFullsize function)

**Step 1: Rewrite showArtifactFullsize() to accept artifact list + index**

Replace the current function (lines 10323-10368) with a new version that:

1. Accepts `(artifacts, currentIndex)` instead of `(artifactId, artifactType)`
2. Renders the current artifact (screenshot as img, text as pre — same logic as existing)
3. Adds left arrow button (positioned absolute, left side, vertically centered)
4. Adds right arrow button (positioned absolute, right side, vertically centered)
5. Adds bottom info bar showing: `{index+1} / {total}` | severity badge | type | caption
6. Arrow buttons call a `navigateTo(newIndex)` inner function that:
   - Removes current content
   - Re-renders the artifact at the new index
   - Updates info bar
7. Keyboard listener: ArrowLeft → prev, ArrowRight → next, Escape → close
8. Arrows hidden when at start/end (no wrapping)

Arrow button style:
- 48px circle, semi-transparent background
- `◄` and `►` characters or SVG chevrons
- Hover: brighter background
- `onclick` stops propagation (don't close overlay)

Bottom info bar style:
- Fixed to bottom of overlay
- Dark background with padding
- Position counter on left, severity badge center, type+caption right
- Font size 0.85em

**Step 2: Update all call sites**

There are 3 call sites that need updating. Each currently passes `(artifactId, artifactType)`. They need to pass `(artifactsList, index)` instead.

1. `renderArtifactCard()` line 10271 — finding detail thumbnail click
2. `renderArtifactCard()` line 10275 — finding detail preview click
3. `renderEvidenceGalleryGrid()` line 10459 — gallery card click

For the gallery grid (call site 3), the `artifacts` array is already available as the function parameter. Pass it and the current map index.

For finding detail (call sites 1-2), the artifacts are from the finding's artifact list. Store them in a variable accessible to the onclick handler.

**Step 3: Verify in browser**

1. Start server: `cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-dashboard && python3 server.py`
2. Navigate to Evidence Gallery
3. Click any artifact — should open with arrows and info bar
4. Click arrows / press arrow keys — should navigate
5. Press ESC — should close

**Step 4: Commit**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA
git add tools/athena-dashboard/index.html
git commit -m "feat: Gallery navigation with prev/next arrows and keyboard support"
```

---

### Task 9: Integration test — upload test screenshots and verify gallery

**Files:**
- No files modified — testing only

**Step 1: Start the dashboard server**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-dashboard
lsof -ti :8080 | xargs kill -9 2>/dev/null
python3 server.py &
```

**Step 2: Create test screenshot files**

Use Python/Pillow to create two test PNG screenshots:

```python
from PIL import Image, ImageDraw, ImageFont
# Create a 1280x900 test image with text
img = Image.new('RGB', (1280, 900), '#1a1a2e')
draw = ImageDraw.Draw(img)
draw.text((100, 100), "Test Baseline Screenshot\nATHENA Evidence Capture", fill='#e0e0e0')
img.save('/tmp/test-baseline.png')

img2 = Image.new('RGB', (1280, 900), '#2e1a1a')
draw2 = ImageDraw.Draw(img2)
draw2.text((100, 100), "Test Exploit Screenshot\nSQL Injection Confirmed", fill='#ff5555')
img2.save('/tmp/test-exploit.png')
```

**Step 3: Upload via curl**

Upload both as screenshot artifacts to an existing engagement + finding:

```bash
# Get current engagement ID
EID=$(curl -s http://localhost:8080/api/engagements | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['id'])")

# Get a finding ID
FID=$(curl -s "http://localhost:8080/api/findings?engagement_id=$EID" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['findings'][0]['id'] if d.get('findings') else 'none')")

# Upload baseline
curl -X POST http://localhost:8080/api/artifacts \
  -F "file=@/tmp/test-baseline.png" \
  -F "finding_id=$FID" \
  -F "engagement_id=$EID" \
  -F "type=screenshot" \
  -F "caption=Test baseline screenshot" \
  -F "capture_mode=baseline"

# Upload exploit
curl -X POST http://localhost:8080/api/artifacts \
  -F "file=@/tmp/test-exploit.png" \
  -F "finding_id=$FID" \
  -F "engagement_id=$EID" \
  -F "type=screenshot" \
  -F "caption=Test exploit screenshot" \
  -F "capture_mode=exploit"
```

**Step 4: Verify in Evidence Gallery**

1. Open `http://localhost:8080` in Playwright
2. Navigate to Evidence Gallery
3. Verify: screenshots show with thumbnails, clicking opens lightbox
4. Verify: prev/next arrows work
5. Verify: keyboard navigation works (ArrowLeft, ArrowRight, Escape)
6. Verify: info bar shows position, type, caption

**Step 5: Clean up test artifacts**

Delete test artifacts from Neo4j after verification.

---

### Task 10: Final commit and push

**Files:**
- No files modified

**Step 1: Check all changes are committed**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA
git status
git log --oneline -10
```

**Step 2: Push to remote**

```bash
git push
```

**Step 3: Discord notification**

Send Kelvin a Discord notification that implementation is complete.

---

## Deployment Notes (Post-Implementation)

### Kali Box Setup (Manual — requires SSH)

After the dashboard-side code is committed, deploy to both Kali boxes:

```bash
# SSH to Kali external (Antsle)
ssh kali-antsle
pip install playwright
playwright install chromium
# Copy terminal-template.html and kali-screenshot-endpoints.py
# Integrate endpoints into the Kali Flask API
# Restart Flask API

# SSH to Kali internal (mini-PC)
ssh kali-athena
# Same steps
```

This is a manual deployment step that Kelvin will do separately. The dashboard code works without the Kali endpoints — screenshots will just return errors (graceful degradation per design doc section 10.5).
