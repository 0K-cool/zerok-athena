"""
ATHENA Kali Screenshot Endpoints
=================================
Flask Blueprint providing screenshot capabilities for Kali boxes.
Deployed to both kali_external (Antsle cloud) and kali_internal (mini-PC).

Endpoints:
  POST /api/tools/screenshot          - Web page screenshot via Playwright
  POST /api/tools/screenshot_terminal - Terminal output rendered as styled HTML screenshot

Usage:
  Register this blueprint in your Flask app:
    from kali_screenshot_endpoints import screenshot_bp
    app.register_blueprint(screenshot_bp)

Requirements:
  pip install flask playwright
  playwright install chromium
"""

import base64
import html
import os
import re
import tempfile
import uuid
from datetime import datetime
from pathlib import Path

from flask import Blueprint, jsonify, request
from playwright.sync_api import sync_playwright

# ---------------------------------------------------------------------------
# Blueprint
# ---------------------------------------------------------------------------

screenshot_bp = Blueprint("screenshot", __name__)

# ---------------------------------------------------------------------------
# Module-level constant — template lives alongside this file
# ---------------------------------------------------------------------------

TERMINAL_TEMPLATE_PATH = Path(__file__).parent / "terminal-template.html"

# ---------------------------------------------------------------------------
# Helper: ANSI → HTML
# ---------------------------------------------------------------------------

# Map simple numeric ANSI codes to CSS class names
_ANSI_CODE_MAP = {
    "0":  None,           # reset — handled specially
    "1":  "ansi-bold",
    "2":  "ansi-dim",
    "31": "ansi-red",
    "32": "ansi-green",
    "33": "ansi-yellow",
    "34": "ansi-blue",
    "35": "ansi-magenta",
    "36": "ansi-cyan",
}


def ansi_to_html(text: str) -> str:
    """Convert ANSI escape sequences in *text* to HTML ``<span>`` elements.

    Supported codes
    ---------------
    - Single codes: ``\\x1b[31m`` → ``<span class="ansi-red">``
    - Compound codes: ``\\x1b[1;31m`` → nested ``<span>`` elements
    - Reset: ``\\x1b[0m`` → closes all currently open spans
    - Unrecognised sequences are stripped silently.

    The caller is responsible for HTML-escaping the text *before* passing it
    here so that the angle brackets introduced by this function are not
    double-escaped.
    """

    # Track how many spans are currently open so we can close them on reset.
    open_spans: list[str] = []

    def _replace(match: re.Match) -> str:
        codes_str = match.group(1)           # e.g. "1;31" or "0" or "32"
        codes = codes_str.split(";")
        result_parts: list[str] = []

        for code in codes:
            if code == "0" or code == "":
                # Reset — close all open spans
                if open_spans:
                    result_parts.append("</span>" * len(open_spans))
                    open_spans.clear()
            elif code in _ANSI_CODE_MAP:
                css_class = _ANSI_CODE_MAP[code]
                if css_class:
                    result_parts.append(f'<span class="{css_class}">')
                    open_spans.append(css_class)
            # Unrecognised code → silently drop

        return "".join(result_parts)

    # Match ESC[ ... m  (both \x1b and \033 are the same byte 0x1B)
    converted = re.sub(r"\x1b\[([0-9;]*)m", _replace, text)

    # Close any spans still open at end of string
    if open_spans:
        converted += "</span>" * len(open_spans)

    # Strip any remaining escape sequences we did not handle
    converted = re.sub(r"\x1b\[[^a-zA-Z]*[a-zA-Z]", "", converted)

    return converted


# ---------------------------------------------------------------------------
# Route 1 — Web Screenshot
# ---------------------------------------------------------------------------

@screenshot_bp.route("/api/tools/screenshot", methods=["POST"])
def screenshot_web():
    """Take a screenshot of a web page.

    Request JSON
    ------------
    url        : str   — Required. Must start with http:// or https://.
    viewport   : str   — Optional. WIDTHxHEIGHT, default "1280x900".
    wait_ms    : int   — Optional. Extra wait after load, default 2000.
    full_page  : bool  — Optional. Capture full scrollable page, default False.

    Response JSON
    -------------
    success    : bool
    image_b64  : str   — Base64-encoded PNG (on success).
    file_size  : int   — Byte length of PNG (on success).
    viewport   : str   — Viewport used (on success).
    error      : str   — Error description (on failure).
    """
    data = request.get_json(force=True, silent=True) or {}

    url = data.get("url", "").strip()
    viewport = data.get("viewport", "1280x900")
    wait_ms = int(data.get("wait_ms", 2000))
    full_page = bool(data.get("full_page", False))

    # Validate URL scheme
    if not (url.startswith("http://") or url.startswith("https://")):
        return jsonify({"success": False, "error": "url must start with http:// or https://"}), 400

    # Parse viewport dimensions
    try:
        width_str, height_str = viewport.split("x", 1)
        width = int(width_str)
        height = int(height_str)
    except (ValueError, AttributeError):
        return jsonify({"success": False, "error": f"Invalid viewport format '{viewport}'. Expected WIDTHxHEIGHT."}), 400

    browser = None
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            try:
                page = browser.new_page(viewport={"width": width, "height": height})
                page.goto(url, wait_until="networkidle", timeout=20000)

                if wait_ms > 0:
                    page.wait_for_timeout(wait_ms)

                png_bytes = page.screenshot(full_page=full_page)
            finally:
                browser.close()

        return jsonify({
            "success": True,
            "image_b64": base64.b64encode(png_bytes).decode(),
            "file_size": len(png_bytes),
            "viewport": viewport,
        })

    except Exception as exc:
        # Surface a friendly message when Chromium is simply not installed
        exc_str = str(exc)
        if "Executable doesn't exist" in exc_str or "chromium" in exc_str.lower() and "install" in exc_str.lower():
            return jsonify({
                "success": False,
                "error": "Chromium is not installed. Run: playwright install chromium",
            })
        return jsonify({"success": False, "error": exc_str})


# ---------------------------------------------------------------------------
# Route 2 — Terminal Screenshot
# ---------------------------------------------------------------------------

@screenshot_bp.route("/api/tools/screenshot_terminal", methods=["POST"])
def screenshot_terminal():
    """Render terminal output as a styled HTML page and screenshot it.

    Request JSON
    ------------
    command    : str   — Required. The command that was run.
    output     : str   — Required. Raw terminal output (may contain ANSI codes).
    tool_name  : str   — Optional. Display name shown in the terminal header, default "Terminal".
    timestamp  : str   — Optional. Human-readable timestamp, default current local time.
    max_lines  : int   — Optional. Maximum output lines before truncation, default 200.

    Response JSON
    -------------
    success    : bool
    image_b64  : str   — Base64-encoded PNG (on success).
    file_size  : int   — Byte length of PNG (on success).
    viewport   : str   — Always "1280x900" (on success).
    error      : str   — Error description (on failure).
    """
    data = request.get_json(force=True, silent=True) or {}

    command = data.get("command", "").strip()
    output = data.get("output", "")
    tool_name = data.get("tool_name", "Terminal")
    timestamp = data.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    max_lines = int(data.get("max_lines", 200))

    if not command:
        return jsonify({"success": False, "error": "'command' is required"}), 400
    if output is None:
        return jsonify({"success": False, "error": "'output' is required"}), 400

    # Truncate to max_lines
    lines = output.splitlines()
    if len(lines) > max_lines:
        remaining = len(lines) - max_lines
        lines = lines[:max_lines]
        lines.append(f"\n[... {remaining} more lines truncated]")
    output_truncated = "\n".join(lines)

    # HTML-escape first, then convert ANSI codes to spans
    output_escaped = html.escape(output_truncated)
    output_html = ansi_to_html(output_escaped)

    command_escaped = html.escape(command)

    # Read HTML template
    try:
        template_content = TERMINAL_TEMPLATE_PATH.read_text(encoding="utf-8")
    except FileNotFoundError:
        return jsonify({
            "success": False,
            "error": f"terminal-template.html not found at {TERMINAL_TEMPLATE_PATH}",
        })

    # Inject values into template placeholders
    rendered_html = (
        template_content
        .replace("{{TOOL_NAME}}", tool_name)
        .replace("{{TIMESTAMP}}", timestamp)
        .replace("{{COMMAND}}", command_escaped)
        .replace("{{OUTPUT}}", output_html)
    )

    # Write to a temp file in /tmp
    tmp_filename = f"/tmp/athena-terminal-{uuid.uuid4().hex[:8]}.html"
    browser = None
    try:
        with open(tmp_filename, "w", encoding="utf-8") as fh:
            fh.write(rendered_html)

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            try:
                page = browser.new_page(viewport={"width": 1280, "height": 900})
                page.goto(f"file://{tmp_filename}")
                page.wait_for_timeout(500)   # Let CSS render
                png_bytes = page.screenshot()
            finally:
                browser.close()

        return jsonify({
            "success": True,
            "image_b64": base64.b64encode(png_bytes).decode(),
            "file_size": len(png_bytes),
            "viewport": "1280x900",
        })

    except Exception as exc:
        exc_str = str(exc)
        if "Executable doesn't exist" in exc_str or "chromium" in exc_str.lower() and "install" in exc_str.lower():
            return jsonify({
                "success": False,
                "error": "Chromium is not installed. Run: playwright install chromium",
            })
        return jsonify({"success": False, "error": exc_str})

    finally:
        # Always clean up the temp file
        try:
            os.remove(tmp_filename)
        except OSError:
            pass
