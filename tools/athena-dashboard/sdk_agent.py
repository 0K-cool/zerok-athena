"""Claude Agent SDK wrapper for ATHENA AI engagements.

Replaces the subprocess-based Claude CLI spawning (Phase E) with the
Agent SDK for interactive, multi-turn operator control of the AI pentest team.

Architecture:
    Uses query() with resume=session_id for multi-turn conversations.
    - start() launches the initial engagement query as a background task
    - send_command() queues commands; they execute when the current turn ends
    - HITL approvals use REST-based polling (in the prompt), proven reliable
    - pause/stop cancel the current query task
    - resume sends a continuation prompt via query(resume=session_id)

Event Translation:
    SDK message types -> ATHENA dashboard WebSocket events
    AssistantMessage(ToolUseBlock)  -> tool_start
    UserMessage(ToolResultBlock)    -> tool_complete
    AssistantMessage(TextBlock)     -> system
    AssistantMessage(ThinkingBlock) -> agent_thinking
    ResultMessage                   -> turn complete (may auto-continue)
"""

import asyncio
import json
import logging
import re
import time
from pathlib import Path
from typing import Any, Callable, Optional

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ResultMessage,
    SystemMessage,
    TextBlock,
    ThinkingBlock,
    ToolResultBlock,
    ToolUseBlock,
    UserMessage,
    query,
)
from claude_agent_sdk.types import StreamEvent

logger = logging.getLogger("athena.sdk_agent")

# ANSI escape code patterns (both real escape chars and literal \u001b strings)
_ANSI_RE = re.compile(
    r"\x1b\[[0-9;]*[A-Za-z]"    # Real ESC [ ... m sequences
    r"|\x1b\].*?\x07"            # Real ESC ] ... BEL sequences
    r"|\\u001b\[[0-9;]*[A-Za-z]" # Literal \u001b[...m strings
    r"|\[(\d+;)*\d*m"            # Bare [31m style remnants
)


def _strip_ansi(text: str) -> str:
    """Remove ANSI escape codes from text (both real and literal)."""
    return _ANSI_RE.sub("", text)


def _to_str(obj: Any) -> str:
    """Convert SDK content objects to a plain string.

    Handles: str, list[TextBlock], list[dict], dict, TextBlock, None.
    Always returns a string suitable for json.loads() when the underlying
    data is JSON.
    """
    if obj is None:
        return ""
    if isinstance(obj, str):
        return obj
    # ToolResultBlock.content can be a list of text/content blocks
    if isinstance(obj, list):
        parts = []
        for item in obj:
            if hasattr(item, "text"):
                parts.append(item.text)
            elif isinstance(item, dict) and "text" in item:
                parts.append(item["text"])
            elif isinstance(item, dict):
                # MCP result dict in a list — serialize as JSON
                parts.append(json.dumps(item))
            else:
                parts.append(str(item))
        # If single item, return as-is (don't wrap in extra newlines)
        if len(parts) == 1:
            return parts[0]
        return "\n".join(parts)
    if isinstance(obj, dict):
        return json.dumps(obj)
    if hasattr(obj, "text"):
        return obj.text
    return str(obj)


def _extract_tool_output(raw: Any, max_len: int = 4000) -> str:
    """Extract human-readable output from SDK tool results.

    MCP tool results come as nested JSON like:
        {"result": {"stdout": "...", "stderr": "...", "return_code": 0}}
    or Neo4j results like:
        {"result": "{\"host\": \"192.168.13.13\", \"port\": 3030}"}
    or tool references like:
        [{"type": "tool_reference", "tool_name": "mcp__athena_neo4j__create_host"}]
    This extracts the meaningful parts and strips ANSI codes.
    """
    text = _to_str(raw)
    if not text:
        return ""

    # Try to parse as JSON and extract structured output
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        data = None

    # Handle list results (tool_reference arrays, etc.)
    if isinstance(data, list):
        names = [
            item.get("tool_name", "")
            for item in data
            if isinstance(item, dict) and "tool_name" in item
        ]
        if names:
            return ", ".join(names)
        return _strip_ansi(json.dumps(data, indent=2))[:max_len]

    if isinstance(data, dict):
        result = data.get("result", data)

        # If result is a JSON string, try to parse it too
        if isinstance(result, str):
            try:
                result = json.loads(result)
            except (json.JSONDecodeError, TypeError):
                # Neo4j / simple MCP results — return the string
                return _strip_ansi(result)[:max_len]

        # MCP Kali tool format: {"stdout": "...", "stderr": "..."}
        if isinstance(result, dict):
            stdout = str(result.get("stdout", "")).strip()
            stderr = str(result.get("stderr", "")).strip()
            rc = result.get("return_code")

            parts = []
            if stdout:
                parts.append(_strip_ansi(stdout))
            if stderr:
                cleaned = _strip_ansi(stderr)
                if cleaned and cleaned != stdout:
                    parts.append(cleaned)
            if rc and rc != 0 and not parts:
                parts.append(f"Exit code: {rc}")

            if parts:
                return "\n".join(parts)[:max_len]

            # Neo4j / other dict — pretty-print without noise
            clean = {k: v for k, v in result.items()
                     if k not in ("partial_results", "return_code", "stderr")}
            # Single meaningful value — return it directly
            vals = list(clean.values())
            if len(vals) == 1 and isinstance(vals[0], str):
                return vals[0][:max_len]
            return _strip_ansi(json.dumps(clean, indent=2))[:max_len]

    # Fallback: strip ANSI from raw text
    return _strip_ansi(text)[:max_len]


# ──────────────────────────────────────────────
# Agent Detection
# ──────────────────────────────────────────────

TOOL_TO_AGENT: dict[str, str] = {
    # Recon / OSINT
    "nmap": "PO", "httpx": "PO", "amass": "PO", "gau": "PO",
    "subfinder": "PO", "whois": "PO", "dig": "PO", "theharvester": "PO",
    "naabu": "AR",
    # Vulnerability scanning
    "nuclei": "WV", "nikto": "WV", "gobuster": "WV", "ffuf": "WV",
    "wpscan": "WV", "dirsearch": "WV",
    # Exploitation
    "sqlmap": "EX", "hydra": "EX", "msfconsole": "EX", "metasploit": "EX",
    "searchsploit": "EX",
    # Lateral movement
    "crackmapexec": "LM", "impacket": "LM", "bloodhound": "LM",
    "responder": "LM", "evil-winrm": "LM",
    # Post-exploitation / privesc
    "linpeas": "PE", "winpeas": "PE", "linux-exploit-suggester": "PE",
}


def detect_agent(tool_name: str, command: str = "") -> str:
    """Infer which ATHENA agent is active from tool/command context."""
    text = f"{tool_name} {command}".lower()
    for keyword, agent_code in TOOL_TO_AGENT.items():
        if keyword in text:
            return agent_code
    return "OR"


# ──────────────────────────────────────────────
# AthenaAgentSession
# ──────────────────────────────────────────────

class AthenaAgentSession:
    """Manages a Claude Agent SDK session for one ATHENA engagement.

    Uses query() with resume=session_id for multi-turn operator control.
    Operator commands are queued and processed between query turns.

    Lifecycle:
        session = AthenaAgentSession(eid, target, backend)
        session.set_event_callback(emit_to_dashboard)
        await session.start(prompt)
        # ... initial engagement runs, events stream to dashboard ...
        await session.send_command("status")  # queued, runs after turn
        await session.pause()                 # cancel current turn
        await session.resume()                # new turn via resume
        await session.stop()                  # full cleanup
    """

    def __init__(
        self,
        engagement_id: str,
        target: str,
        backend: str = "external",
        athena_root: str | Path = "",
    ):
        self.engagement_id = engagement_id
        self.target = target
        self.backend = backend
        self.athena_root = (
            Path(athena_root) if athena_root
            else Path(__file__).resolve().parent.parent.parent
        )
        self.session_id: str | None = None
        self.is_running = False
        self.is_paused = False
        self._query_task: asyncio.Task | None = None
        self._event_callback: Optional[Callable] = None
        self._command_queue: asyncio.Queue[str] = asyncio.Queue()
        self._current_agent = "OR"
        self._tool_count = 0
        self._total_cost_usd: float = 0.0

    def set_event_callback(self, callback: Callable):
        """Set async callback for streaming events to the dashboard.

        Callback signature: async def callback(event: dict) -> None
        """
        self._event_callback = callback

    # ── Internal Helpers ──────────────────────

    async def _emit(self, event_type: str, agent: str, content: str,
                    metadata: dict | None = None):
        """Emit an event to the dashboard via callback."""
        if self._event_callback:
            await self._event_callback({
                "type": event_type,
                "agent": agent,
                "content": content,
                "metadata": metadata or {},
                "timestamp": time.time(),
            })

    def _build_options(self, resume_id: str | None = None) -> ClaudeAgentOptions:
        """Build SDK options for a query call."""
        opts = ClaudeAgentOptions(
            model="sonnet",
            cwd=str(self.athena_root),
            mcp_servers=str(self.athena_root / ".mcp.json"),
            allowed_tools=[
                "Bash", "Read", "Write", "Edit",
                f"mcp__kali_{self.backend}__*",
                "mcp__kali_external__*",
                "mcp__kali_internal__*",
                "mcp__athena_neo4j__*",
                "mcp__athena-neo4j__*",
            ],
            permission_mode="bypassPermissions",
            max_budget_usd=5.0,
            env={
                # Prevent "nested session" error if started from Claude Code
                "CLAUDECODE": "",
            },
        )
        if resume_id:
            opts.resume = resume_id
        return opts

    # ── Query Execution ───────────────────────

    async def _run_query(self, prompt: str, resume_id: str | None = None):
        """Execute a single SDK query and process all messages.

        This is the core loop that translates SDK events to dashboard events.
        """
        opts = self._build_options(resume_id)
        try:
            async for msg in query(prompt=prompt, options=opts):
                if not self.is_running:
                    break

                if isinstance(msg, SystemMessage):
                    if msg.subtype == "init" and "session_id" in msg.data:
                        self.session_id = msg.data["session_id"]
                        logger.info("SDK session_id: %s", self.session_id)

                elif isinstance(msg, AssistantMessage):
                    await self._handle_assistant_message(msg)

                elif isinstance(msg, UserMessage):
                    await self._handle_user_message(msg)

                elif isinstance(msg, ResultMessage):
                    self.session_id = msg.session_id
                    if msg.total_cost_usd:
                        self._total_cost_usd += msg.total_cost_usd
                    result_text = msg.result or "Turn complete"
                    await self._emit("system", "OR",
                        f"AI turn complete: {result_text[:500]}", {
                            "session_id": msg.session_id,
                            "cost_usd": msg.total_cost_usd,
                            "duration_ms": msg.duration_ms,
                            "turns": msg.num_turns,
                        })

                elif isinstance(msg, StreamEvent):
                    if not self.session_id and msg.session_id:
                        self.session_id = msg.session_id

        except asyncio.CancelledError:
            await self._emit("system", "OR", "SDK query cancelled.")
            raise
        except Exception as e:
            logger.exception("SDK query error")
            await self._emit("system", "OR",
                f"SDK query error: {str(e)[:500]}")

    async def _engagement_loop(self, initial_prompt: str):
        """Main engagement loop: run initial query, then process command queue."""
        try:
            # Run the initial engagement query
            await self._emit("system", "OR",
                "Starting AI engagement via Agent SDK...")
            await self._run_query(initial_prompt)

            # After initial query completes, process any queued commands
            while self.is_running and not self.is_paused:
                try:
                    # Wait for a command with a short timeout
                    cmd = await asyncio.wait_for(
                        self._command_queue.get(), timeout=2.0
                    )
                except asyncio.TimeoutError:
                    # No commands queued — check if we should continue
                    if self._command_queue.empty():
                        # Engagement turn complete, no pending commands
                        break
                    continue

                if not self.session_id:
                    await self._emit("system", "OR",
                        "Cannot process command — no session_id available.")
                    continue

                await self._emit("system", "OR",
                    f"Processing operator command: {cmd[:200]}")
                await self._run_query(cmd, resume_id=self.session_id)

        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.exception("Engagement loop error")
            await self._emit("system", "OR",
                f"Engagement error: {str(e)[:500]}")
        finally:
            self.is_running = False
            await self._emit("system", "OR",
                f"AI engagement session ended. "
                f"{self._tool_count} tool calls, ${self._total_cost_usd:.4f} total cost.")

    # ── Lifecycle ─────────────────────────────

    async def start(self, prompt: str):
        """Start the engagement with the given system prompt.

        Launches the engagement query as a background asyncio task.
        Events stream to the dashboard via the event callback.
        """
        self.is_running = True
        self.is_paused = False
        self._query_task = asyncio.create_task(self._engagement_loop(prompt))
        logger.info("SDK engagement started for %s", self.engagement_id)

    async def send_command(self, command: str) -> str:
        """Send an operator command to the engagement.

        If a query is currently running, the command is queued and will
        be processed as a new turn (with full session context) once the
        current turn completes.
        """
        if not self.is_running:
            return "Error: No active engagement."

        await self._command_queue.put(command)

        if self.session_id:
            return "Command queued — will execute after current turn completes."
        else:
            return "Command queued — waiting for session to initialize."

    async def pause(self):
        """Pause the engagement by cancelling the current query."""
        self.is_paused = True
        if self._query_task and not self._query_task.done():
            self._query_task.cancel()
            try:
                await self._query_task
            except asyncio.CancelledError:
                pass
        await self._emit("system", "OR", "Engagement paused by operator.")

    async def resume(
        self,
        prompt: str = "Continue the engagement from where you left off. Pick up the next phase or tool."
    ):
        """Resume a paused engagement with a continuation prompt."""
        if not self.session_id:
            await self._emit("system", "OR",
                "Cannot resume — no session_id. Start a new engagement.")
            return

        self.is_paused = False
        self.is_running = True

        # Queue the resume prompt and restart the engagement loop
        await self._command_queue.put(prompt)
        self._query_task = asyncio.create_task(self._resume_loop())

    async def _resume_loop(self):
        """Resume loop: process queued commands using session resume."""
        try:
            while self.is_running and not self.is_paused:
                try:
                    cmd = await asyncio.wait_for(
                        self._command_queue.get(), timeout=2.0
                    )
                except asyncio.TimeoutError:
                    if self._command_queue.empty():
                        break
                    continue

                await self._emit("system", "OR",
                    f"Resuming with: {cmd[:200]}")
                await self._run_query(cmd, resume_id=self.session_id)

        except asyncio.CancelledError:
            pass
        except Exception as e:
            await self._emit("system", "OR",
                f"Resume error: {str(e)[:500]}")
        finally:
            self.is_running = False

    async def stop(self):
        """Stop the engagement and clean up."""
        self.is_running = False
        self.is_paused = False

        if self._query_task and not self._query_task.done():
            self._query_task.cancel()
            try:
                await self._query_task
            except asyncio.CancelledError:
                pass
            self._query_task = None

        # Drain the command queue
        while not self._command_queue.empty():
            try:
                self._command_queue.get_nowait()
            except asyncio.QueueEmpty:
                break

        logger.info("SDK session stopped for engagement %s "
                     "(%d tool calls, $%.4f)",
                     self.engagement_id, self._tool_count, self._total_cost_usd)

    # ── Message Handlers ──────────────────────

    async def _handle_assistant_message(self, msg: AssistantMessage):
        """Translate assistant messages to dashboard events."""
        for block in msg.content:
            if isinstance(block, ThinkingBlock):
                thought = block.thinking[:500]
                await self._emit("agent_thinking", self._current_agent,
                    thought, {
                        "thought": thought,
                        "reasoning": block.thinking[:1000],
                    })

            elif isinstance(block, TextBlock):
                text = block.text.strip()
                if text:
                    await self._emit("system", self._current_agent,
                        text[:1000])

            elif isinstance(block, ToolUseBlock):
                self._tool_count += 1
                command = str(block.input.get("command", ""))
                new_agent = detect_agent(block.name, command)

                # Emit agent transition if changed
                if new_agent != self._current_agent:
                    await self._emit("agent_status", self._current_agent,
                        "idle", {"status": "idle"})
                    self._current_agent = new_agent
                    await self._emit("agent_status", new_agent,
                        "running", {"status": "running"})

                tool_desc = block.name
                if command:
                    tool_desc += f": {command[:100]}"

                await self._emit("tool_start", self._current_agent,
                    f"Calling {tool_desc}", {
                        "tool": block.name,
                        "tool_id": block.id,
                        "input": {
                            k: str(v)[:200]
                            for k, v in block.input.items()
                        },
                    })

    async def _handle_user_message(self, msg: UserMessage):
        """Translate user messages (tool results) to dashboard events."""
        if isinstance(msg.content, list):
            for block in msg.content:
                if isinstance(block, ToolResultBlock):
                    output = _extract_tool_output(block.content)
                    await self._emit("tool_complete", self._current_agent,
                        output, {
                            "tool_id": block.tool_use_id,
                            "success": not block.is_error,
                            "output": output,
                        })
        elif msg.tool_use_result:
            raw = msg.tool_use_result.get("content", "")
            output = _extract_tool_output(raw)
            await self._emit("tool_complete", self._current_agent,
                output, {
                    "tool_id": msg.tool_use_result.get("tool_use_id", ""),
                    "success": not msg.tool_use_result.get("is_error", False),
                    "output": output,
                })
