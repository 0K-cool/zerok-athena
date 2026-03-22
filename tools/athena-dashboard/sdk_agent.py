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
import io
import json
import logging
import re
import time
from pathlib import Path
from typing import Any, Callable, Optional

import httpx

from langfuse_integration import trace_agent_run, is_enabled as langfuse_enabled
from graphiti_integration import ingest_episode, is_enabled as graphiti_enabled
from message_bus import format_intel_update
from finding_pipeline import extract_findings_v2, BROADCAST_CONFIDENCES

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

# Multi-agent role configs (Phase F1a)
try:
    from agent_configs import AgentRoleConfig, format_prompt
except ImportError:
    AgentRoleConfig = None
    format_prompt = None

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


def _clean_cmd_display(cmd: str) -> str:
    """Clean inter-agent message wrappers for display in timeline.

    Strips ====== delimiters, INCOMING MESSAGE headers, and
    ACTION REQUIRED footers so the timeline shows only the content.
    """
    lines = cmd.strip().split("\n")
    cleaned = [
        ln for ln in lines
        if not ln.startswith("=" * 10)
        and not ln.startswith("URGENT INCOMING MESSAGE")
        and not ln.startswith("PENDING MESSAGE")
        and not ln.startswith("INCOMING MESSAGE")
        and not ln.startswith("ACTION REQUIRED:")
        and not ln.startswith("Incorporate this intelligence")
    ]
    result = "\n".join(cleaned).strip()
    return result[:200] if result else cmd[:200]


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


def _is_tool_output_noise(text: str) -> bool:
    """Return True if this tool output is internal noise, not relevant to pentesters."""
    stripped = text.strip()
    if not stripped:
        return True
    # Quick regex: tool_reference JSON anywhere in text
    if '"tool_reference"' in stripped and '"tool_name"' in stripped:
        return True
    # "Permission to use mcp__..." messages
    if "Permission to use " in stripped and "mcp__" in stripped:
        return True
    # "The operator denied/approved..." messages
    if stripped.startswith("The operator denied") or stripped.startswith("The operator approved"):
        return True
    # Agent-generated permission complaint text (BUG: WV "tools were denied permission")
    if "denied permission" in stripped and "mcp" in stripped.lower():
        return True
    if "operator needs to approve" in stripped:
        return True
    # Raw tool_reference JSON objects
    try:
        obj = json.loads(stripped)
        if isinstance(obj, dict) and obj.get("type") in (
            "tool_reference", "content_block_start", "content_block_stop",
            "tool_use", "input_json_delta", "text_delta",
        ):
            return True
        # tool_reference arrays
        if isinstance(obj, list) and all(
            isinstance(i, dict) and "tool_name" in i for i in obj
        ):
            return True
    except (json.JSONDecodeError, TypeError, ValueError):
        pass
    # "Todos have been modified successfully" internal SDK messages
    if "odos have been modified successfully" in stripped:
        return True
    # Phase 4.5: DA↔PX bilateral probe noise
    if "probe_request" in stripped and "msg_type" in stripped:
        return True
    if "probe_result" in stripped and "msg_type" in stripped:
        return True
    return False


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
            return ""  # Suppress tool_reference lists — internal noise
        return _strip_ansi(json.dumps(data, indent=2))[:max_len]

    if isinstance(data, dict):
        # Suppress internal SDK objects (tool_reference, etc.)
        if data.get("type") in (
            "tool_reference", "content_block_start", "content_block_stop",
            "tool_use", "input_json_delta", "text_delta",
        ):
            return ""

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
            # Preserve leading whitespace (ASCII art banners) — only strip trailing
            stdout = _strip_ansi(str(result.get("stdout", ""))).rstrip()
            stderr = _strip_ansi(str(result.get("stderr", ""))).rstrip()
            rc = result.get("return_code")

            parts = []
            if stdout.strip():
                parts.append(stdout)
            if stderr.strip() and stderr.strip() != stdout.strip():
                parts.append(stderr)
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
# Debug noise filters — suppress internal orchestration chatter from OR timeline
# These match agent status dumps and "still running" polling messages
_RE_DEBUG_STATUS = re.compile(
    r"^[A-Z]{2}:\s*running=|^[A-Z]{2}:\s*tool_calls=|"
    r"cost=\$[\d.]+|running=True|running=False|"
    r"^Right\s*[-—]\s*as\s+ST\s+I\s+coordinate",
    re.MULTILINE,
)
_RE_STILL_RUNNING = re.compile(
    r"[A-Z]{2}\s+is\s+still\s+running\s*\(|"
    r"still running\s*\(\d+\s+tool|"
    r"Let me poll|let me check|Let me wait",
    re.IGNORECASE,
)
_RE_AGENT_SHOWS_IDLE = re.compile(
    r"[A-Z]{2}\s+agent\s+shows\s+as\s+['\"]?idle|"
    r"spawn\s+request\s+was\s+registered\s+but\s+no\s+subprocess|"
    r"I'll\s+spawn\s+a\s+subagent|"
    r"let me take direct action",
    re.IGNORECASE,
)


# Agent Detection
# ──────────────────────────────────────────────

TOOL_TO_AGENT: dict[str, str] = {
    # Passive Recon (PR) — OSINT, subdomain enum, DNS intel, Shodan/Censys
    "subfinder": "PR", "amass": "PR", "theharvester": "PR",
    "whois": "PR", "dig": "PR", "gau": "PR",
    "shodan": "PR", "s3scanner": "PR", "censys": "PR",
    # Active Recon (AR) — port scanning, service enum
    "nmap": "AR", "httpx": "AR", "naabu": "AR",
    # Web Vulnerability scanning (WV)
    "nuclei": "WV", "nikto": "WV", "gobuster": "WV", "ffuf": "WV",
    "wpscan": "WV", "dirsearch": "WV",
    # Exploitation (EX) — includes lateral movement & post-exploit
    "sqlmap": "EX", "hydra": "EX", "msfconsole": "EX", "metasploit": "EX",
    "searchsploit": "EX",
    "crackmapexec": "EX", "impacket": "EX", "bloodhound": "EX",
    "responder": "EX", "evil-winrm": "EX",
    "linpeas": "EX", "winpeas": "EX", "linux-exploit-suggester": "EX",
}


def detect_agent(tool_name: str, command: str = "") -> str:
    """Infer which ATHENA agent is active from tool/command context."""
    text = f"{tool_name} {command}".lower()
    # Strategy Agent detection: reasoning about attack paths, not running tools
    strategy_keywords = [
        "strategy", "attack plan", "prioritiz", "chain", "pivot",
        "red team lead", "adversarial", "go/no-go", "exploit now",
        "investigate further", "deprioritize",
    ]
    if any(kw in text for kw in strategy_keywords):
        return "ST"
    # Deep Analysis detection: static analysis, code review, 0-day hunting
    da_keywords = [
        "semgrep", "bandit", "codeql", "gosec", "njsscan", "source code",
        "static analysis", "code review", "code audit", "sast",
        "code path", "taint analysis", "dataflow",
    ]
    if any(kw in text for kw in da_keywords):
        return "DA"
    for keyword, agent_code in TOOL_TO_AGENT.items():
        if keyword in text:
            return agent_code
    return "ST"


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
        self._budget_exhausted = False  # Set by early_stop to break query loop
        self._pending_tools: dict[str, str] = {}  # tool_use_id → tool_name
        # F5: Per-agent budget tracking
        self._agent_tool_counts: dict[str, int] = {}  # agent_code → tool_calls
        self._budget_server_url = "http://localhost:8080"
        # Phase F1a: Multi-agent role config (set via create_for_role())
        self._role_config: "AgentRoleConfig | None" = None
        self._role_prior_context: str = ""
        # Shared httpx client — created lazily, reused for the session lifetime
        self._http_client: httpx.AsyncClient | None = None
        # F4: CTF mode
        self.ctf_mode = False
        self._ctf_flag_patterns = [
            re.compile(r"flag\{[^}]+\}", re.IGNORECASE),
            re.compile(r"CTF\{[^}]+\}", re.IGNORECASE),
            re.compile(r"picoCTF\{[^}]+\}"),
            re.compile(r"HTB\{[^}]+\}"),
            re.compile(r"THM\{[^}]+\}"),
            re.compile(r"FLAG-[A-Za-z0-9\-]+"),
            re.compile(r"0xL4BS\{[^}]+\}"),
        ]
        self._engagement_id = engagement_id  # H3: Langfuse trace correlation
        # BUG-013: In multi-agent mode, suppress per-agent engagement_ended
        # emission — the manager emits the authoritative engagement_ended event.
        self._suppress_engagement_ended = False
        # Real-time bus: set via create_for_role() when MessageBus is available
        self._bus = None
        self._pending_injection: str = ""
        # Fix 9: Track latest finding_id for exploitation evidence linking
        self._last_finding_id: str = ""

    def set_event_callback(self, callback: Callable):
        """Set async callback for streaming events to the dashboard.

        Callback signature: async def callback(event: dict) -> None
        """
        self._event_callback = callback

    async def _get_http_client(self) -> httpx.AsyncClient:
        """Return the shared httpx client, creating it if needed."""
        if self._http_client is None or self._http_client.is_closed:
            self._http_client = httpx.AsyncClient(timeout=5.0)
        return self._http_client

    # ── Phase F1a: Multi-Agent Factory ─────────

    @classmethod
    def create_for_role(
        cls,
        role: "AgentRoleConfig",
        engagement_id: str,
        target: str,
        backend: str = "external",
        athena_root: str | Path = "",
        prior_context: str = "",
        bus=None,
    ) -> "AthenaAgentSession":
        """Create a session configured for a specific agent role.

        This is the multi-agent entry point. Each agent gets its own
        SDK session with restricted tools, role-specific prompt, and budget.

        Args:
            role: Agent role configuration from agent_configs.py
            engagement_id: Active engagement ID
            target: Target scope (IP/CIDR/URL)
            backend: Kali backend name ("external" or "internal")
            athena_root: Path to ATHENA project root
            prior_context: Findings/context from prior phases (injected into prompt)
            bus: Optional MessageBus for real-time inter-agent communication

        Returns:
            Configured AthenaAgentSession ready for start()
        """
        session = cls(engagement_id, target, backend, athena_root)
        session._role_config = role
        session._role_prior_context = prior_context
        session._bus = bus
        # Set the current agent code so events are attributed correctly
        session._current_agent = role.code
        logger.info("Agent %s workspace: %s (model=%s, budget=$%.2f)",
                     role.code, athena_root, role.model, role.max_cost_usd)
        return session

    # ── F2: Bilateral Messaging ────────────────

    async def send_bilateral_message(
        self,
        from_agent: str,
        to_agent: str,
        msg_type: str,
        content: str,
        priority: str = "medium",
        neo4j_ref: str | None = None,
    ):
        """Send a bilateral agent-to-agent message (F2).

        This emits an agent_message event that the dashboard renders as
        a from→to arrow in the AI drawer timeline.

        Args:
            from_agent: Sender agent code (e.g. "AR")
            to_agent: Recipient agent code (e.g. "WV")
            msg_type: One of: discovery, vulnerability, credential,
                      verification, strategy, pivot
            content: Message content
            priority: low, medium, high, critical
            neo4j_ref: Optional Neo4j node ID reference
        """
        meta = {
            "from_agent": from_agent,
            "to_agent": to_agent,
            "msg_type": msg_type,
            "priority": priority,
        }
        if neo4j_ref:
            meta["neo4j_ref"] = neo4j_ref
        await self._emit("agent_message", from_agent, content, meta)

    # ── F3: Verification Pipeline ────────────

    async def submit_for_verification(
        self,
        finding_id: str,
        priority: str = "medium",
        canary_url: str | None = None,
        source_path: str | None = None,
    ):
        """Submit a finding to The Moat for independent verification (F3).

        This emits a verification_queued event and triggers the VF agent
        to independently re-test the finding using different tools.

        Args:
            finding_id: ID of the finding to verify
            priority: low, medium, high, critical
            canary_url: Optional interactsh URL for OOB verification
            source_path: Optional source code path for code review
        """
        meta = {
            "finding_id": finding_id,
            "priority": priority,
            "verification_type": "moat",
        }
        if canary_url:
            meta["canary_url"] = canary_url
        if source_path:
            meta["source_path"] = source_path
        await self._emit("verification_queued", "VF",
            f"Finding {finding_id} submitted for verification", meta)

    async def report_verification_result(
        self,
        finding_id: str,
        status: str,
        method: str,
        confidence: float,
        poc_script: str | None = None,
        impact: str | None = None,
        canary_callback: dict | None = None,
    ):
        """Report a verification result from the VF agent (F3).

        Args:
            finding_id: Finding being verified
            status: confirmed, likely, unverified, false_positive
            method: independent_retest, canary_callback, poc_execution,
                    code_review, manual
            confidence: 0.0 - 1.0
            poc_script: Runnable PoC command
            impact: What was demonstrated
            canary_callback: OOB callback details if applicable
        """
        meta = {
            "finding_id": finding_id,
            "status": status,
            "method": method,
            "confidence": confidence,
        }
        if poc_script:
            meta["poc_script"] = poc_script
        if impact:
            meta["impact"] = impact
        if canary_callback:
            meta["canary"] = canary_callback

        label = status.upper()
        await self._emit("verification_result", "VF",
            f"{label}: Finding {finding_id} ({method}, {confidence:.0%})", meta)

    # ── F6: Attack Chain Reasoning ──────────

    async def create_attack_link(
        self,
        from_id: str,
        from_label: str,
        to_id: str,
        to_label: str,
        relationship: str,
        description: str = "",
        confidence: float = 0.8,
    ):
        """Create a chain link between two findings/hosts (F6).

        Relationship types: ENABLES, PIVOTS_TO, ESCALATES_TO, EXPOSES

        Emits the chain_link WebSocket event AND persists to Neo4j via
        the /api/chains/link endpoint (Fix 11).
        """
        await self._emit("system", "ST",
            f"Chain: {from_label} —[{relationship}]→ {to_label}",
            {"chain_link": True, "relationship": relationship,
             "from_id": from_id, "from_label": from_label,
             "to_id": to_id, "to_label": to_label,
             "description": description, "confidence": confidence})

        # Fix 11: Persist attack link to Neo4j via server API
        try:
            client = await self._get_http_client()
            await client.post(
                f"{self._budget_server_url}/api/chains/link",
                json={
                    "engagement_id": self.engagement_id,
                    "from_finding_id": from_id,
                    "from_label": from_label,
                    "to_finding_id": to_id,
                    "to_label": to_label,
                    "relationship": relationship,
                    "description": description,
                    "confidence": confidence,
                },
            )
        except Exception:
            # Non-critical — don't interrupt the main engagement flow
            pass

    async def register_attack_chain(
        self,
        chain_id: str,
        name: str,
        steps: list[str],
        impact: str,
        blast_radius: str = "",
        priority: int = 1,
    ):
        """Register a full attack chain discovered by Strategy Agent (F6).

        Args:
            chain_id: Unique chain identifier
            name: Short chain name (e.g. "SQLi → Admin → RCE")
            steps: List of step labels for display
            impact: What the full chain achieves
            blast_radius: How much damage is possible
            priority: 1=highest

        Emits the attack_chain WebSocket event AND persists to Neo4j via
        the /api/chains endpoint (Fix 11).
        """
        chain_str = " → ".join(steps)
        await self._emit("system", "ST",
            f"ATTACK CHAIN [{priority}]: {chain_str} — {impact}",
            {"attack_chain": True, "chain_id": chain_id,
             "chain_name": name, "steps_count": len(steps),
             "steps": steps, "impact": impact,
             "blast_radius": blast_radius, "priority": priority})

        # Fix 11: Persist full attack chain to Neo4j via server API
        try:
            client = await self._get_http_client()
            await client.post(
                f"{self._budget_server_url}/api/chains",
                json={
                    "engagement_id": self.engagement_id,
                    "chain_id": chain_id,
                    "chain_name": name,
                    "steps": steps,
                    "impact": impact,
                    "blast_radius": blast_radius,
                    "priority": priority,
                },
            )
        except Exception:
            # Non-critical — don't interrupt the main engagement flow
            pass

    # ── F5: Budget Tracking ─────────────────

    async def _record_budget_tool_call(self, agent: str):
        """Record a tool call against the agent's budget via server API."""
        self._agent_tool_counts[agent] = self._agent_tool_counts.get(agent, 0) + 1
        try:
            client = await self._get_http_client()
            resp = await client.post(
                f"{self._budget_server_url}/api/budget/tool-call",
                params={"agent": agent},
                timeout=2.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("early_stop"):
                    self._budget_exhausted = True
                    await self._emit("system", agent,
                        f"EARLY STOP: {agent} budget exhausted — "
                        f"{data.get('tool_calls', '?')}/{data.get('max_tool_calls', '?')} calls",
                        {"budget_early_stop": True, "agent": agent})
        except Exception:
            # Non-critical — budget tracking is best-effort
            pass

    async def _report_actual_cost(self, agent: str, cost_usd: float):
        """Report actual SDK cost to the server budget tracker.

        BUG-008b: Called on each ResultMessage to replace estimated costs
        with real costs from the Claude Agent SDK.
        BUG-016: Uses engagement_remaining for budget warnings instead of
        per-agent remaining, which was misleadingly low.
        P0-FIX: Retry with exponential backoff — lost cost reports cause
        dashboard to show $0.10 when actual cost is $2.93+.
        """
        max_retries = 2
        base_timeout = 5.0

        for attempt in range(max_retries + 1):
            try:
                timeout = base_timeout * (2 ** attempt)  # 5s, 10s, 20s
                client = await self._get_http_client()
                resp = await client.post(
                    f"{self._budget_server_url}/api/budget/actual-cost",
                    params={"agent": agent, "cost_usd": round(cost_usd, 6)},
                    timeout=timeout,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    eng_remaining = data.get("engagement_remaining")
                    if data.get("early_stop"):
                        # BUG-FIX: Only warn, don't set _budget_exhausted.
                        # Tool-call endpoint is the single authority for
                        # early stop. Actual-cost early_stop was a second
                        # competing trigger that killed agents prematurely.
                        remaining_msg = (f" (engagement has ${eng_remaining:.2f} remaining)"
                                         if eng_remaining is not None else "")
                        await self._emit("system", agent,
                            f"COST WARNING: {agent} actual cost ${cost_usd:.2f} "
                            f"approaching per-agent cap{remaining_msg}",
                            {"budget_cost_warning": True, "agent": agent,
                             "actual_cost": round(cost_usd, 4),
                             "engagement_remaining": eng_remaining})
                    if data.get("engagement_cap_exceeded"):
                        await self._emit("system", agent,
                            f"ENGAGEMENT CAP WARNING: Total cost "
                            f"${data.get('engagement_cost', 0):.2f}",
                            {"engagement_cap": True})
                    return  # Success — exit retry loop
                else:
                    logger.warning(
                        "Cost report HTTP %d for %s ($%.4f), attempt %d/%d",
                        resp.status_code, agent, cost_usd,
                        attempt + 1, max_retries + 1)
            except Exception as e:
                logger.warning(
                    "Cost report failed for %s ($%.4f), attempt %d/%d: %s",
                    agent, cost_usd, attempt + 1, max_retries + 1,
                    str(e)[:200])
                if attempt < max_retries:
                    await asyncio.sleep(0.5 * (2 ** attempt))  # 0.5s, 1s backoff

        # All retries exhausted — log final warning so it's visible
        logger.error(
            "COST REPORT LOST: %s $%.4f after %d attempts",
            agent, cost_usd, max_retries + 1)

    async def _report_budget_finding(self, agent: str):
        """Report that an agent produced a finding (BUG-008b)."""
        try:
            client = await self._get_http_client()
            await client.post(
                f"{self._budget_server_url}/api/budget/finding",
                params={"agent": agent},
                timeout=2.0,
            )
        except Exception:
            pass

    # ── Fix 9: Exploitation Evidence Capture ─

    EXPLOIT_INDICATORS = [
        'uid=', 'root:', 'www-data', 'nt authority',  # RCE confirmation
        'shell>', 'meterpreter>', 'reverse shell',      # Shell access
        'uploaded successfully', 'webshell',             # File upload
        'password:', 'credentials found',                # Credential access
    ]

    @staticmethod
    def _is_debug_noise(text: str) -> bool:
        """Filter out internal debug/orchestration noise from agent text blocks.

        Suppresses raw JSON tool references, agent status dumps, and other
        internal chatter that isn't relevant to the pentester watching the
        dashboard. Tool output (from tool_complete events) is NOT affected.
        """
        stripped = text.strip()
        # Quick regex: any text that is predominantly tool_reference JSON lines
        if '"tool_reference"' in stripped and '"tool_name"' in stripped:
            return True
        # Raw JSON objects (tool_reference, content_block metadata, etc.)
        if stripped.startswith("{") and stripped.endswith("}"):
            try:
                obj = json.loads(stripped)
                if isinstance(obj, dict) and obj.get("type") in (
                    "tool_reference", "content_block_start", "content_block_stop",
                    "tool_use", "input_json_delta", "text_delta",
                ):
                    return True
            except (json.JSONDecodeError, ValueError):
                pass
        # Raw JSON arrays (tool reference lists)
        if stripped.startswith("[") and stripped.endswith("]"):
            try:
                arr = json.loads(stripped)
                if isinstance(arr, list) and all(
                    isinstance(i, dict) and "tool_name" in i for i in arr
                ):
                    return True
            except (json.JSONDecodeError, ValueError):
                pass
        # Agent status dump lines (e.g. "ST: running=True, tool_calls=14, cost=$0.28")
        if _RE_DEBUG_STATUS.search(stripped):
            return True
        # "Permission to use mcp__..." permission request text
        if "Permission to use " in stripped and "mcp__" in stripped:
            return True
        # "The operator denied/approved the..." permission resolution
        if stripped.startswith("The operator denied the") or stripped.startswith("The operator approved the"):
            return True
        # Agent-generated permission complaint (e.g. "The Kali MCP tools were denied permission")
        if "denied permission" in stripped.lower():
            return True
        if "operator needs to approve" in stripped.lower():
            return True
        # "AR is still running (6 tool ...)" status polling text
        if _RE_STILL_RUNNING.search(stripped):
            return True
        # "AR agent shows as idle" — internal status polling
        if _RE_AGENT_SHOWS_IDLE.search(stripped):
            return True
        # Phase 4.5: DA hypothesis loop internal chatter
        if "hypothesis" in stripped.lower() and "confidence" in stripped.lower() and len(stripped) < 200:
            return True
        return False

    _ST_BAR_NOISE_PREFIXES = (
        "initial state", "checking", "querying", "looking at",
        "strategy posted", "ar agent requested", "let me",
        "i'll ", "i will", "now i", "ok,", "ok ",
        "stale", "this is a stale", "queued before",
        "acknowledged", "no action needed", "no further action",
    )

    def _extract_st_summary(self, text: str) -> str:
        """Extract a concise strategic summary that fits in the bar (120 chars).

        Strategy: find the first meaningful line, then trim to the first
        complete sentence that fits. This gives a coherent thought, not
        a mid-word truncation.
        """
        import re
        # Find first qualifying line
        candidate = ""
        for line in text.split("\n"):
            stripped = line.strip()
            if not stripped or len(stripped) < 20:
                continue
            if re.fullmatch(r"[\d\s.,:/\-]+", stripped):
                continue
            if stripped.startswith(("{", "[", "```")):
                continue
            lower = stripped.lower()
            if any(lower.startswith(p) for p in self._ST_BAR_NOISE_PREFIXES):
                continue
            candidate = stripped
            break
        if not candidate:
            return ""
        # If it fits, use it directly
        if len(candidate) <= 120:
            return candidate
        # Try to cut at the last sentence boundary that fits
        for sep in (". ", " — ", "; ", ", "):
            idx = candidate.rfind(sep, 0, 120)
            if idx > 30:  # Must keep at least 30 chars
                return candidate[:idx + (1 if sep == ". " else 0)].strip()
        # No good boundary — cut at last space before 120
        idx = candidate.rfind(" ", 0, 117)
        if idx > 30:
            return candidate[:idx] + "..."
        return candidate[:117] + "..."

    def _is_finding_creation(self, tool_name: str, output: str) -> bool:
        """Detect if a tool result indicates a finding was created.

        BUG-008b: Used to track findings_count for cost-per-finding metrics.
        """
        tool_lower = tool_name.lower()
        if "create_finding" in tool_lower or "report_finding" in tool_lower:
            return True
        output_lower = output.lower()
        # Neo4j MCP tool creating a Finding node
        if "neo4j" in tool_lower and "finding" in output_lower and \
                ("created" in output_lower or "merged" in output_lower):
            return True
        # POST to /api/findings via bash/curl
        if "api/findings" in output and \
                ("ok" in output_lower or '"finding_id"' in output_lower):
            return True
        return False

    def _is_exploitation_result(self, tool_name: str, output: str) -> bool:
        """Detect if a tool result indicates successful exploitation."""
        if tool_name not in ('bash', 'execute_command', 'run_command',
                             'mcp__kali_external__bash', 'mcp__kali_internal__bash',
                             'mcp__kali_external__execute_command',
                             'mcp__kali_internal__execute_command'):
            return False
        output_lower = output.lower()
        return any(indicator in output_lower for indicator in self.EXPLOIT_INDICATORS)

    async def _capture_exploitation_evidence(self, tool_name: str, output: str):
        """Capture exploitation result as an artifact via the dashboard API.

        Called when a bash/command tool result contains exploitation indicators.
        Creates an artifact and links it to the most recent finding via
        HAS_ARTIFACT relationship.
        """
        try:
            artifact_payload = {
                "engagement_id": self.engagement_id,
                "type": "command_output",
                "caption": f"Exploitation evidence — {tool_name}",
                "content": output[:8000],  # cap to avoid oversized payloads
                "agent": self._role_config.code if self._role_config else self._current_agent,
                "finding_id": self._last_finding_id,
                "auto_link_latest_finding": not bool(self._last_finding_id),
            }
            client = await self._get_http_client()
            resp = await client.post(
                f"{self._budget_server_url}/api/artifacts/text",
                json=artifact_payload,
            )
            if resp.status_code in (200, 201):
                data = resp.json()
                artifact_id = data.get("artifact_id", "")
                await self._emit("system", self._current_agent,
                    f"Exploitation evidence captured: {artifact_id}",
                    {"artifact_captured": True,
                     "artifact_id": artifact_id,
                     "tool": tool_name})
            else:
                logger.warning(
                    "Artifact API returned %d for exploitation capture",
                    resp.status_code)
        except Exception as e:
            # Non-critical — don't interrupt the main engagement flow
            logger.warning("Exploitation evidence capture failed: %s", e)

    # ── F4: CTF Mode Helpers ─────────────────

    def enable_ctf_mode(self):
        """Enable CTF mode — activates flag detection in tool output."""
        self.ctf_mode = True

    def disable_ctf_mode(self):
        """Disable CTF mode."""
        self.ctf_mode = False

    def detect_flags_in_text(self, text: str) -> list[str]:
        """Extract CTF flags from text using compiled patterns."""
        flags = []
        for pattern in self._ctf_flag_patterns:
            flags.extend(pattern.findall(text))
        return list(set(flags))

    async def _check_for_flags(self, text: str, agent: str):
        """Check tool output for CTF flags and emit capture events."""
        if not self.ctf_mode or not text:
            return
        flags = self.detect_flags_in_text(text)
        for flag in flags:
            await self._emit("system", agent,
                f"FLAG DETECTED: {flag}",
                {"ctf_flag_detected": True, "flag": flag, "agent": agent})

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

    def _build_options(
        self,
        resume_id: str | None = None,
        max_turns: int = 15,
    ) -> ClaudeAgentOptions:
        """Build SDK options for a query call.

        When _role_config is set (via create_for_role()), uses the role's
        model, tools, budget, and prompt. Otherwise falls back to the
        original single-agent behavior for backwards compatibility.

        Args:
            resume_id: Session ID to resume an existing conversation.
            max_turns: Maximum tool-call turns per query chunk. Defaults to 15
                (~1-2 minutes), which keeps each chunk short enough that
                operator commands are picked up promptly between chunks.
        """
        role = self._role_config

        if role and format_prompt:
            # ── Multi-agent mode: role-specific configuration ──
            model = role.model
            allowed = list(role.allowed_tools)
            disallowed = list(role.disallowed_tools)
            budget = role.max_cost_usd
            turns = role.max_turns_per_chunk

            # Build role-specific prompt with engagement context
            role_prompt = format_prompt(
                role, self.engagement_id, self.target,
                self.backend, self._role_prior_context,
            )

            prompt_append = (
                f"You are {role.name} ({role.code}) in an ATHENA multi-agent "
                f"penetration test. Follow your role instructions precisely.\n\n"
                f"{role_prompt}"
            )
        else:
            # ── Single-agent fallback (original behavior) ──
            model = "sonnet"
            allowed = [
                "Bash", "Read", "Write", "Edit",
                f"mcp__kali_{self.backend}__*",
                "mcp__kali_external__*",
                "mcp__kali_internal__*",
                "mcp__athena_neo4j__*",
                "mcp__athena-neo4j__*",
            ]
            disallowed = []
            budget = 5.0
            turns = max_turns
            prompt_append = (
                "You are an ATHENA AI pentesting agent. You execute "
                "authorized penetration tests following PTES methodology. "
                "Read CLAUDE.md for full methodology, tool docs, and "
                "security constraints. Read the relevant playbook from "
                "playbooks/ BEFORE starting each attack phase. Report "
                "all findings to Neo4j and the dashboard API."
            )

        def _sdk_stderr(line: str):
            """Capture SDK CLI stderr for MCP/tool debugging."""
            stripped = line.strip()
            if stripped:
                logger.debug("SDK stderr [%s]: %s",
                             role.code if role else "SINGLE", stripped)
                # Log MCP-related lines at INFO for visibility
                if any(k in stripped.lower() for k in ("mcp", "server", "tool", "error", "fail", "timeout")):
                    logger.info("SDK stderr [%s]: %s",
                                role.code if role else "SINGLE", stripped)

        # MCP servers: explicitly pass .mcp.json via --mcp-config, and use
        # --strict-mcp-config to prevent the CLI from ALSO loading .mcp.json
        # via project root detection (which caused duplicate server processes
        # and silent tool unavailability).
        mcp_json = Path(self.athena_root) / ".mcp.json"
        opts = ClaudeAgentOptions(
            model=model,
            cwd=str(self.athena_root),
            allowed_tools=allowed,
            permission_mode="bypassPermissions",
            max_budget_usd=budget,
            mcp_servers=str(mcp_json),
            setting_sources=["project"],
            system_prompt={
                "type": "preset",
                "preset": "claude_code",
                "append": prompt_append,
            },
            env={
                "CLAUDECODE": "",
                # BUG-041 fix: Unset ANTHROPIC_API_KEY so Agent SDK subprocesses
                # use Max subscription auth instead of the Graphiti API key
                # (which start.sh exports for Graphiti's Haiku calls).
                "ANTHROPIC_API_KEY": "",
            },
            stderr=_sdk_stderr,
            extra_args={"strict-mcp-config": None},
        )
        if disallowed:
            opts.disallowed_tools = disallowed
        if resume_id:
            opts.resume = resume_id
        opts.max_turns = turns
        return opts

    # ── Query Execution ───────────────────────

    async def _run_query(self, prompt: str, resume_id: str | None = None):
        """Execute a single SDK query and process all messages.

        This is the core loop that translates SDK events to dashboard events.
        """
        opts = self._build_options(resume_id)
        # H3: Agent-level Langfuse span
        _lf_ctx = None
        if langfuse_enabled() and self._engagement_id:
            _lf_ctx = trace_agent_run(
                engagement_id=self._engagement_id,
                agent_code=self._current_agent,
                agent_name=self._role_config.name if self._role_config else self._current_agent,
                model=self._role_config.model if self._role_config else "claude-sonnet-4-6",
            )
            _lf_ctx.__enter__()
        try:
            async for msg in query(prompt=prompt, options=opts):
                if not self.is_running or self._budget_exhausted:
                    break

                if isinstance(msg, SystemMessage):
                    logger.info("SDK SystemMessage [%s]: %s",
                                msg.subtype, json.dumps(msg.data, default=str)[:3000])
                    # Log tool list separately for debugging
                    if msg.subtype == "init" and "tools" in msg.data:
                        tools = msg.data["tools"]
                        kali_tools = [t for t in tools if "kali" in t.lower()]
                        logger.info("SDK init tools: %d total, %d kali: %s",
                                    len(tools), len(kali_tools), kali_tools)
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
                        self._total_cost_usd = msg.total_cost_usd  # Cumulative from SDK, not additive
                        # BUG-008b: Report actual cost to server budget tracker
                        # BUG-032 fix: Use _role_config.code for correct cost attribution
                        cost_agent = self._role_config.code if self._role_config else self._current_agent
                        await self._report_actual_cost(
                            cost_agent, self._total_cost_usd)
                    # BUG-D fix: ST emits strategy_decision on TextBlock — skip the redundant
                    # "AI turn complete" system event that would duplicate the summary in the drawer.
                    agent_code = self._role_config.code if self._role_config else self._current_agent
                    if agent_code != "ST":
                        result_text = msg.result or "Turn complete"
                        await self._emit("system", "OR",
                            f"AI turn complete: {result_text}", {
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
        finally:
            # H3: Close agent span
            if _lf_ctx:
                try:
                    _lf_ctx.__exit__(None, None, None)
                except Exception:
                    pass

    def _build_next_prompt(self, base_prompt: str) -> str:
        """Prepend any pending bus intel injection to the base prompt.

        Clears _pending_injection after consuming it so each injection
        is only delivered once.
        """
        if not self._pending_injection:
            return base_prompt
        combined = f"{self._pending_injection}\n\n{base_prompt}"
        self._pending_injection = ""
        return combined

    async def _drain_bus_inbox(self):
        """Drain the message bus and format pending intel for injection."""
        if not self._bus:
            return
        agent_code = self._role_config.code if self._role_config else self._current_agent
        messages = await self._bus.drain(agent_code)
        if messages:
            self._pending_injection = format_intel_update(messages, agent_code)

    async def _engagement_loop(self, initial_prompt: str):
        """Main engagement loop: chunked query execution with operator command injection.

        Uses max_turns to limit each query to ~15 tool calls, then checks the
        command queue before auto-continuing. This ensures operator commands
        are picked up within ~1-2 minutes instead of waiting for the entire
        engagement turn to complete (which could be 30+ minutes).
        """
        try:
            await self._emit("system", "OR",
                "Starting AI engagement via Agent SDK...")

            prompt = initial_prompt
            resume_id = None

            while self.is_running and not self.is_paused and not self._budget_exhausted:
                # Track tool count to detect when AI finishes (no tools used)
                tools_before = self._tool_count

                # Run a bounded query chunk (max_turns limits duration)
                await self._run_query(prompt, resume_id)

                # Real-time bus: drain inbox after each query chunk
                await self._drain_bus_inbox()

                if not self.is_running or self.is_paused or self._budget_exhausted:
                    break

                tools_used = self._tool_count - tools_before
                resume_id = self.session_id

                if tools_used == 0:
                    # AI didn't use any tools — likely done or waiting for input
                    # BUG-012 FIX: ST waiting for workers needs a longer timeout.
                    # Workers report back to ST via send_command(), so ST legitimately
                    # sits idle while waiting. Use 300s for ST, 60s for workers.
                    # BUG-024 FIX: Use _role_config.code (spawned agent), not _current_agent
                    # (which tracks last tool's detected agent and may have shifted).
                    spawned_code = self._role_config.code if self._role_config else self._current_agent
                    idle_timeout = 300.0 if spawned_code == "ST" else 60.0  # BUG-038: ST needs longer wait for workers
                    await self._emit("system", "OR",
                        "AI turn complete. Waiting for operator commands...",
                        {"control": "awaiting_commands"})
                    try:
                        cmd = await asyncio.wait_for(
                            self._command_queue.get(), timeout=idle_timeout)
                        await self._emit("system", "OR",
                            f"Processing operator command: {_clean_cmd_display(cmd)}")
                        prompt = self._build_next_prompt(cmd)
                    except asyncio.TimeoutError:
                        await self._emit("system", "OR",
                            f"No operator commands for {int(idle_timeout)} seconds. Ending session.")
                        break
                else:
                    # AI is actively working — check for operator commands frequently
                    try:
                        cmd = await asyncio.wait_for(
                            self._command_queue.get(), timeout=0.2)
                        # Operator command takes priority over auto-continue
                        await self._emit("system", "OR",
                            f"Processing operator command: {_clean_cmd_display(cmd)}")
                        prompt = self._build_next_prompt(cmd)
                    except asyncio.TimeoutError:
                        # No commands — auto-continue the engagement
                        if resume_id:
                            prompt = self._build_next_prompt(
                                "Continue with the next step of the penetration test.")
                        else:
                            break

        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.exception("Engagement loop error")
            await self._emit("system", "OR",
                f"Engagement error: {str(e)[:500]}")
        finally:
            self.is_running = False
            # BUG-037: Don't emit engagement_ended when paused — pause is not termination
            if self.is_paused:
                await self._emit("system", "OR",
                    f"SDK query cancelled. "
                    f"{self._tool_count} tool calls, ${self._total_cost_usd:.4f} total cost.",
                    {"control": "engagement_paused",
                     "cost_usd": round(self._total_cost_usd, 4),
                     "tool_calls": self._tool_count})
            elif self._suppress_engagement_ended:
                # BUG-013: In multi-agent mode, don't emit engagement_ended —
                # that would cause the frontend to reset as if the whole
                # engagement ended. The manager emits the authoritative event.
                # Emit agent_session_ended instead (filtered as noise by frontend).
                agent_code = (self._role_config.code
                              if self._role_config else "OR")
                # BUG-023: Always emit agent_complete so server.py watchdog
                # can detect ST/RP completion and trigger auto-stop correctly.
                await self._emit("agent_complete", agent_code,
                    f"Agent {agent_code} session ended")
                await self._emit("system", agent_code,
                    f"Agent {agent_code} session ended. "
                    f"{self._tool_count} tool calls, ${self._total_cost_usd:.4f} cost.",
                    {"control": "agent_session_ended",
                     "cost_usd": round(self._total_cost_usd, 4),
                     "tool_calls": self._tool_count,
                     "agent": agent_code})
                await self._cleanup_orphan_scans()
            else:
                await self._emit("system", "OR",
                    f"AI engagement session ended. "
                    f"{self._tool_count} tool calls, ${self._total_cost_usd:.4f} total cost.",
                    {"control": "engagement_ended",
                     "cost_usd": round(self._total_cost_usd, 4),
                     "tool_calls": self._tool_count})
                await self._cleanup_orphan_scans()

    async def _cleanup_orphan_scans(self):
        """Mark any running scans as aborted when the session ends unexpectedly."""
        try:
            client = await self._get_http_client()
            url = f"{self._budget_server_url}/api/engagement/{self.engagement_id}/cleanup-orphans"
            resp = await client.post(
                url,
                content=b"",
                headers={"Content-Type": "application/json"},
                timeout=5.0,
            )
            if resp.status_code == 200:
                logger.info("Orphan scans cleaned for %s", self.engagement_id)
        except Exception as e:
            logger.warning("Failed to cleanup orphan scans: %s", e)

    # ── Lifecycle ─────────────────────────────

    async def start(self, prompt_text: str):
        """Start the engagement with the given system prompt.

        Launches the engagement query as a background asyncio task.
        Events stream to the dashboard via the event callback.
        """
        self.is_running = True
        self.is_paused = False
        self._query_task = asyncio.create_task(self._engagement_loop(prompt_text))
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
            return "Command queued — will execute within ~1-2 minutes."
        else:
            return "Command queued — waiting for session to initialize."

    async def pause(self):
        """Pause the engagement by cancelling the current query."""
        self.is_paused = True
        if self._query_task and not self._query_task.done():
            self._query_task.cancel()
            try:
                await asyncio.wait_for(self._query_task, timeout=3.0)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                pass
        await self._emit("system", "OR", "Engagement paused by operator.",
            {"control": "engagement_paused"})

    async def resume(
        self,
        prompt: str = "Continue the engagement from where you left off. Pick up the next phase or tool."
    ):
        """Resume a paused engagement by re-entering the engagement loop."""
        if not self.session_id:
            await self._emit("system", "OR",
                "Cannot resume — no session_id. Start a new engagement.")
            return

        self.is_paused = False
        self.is_running = True
        self._budget_exhausted = False

        # Re-enter the main engagement loop with resume prompt.
        # _engagement_loop handles auto-continuation, operator commands,
        # idle timeout, and budget checks — _resume_loop was too simple
        # and exited after one turn.
        self._query_task = asyncio.create_task(
            self._resume_engagement_loop(prompt)
        )

    async def _resume_engagement_loop(self, prompt: str):
        """Resume by running a single query with session resume, then
        re-enter the standard engagement loop for auto-continuation."""
        try:
            await self._emit("system", "OR",
                f"Resuming engagement: {prompt[:200]}")

            resume_id = self.session_id

            while self.is_running and not self.is_paused and not self._budget_exhausted:
                tools_before = self._tool_count

                await self._run_query(prompt, resume_id)

                # Real-time bus: drain inbox after each query chunk
                await self._drain_bus_inbox()

                if not self.is_running or self.is_paused or self._budget_exhausted:
                    break

                tools_used = self._tool_count - tools_before
                resume_id = self.session_id

                if tools_used == 0:
                    # HIGH-6 + BUG-024 fix: Use spawned agent code for timeout
                    spawned_code = self._role_config.code if self._role_config else self._current_agent
                    idle_timeout = 300.0 if spawned_code == "ST" else 60.0  # BUG-038: ST needs longer wait for workers
                    await self._emit("system", "OR",
                        "AI turn complete. Waiting for operator commands...",
                        {"control": "awaiting_commands"})
                    try:
                        cmd = await asyncio.wait_for(
                            self._command_queue.get(), timeout=idle_timeout)
                        await self._emit("system", "OR",
                            f"Processing operator command: {_clean_cmd_display(cmd)}")
                        prompt = self._build_next_prompt(cmd)
                    except asyncio.TimeoutError:
                        await self._emit("system", "OR",
                            f"No operator commands for {int(idle_timeout)} seconds. Ending session.")
                        break
                else:
                    try:
                        cmd = await asyncio.wait_for(
                            self._command_queue.get(), timeout=0.2)
                        await self._emit("system", "OR",
                            f"Processing operator command: {_clean_cmd_display(cmd)}")
                        prompt = self._build_next_prompt(cmd)
                    except asyncio.TimeoutError:
                        if resume_id:
                            prompt = self._build_next_prompt(
                                "Continue with the next step of the penetration test.")
                        else:
                            break

        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.exception("Resume loop error")
            await self._emit("system", "OR",
                f"Resume error: {str(e)[:500]}")
        finally:
            self.is_running = False
            # BUG-037: Don't emit engagement_ended when paused — pause is not termination
            if self.is_paused:
                await self._emit("system", "OR",
                    f"SDK query cancelled. "
                    f"{self._tool_count} tool calls, ${self._total_cost_usd:.4f} total cost.",
                    {"control": "engagement_paused",
                     "cost_usd": round(self._total_cost_usd, 4),
                     "tool_calls": self._tool_count})
            elif self._suppress_engagement_ended:
                # BUG-013: Multi-agent mode — emit agent-scoped event, not engagement_ended
                agent_code = (self._role_config.code
                              if self._role_config else "OR")
                # BUG-023: Always emit agent_complete so server.py watchdog
                # can detect ST/RP completion and trigger auto-stop correctly.
                await self._emit("agent_complete", agent_code,
                    f"Agent {agent_code} session ended")
                await self._emit("system", agent_code,
                    f"Agent {agent_code} session ended. "
                    f"{self._tool_count} tool calls, ${self._total_cost_usd:.4f} cost.",
                    {"control": "agent_session_ended",
                     "cost_usd": round(self._total_cost_usd, 4),
                     "tool_calls": self._tool_count,
                     "agent": agent_code})
                await self._cleanup_orphan_scans()
            else:
                await self._emit("system", "OR",
                    f"AI engagement session ended. "
                    f"{self._tool_count} tool calls, ${self._total_cost_usd:.4f} total cost.",
                    {"control": "engagement_ended",
                     "cost_usd": round(self._total_cost_usd, 4),
                     "tool_calls": self._tool_count})
                await self._cleanup_orphan_scans()

    async def stop(self):
        """Stop the engagement and clean up."""
        self.is_running = False
        self.is_paused = False

        if self._query_task and not self._query_task.done():
            self._query_task.cancel()
            try:
                await self._query_task
            except (asyncio.CancelledError, RuntimeError):
                # RuntimeError: "Attempted to exit cancel scope in a different task"
                # This is a known anyio/SDK issue when cancelling process_query
                # from a different task context. Safe to suppress.
                pass
            self._query_task = None

        # Drain the command queue
        while not self._command_queue.empty():
            try:
                self._command_queue.get_nowait()
            except asyncio.QueueEmpty:
                break

        # Close the shared httpx client
        if self._http_client and not self._http_client.is_closed:
            await self._http_client.aclose()  # LOW-6: use async close

        logger.info("SDK session stopped for engagement %s "
                     "(%d tool calls, $%.4f)",
                     self.engagement_id, self._tool_count, self._total_cost_usd)

    # ── Message Handlers ──────────────────────

    async def _handle_assistant_message(self, msg: AssistantMessage):
        """Translate assistant messages to dashboard events."""
        for block in msg.content:
            if isinstance(block, ThinkingBlock):
                thought = block.thinking
                # ST thinking → strategy_thinking (lights up blue bar)
                event_type = ("strategy_thinking"
                              if self._current_agent == "ST"
                              else "agent_thinking")
                await self._emit(event_type, self._current_agent,
                    thought, {
                        "thought": thought,
                        # removed "reasoning" — same source as thought, caused duplication
                    })

            elif isinstance(block, TextBlock):
                text = block.text.strip()
                if text and not self._is_debug_noise(text):
                    if self._current_agent == "ST":
                        # Show ST's strategic reasoning in the bar
                        bar_summary = self._extract_st_summary(text)
                        if bar_summary:
                            await self._emit("strategy_decision", self._current_agent,
                                text[:1000], {
                                    "summary": bar_summary[:120],
                                })
                        else:
                            await self._emit("strategy_thinking", self._current_agent,
                                text[:1000])
                    else:
                        await self._emit("system", self._current_agent,
                            text[:1000])

            elif isinstance(block, ToolUseBlock):
                self._tool_count += 1
                command = str(block.input.get("command", ""))
                new_agent = detect_agent(block.name, command)

                # F5: Record tool call against AUTHORITATIVE agent budget
                # BUG-031 fix: detect_agent() defaults to "ST" for unrecognized
                # MCP tools, causing budget misattribution. Use _role_config.code
                # (the actual spawned agent) for all operational decisions.
                budget_agent = self._role_config.code if self._role_config else new_agent
                await self._record_budget_tool_call(budget_agent)

                # Emit agent transition if changed — only in single-session mode.
                # In multi-agent mode (_role_config set), the session IS the agent;
                # detect_agent heuristics must not flip the identity.
                if self._role_config is None and new_agent != self._current_agent:
                    await self._emit("agent_status", self._current_agent,
                        "idle", {"status": "idle"})
                    self._current_agent = new_agent
                    await self._emit("agent_status", new_agent,
                        "running", {"status": "running"})

                tool_desc = block.name
                if command:
                    tool_desc += f": {command[:100]}"

                # Track tool_use_id → name for tool_complete correlation
                self._pending_tools[block.id] = block.name
                # Track Bash command for finding pipeline whitelist check
                if block.name == "Bash" and command:
                    if not hasattr(self, '_pending_commands'):
                        self._pending_commands = {}
                    self._pending_commands[block.id] = command

                await self._emit("tool_start", self._current_agent,
                    f"Calling {tool_desc}", {
                        "tool": block.name,
                        "tool_id": block.id,
                        "command": command,
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
                    tool_name = self._pending_tools.pop(block.tool_use_id, "")
                    # Skip noise: empty output (suppressed), permission msgs, etc.
                    if _is_tool_output_noise(output):
                        continue
                    await self._emit("tool_complete", self._current_agent,
                        output, {
                            "tool": tool_name,
                            "tool_id": block.tool_use_id,
                            "success": not block.is_error,
                            "output": output,
                        })
                    # F4: Check tool output for CTF flags
                    await self._check_for_flags(output, self._current_agent)
                    # Fix 9: Capture exploitation evidence as artifact
                    if not block.is_error and self._is_exploitation_result(tool_name, output):
                        await self._capture_exploitation_evidence(tool_name, output)
                    # BUG-008b: Detect finding creation for budget metrics
                    if not block.is_error and self._is_finding_creation(tool_name, output):
                        await self._report_budget_finding(self._current_agent)
                        # Fix 9c: Extract and track latest finding_id for artifact linking
                        m = re.search(r'"finding_id"\s*:\s*"([^"]+)"', output)
                        if m:
                            self._last_finding_id = m.group(1)
                    # H1: Feed tool outputs into Graphiti for knowledge extraction
                    if graphiti_enabled() and self._engagement_id and len(output) > 50:
                        asyncio.create_task(ingest_episode(
                            engagement_id=self._engagement_id,
                            name=f"{self._current_agent}_tool_{block.tool_use_id[:8]}",
                            content=output[:4000],
                            source_description=f"Tool output from {self._current_agent}",
                        ))
                    # Real-time bus: extract findings from tool output and broadcast
                    if self._bus and output and len(output) > 20:
                        cmd = ""
                        if hasattr(self, '_pending_commands'):
                            cmd = self._pending_commands.pop(block.tool_use_id, "")
                        findings = extract_findings_v2(
                            self._current_agent, tool_name, output, command=cmd)
                        for finding in findings:
                            from message_bus import BusMessage
                            msg_bus = BusMessage(
                                from_agent=self._current_agent,
                                to="ALL",
                                bus_type="finding",
                                priority=finding.severity,
                                summary=finding.summary,
                                target=finding.target,
                                data=finding.to_dict(),
                                action_needed=finding.action_needed,
                            )
                            if finding.confidence in BROADCAST_CONFIDENCES:
                                await self._bus.broadcast(msg_bus)
                                if finding.severity in ("high", "critical"):
                                    await self.send_bilateral_message(
                                        from_agent=self._current_agent,
                                        to_agent="ST",
                                        msg_type="discovery",
                                        content=finding.summary[:500],
                                        priority=finding.severity,
                                    )
                            else:
                                # LOW confidence: dashboard only (no agent broadcast)
                                self._bus._history.append(msg_bus)
                                for cb in self._bus._callbacks:
                                    asyncio.create_task(cb(msg_bus))
        elif msg.tool_use_result:
            raw = msg.tool_use_result.get("content", "")
            output = _extract_tool_output(raw)
            tool_use_id = msg.tool_use_result.get("tool_use_id", "")
            tool_name = self._pending_tools.pop(tool_use_id, "")
            # Skip noise
            if _is_tool_output_noise(output):
                return
            await self._emit("tool_complete", self._current_agent,
                output, {
                    "tool": tool_name,
                    "tool_id": tool_use_id,
                    "success": not msg.tool_use_result.get("is_error", False),
                    "output": output,
                })
            # F4: Check tool output for CTF flags
            await self._check_for_flags(output, self._current_agent)
            # Fix 9: Capture exploitation evidence as artifact
            if not msg.tool_use_result.get("is_error", False) and \
                    self._is_exploitation_result(tool_name, output):
                await self._capture_exploitation_evidence(tool_name, output)
            # Fix 9c: Track latest finding_id for artifact linking
            if not msg.tool_use_result.get("is_error", False) and \
                    self._is_finding_creation(tool_name, output):
                m = re.search(r'"finding_id"\s*:\s*"([^"]+)"', output)
                if m:
                    self._last_finding_id = m.group(1)
            # H1: Feed tool outputs into Graphiti for knowledge extraction
            if graphiti_enabled() and self._engagement_id and len(output) > 50:
                asyncio.create_task(ingest_episode(
                    engagement_id=self._engagement_id,
                    name=f"{self._current_agent}_tool_{tool_use_id[:8]}",
                    content=output[:4000],
                    source_description=f"Tool output from {self._current_agent}",
                ))
            # Real-time bus: extract findings from tool output and broadcast
            if self._bus and output and len(output) > 20:
                cmd = ""
                if hasattr(self, '_pending_commands'):
                    cmd = self._pending_commands.pop(tool_use_id, "")
                findings = extract_findings_v2(
                    self._current_agent, tool_name, output, command=cmd)
                for finding in findings:
                    from message_bus import BusMessage
                    msg_bus = BusMessage(
                        from_agent=self._current_agent,
                        to="ALL",
                        bus_type="finding",
                        priority=finding.severity,
                        summary=finding.summary,
                        target=finding.target,
                        data=finding.to_dict(),
                        action_needed=finding.action_needed,
                    )
                    if finding.confidence in BROADCAST_CONFIDENCES:
                        await self._bus.broadcast(msg_bus)
                        if finding.severity in ("high", "critical"):
                            await self.send_bilateral_message(
                                from_agent=self._current_agent,
                                to_agent="ST",
                                msg_type="discovery",
                                content=finding.summary[:500],
                                priority=finding.severity,
                            )
                    else:
                        # LOW confidence: dashboard only (no agent broadcast)
                        self._bus._history.append(msg_bus)
                        for cb in self._bus._callbacks:
                            asyncio.create_task(cb(msg_bus))
