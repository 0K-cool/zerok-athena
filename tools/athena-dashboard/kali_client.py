"""
Async HTTP client for ATHENA's dual Kali backends.

Reads tool definitions from tool-registry.json so new tools can be added
without code changes. Supports both dedicated Flask endpoints and the
generic /api/command fallback.

Usage:
    client = KaliClient.from_env()
    await client.health_check("external")
    result = await client.run_tool("nmap_scan", {"target": "10.0.0.0/24"})
"""

import asyncio
import base64
import json
import logging
import os
import re
import shlex
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

REGISTRY_PATH = Path(__file__).parent / "tool-registry.json"


@dataclass
class ToolResult:
    """Result from a Kali tool execution."""
    tool: str
    backend: str
    success: bool
    stdout: str
    stderr: str
    returncode: int
    elapsed_s: float
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "backend": self.backend,
            "success": self.success,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "returncode": self.returncode,
            "elapsed_s": round(self.elapsed_s, 2),
            "error": self.error,
        }


@dataclass
class KaliBackend:
    """Configuration for a single Kali backend."""
    name: str
    base_url: str
    api_key: Optional[str] = None
    available: bool = False
    tools: set = field(default_factory=set)

    def headers(self) -> dict:
        h = {"Content-Type": "application/json"}
        if self.api_key:
            h["X-API-Key"] = self.api_key
        return h


class KaliClient:
    """Async HTTP client for dual Kali Flask API backends."""

    def __init__(self, backends: dict[str, KaliBackend], registry: dict):
        self.backends = backends
        self.registry = registry
        self._client: Optional[httpx.AsyncClient] = None

    @classmethod
    def from_env(cls) -> "KaliClient":
        """Create client from environment variables and tool registry."""
        backends = {
            "external": KaliBackend(
                name="external",
                base_url=os.environ.get(
                    "KALI_EXTERNAL_URL",
                    "http://your-kali-host:5000",
                ),
            ),
            "internal": KaliBackend(
                name="internal",
                base_url=os.environ.get(
                    "KALI_INTERNAL_URL",
                    "http://your-internal-kali:5000",
                ),
                api_key=os.environ.get("KALI_API_KEY", ""),
            ),
        }

        registry = cls._load_registry()

        # Populate backend tool sets from registry
        for tool_name, tool_def in registry.items():
            if tool_name.startswith("_"):
                continue
            for backend_name in tool_def.get("backends", []):
                if backend_name in backends:
                    backends[backend_name].tools.add(tool_name)

        return cls(backends, registry)

    @staticmethod
    def _load_registry() -> dict:
        """Load tool registry from JSON file."""
        if not REGISTRY_PATH.exists():
            logger.warning("Tool registry not found at %s, using empty registry", REGISTRY_PATH)
            return {}
        with open(REGISTRY_PATH) as f:
            data = json.load(f)
        # Filter out metadata keys
        return {k: v for k, v in data.items() if not k.startswith("_")}

    def reload_registry(self):
        """Reload tool registry from disk (hot reload without restart).
        HIGH-4 fix: Copy-on-write — build new state fully, then swap atomically.
        """
        new_registry = self._load_registry()
        new_tools: dict[str, set] = {name: set() for name in self.backends}
        for tool_name, tool_def in new_registry.items():
            for backend_name in tool_def.get("backends", []):
                if backend_name in new_tools:
                    new_tools[backend_name].add(tool_name)
        # Atomic swap
        self.registry = new_registry
        for name, backend in self.backends.items():
            backend.tools = new_tools.get(name, set())
        logger.info("Tool registry reloaded: %d tools", len(self.registry))

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create the shared async HTTP client."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=httpx.Timeout(600.0, connect=10.0))
        return self._client

    async def close(self):
        """Close the HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    # ── Health Check ──

    async def health_check(self, backend_name: str) -> dict:
        """Check backend health and available tools."""
        backend = self.backends.get(backend_name)
        if not backend:
            return {"available": False, "error": f"Unknown backend: {backend_name}"}

        try:
            client = await self._get_client()
            resp = await client.get(
                f"{backend.base_url}/health",
                headers=backend.headers(),
                timeout=10.0,
            )
            data = resp.json()
            backend.available = True
            # Map Kali health tool names to registry tool names
            _TOOL_NAME_MAP = {
                "naabu": "naabu_scan",
                "nikto": "nikto_scan",
                "gobuster": "gobuster_scan",
                "sqlmap": "sqlmap_scan",
                "hydra": "hydra_attack",
                "john": "john_crack",
                "wpscan": "wpscan_analyze",
                "whatweb": "whatweb_scan",
                "nmap": "nmap_scan",
                "httpx": "httpx_probe",
                "katana": "katana_crawl",
                "nuclei": "nuclei_scan",
                "responder": "responder_listen",
                "crackmapexec": "crackmapexec_scan",
                "kiterunner": "kiterunner_scan",
                "s3scanner": "s3scanner_scan",
                "eyewitness": "eyewitness_capture",
                "dirb": "dirb_scan",
            }
            raw_tools = data.get("tools_status", {})
            mapped_tools = {}
            for tool_name, status in raw_tools.items():
                registry_name = _TOOL_NAME_MAP.get(tool_name, tool_name)
                mapped_tools[registry_name] = status
            return {
                "available": True,
                "backend": backend_name,
                "url": backend.base_url,
                "status": data.get("status", "unknown"),
                "tools_status": mapped_tools,
            }
        except Exception as e:
            backend.available = False
            return {
                "available": False,
                "backend": backend_name,
                "url": backend.base_url,
                "error": str(e),
            }

    async def health_check_all(self) -> dict:
        """Check all backends concurrently."""
        results = await asyncio.gather(
            *[self.health_check(name) for name in self.backends],
            return_exceptions=True,
        )
        return {
            name: (r if not isinstance(r, Exception) else {"available": False, "error": str(r)})
            for name, r in zip(self.backends, results)
        }

    # ── Backend Selection ──

    def select_backend(self, tool_name: str, target_type: str = "external") -> Optional[str]:
        """Select the best backend for a tool.

        Priority:
        1. If tool only available on one backend, use that.
        2. For external targets, prefer external backend.
        3. For internal targets, prefer internal backend.
        4. Fallback to whichever is available.
        """
        tool_def = self.registry.get(tool_name, {})
        available_backends = tool_def.get("backends", [])

        if not available_backends:
            return None

        if len(available_backends) == 1:
            name = available_backends[0]
            return name if self.backends.get(name, KaliBackend("", "")).available else None

        # Prefer based on target type
        preferred = "external" if target_type == "external" else "internal"
        fallback = "internal" if preferred == "external" else "external"

        if preferred in available_backends and self.backends.get(preferred, KaliBackend("", "")).available:
            return preferred
        if fallback in available_backends and self.backends.get(fallback, KaliBackend("", "")).available:
            return fallback

        return None

    # ── Tool Execution ──

    async def run_tool(
        self,
        tool_name: str,
        params: dict,
        backend: str = "auto",
        target_type: str = "external",
    ) -> ToolResult:
        """Execute a tool on a Kali backend.

        Args:
            tool_name: Tool name from the registry (e.g. "nmap_scan").
            params: Tool parameters matching the registry definition.
            backend: "auto", "external", or "internal".
            target_type: "external" or "internal" (used for auto backend selection).

        Returns:
            ToolResult with stdout/stderr/returncode.
        """
        tool_def = self.registry.get(tool_name)
        if not tool_def:
            return ToolResult(
                tool=tool_name, backend="none", success=False,
                stdout="", stderr="", returncode=-1, elapsed_s=0,
                error=f"Unknown tool: {tool_name}. Add it to tool-registry.json.",
            )

        # Select backend
        if backend == "auto":
            backend = self.select_backend(tool_name, target_type)
            if not backend:
                return ToolResult(
                    tool=tool_name, backend="none", success=False,
                    stdout="", stderr="", returncode=-1, elapsed_s=0,
                    error=f"No available backend for {tool_name}",
                )

        backend_obj = self.backends.get(backend)
        if not backend_obj:
            return ToolResult(
                tool=tool_name, backend=backend, success=False,
                stdout="", stderr="", returncode=-1, elapsed_s=0,
                error=f"Unknown backend: {backend}",
            )

        endpoint = tool_def.get("endpoint", "/api/command")
        timeout = tool_def.get("timeout", 300)
        start = time.monotonic()

        try:
            if endpoint == "/api/command":
                result = await self._run_via_command(backend_obj, tool_name, tool_def, params, timeout)
            else:
                result = await self._run_via_endpoint(backend_obj, endpoint, params, timeout)

            elapsed = time.monotonic() - start
            return ToolResult(
                tool=tool_name,
                backend=backend,
                success=result.get("success", result.get("returncode", 1) == 0),
                stdout=result.get("stdout", ""),
                stderr=result.get("stderr", ""),
                returncode=result.get("returncode", -1),
                elapsed_s=elapsed,
                error=result.get("error"),
            )
        except httpx.TimeoutException:
            return ToolResult(
                tool=tool_name, backend=backend, success=False,
                stdout="", stderr="", returncode=-1,
                elapsed_s=time.monotonic() - start,
                error=f"HTTP timeout after {timeout}s",
            )
        except httpx.ConnectError as e:
            # Mark backend as unavailable
            backend_obj.available = False
            return ToolResult(
                tool=tool_name, backend=backend, success=False,
                stdout="", stderr="", returncode=-1,
                elapsed_s=time.monotonic() - start,
                error=f"Connection failed: {e}",
            )
        except Exception as e:
            return ToolResult(
                tool=tool_name, backend=backend, success=False,
                stdout="", stderr="", returncode=-1,
                elapsed_s=time.monotonic() - start,
                error=f"Unexpected error: {e}",
            )

    async def _run_via_endpoint(
        self, backend: KaliBackend, endpoint: str, params: dict, timeout: float
    ) -> dict:
        """Call a dedicated Flask tool endpoint (e.g. /api/tools/nmap)."""
        client = await self._get_client()
        resp = await client.post(
            f"{backend.base_url}{endpoint}",
            json=params,
            headers=backend.headers(),
            timeout=timeout,
        )
        resp.raise_for_status()
        return resp.json()

    async def _run_via_command(
        self, backend: KaliBackend, tool_name: str, tool_def: dict,
        params: dict, timeout: float
    ) -> dict:
        """Build command from template and call /api/command."""
        template = tool_def.get("command_template", "")
        if not template:
            return {"success": False, "error": f"No command_template for {tool_name}"}

        # Handle list-type params (write to temp file on target via command)
        targets = params.get("targets")
        run_id = uuid.uuid4().hex[:8]

        if targets and isinstance(targets, list):
            # Write targets to a temp file on the Kali box first
            target_content = "\n".join(targets)
            input_file = f"/tmp/athena-{run_id}-targets.txt"
            encoded = base64.b64encode(target_content.encode()).decode()
            write_cmd = f"echo '{encoded}' | base64 -d > {input_file}"
            client = await self._get_client()
            await client.post(
                f"{backend.base_url}/api/command",
                json={"command": write_cmd},
                headers=backend.headers(),
                timeout=30,
            )
            params = {**params, "input_file": input_file}

        # Apply default param values from tool registry so callers don't need
        # to provide every template variable (e.g. severity defaults to
        # "critical,high,medium" for nuclei_scan).
        registry_params = tool_def.get("params", {})
        merged = {}
        for pname, pdef in registry_params.items():
            if "default" in pdef:
                merged[pname] = pdef["default"]
        # Caller-supplied params override defaults
        for k, v in params.items():
            if isinstance(v, (str, int, float)):
                merged[k] = v

        # Build command from template — shell-escape all substituted values
        command = template.format(
            run_id=run_id,
            **{k: shlex.quote(str(v)) for k, v in merged.items()}
        )

        # Append additional_args if present — allowlist only safe tokens
        additional = params.get("additional_args", "")
        if additional:
            safe_parts = []
            for part in shlex.split(additional):
                if re.match(r'^-{1,2}[a-zA-Z][a-zA-Z0-9_-]*(?:=\S+)?$', part):
                    safe_parts.append(part)
                elif re.match(r'^[a-zA-Z0-9._:/-]+$', part):
                    safe_parts.append(part)
                else:
                    logger.debug("Dropping unsafe additional_args token: %r", part)  # LOW-4
            if safe_parts:
                command = f"{command} {' '.join(safe_parts)}"

        client = await self._get_client()
        resp = await client.post(
            f"{backend.base_url}/api/command",
            json={"command": command},
            headers=backend.headers(),
            timeout=timeout,
        )
        resp.raise_for_status()
        result = resp.json()

        # Cleanup temp file
        if targets and isinstance(targets, list):
            try:
                await client.post(
                    f"{backend.base_url}/api/command",
                    json={"command": f"rm -f {input_file}"},
                    headers=backend.headers(),
                    timeout=10,
                )
            except Exception:
                pass

        return result

    # ── Convenience Methods ──

    def get_tool_info(self, tool_name: str) -> Optional[dict]:
        """Get tool definition from registry."""
        return self.registry.get(tool_name)

    def list_tools(self, category: Optional[str] = None, backend: Optional[str] = None) -> list[dict]:
        """List available tools with optional filtering."""
        tools = []
        for name, defn in self.registry.items():
            if category and defn.get("category") != category:
                continue
            if backend and backend not in defn.get("backends", []):
                continue
            tool_info = {
                "name": name,
                "display_name": defn.get("display_name", name),
                "category": defn.get("category", ""),
                "backends": defn.get("backends", []),
                "hitl_required": defn.get("hitl_required", False),
                "timeout": defn.get("timeout", 300),
            }
            if defn.get("flag_notes"):
                tool_info["flag_notes"] = defn["flag_notes"]
            tools.append(tool_info)
        return tools

    def requires_hitl(self, tool_name: str) -> bool:
        """Check if a tool requires HITL approval."""
        tool_def = self.registry.get(tool_name, {})
        return tool_def.get("hitl_required", False)

    async def kill_all(self) -> dict:
        """Kill all active processes on all available backends.

        Calls /api/kill-all on each backend IN PARALLEL with 3s timeout.
        """
        client = await self._get_client()

        async def _kill_backend(name: str, backend) -> tuple:
            if not backend.available:
                return name, {"skipped": True, "reason": "backend unavailable"}
            try:
                resp = await client.post(
                    f"{backend.base_url}/api/kill-all",
                    headers=backend.headers(),
                    timeout=3,
                )
                return name, resp.json()
            except Exception as e:
                return name, {"error": str(e)}

        import asyncio
        tasks = [_kill_backend(n, b) for n, b in self.backends.items()]
        pairs = await asyncio.gather(*tasks, return_exceptions=True)
        results = {}
        for pair in pairs:
            if isinstance(pair, Exception):
                continue
            results[pair[0]] = pair[1]
        return results
