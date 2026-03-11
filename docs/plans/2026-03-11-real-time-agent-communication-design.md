# ATHENA Real-Time Multi-Agent Communication Architecture

**Date:** 2026-03-11
**Status:** Approved (brainstorming complete)
**Author:** Vex 🦖⚡
**Priority:** CRITICAL — core value proposition

---

## Problem Statement

ATHENA's current agent architecture is hub-and-spoke task dispatch: ST spawns workers, workers execute independently, results return when complete. There is no real-time intelligence sharing between agents during an engagement.

**Impact:**
- AR discovers open ports but WV doesn't know until the next engagement phase
- EX can't act on WV's fingerprinting results until WV fully completes
- ST can't pivot strategy based on live findings
- Agents duplicate work or miss attack chain opportunities
- Engagement results are inferior to what coordinated agents could achieve

**Competitors:**
- **XBOW** — coordinator-to-solver real-time, but no solver-to-solver comms
- **Shannon** — pipeline-based JSON queue handoff between phases, no real-time
- **PentAGI** — sequential subtask execution via shared PostgreSQL, no real-time bus

**ATHENA's differentiator:** True peer-to-peer agent communication with strategic oversight.

---

## Architecture Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Latency target | **Real-time (<5s)** | Intel must reach agents before their next tool call completes |
| ST's role | **Hybrid** — sets strategy, workers coordinate tactically, ST monitors + directs | Best of active command + worker autonomy |
| Message topology | **Broadcast + Direct** — shared channel for situational awareness, direct agent-to-agent for targeted requests | Maximum visibility + targeted coordination |
| Message consumption | **Inject into tool results** — manager drains inbox and injects before next SDK turn | Works within Claude API turn-based model, no SDK changes |
| ST directives | **Same bus, no task cancellation** — directives broadcast to all workers, workers pivot at next tool-call boundary | Simple, uses same infrastructure, cancellation deferred to v2 |
| Implementation | **In-memory message bus** (asyncio queues) | Zero external deps, <1ms latency, fits ATHENA's single-process model |
| Future upgrade path | **Redis Pub/Sub** when needed | Multi-process scaling, persistence, if ATHENA grows beyond single process |

---

## Workspace Isolation Compatibility (Phase G)

ATHENA uses Anthropic's workspace isolation pattern: each worker agent (AR, WV, EX, PE, VF, PX) runs in its own isolated directory under `/tmp/athena-{eid}/` with symlinks to shared read-only resources (CLAUDE.md, .claude/, playbooks/, docs/). ST, RP, and DA run in the main ATHENA root. This is managed by `WorkspaceManager` in `agent_session_manager.py`.

**The message bus is fully compatible with workspace isolation because it is in-memory, not filesystem-based:**

- The `MessageBus` instance lives in the `AgentSessionManager` process — shared across all agent sessions via Python object reference, not via files
- Each `AthenaAgentSession` receives the bus as a constructor parameter (`self._bus = bus`) — no workspace path dependency
- `publish_finding` and `send_directive` are SDK-native tools with Python handlers that call `self._bus.broadcast()` directly — they execute in-process, not in the agent's workspace filesystem
- The `Finding Extractor` parses tool results that are already in-memory (received from Claude API response) — no workspace file I/O
- `drain()` returns messages from asyncio queues — zero filesystem interaction

**What this means:** An agent in `/tmp/athena-abc123/ar-d4e5f6/` and an agent in `/tmp/athena-abc123/ex-a1b2c3/` share the same bus instance. Workspace isolation provides filesystem separation for evidence collection and tool execution; the bus provides real-time communication that crosses workspace boundaries through shared memory.

---

## Components

### 1. MessageBus (`message_bus.py` — new file)

Core in-memory pub/sub with per-agent queues and broadcast routing.

```python
@dataclass
class BusMessage:
    id: str                    # uuid4
    from_agent: str            # "AR", "EX", "ST", etc.
    to: str                    # "ALL" (broadcast) or specific agent code
    bus_type: str              # finding | request | directive | status | escalation (named bus_type to avoid collision with existing bilateral msg_type)
    priority: str              # low | medium | high | critical
    summary: str               # human-readable one-liner
    target: str | None         # IP:port or hostname
    data: dict                 # structured payload (CVEs, creds, evidence)
    action_needed: str | None  # what recipient should do
    timestamp: float           # time.time()
```

**Message types:**
- `finding` — Agent discovered actionable intel (port, service, vuln, credential)
- `request` — Agent asks another agent to do something specific (e.g., "VF, verify this exploit")
- `directive` — ST strategic command (priority shift, pivot, abort)
- `status` — Progress update / heartbeat
- `escalation` — Worker needs ST decision (scope boundary, critical finding)

**MessageBus API:**

```python
class MessageBus:
    def __init__(self, engagement_id: str):
        self.engagement_id = engagement_id
        self._queues: dict[str, asyncio.Queue] = {}
        self._history: collections.deque[BusMessage] = collections.deque(maxlen=1000)
        self._callbacks: list[Callable[[BusMessage], Coroutine]] = []

    def register(self, agent_code: str) -> None
    def unregister(self, agent_code: str) -> None
    async def broadcast(self, msg: BusMessage) -> None      # to all except sender
    async def send(self, msg: BusMessage) -> None            # to msg.to only
    async def drain(self, agent_code: str) -> list[BusMessage]  # non-blocking, fully empties queue
    def get_history(self, limit: int = 50) -> list[BusMessage]
    def on_message(self, callback: Callable[[BusMessage], Coroutine]) -> None
```

**Key behaviors:**
- `broadcast()` enqueues to ALL registered agents except the sender (no echo)
- `drain()` is non-blocking — returns empty list if nothing pending. **Always fully empties the queue.** Messages not included in the injection (due to the 20-message cap) are discarded, not re-queued — by the next turn, they are stale.
- `_history` is a bounded deque (maxlen=1000) — prevents memory growth in long engagements
- `on_message()` callbacks must be async coroutines. Bus fires them via `asyncio.create_task(callback(msg))` for fire-and-forget delivery to WebSocket and Graphiti.
- `engagement_id` is set at construction for Graphiti persistence tagging
- Thread-safe via asyncio (single event loop, no locks needed)
- **Ordering contract:** In `_process_tool_result`, publish happens BEFORE drain. This ensures an agent's own findings are broadcast to others before it checks its inbox. An agent never receives its own broadcasts (sender excluded).

---

### 2. Finding Extractor

Parses tool call results and produces `BusMessage` objects automatically.

**Extraction triggers:**

| Tool Result Contains | Message Type | Priority | Example |
|---|---|---|---|
| Open ports | `finding` | `high` | "3 open ports: 22, 80, 8443 on 10.0.0.5" |
| Service/version ID | `finding` | `medium` | "Tomcat 9.0.31 on 10.0.0.5:8443" |
| CVE match | `finding` | `high` | "CVE-2024-XXXX affects Tomcat 9.0.31" |
| Credential found | `finding` | `critical` | "Valid creds: admin:admin on SSH" |
| Exploit success | `escalation` | `critical` | "Shell obtained on 10.0.0.5 via CVE-2024-XXXX" |
| New network/subnet | `escalation` | `high` | "Internal subnet 192.168.1.0/24 discovered" |
| Vulnerability confirmed | `finding` | `high` | "SQLi confirmed on /api/login" |
| Scan complete (no findings) | `status` | `low` | "nmap full port scan complete, 0 new ports" |

```python
def extract_findings(agent_code: str, tool_name: str, tool_result: str) -> list[BusMessage]:
    """Parse tool output for actionable intel. Returns 0+ messages.

    Uses regex for ports, IPs, CVEs, service banners.
    Keyword detection for credentials, shells, exploits.
    Structured JSON parsing when tools return JSON.
    Best-effort — missing something is acceptable.
    """
```

**Agent-initiated publishing:**

Agents also get a `publish_finding` tool for explicit broadcasts.

**Tool registration mechanism:** Both `publish_finding` and `send_directive` (ST-only) are registered as **SDK-native tools** via `ClaudeAgentOptions.tools`, NOT as MCP tools. Each tool has a Python handler function inside `SDKAgentSession` that constructs a `BusMessage` and calls `self._bus.broadcast(msg)` or `self._bus.send(msg)` directly. This avoids requiring a new MCP server and keeps bus communication in-process.

```python
# Registered in SDKAgentSession._build_tools() for ALL agents:
{
    "name": "publish_finding",
    "description": "Share a finding with all other agents on the engagement. Use IMMEDIATELY when you discover ports, services, vulnerabilities, credentials, or exploits.",
    "input_schema": {
        "type": "object",
        "properties": {
            "summary": {"type": "string", "description": "What you found"},
            "target": {"type": "string", "description": "IP:port or hostname (optional)"},
            "priority": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
            "data": {"type": "object", "description": "Structured payload (CVEs, evidence, etc.)"}
        },
        "required": ["summary", "priority"]
    }
}

# Registered for ST only:
{
    "name": "send_directive",
    "description": "Broadcast a strategic directive to all agents or a specific agent.",
    "input_schema": {
        "type": "object",
        "properties": {
            "directive": {"type": "string", "description": "The order — what agents should do differently"},
            "priority": {"type": "string", "enum": ["normal", "urgent", "critical"]},
            "to": {"type": "string", "description": "ALL or specific agent code", "default": "ALL"}
        },
        "required": ["directive", "priority"]
    }
}
```

**Handler code path:**
```python
# In SDKAgentSession:
async def _handle_publish_finding(self, params: dict) -> str:
    msg = BusMessage(
        id=str(uuid4()), from_agent=self._role_config.code,
        to="ALL", bus_type="finding", priority=params["priority"],
        summary=params["summary"], target=params.get("target"),
        data=params.get("data", {}), action_needed=None,
        timestamp=time.time()
    )
    await self._bus.broadcast(msg)
    return f"Finding published to {len(self._bus._queues) - 1} agents"

async def _handle_send_directive(self, params: dict) -> str:
    msg = BusMessage(
        id=str(uuid4()), from_agent="ST",
        to=params.get("to", "ALL"), bus_type="directive",
        priority=params["priority"], summary=params["directive"],
        target=None, data={}, action_needed=params["directive"],
        timestamp=time.time()
    )
    if msg.to == "ALL":
        await self._bus.broadcast(msg)
    else:
        await self._bus.send(msg)
    return f"Directive sent ({msg.priority}): {msg.summary[:80]}"
```

---

### 3. Context Injector

Formats drained messages into a prompt block injected before the agent's next SDK turn.

**Injection format for workers:**

```
═══ INTELLIGENCE UPDATE (3 new messages) ═══

[CRITICAL] from EX → ALL (2s ago)
  Shell obtained on 10.0.0.5:8443 via CVE-2024-50623
  Action needed: Verify persistence, check for lateral movement paths

[HIGH] from AR → ALL (8s ago)
  Internal subnet 192.168.1.0/24 discovered via ARP on compromised host
  Action needed: Enumerate internal hosts

[MEDIUM] from WV → ALL (12s ago)
  Service identified: PostgreSQL 14.2 on 10.0.0.5:5432 (auth required)

═══ END INTELLIGENCE UPDATE ═══
```

**ST gets additional strategic overview:**

```
═══ STRATEGIC OVERVIEW ═══
Active workers: AR (scanning), EX (exploiting), WV (fingerprinting)
Completed: DA (enumeration done, 12 findings)
Findings total: 18 | Exploited: 2 | Pending verification: 1
═══ END STRATEGIC OVERVIEW ═══
```

**Injection rules:**
- Only inject if `drain()` returns non-empty list
- Sort by priority (critical first), then recency
- Max 20 messages per injection (prevent context bloat)
- Older low-priority messages dropped; high/critical always delivered
- **Injected as user-turn prompt prefix** — prepended to the next `query(prompt=injection + original_prompt, resume=session_id)` call. The Claude Agent SDK does not support injecting new system messages mid-session; user-turn injection is the correct mechanism.
- `format_intel_update(inbox: list[BusMessage], agent_code: str) -> str` — lives in `message_bus.py`, returns the formatted injection string. Returns strategic overview block when `agent_code == "ST"`.

**Heartbeat fallback:**
The bus does NOT fully replace the heartbeat for ST idle timeout prevention. During long-running tool calls (e.g., 10-minute nmap scan), no bus messages flow because `drain()` only runs between tool calls. The `_maybe_send_heartbeat()` mechanism is **retained as a fallback** — if no bus message has been delivered to ST for `_heartbeat_interval` seconds (60s), the manager sends a keepalive status update to prevent the 300s SDK idle timeout. The heartbeat message is a simplified version: active worker count + elapsed time only.

---

### 4. ST Directive System

ST publishes strategic directives via a `send_directive` tool:

```
Tool: send_directive
Description: Broadcast a strategic directive to all agents or a specific agent.
Parameters:
  - directive (str): The order — what agents should do differently
  - priority (normal|urgent|critical): How urgently agents should pivot
  - to (str): "ALL" or specific agent code (default: "ALL")
```

**Directive format in worker injection:**

```
═══ STRATEGIC DIRECTIVE from ST ═══
Priority: URGENT
"Credential admin:admin123 found. All agents: test against
every discovered service immediately."
═══ END DIRECTIVE ═══
```

**Worker behavior on directives:**
- `normal` — incorporate when convenient (finish current tool, then adjust)
- `urgent` — finish current tool call, then pivot immediately
- `critical` — finish current tool call, then pivot immediately (v2: may cancel task)

---

### 5. Integration Points

#### AgentSessionManager (`agent_session_manager.py`)

```python
class AgentSessionManager:
    def __init__(self, ..., ws_broadcast_callback: Callable = None):
        self.bus = MessageBus(engagement_id=self.engagement_id)
        # Register WebSocket callback using existing set_event_callback pattern
        if ws_broadcast_callback:
            self.bus.on_message(ws_broadcast_callback)

    async def spawn_agent(self, role_config):
        self.bus.register(role_config.code)
        # pass bus reference to agent session

    async def on_agent_complete(self, agent_code):
        self.bus.unregister(agent_code)

    # RETAIN: _maybe_send_heartbeat() as fallback for ST idle timeout
    # during long tool calls when no bus messages flow.
    # Heartbeat fires if no bus delivery to ST for 60s.
```

#### SDKAgentSession (`sdk_agent.py`)

```python
class SDKAgentSession:
    def __init__(self, ..., bus: MessageBus):
        self._bus = bus

    async def _process_tool_result(self, tool_name, result):
        # 1. Record budget (existing, uses _role_config.code)
        # 2. Auto-extract findings from tool result
        findings = extract_findings(self._role_config.code, tool_name, result)
        for msg in findings:
            if msg.to == "ALL":
                await self._bus.broadcast(msg)
            else:
                await self._bus.send(msg)
        # 3. Drain inbox and build injection for next turn
        #    ORDERING: publish BEFORE drain (contract)
        inbox = await self._bus.drain(self._role_config.code)
        if inbox:
            self._pending_injection = format_intel_update(inbox, self._role_config.code)
            # Prepended to next query() prompt as user-turn prefix
```

#### Server (`server.py`)

```python
# Wiring: server passes async callback to manager at construction
async def _broadcast_bus_to_ws(msg: BusMessage):
    """Async callback — fires via asyncio.create_task inside bus."""
    await _emit("agent_intel", msg.from_agent, msg.summary, msg.to_dict())

# In start_engagement_ai():
manager = AgentSessionManager(..., ws_broadcast_callback=_broadcast_bus_to_ws)
```

#### Graphiti Integration (existing infrastructure)

```python
# Persist bus messages as knowledge graph entities
async def _persist_to_graphiti(msg: BusMessage):
    # Create entity: finding, credential, service, vulnerability
    # Create relationships: found_on, exploited_via, leads_to
    # Tag with engagement_id for cross-engagement queries
```

#### Langfuse Integration (existing infrastructure)

```python
# Trace bus messages for observability
async def _trace_to_langfuse(msg: BusMessage):
    # Create span: agent communication event
    # Track: message latency, delivery count, action taken
    # Enable: engagement replay, agent performance analysis
```

---

### 6. Agent System Prompt Additions

**All workers (AR, WV, EX, DA, VF) — append to existing prompts:**

```
## Real-Time Intelligence

You are part of a coordinated multi-agent team. You have two communication tools:

1. **publish_finding** — Share discoveries with the team. Use IMMEDIATELY when you find:
   - Open ports, services, versions
   - Vulnerabilities or CVE matches
   - Valid credentials
   - Successful exploits
   - New networks or hosts

2. Intel from other agents is automatically injected between your tool calls.
   Read it. Act on it. Don't ignore teammates.

### How to use incoming intel:
- If another agent found a service version → check for known CVEs before scanning
- If credentials were shared → try them on your target services
- If a directive from ST arrives → reprioritize immediately
- If an exploit succeeded → note it for reports, avoid redundant work

### When to escalate to ST:
- Scope boundary reached (new subnet, out-of-scope host)
- Critical finding (shell, domain admin, data breach)
- Stuck or blocked (need different approach)
- Conflict with another agent's work
```

**ST — append to existing prompt:**

```
## Real-Time Command

You command a team of agents who share intel in real-time. You have:

1. **send_directive** — Issue strategic orders to all agents or specific agents
2. **publish_finding** — Share your own strategic observations

### Your role:
- Monitor incoming intel for strategic opportunities (pivots, credential reuse, lateral movement)
- Issue directives when the situation changes
- Don't micromanage — workers handle tactics autonomously
- Escalations from workers require your decision

### Intel arrives automatically between your tool calls. Act on it.
```

---

## Cross-Engagement Intelligence (Graphiti Flywheel)

Every bus message is structured data that feeds Graphiti. Over time, ATHENA builds institutional knowledge:

```
Engagement 1 → Bus intel → Graphiti patterns →
Engagement 2 → Bus intel + prior patterns → Graphiti (richer) →
Engagement 3 → Starts smarter than Engagement 1 ever finished
```

**What gets persisted:**
- Service→CVE mappings that led to successful exploits
- Credential patterns (default creds, reuse across services)
- Attack chain sequences that worked (recon→fingerprint→exploit paths)
- Techniques that failed (avoid repeating on similar targets)
- Timing data (which agent combinations are most efficient)

**What ST queries at engagement start:**
- "What worked against similar tech stacks?"
- "Known CVEs for detected services?"
- "Credential patterns for this target type?"

**Langfuse enables:**
- Replay full engagement agent communications
- Identify where agents wasted time or missed intel
- Optimize agent prompts based on what led to successful outcomes
- Cost analysis per agent per engagement type

---

## Competitive Positioning

| Capability | ATHENA | XBOW | Shannon | PentAGI |
|---|---|---|---|---|
| Real-time agent-to-agent comms | ✅ Broadcast + Direct | ⚠️ Coordinator only | ❌ Pipeline queues | ❌ DB state |
| Peer-to-peer (worker↔worker) | ✅ | ❌ | ❌ | ❌ |
| Strategic oversight | ✅ ST hybrid | ✅ Coordinator | ⚠️ Temporal engine | ⚠️ Primary agent |
| Cross-engagement learning | ✅ Graphiti KG | ❓ Unknown | ❌ | ⚠️ Graphiti (single flow) |
| Full observability | ✅ Langfuse | ❓ Unknown | ❌ | ✅ Langfuse |
| Operator transparency | ✅ Dashboard + intel feed | ❌ Black box | ⚠️ Limited | ✅ GraphQL sub |
| Cost tracking per agent | ✅ | ❌ | ❌ | ✅ |
| Validation layer | ✅ VF agent | ✅ Multi-model debate | ✅ "No exploit, no report" | ✅ Reflector loop |
| Model flexibility | ✅ Opus ST + Sonnet workers | ✅ Model Alloys | ✅ 3-tier model sizing | ✅ Per-agent model |

**ATHENA's unique value:** The only platform with real-time peer-to-peer agent communication + persistent cross-engagement intelligence + full operator transparency. This is the trifecta that makes ATHENA a platform, not a script runner.

---

## What Gets Modified

- `_maybe_send_heartbeat()` in `agent_session_manager.py` — **simplified to fallback keepalive** (fires only when no bus delivery to ST for 60s, prevents idle timeout during long tool calls)
- `_build_heartbeat_message()` — simplified to worker count + elapsed time only
- `detect_agent()` dependency for message routing — bus uses `_role_config.code` exclusively

## What Stays Unchanged

- Budget tracking (already fixed with `_role_config.code`)
- LED status management
- Attack chain recording
- Neo4j finding storage
- HITL approval flow
- Scope expansion logic

---

## Future Enhancements (Not in v1)

1. **Intel Feed panel** on dashboard — live view of all bus messages
2. **Task cancellation** — ST can kill a worker's current task for urgent pivots
3. **Redis upgrade** — if ATHENA needs multi-process scaling
4. **Model Alloys** — alternate models within a single agent session (XBOW technique)
5. **Reflector pattern** — self-critique loop when agent stalls (PentAGI technique)
6. **Conditional agent spawning** — only spawn exploit agents when vulns exist (Shannon technique)

---

## Success Criteria

1. Messages are available in the recipient's inbox within 50ms of publication (asyncio queue latency). Injection into agent context occurs at the agent's next tool-call boundary.
2. Agents demonstrably act on intel from other agents (visible in Langfuse traces — at least 1 agent references another agent's finding in its tool call reasoning)
3. ST can issue a directive via `send_directive` tool and workers pivot within one tool-call cycle
4. Bus messages persist to Graphiti for cross-engagement queries (verifiable via Neo4j query)
5. Dashboard receives `agent_intel` WebSocket events in real-time (visible in browser console)
6. No regression in budget tracking, LED status, or attack chain recording
7. ST does not idle-timeout during long worker scans (heartbeat fallback prevents 300s timeout)
