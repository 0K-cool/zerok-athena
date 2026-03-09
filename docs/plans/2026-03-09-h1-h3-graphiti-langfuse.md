# H1 + H3: Cross-Session Memory (Graphiti) + LLM Observability (Langfuse)

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add temporal knowledge graph memory across engagements (Graphiti) and full LLM observability (Langfuse) to ATHENA, closing the two highest-priority competitive gaps.

**Architecture:** Graphiti embeds directly in server.py as a module-level singleton (like Neo4j driver), using the existing Neo4j instance with `group_id` per engagement for isolation. Langfuse runs as a self-hosted Docker Compose stack (6 services) with Python SDK auto-instrumentation wrapping all Claude Agent SDK calls. Both integrate at the event emission layer in `sdk_agent.py` and `agent_session_manager.py`.

**Tech Stack:** `graphiti-core[anthropic]` v0.28+, `langfuse` v3, `opentelemetry-instrumentation-anthropic`, Docker Compose (PostgreSQL, ClickHouse, Redis, MinIO), Neo4j 5.26+ (existing instance)

---

## Architecture Overview

```
                    ┌─────────────────────────────────────┐
                    │         ATHENA Dashboard             │
                    │         (FastAPI server.py)           │
                    │                                       │
                    │  ┌─────────┐  ┌──────────┐           │
                    │  │Graphiti │  │ Langfuse │           │
                    │  │singleton│  │  client  │           │
                    │  └────┬────┘  └────┬─────┘           │
                    │       │            │                  │
                    └───────┼────────────┼──────────────────┘
                            │            │
              ┌─────────────┤            │
              ▼             ▼            ▼
        ┌──────────┐  ┌──────────┐  ┌──────────────────┐
        │  Neo4j   │  │  Neo4j   │  │  Langfuse Stack  │
        │ ATHENA   │  │ Graphiti │  │  (Docker Compose) │
        │ findings │  │ temporal │  │  PG+CH+Redis+S3  │
        │ (existing)│  │ memory  │  │                  │
        └──────────┘  └──────────┘  └──────────────────┘
           same Neo4j instance
           (group_id isolation)
```

## Key Decisions (Pre-Approved in Roadmap)

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Graphiti deployment | Embedded in server.py | Single-server architecture, no sidecar overhead |
| Neo4j isolation | `group_id` per engagement | Logical partition, no extra DB instances needed |
| Graphiti LLM | Anthropic Claude (Haiku 4.5) | Same provider, cheapest model for entity extraction |
| Langfuse deployment | Self-hosted Docker Compose | Client data security — zero cloud exfiltration |
| Langfuse instrumentation | AnthropicInstrumentor + native SDK | Auto-capture raw calls + explicit agent spans |
| Embedding model | OpenAI `text-embedding-3-small` | Graphiti default, $0.02/1M tokens, good enough |

---

## Phase H3: Langfuse Observability (Do First — Simpler, Unblocks Monitoring)

### Task 1: Langfuse Docker Compose Infrastructure

**Files:**
- Create: `tools/athena-dashboard/docker/docker-compose.langfuse.yml`
- Create: `tools/athena-dashboard/docker/.env.langfuse.example`

**Step 1: Create docker directory**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-dashboard
mkdir -p docker
```

**Step 2: Write docker-compose.langfuse.yml**

```yaml
# tools/athena-dashboard/docker/docker-compose.langfuse.yml
# ATHENA H3: Self-hosted Langfuse v3 for LLM observability
# Usage: docker compose -f docker/docker-compose.langfuse.yml up -d

services:
  langfuse-web:
    image: langfuse/langfuse:3
    container_name: athena-langfuse-web
    restart: unless-stopped
    ports:
      - "3000:3000"
    environment:
      DATABASE_URL: postgresql://langfuse:${LANGFUSE_PG_PASSWORD}@langfuse-postgres:5432/langfuse
      NEXTAUTH_URL: http://localhost:3000
      NEXTAUTH_SECRET: ${LANGFUSE_NEXTAUTH_SECRET}
      SALT: ${LANGFUSE_SALT}
      CLICKHOUSE_URL: http://langfuse-clickhouse:8123
      CLICKHOUSE_USER: default
      CLICKHOUSE_PASSWORD: ${LANGFUSE_CH_PASSWORD}
      REDIS_HOST: langfuse-redis
      REDIS_PORT: 6379
      LANGFUSE_S3_EVENT_UPLOAD_ENABLED: "true"
      LANGFUSE_S3_EVENT_UPLOAD_ENDPOINT: http://langfuse-minio:9000
      LANGFUSE_S3_EVENT_UPLOAD_ACCESS_KEY_ID: ${LANGFUSE_S3_ACCESS_KEY}
      LANGFUSE_S3_EVENT_UPLOAD_SECRET_ACCESS_KEY: ${LANGFUSE_S3_SECRET_KEY}
      LANGFUSE_S3_EVENT_UPLOAD_BUCKET: langfuse
      LANGFUSE_S3_EVENT_UPLOAD_REGION: us-east-1
      LANGFUSE_S3_EVENT_UPLOAD_FORCE_PATH_STYLE: "true"
      LANGFUSE_INIT_ORG_ID: athena
      LANGFUSE_INIT_ORG_NAME: "ATHENA Pentest Platform"
      LANGFUSE_INIT_PROJECT_ID: athena-default
      LANGFUSE_INIT_PROJECT_NAME: "ATHENA Engagements"
      LANGFUSE_INIT_PROJECT_PUBLIC_KEY: pk-lf-athena
      LANGFUSE_INIT_PROJECT_SECRET_KEY: ${LANGFUSE_PROJECT_SECRET_KEY}
      LANGFUSE_INIT_USER_EMAIL: ${LANGFUSE_ADMIN_EMAIL}
      LANGFUSE_INIT_USER_PASSWORD: ${LANGFUSE_ADMIN_PASSWORD}
      LANGFUSE_INIT_USER_NAME: "ATHENA Admin"
    depends_on:
      langfuse-postgres:
        condition: service_healthy
      langfuse-clickhouse:
        condition: service_healthy
      langfuse-redis:
        condition: service_started
      langfuse-minio:
        condition: service_started
    healthcheck:
      test: ["CMD", "wget", "--spider", "-q", "http://localhost:3000/api/public/health"]
      interval: 15s
      timeout: 5s
      retries: 5

  langfuse-worker:
    image: langfuse/langfuse-worker:3
    container_name: athena-langfuse-worker
    restart: unless-stopped
    environment:
      DATABASE_URL: postgresql://langfuse:${LANGFUSE_PG_PASSWORD}@langfuse-postgres:5432/langfuse
      CLICKHOUSE_URL: http://langfuse-clickhouse:8123
      CLICKHOUSE_USER: default
      CLICKHOUSE_PASSWORD: ${LANGFUSE_CH_PASSWORD}
      REDIS_HOST: langfuse-redis
      REDIS_PORT: 6379
      LANGFUSE_S3_EVENT_UPLOAD_ENABLED: "true"
      LANGFUSE_S3_EVENT_UPLOAD_ENDPOINT: http://langfuse-minio:9000
      LANGFUSE_S3_EVENT_UPLOAD_ACCESS_KEY_ID: ${LANGFUSE_S3_ACCESS_KEY}
      LANGFUSE_S3_EVENT_UPLOAD_SECRET_ACCESS_KEY: ${LANGFUSE_S3_SECRET_KEY}
      LANGFUSE_S3_EVENT_UPLOAD_BUCKET: langfuse
      LANGFUSE_S3_EVENT_UPLOAD_REGION: us-east-1
      LANGFUSE_S3_EVENT_UPLOAD_FORCE_PATH_STYLE: "true"
    depends_on:
      langfuse-web:
        condition: service_healthy

  langfuse-postgres:
    image: postgres:16-alpine
    container_name: athena-langfuse-postgres
    restart: unless-stopped
    volumes:
      - langfuse_pg_data:/var/lib/postgresql/data
    environment:
      POSTGRES_DB: langfuse
      POSTGRES_USER: langfuse
      POSTGRES_PASSWORD: ${LANGFUSE_PG_PASSWORD}
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U langfuse"]
      interval: 5s
      timeout: 3s
      retries: 5

  langfuse-clickhouse:
    image: clickhouse/clickhouse-server:24-alpine
    container_name: athena-langfuse-clickhouse
    restart: unless-stopped
    volumes:
      - langfuse_ch_data:/var/lib/clickhouse
    environment:
      CLICKHOUSE_USER: default
      CLICKHOUSE_PASSWORD: ${LANGFUSE_CH_PASSWORD}
    healthcheck:
      test: ["CMD", "wget", "--spider", "-q", "http://localhost:8123/ping"]
      interval: 5s
      timeout: 3s
      retries: 5
    ulimits:
      nofile:
        soft: 262144
        hard: 262144

  langfuse-redis:
    image: redis:7-alpine
    container_name: athena-langfuse-redis
    restart: unless-stopped
    volumes:
      - langfuse_redis_data:/data
    command: redis-server --appendonly yes

  langfuse-minio:
    image: minio/minio
    container_name: athena-langfuse-minio
    restart: unless-stopped
    volumes:
      - langfuse_minio_data:/data
    environment:
      MINIO_ROOT_USER: ${LANGFUSE_S3_ACCESS_KEY}
      MINIO_ROOT_PASSWORD: ${LANGFUSE_S3_SECRET_KEY}
    command: server /data
    healthcheck:
      test: ["CMD", "mc", "ready", "local"]
      interval: 10s
      timeout: 5s
      retries: 3

  langfuse-minio-init:
    image: minio/mc
    container_name: athena-langfuse-minio-init
    depends_on:
      langfuse-minio:
        condition: service_healthy
    entrypoint: >
      /bin/sh -c "
      mc alias set myminio http://langfuse-minio:9000 $${MINIO_ROOT_USER} $${MINIO_ROOT_PASSWORD};
      mc mb myminio/langfuse --ignore-existing;
      exit 0;
      "
    environment:
      MINIO_ROOT_USER: ${LANGFUSE_S3_ACCESS_KEY}
      MINIO_ROOT_PASSWORD: ${LANGFUSE_S3_SECRET_KEY}

volumes:
  langfuse_pg_data:
  langfuse_ch_data:
  langfuse_redis_data:
  langfuse_minio_data:
```

**Step 3: Write .env.langfuse.example**

```bash
# tools/athena-dashboard/docker/.env.langfuse.example
# Copy to .env.langfuse and fill in values
# Usage: docker compose -f docker/docker-compose.langfuse.yml --env-file docker/.env.langfuse up -d

# PostgreSQL
LANGFUSE_PG_PASSWORD=changeme_pg_password

# ClickHouse
LANGFUSE_CH_PASSWORD=changeme_ch_password

# NextAuth (generate with: openssl rand -base64 32)
LANGFUSE_NEXTAUTH_SECRET=changeme_nextauth_secret
LANGFUSE_SALT=changeme_salt

# MinIO / S3
LANGFUSE_S3_ACCESS_KEY=langfuse-s3-access
LANGFUSE_S3_SECRET_KEY=changeme_s3_secret

# Langfuse project (auto-created on first boot)
LANGFUSE_PROJECT_SECRET_KEY=sk-lf-athena-changeme
LANGFUSE_ADMIN_EMAIL=kelvin@zeroklabs.ai
LANGFUSE_ADMIN_PASSWORD=changeme_admin_password
```

**Step 4: Create actual .env.langfuse with generated secrets**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-dashboard/docker
cp .env.langfuse.example .env.langfuse
# Then generate and replace secrets using openssl rand
```

**Step 5: Add .env.langfuse to .gitignore**

Append `docker/.env.langfuse` to the project `.gitignore`.

**Step 6: Start Langfuse stack and verify**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-dashboard
docker compose -f docker/docker-compose.langfuse.yml --env-file docker/.env.langfuse up -d

# Wait for health checks (30-60 seconds)
docker compose -f docker/docker-compose.langfuse.yml ps

# Verify web UI
curl -s http://localhost:3000/api/public/health
# Expected: {"status":"OK"}
```

**Step 7: Commit**

```bash
git add docker/docker-compose.langfuse.yml docker/.env.langfuse.example .gitignore
git commit -m "feat(H3): Add self-hosted Langfuse Docker Compose stack

6-service stack: web, worker, PostgreSQL, ClickHouse, Redis, MinIO.
Auto-creates ATHENA project with init env vars.
Secrets generated locally, .env.langfuse gitignored."
```

---

### Task 2: Langfuse Python SDK Integration

**Files:**
- Modify: `tools/athena-dashboard/requirements.txt`
- Create: `tools/athena-dashboard/langfuse_integration.py`
- Modify: `tools/athena-dashboard/server.py` (lifespan hooks)

**Step 1: Add dependencies to requirements.txt**

Append to `requirements.txt`:
```
# H3: LLM Observability
langfuse>=3.0.0
opentelemetry-instrumentation-anthropic>=0.1.0
opentelemetry-sdk>=1.20.0
```

**Step 2: Install dependencies**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-dashboard
source .venv/bin/activate
pip install langfuse opentelemetry-instrumentation-anthropic opentelemetry-sdk
```

**Step 3: Write langfuse_integration.py**

```python
# tools/athena-dashboard/langfuse_integration.py
# SPDX-License-Identifier: AGPL-3.0-or-later
"""
ATHENA H3: Langfuse LLM Observability Integration

Provides auto-instrumentation of all Anthropic/Claude API calls and
explicit trace/span helpers for engagement-level observability.

Usage:
    from langfuse_integration import init_langfuse, shutdown_langfuse, trace_engagement

    # At startup
    await init_langfuse()

    # Per engagement
    with trace_engagement(engagement_id, target) as trace:
        # All Claude calls inside are auto-traced
        ...

    # At shutdown
    await shutdown_langfuse()
"""

import os
import logging
from contextlib import contextmanager
from typing import Optional

logger = logging.getLogger("athena.langfuse")

# Langfuse client singleton
_langfuse = None
_enabled = False


def is_enabled() -> bool:
    """Check if Langfuse observability is enabled."""
    return _enabled


async def init_langfuse() -> bool:
    """Initialize Langfuse client and auto-instrumentation.

    Reads config from environment variables:
        LANGFUSE_PUBLIC_KEY, LANGFUSE_SECRET_KEY, LANGFUSE_BASE_URL
        ATHENA_LANGFUSE_ENABLED (default: true if keys present)

    Returns True if successfully initialized, False if skipped/failed.
    """
    global _langfuse, _enabled

    public_key = os.environ.get("LANGFUSE_PUBLIC_KEY", "pk-lf-athena")
    secret_key = os.environ.get("LANGFUSE_SECRET_KEY")
    base_url = os.environ.get("LANGFUSE_BASE_URL", "http://localhost:3000")
    explicitly_disabled = os.environ.get("ATHENA_LANGFUSE_ENABLED", "").lower() == "false"

    if explicitly_disabled:
        logger.info("Langfuse disabled via ATHENA_LANGFUSE_ENABLED=false")
        return False

    if not secret_key:
        logger.warning("Langfuse not configured (LANGFUSE_SECRET_KEY missing). Observability disabled.")
        return False

    try:
        from langfuse import get_client
        from opentelemetry.instrumentation.anthropic import AnthropicInstrumentor

        # Set env vars for SDK auto-discovery
        os.environ.setdefault("LANGFUSE_PUBLIC_KEY", public_key)
        os.environ.setdefault("LANGFUSE_SECRET_KEY", secret_key)
        os.environ.setdefault("LANGFUSE_BASE_URL", base_url)

        # Auto-instrument all Anthropic client calls
        AnthropicInstrumentor().instrument()
        logger.info("AnthropicInstrumentor activated — all Claude calls auto-traced")

        # Initialize Langfuse client
        _langfuse = get_client()

        # Verify connectivity
        if not _langfuse.auth_check():
            logger.error(f"Langfuse auth failed at {base_url}. Check keys.")
            _enabled = False
            return False

        _enabled = True
        logger.info(f"Langfuse initialized -> {base_url}")
        return True

    except ImportError as e:
        logger.warning(f"Langfuse packages not installed: {e}. Observability disabled.")
        return False
    except Exception as e:
        logger.error(f"Langfuse init failed: {e}. Observability disabled.")
        return False


async def shutdown_langfuse():
    """Flush pending events and shutdown Langfuse client.

    CRITICAL: Must be called in FastAPI lifespan teardown or events are lost.
    """
    global _langfuse, _enabled
    if _langfuse and _enabled:
        try:
            _langfuse.shutdown()
            logger.info("Langfuse shutdown complete — all events flushed")
        except Exception as e:
            logger.error(f"Langfuse shutdown error: {e}")
    _enabled = False
    _langfuse = None


@contextmanager
def trace_engagement(engagement_id: str, target: str, mode: str = "ai-sdk"):
    """Create a root trace for an entire engagement.

    All Claude calls within this context are nested under the engagement trace.

    Args:
        engagement_id: ATHENA engagement UUID
        target: Target hostname/IP
        mode: Engagement mode (ai-sdk, automation, legacy)

    Yields:
        Langfuse trace object (or None if disabled)
    """
    if not _enabled or not _langfuse:
        yield None
        return

    try:
        from langfuse import propagate_attributes

        trace = _langfuse.trace(
            name=f"engagement-{engagement_id}",
            session_id=engagement_id,
            user_id="athena-orchestrator",
            tags=["engagement", mode],
            metadata={"target": target, "mode": mode},
            input={"engagement_id": engagement_id, "target": target},
        )

        with propagate_attributes(
            session_id=engagement_id,
            tags=["engagement", mode],
        ):
            yield trace

        trace.update(output={"status": "completed"})

    except Exception as e:
        logger.error(f"Langfuse trace_engagement error: {e}")
        yield None


@contextmanager
def trace_agent_run(engagement_id: str, agent_code: str, agent_name: str,
                    model: str = "claude-sonnet-4-6"):
    """Create a span for an individual agent's execution within an engagement.

    Args:
        engagement_id: Parent engagement ID
        agent_code: Agent code (ST, AR, WV, EX, VF, RP)
        agent_name: Human-readable agent name
        model: Claude model used
    """
    if not _enabled or not _langfuse:
        yield None
        return

    try:
        span = _langfuse.start_as_current_observation(
            as_type="span",
            name=f"agent-{agent_code}",
            session_id=engagement_id,
            metadata={
                "agent_code": agent_code,
                "agent_name": agent_name,
                "model": model,
            },
        )
        with span:
            yield span
    except Exception as e:
        logger.error(f"Langfuse trace_agent_run error: {e}")
        yield None


def score_finding(engagement_id: str, finding_id: str, severity: str,
                  confidence: str, agent_code: str):
    """Record a score for a finding (for evaluation pipelines).

    Args:
        engagement_id: Engagement that produced this finding
        finding_id: Neo4j finding UUID
        severity: CRITICAL/HIGH/MEDIUM/LOW
        confidence: HIGH/MEDIUM/LOW/UNCONFIRMED
        agent_code: Agent that discovered it
    """
    if not _enabled or not _langfuse:
        return

    severity_scores = {"CRITICAL": 1.0, "HIGH": 0.75, "MEDIUM": 0.5, "LOW": 0.25}
    confidence_scores = {"HIGH": 1.0, "MEDIUM": 0.66, "LOW": 0.33, "UNCONFIRMED": 0.0}

    try:
        _langfuse.score(
            name="finding_severity",
            value=severity_scores.get(severity, 0.0),
            comment=f"{severity} finding by {agent_code}",
            trace_id=engagement_id,
            observation_id=finding_id,
        )
        _langfuse.score(
            name="finding_confidence",
            value=confidence_scores.get(confidence, 0.0),
            comment=f"{confidence} confidence by {agent_code}",
            trace_id=engagement_id,
            observation_id=finding_id,
        )
    except Exception as e:
        logger.error(f"Langfuse score error: {e}")
```

**Step 4: Integrate into server.py lifespan**

In `server.py`, add to imports section (near top):
```python
from langfuse_integration import init_langfuse, shutdown_langfuse
```

In the `lifespan()` async context manager, add after Neo4j init:
```python
    # H3: Initialize Langfuse observability
    langfuse_ok = await init_langfuse()
    if langfuse_ok:
        logger.info("Langfuse observability active")
    else:
        logger.info("Langfuse disabled — running without LLM observability")
```

In the lifespan teardown:
```python
    # H3: Flush Langfuse before shutdown
    await shutdown_langfuse()
```

**Step 5: Verify import works**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-dashboard
source .venv/bin/activate
python3 -c "from langfuse_integration import init_langfuse; print('OK')"
```

Expected: `OK`

**Step 6: Commit**

```bash
git add langfuse_integration.py requirements.txt server.py
git commit -m "feat(H3): Add Langfuse Python SDK integration module

- langfuse_integration.py: init/shutdown, trace_engagement, trace_agent_run, score_finding
- AnthropicInstrumentor auto-captures all Claude calls
- Graceful degradation if Langfuse not running
- Integrated into FastAPI lifespan hooks"
```

---

### Task 3: Wire Langfuse Traces into Agent Lifecycle

**Files:**
- Modify: `tools/athena-dashboard/sdk_agent.py` (agent-level spans)
- Modify: `tools/athena-dashboard/agent_session_manager.py` (engagement-level trace)

**Step 1: Add engagement trace to AgentSessionManager.start()**

In `agent_session_manager.py`, add import:
```python
from langfuse_integration import trace_engagement, trace_agent_run, is_enabled as langfuse_enabled
```

In `AgentSessionManager.start()` (around line 322), wrap the engagement lifecycle:
```python
async def start(self, st_context: str = ""):
    """Start the engagement with optional ST context."""
    # H3: Create root Langfuse trace for this engagement
    if langfuse_enabled():
        self._langfuse_trace_ctx = trace_engagement(
            engagement_id=self._engagement_id,
            target=self._target or "unknown",
            mode="ai-sdk",
        )
        self._langfuse_trace = self._langfuse_trace_ctx.__enter__()
    else:
        self._langfuse_trace_ctx = None
        self._langfuse_trace = None

    # ... existing start logic ...
```

In `AgentSessionManager.stop()` (around line 343), close the trace:
```python
async def stop(self):
    """Stop all agents and cleanup."""
    # ... existing stop logic ...

    # H3: Close engagement trace
    if self._langfuse_trace_ctx:
        self._langfuse_trace_ctx.__exit__(None, None, None)
```

**Step 2: Add agent spans to _spawn_agent()**

In `_spawn_agent()` (around line 675), pass engagement_id to AthenaAgentSession:
```python
# In the AthenaAgentSession constructor call, add:
session = AthenaAgentSession(
    # ... existing args ...
    engagement_id=self._engagement_id,  # H3: for Langfuse trace correlation
)
```

**Step 3: Add trace context to AthenaAgentSession**

In `sdk_agent.py`, modify `AthenaAgentSession.__init__()` to accept and store engagement_id:
```python
def __init__(self, ..., engagement_id: str = ""):
    # ... existing init ...
    self._engagement_id = engagement_id  # H3: Langfuse trace correlation
```

In `_run_query()` (around line 957), wrap the query call with an agent span:
```python
async def _run_query(self, prompt: str, ...):
    from langfuse_integration import trace_agent_run, is_enabled as langfuse_enabled

    ctx = None
    if langfuse_enabled():
        ctx = trace_agent_run(
            engagement_id=self._engagement_id,
            agent_code=self._agent_code,
            agent_name=self._agent_name,
            model=self._model,
        )
        ctx.__enter__()

    try:
        # ... existing query logic ...
        async for msg in query(prompt=prompt, options=opts):
            # ... existing handling ...
            pass
    finally:
        if ctx:
            ctx.__exit__(None, None, None)
```

**Step 4: Add Langfuse config to .env**

Add to `tools/athena-dashboard/.env` (or `.env.example`):
```bash
# H3: Langfuse Observability (optional — runs without it)
LANGFUSE_PUBLIC_KEY=pk-lf-athena
LANGFUSE_SECRET_KEY=  # Set from docker/.env.langfuse LANGFUSE_PROJECT_SECRET_KEY
LANGFUSE_BASE_URL=http://localhost:3000
ATHENA_LANGFUSE_ENABLED=true
```

**Step 5: Test with Langfuse running**

```bash
# Terminal 1: Start Langfuse
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-dashboard
docker compose -f docker/docker-compose.langfuse.yml --env-file docker/.env.langfuse up -d

# Terminal 2: Start ATHENA
./start.sh
# Look for: "Langfuse observability active" in logs

# Terminal 3: Verify traces appear
# Open http://localhost:3000 — login with admin creds from .env.langfuse
# Start a test engagement and check traces appear in Langfuse UI
```

**Step 6: Test without Langfuse running**

```bash
# Stop Langfuse
docker compose -f docker/docker-compose.langfuse.yml down

# Restart ATHENA
./start.sh
# Look for: "Langfuse disabled" in logs — no crash, graceful degradation
```

**Step 7: Commit**

```bash
git add sdk_agent.py agent_session_manager.py
git commit -m "feat(H3): Wire Langfuse traces into agent lifecycle

- Engagement-level root trace in AgentSessionManager
- Per-agent spans in AthenaAgentSession._run_query()
- Graceful degradation when Langfuse unavailable
- All Claude API calls auto-captured via AnthropicInstrumentor"
```

---

### Task 4: Langfuse Dashboard Link in ATHENA UI

**Files:**
- Modify: `tools/athena-dashboard/index.html`
- Modify: `tools/athena-dashboard/server.py` (status endpoint)

**Step 1: Add Langfuse status to /api/observability/status endpoint**

In `server.py`, add:
```python
@app.get("/api/observability/status")
async def get_observability_status():
    """H3: Return Langfuse observability status."""
    from langfuse_integration import is_enabled
    return {
        "langfuse_enabled": is_enabled(),
        "langfuse_url": os.environ.get("LANGFUSE_BASE_URL", "http://localhost:3000"),
    }
```

**Step 2: Add Langfuse link to Settings view in index.html**

In the Settings section of `index.html`, add an "Observability" card:
```html
<!-- H3: Langfuse Observability Link -->
<div class="card" style="margin-top: 1rem;">
    <h3>LLM Observability</h3>
    <p>Langfuse traces all Claude API calls — token usage, cost, latency, and agent reasoning chains.</p>
    <div style="display: flex; gap: 0.5rem; margin-top: 0.5rem;">
        <button onclick="window.open(langfuseUrl, '_blank')" class="btn btn-primary" id="langfuse-link-btn">
            Open Langfuse Dashboard
        </button>
        <span id="langfuse-status-badge" class="badge badge-low">Checking...</span>
    </div>
</div>
```

Add JS to fetch status on Settings view load:
```javascript
async function checkLangfuseStatus() {
    try {
        const resp = await fetch('/api/observability/status');
        const data = await resp.json();
        const badge = document.getElementById('langfuse-status-badge');
        const btn = document.getElementById('langfuse-link-btn');
        if (data.langfuse_enabled) {
            badge.textContent = 'Active';
            badge.className = 'badge badge-critical';
            window.langfuseUrl = data.langfuse_url;
        } else {
            badge.textContent = 'Disabled';
            badge.className = 'badge badge-low';
            btn.disabled = true;
        }
    } catch (e) {
        console.warn('Langfuse status check failed:', e);
    }
}
```

**Step 3: Commit**

```bash
git add index.html server.py
git commit -m "feat(H3): Add Langfuse dashboard link in Settings view

- /api/observability/status endpoint
- Langfuse link with active/disabled status badge
- Opens Langfuse UI in new tab for trace exploration"
```

---

## Phase H1: Cross-Session Memory (Graphiti)

### Task 5: Graphiti Dependencies and Pentest Ontology

**Files:**
- Modify: `tools/athena-dashboard/requirements.txt`
- Create: `tools/athena-dashboard/graphiti_ontology.py`

**Step 1: Add Graphiti dependency**

Append to `requirements.txt`:
```
# H1: Cross-Session Temporal Memory
graphiti-core[anthropic]>=0.28.0
```

**Step 2: Install**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-dashboard
source .venv/bin/activate
pip install "graphiti-core[anthropic]"
```

**Step 3: Write graphiti_ontology.py — ATHENA pentest entity/edge types**

```python
# tools/athena-dashboard/graphiti_ontology.py
# SPDX-License-Identifier: AGPL-3.0-or-later
"""
ATHENA H1: Pentest Knowledge Graph Ontology for Graphiti

Defines entity and edge types that Graphiti's LLM uses to extract structured
knowledge from agent outputs. Docstrings are critical — Graphiti's LLM reads
them to classify entities during episode ingestion.

Entity hierarchy:
    Target -> Host -> Service -> Vulnerability -> Exploit
    Credential <-> Host
    Technique -> Vulnerability (attack methodology)

Edge semantics are temporal — each relationship has valid_at/invalid_at
timestamps, enabling queries like "what was the attack surface at hour 3?"
"""

from pydantic import BaseModel, Field
from typing import Optional


# --- Entity Types ---

class Target(BaseModel):
    """A target organization, network range, or domain being assessed in a penetration test."""
    scope: Optional[str] = Field(None, description="IP range or domain scope")
    engagement_type: Optional[str] = Field(None, description="External, Internal, Web App, API, Cloud")
    industry: Optional[str] = Field(None, description="Target industry")


class Host(BaseModel):
    """A network host, server, endpoint, or virtual machine discovered during reconnaissance."""
    ip_address: Optional[str] = Field(None, description="IPv4 or IPv6 address")
    hostname: Optional[str] = Field(None, description="DNS hostname or FQDN")
    os: Optional[str] = Field(None, description="Operating system and version")
    open_ports: Optional[str] = Field(None, description="Comma-separated list of open ports")
    is_compromised: Optional[bool] = Field(False, description="Whether this host has been compromised")


class Service(BaseModel):
    """A network service running on a host, such as HTTP, SSH, SMB, or a database."""
    name: Optional[str] = Field(None, description="Service name (e.g., Apache, OpenSSH, MySQL)")
    version: Optional[str] = Field(None, description="Service version string")
    port: Optional[int] = Field(None, description="Port number the service listens on")
    protocol: Optional[str] = Field(None, description="TCP or UDP")
    banner: Optional[str] = Field(None, description="Service banner or fingerprint")


class Vulnerability(BaseModel):
    """A security vulnerability or weakness found during the penetration test."""
    cve_id: Optional[str] = Field(None, description="CVE identifier (e.g., CVE-2024-12345)")
    cvss_score: Optional[float] = Field(None, description="CVSS v3 base score (0.0-10.0)")
    severity: Optional[str] = Field(None, description="CRITICAL, HIGH, MEDIUM, or LOW")
    vuln_type: Optional[str] = Field(None, description="OWASP category or CWE type")
    affected_component: Optional[str] = Field(None, description="Specific component or parameter affected")


class Exploit(BaseModel):
    """An exploit, proof-of-concept, or attack payload used to compromise a vulnerability."""
    tool: Optional[str] = Field(None, description="Tool used (e.g., sqlmap, metasploit, custom)")
    payload: Optional[str] = Field(None, description="Attack payload or technique description")
    success: Optional[bool] = Field(None, description="Whether the exploit succeeded")
    source: Optional[str] = Field(None, description="Exploit source (ExploitDB, Metasploit, GitHub)")


class Credential(BaseModel):
    """Credentials discovered, cracked, or extracted during the penetration test."""
    username: Optional[str] = Field(None, description="Username or account name")
    credential_type: Optional[str] = Field(None, description="password, hash, token, key, certificate")
    service: Optional[str] = Field(None, description="Service these credentials are valid for")
    privilege_level: Optional[str] = Field(None, description="user, admin, root, domain_admin")


class Technique(BaseModel):
    """A MITRE ATT&CK technique or PTES methodology step used during the engagement."""
    mitre_id: Optional[str] = Field(None, description="MITRE ATT&CK technique ID (e.g., T1190)")
    tactic: Optional[str] = Field(None, description="ATT&CK tactic (e.g., Initial Access)")
    ptes_phase: Optional[str] = Field(None, description="PTES phase (e.g., Exploitation)")


class Tool(BaseModel):
    """A security tool used during the penetration test engagement."""
    name: Optional[str] = Field(None, description="Tool name (e.g., nmap, gobuster, sqlmap)")
    category: Optional[str] = Field(None, description="Tool category (recon, vuln_scan, exploit)")
    effectiveness: Optional[str] = Field(None, description="How effective: high, medium, low, none")


class Defense(BaseModel):
    """A security defense, WAF, or mitigation encountered during testing."""
    name: Optional[str] = Field(None, description="Defense name (e.g., Cloudflare WAF)")
    type: Optional[str] = Field(None, description="WAF, IDS, IPS, firewall, rate_limit, CAPTCHA")
    bypass_found: Optional[bool] = Field(None, description="Whether a bypass was discovered")
    bypass_technique: Optional[str] = Field(None, description="Description of bypass method")


# --- Edge Types ---

class RunsOn(BaseModel):
    """A service runs on a specific host and port."""
    port: Optional[int] = Field(None, description="Port number")


class HasVulnerability(BaseModel):
    """A service or host has a specific vulnerability."""
    discovery_method: Optional[str] = Field(None, description="How the vuln was found")
    confirmed: Optional[bool] = Field(None, description="Whether the vulnerability was confirmed")


class ExploitedBy(BaseModel):
    """A vulnerability was exploited using a specific exploit or technique."""
    success: Optional[bool] = Field(None, description="Whether exploitation succeeded")
    impact: Optional[str] = Field(None, description="Impact: RCE, data_access, privilege_escalation")


class AuthenticatesTo(BaseModel):
    """Credentials authenticate to a specific service or host."""
    method: Optional[str] = Field(None, description="Auth method: password, key, token, pass-the-hash")


class LateralMovement(BaseModel):
    """Movement from one compromised host to another."""
    technique: Optional[str] = Field(None, description="Lateral movement technique used")
    tool: Optional[str] = Field(None, description="Tool used for lateral movement")


class ProtectedBy(BaseModel):
    """A service or host is protected by a defense mechanism."""
    effectiveness: Optional[str] = Field(None, description="blocked, partially_bypassed, fully_bypassed")


class ChainedWith(BaseModel):
    """Two techniques or exploits are chained together in an attack path."""
    order: Optional[int] = Field(None, description="Position in the attack chain (1, 2, 3...)")
    dependency: Optional[str] = Field(None, description="What the next step depends on")


# --- Ontology Registration ---

ENTITY_TYPES = {
    "Target": Target,
    "Host": Host,
    "Service": Service,
    "Vulnerability": Vulnerability,
    "Exploit": Exploit,
    "Credential": Credential,
    "Technique": Technique,
    "Tool": Tool,
    "Defense": Defense,
}

EDGE_TYPES = {
    "RunsOn": RunsOn,
    "HasVulnerability": HasVulnerability,
    "ExploitedBy": ExploitedBy,
    "AuthenticatesTo": AuthenticatesTo,
    "LateralMovement": LateralMovement,
    "ProtectedBy": ProtectedBy,
    "ChainedWith": ChainedWith,
}

# Map which edge types connect which entity pairs
EDGE_TYPE_MAP = {
    ("Service", "Host"): ["RunsOn"],
    ("Host", "Vulnerability"): ["HasVulnerability"],
    ("Service", "Vulnerability"): ["HasVulnerability"],
    ("Vulnerability", "Exploit"): ["ExploitedBy"],
    ("Credential", "Host"): ["AuthenticatesTo"],
    ("Credential", "Service"): ["AuthenticatesTo"],
    ("Host", "Host"): ["LateralMovement"],
    ("Host", "Defense"): ["ProtectedBy"],
    ("Service", "Defense"): ["ProtectedBy"],
    ("Technique", "Technique"): ["ChainedWith"],
    ("Exploit", "Exploit"): ["ChainedWith"],
    ("Tool", "Vulnerability"): ["HasVulnerability"],
}
```

**Step 4: Verify ontology loads**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-dashboard
source .venv/bin/activate
python3 -c "from graphiti_ontology import ENTITY_TYPES, EDGE_TYPES, EDGE_TYPE_MAP; print(f'{len(ENTITY_TYPES)} entities, {len(EDGE_TYPES)} edges, {len(EDGE_TYPE_MAP)} mappings')"
```

Expected: `9 entities, 7 edges, 12 mappings`

**Step 5: Commit**

```bash
git add graphiti_ontology.py requirements.txt
git commit -m "feat(H1): Define ATHENA pentest ontology for Graphiti

9 entity types: Target, Host, Service, Vulnerability, Exploit,
Credential, Technique, Tool, Defense.
7 edge types with temporal semantics.
12 entity-pair edge mappings for knowledge graph construction."
```

---

### Task 6: Graphiti Integration Module

**Files:**
- Create: `tools/athena-dashboard/graphiti_integration.py`
- Modify: `tools/athena-dashboard/server.py` (lifespan hooks)

**Step 1: Write graphiti_integration.py**

```python
# tools/athena-dashboard/graphiti_integration.py
# SPDX-License-Identifier: AGPL-3.0-or-later
"""
ATHENA H1: Graphiti Cross-Session Temporal Memory

Provides engagement-aware temporal knowledge graph using Graphiti.
Each engagement gets its own group_id for data isolation within
the shared Neo4j instance.

Key operations:
    - ingest_episode(): Feed tool outputs, agent reasoning, findings
    - search_memory(): Query past engagement knowledge
    - get_similar_cases(): Find similar hosts/vulns from history

Usage:
    from graphiti_integration import init_graphiti, shutdown_graphiti
    from graphiti_integration import ingest_episode, search_memory

    await init_graphiti()

    await ingest_episode(
        engagement_id="eng_123",
        name="nmap_scan_webserver",
        content="Nmap scan: 192.168.1.10 port 80 (Apache 2.4.49), port 443",
        source_description="nmap port scan output",
    )

    results = await search_memory(
        query="Apache 2.4.49 vulnerabilities and bypasses",
        engagement_ids=["eng_123"],
        include_global=True,
    )
"""

import os
import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("athena.graphiti")

# Graphiti singleton
_graphiti = None
_enabled = False


def is_enabled() -> bool:
    """Check if Graphiti cross-session memory is enabled."""
    return _enabled


async def init_graphiti() -> bool:
    """Initialize Graphiti with existing Neo4j instance.

    Reads config from environment variables:
        NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD (shared with existing Neo4j)
        ATHENA_GRAPHITI_ENABLED (default: true)
        GRAPHITI_LLM_MODEL (default: claude-haiku-4-5)

    Returns True if successfully initialized, False if skipped/failed.
    """
    global _graphiti, _enabled

    explicitly_disabled = os.environ.get("ATHENA_GRAPHITI_ENABLED", "").lower() == "false"
    if explicitly_disabled:
        logger.info("Graphiti disabled via ATHENA_GRAPHITI_ENABLED=false")
        return False

    neo4j_uri = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
    neo4j_user = os.environ.get("NEO4J_USER", "neo4j")
    neo4j_password = os.environ.get("NEO4J_PASSWORD")

    if not neo4j_password:
        logger.warning("Graphiti: NEO4J_PASSWORD not set. Cross-session memory disabled.")
        return False

    anthropic_key = os.environ.get("ANTHROPIC_API_KEY")
    if not anthropic_key:
        logger.warning("Graphiti: ANTHROPIC_API_KEY not set. Cross-session memory disabled.")
        return False

    try:
        from graphiti_core import Graphiti
        from graphiti_core.llm_client.anthropic_client import AnthropicClient

        llm_model = os.environ.get("GRAPHITI_LLM_MODEL", "claude-haiku-4-5")

        llm_client = AnthropicClient(
            api_key=anthropic_key,
            model=llm_model,
        )

        _graphiti = Graphiti(
            neo4j_uri=neo4j_uri,
            neo4j_user=neo4j_user,
            neo4j_password=neo4j_password,
            llm_client=llm_client,
        )

        # Build indices (idempotent — safe to call every startup)
        await _graphiti.build_indices_and_constraints()

        _enabled = True
        logger.info(f"Graphiti initialized -> {neo4j_uri} (LLM: {llm_model})")
        return True

    except ImportError as e:
        logger.warning(f"Graphiti packages not installed: {e}. Cross-session memory disabled.")
        return False
    except Exception as e:
        logger.error(f"Graphiti init failed: {e}. Cross-session memory disabled.")
        return False


async def shutdown_graphiti():
    """Close Graphiti connections."""
    global _graphiti, _enabled
    if _graphiti:
        try:
            await _graphiti.close()
            logger.info("Graphiti shutdown complete")
        except Exception as e:
            logger.error(f"Graphiti shutdown error: {e}")
    _enabled = False
    _graphiti = None


async def ingest_episode(
    engagement_id: str,
    name: str,
    content: str,
    source_description: str = "agent output",
    reference_time: Optional[datetime] = None,
) -> bool:
    """Feed an episode into Graphiti for knowledge extraction.

    Episodes are the primary input — tool outputs, agent reasoning, findings,
    HITL decisions. Graphiti's LLM extracts entities and relationships using
    the ATHENA pentest ontology.

    Args:
        engagement_id: Used as group_id for data isolation
        name: Unique episode name (e.g., "nmap_scan_192.168.1.0")
        content: Full text content to extract knowledge from
        source_description: What produced this content
        reference_time: When this happened (defaults to now)

    Returns:
        True if ingested successfully, False otherwise
    """
    if not _enabled or not _graphiti:
        return False

    if reference_time is None:
        reference_time = datetime.now(timezone.utc)

    try:
        from graphiti_core.nodes import EpisodeType
        from graphiti_ontology import ENTITY_TYPES, EDGE_TYPES, EDGE_TYPE_MAP

        await _graphiti.add_episode(
            name=name,
            episode_body=content,
            source=EpisodeType.text,
            source_description=source_description,
            reference_time=reference_time,
            group_id=engagement_id,
            entity_types=ENTITY_TYPES,
            edge_types=EDGE_TYPES,
            edge_type_map=EDGE_TYPE_MAP,
        )

        logger.debug(f"Graphiti episode ingested: {name} -> group={engagement_id}")
        return True

    except Exception as e:
        logger.error(f"Graphiti ingest_episode failed for '{name}': {e}")
        return False


async def search_memory(
    query: str,
    engagement_ids: Optional[list[str]] = None,
    include_global: bool = False,
    num_results: int = 10,
) -> list[dict]:
    """Search Graphiti knowledge graph for relevant context.

    Used by Strategy Agent (ST) to recall past experience:
    - "What vulnerabilities were found on Apache 2.4 behind Cloudflare?"
    - "What techniques worked against Windows Server 2019 AD?"

    Args:
        query: Natural language search query
        engagement_ids: Limit search to specific engagements
        include_global: If True, search across ALL past engagements
        num_results: Maximum results to return

    Returns:
        List of dicts with: fact, source_name, target_name, valid_at, invalid_at
    """
    if not _enabled or not _graphiti:
        return []

    try:
        group_ids = list(engagement_ids) if engagement_ids else []
        if include_global:
            group_ids = None  # None = search all groups

        results = await _graphiti.search(
            query=query,
            group_ids=group_ids,
            num_results=num_results,
        )

        return [
            {
                "fact": edge.fact if hasattr(edge, 'fact') else str(edge),
                "source_name": getattr(edge, 'source_node_name', 'unknown'),
                "target_name": getattr(edge, 'target_node_name', 'unknown'),
                "valid_at": str(getattr(edge, 'valid_at', '')),
                "invalid_at": str(getattr(edge, 'invalid_at', '')),
                "group_id": getattr(edge, 'group_id', ''),
            }
            for edge in results
        ]

    except Exception as e:
        logger.error(f"Graphiti search failed for '{query}': {e}")
        return []


async def get_similar_cases(
    service_name: str,
    version: str = "",
    num_results: int = 5,
) -> list[dict]:
    """Find similar services/hosts from past engagements.

    Convenience wrapper for the Strategy Agent's most common query:
    "What do we know about this service?"

    Args:
        service_name: Service name (e.g., "Apache", "OpenSSH", "MySQL")
        version: Optional version string
        num_results: Max results

    Returns:
        List of relevant facts from past engagements
    """
    query = f"{service_name} {version}".strip()
    query += " vulnerabilities exploits techniques"
    return await search_memory(
        query=query,
        include_global=True,
        num_results=num_results,
    )
```

**Step 2: Integrate into server.py lifespan**

Add to imports in `server.py`:
```python
from graphiti_integration import init_graphiti, shutdown_graphiti
```

In `lifespan()`, after Neo4j init and Langfuse init:
```python
    # H1: Initialize Graphiti cross-session memory
    graphiti_ok = await init_graphiti()
    if graphiti_ok:
        logger.info("Graphiti cross-session memory active")
    else:
        logger.info("Graphiti disabled — running without cross-session memory")
```

In lifespan teardown (before Neo4j close):
```python
    # H1: Close Graphiti before Neo4j
    await shutdown_graphiti()
```

**Step 3: Verify Graphiti initializes with existing Neo4j**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-dashboard
./start.sh
# Look for: "Graphiti cross-session memory active" in logs
```

**Step 4: Commit**

```bash
git add graphiti_integration.py server.py
git commit -m "feat(H1): Add Graphiti cross-session memory integration

- graphiti_integration.py: init/shutdown, ingest_episode, search_memory
- Shares existing Neo4j instance with group_id isolation per engagement
- Uses Claude Haiku 4.5 for entity extraction (cheapest model)
- ATHENA pentest ontology for knowledge classification
- Graceful degradation if Graphiti not available"
```

---

### Task 7: Feed Agent Episodes into Graphiti

**Files:**
- Modify: `tools/athena-dashboard/sdk_agent.py` (feed tool outputs and findings)
- Modify: `tools/athena-dashboard/server.py` (feed HITL decisions)

**Step 1: Add Graphiti episode ingestion to tool_complete events**

In `sdk_agent.py`, import at top:
```python
from graphiti_integration import ingest_episode, is_enabled as graphiti_enabled
```

In `_handle_user_message()` (around line 1315), after emitting tool_complete:
```python
    # H1: Feed tool outputs into Graphiti for knowledge extraction
    if graphiti_enabled() and self._engagement_id:
        import asyncio
        for item in msg.content:
            if isinstance(item, ToolResultBlock) and item.content:
                output_text = item.content if isinstance(item.content, str) else str(item.content)
                # Only ingest substantial outputs (skip empty/trivial)
                if len(output_text) > 50:
                    # Fire-and-forget — don't block agent execution
                    asyncio.create_task(ingest_episode(
                        engagement_id=self._engagement_id,
                        name=f"{self._agent_code}_tool_{item.tool_use_id[:8]}",
                        content=output_text[:4000],  # cap at 4K chars
                        source_description=f"Tool output from {self._agent_name}",
                    ))
```

**Step 2: Feed findings into Graphiti**

In `server.py`, find the finding creation endpoint (where findings are persisted to Neo4j). After the Neo4j write:
```python
    # H1: Feed finding into Graphiti for cross-session memory
    from graphiti_integration import ingest_episode, is_enabled as graphiti_enabled
    if graphiti_enabled():
        import asyncio
        finding_text = (
            f"Finding: {finding.title}\n"
            f"Severity: {finding.severity}\n"
            f"OWASP: {finding.owasp_category}\n"
            f"Description: {finding.description}\n"
            f"Affected: {finding.affected_hosts}\n"
            f"Remediation: {finding.remediation}"
        )
        asyncio.create_task(ingest_episode(
            engagement_id=eid,
            name=f"finding_{finding.id[:8]}",
            content=finding_text,
            source_description=f"Confirmed finding from {finding.discovered_by}",
        ))
```

**Step 3: Feed HITL decisions into Graphiti**

In `server.py`, find the approval resolution endpoint. After resolving:
```python
    # H1: Feed HITL decision into Graphiti
    if graphiti_enabled():
        decision_text = (
            f"Operator {'approved' if approved else 'rejected'} "
            f"{approval_type}: {approval_description}"
        )
        asyncio.create_task(ingest_episode(
            engagement_id=eid,
            name=f"hitl_{approval_id[:8]}",
            content=decision_text,
            source_description="Operator HITL decision",
        ))
```

**Step 4: Commit**

```bash
git add sdk_agent.py server.py
git commit -m "feat(H1): Feed agent outputs, findings, and HITL decisions into Graphiti

- Tool outputs (>50 chars) auto-ingested via fire-and-forget tasks
- Confirmed findings ingested with full context
- HITL approval/rejection decisions recorded for temporal reasoning
- All episodes capped at 4K chars, non-blocking async ingestion"
```

---

### Task 8: Strategy Agent Queries Graphiti for Context

**Files:**
- Modify: `tools/athena-dashboard/agent_configs.py` (ST prompt enhancement)
- Modify: `tools/athena-dashboard/agent_session_manager.py` (inject Graphiti context)
- Modify: `tools/athena-dashboard/server.py` (memory search endpoint)

**Step 1: Add memory search API endpoint**

In `server.py`, add:
```python
@app.get("/api/memory/search")
async def search_graphiti_memory(
    q: str,
    engagement_id: Optional[str] = None,
    include_global: bool = True,
    limit: int = 10,
):
    """H1: Search Graphiti cross-session memory."""
    from graphiti_integration import search_memory, is_enabled as graphiti_enabled
    if not graphiti_enabled():
        return {"results": [], "enabled": False}

    engagement_ids = [engagement_id] if engagement_id else None
    results = await search_memory(
        query=q,
        engagement_ids=engagement_ids,
        include_global=include_global,
        num_results=limit,
    )
    return {"results": results, "enabled": True}


@app.get("/api/memory/similar")
async def find_similar_cases(service: str, version: str = ""):
    """H1: Find similar services from past engagements."""
    from graphiti_integration import get_similar_cases, is_enabled as graphiti_enabled
    if not graphiti_enabled():
        return {"results": [], "enabled": False}

    results = await get_similar_cases(service_name=service, version=version)
    return {"results": results, "enabled": True}
```

**Step 2: Inject Graphiti context when spawning ST agent**

In `agent_session_manager.py`, in `start()` method, before spawning ST:
```python
    # H1: Query Graphiti for relevant past experience
    graphiti_context = ""
    from graphiti_integration import is_enabled as graphiti_enabled
    if graphiti_enabled():
        from graphiti_integration import search_memory
        target = self._target or ""
        if target:
            past_facts = await search_memory(
                query=f"penetration test {target} vulnerabilities exploits",
                include_global=True,
                num_results=5,
            )
            if past_facts:
                graphiti_context = "\n\n## Past Engagement Intelligence (from Graphiti memory)\n"
                graphiti_context += "The following facts were learned from previous engagements:\n"
                for fact in past_facts:
                    graphiti_context += (
                        f"- {fact['fact']} "
                        f"(source: {fact['source_name']} -> {fact['target_name']})\n"
                    )
                graphiti_context += "\nUse these insights to inform your strategy.\n"
```

Then append `graphiti_context` to the ST prompt in the spawn call.

**Step 3: Update ST agent prompt template**

In `agent_configs.py`, add to the ST system prompt template:
```
## Cross-Session Memory
You have access to ATHENA's temporal knowledge graph. Past engagement facts
are injected into your context when available. Use them to:
- Skip known dead-ends ("last time X bypass didn't work against Cloudflare")
- Prioritize proven techniques ("Apache 2.4.49 path traversal was confirmed exploitable")
- Warn about common defenses ("targets behind Akamai typically block automated sqlmap")

You can also search for more context by curling:
  curl -s "http://localhost:8080/api/memory/search?q=YOUR+QUERY&include_global=true"
  curl -s "http://localhost:8080/api/memory/similar?service=Apache&version=2.4.49"
```

**Step 4: Commit**

```bash
git add server.py agent_session_manager.py agent_configs.py
git commit -m "feat(H1): Strategy Agent queries Graphiti for past engagement intelligence

- /api/memory/search and /api/memory/similar REST endpoints
- ST agent receives past facts on spawn (up to 5 relevant facts)
- ST prompt updated with cross-session memory usage instructions
- Agents can curl memory endpoints for ad-hoc queries during execution"
```

---

### Task 9: Memory Status in Dashboard + Intelligence View Integration

**Files:**
- Modify: `tools/athena-dashboard/server.py` (memory stats endpoint)
- Modify: `tools/athena-dashboard/index.html` (Intelligence view + Settings)

**Step 1: Add memory stats endpoint**

In `server.py`:
```python
@app.get("/api/memory/stats")
async def get_memory_stats():
    """H1: Return Graphiti memory statistics."""
    from graphiti_integration import is_enabled as graphiti_enabled
    if not graphiti_enabled():
        return {"enabled": False, "episodes": 0, "entities": 0}

    try:
        episodes = await neo4j_exec("MATCH (n:EpisodicNode) RETURN count(n) as c")
        entities = await neo4j_exec("MATCH (n:EntityNode) RETURN count(n) as c")
        edges = await neo4j_exec("MATCH ()-[r:RELATES_TO]->() RETURN count(r) as c")
        return {
            "enabled": True,
            "episodes": episodes[0]["c"] if episodes else 0,
            "entities": entities[0]["c"] if entities else 0,
            "relationships": edges[0]["c"] if edges else 0,
        }
    except Exception as e:
        logger.error(f"Memory stats query failed: {e}")
        return {"enabled": True, "episodes": -1, "entities": -1, "error": str(e)}
```

**Step 2: Add Memory KPI card to Intelligence view in index.html**

```html
<!-- H1: Cross-Session Memory Status -->
<div class="kpi-card" id="memory-kpi">
    <div class="kpi-value" id="memory-entities-count">--</div>
    <div class="kpi-label">Knowledge Entities</div>
    <div class="kpi-sublabel" id="memory-episodes-count">-- episodes ingested</div>
</div>
```

Add JS to fetch memory stats:
```javascript
async function loadMemoryStats() {
    try {
        const resp = await fetch('/api/memory/stats');
        const data = await resp.json();
        document.getElementById('memory-entities-count').textContent = data.entities || 0;
        document.getElementById('memory-episodes-count').textContent =
            (data.episodes || 0) + ' episodes ingested';
    } catch (e) {
        console.warn('Memory stats load failed:', e);
    }
}
```

**Step 3: Add memory search to Intelligence view**

```html
<!-- H1: Memory Search -->
<div style="margin-bottom: 1rem;">
    <input type="text" id="memory-search-input"
           placeholder="Search past engagement knowledge..."
           style="width: 100%; padding: 0.5rem; background: var(--zerok-input-bg);
                  border: 1px solid var(--zerok-border); color: var(--zerok-text);
                  border-radius: 4px;">
    <div id="memory-search-results" style="margin-top: 0.5rem;"></div>
</div>
```

```javascript
document.getElementById('memory-search-input').addEventListener('keydown', async (e) => {
    if (e.key !== 'Enter') return;
    const query = e.target.value.trim();
    if (!query) return;

    const resp = await fetch(
        '/api/memory/search?q=' + encodeURIComponent(query) + '&include_global=true'
    );
    const data = await resp.json();
    const container = document.getElementById('memory-search-results');

    if (!data.enabled) {
        container.innerHTML = '<p style="color: var(--zerok-muted);">Graphiti memory not enabled</p>';
        return;
    }

    if (data.results.length === 0) {
        container.innerHTML = '<p style="color: var(--zerok-muted);">No matching memories found</p>';
        return;
    }

    container.innerHTML = data.results.map(r =>
        '<div class="card" style="padding: 0.5rem; margin-bottom: 0.25rem;">' +
        '<strong>' + r.source_name + '</strong> -> <strong>' + r.target_name + '</strong>' +
        '<p style="margin: 0.25rem 0 0; color: var(--zerok-text-secondary);">' + r.fact + '</p>' +
        '</div>'
    ).join('');
});
```

**Step 4: Add Memory card to Settings view**

```html
<!-- H1: Cross-Session Memory -->
<div class="card" style="margin-top: 1rem;">
    <h3>Cross-Session Memory (Graphiti)</h3>
    <p>Temporal knowledge graph — engagements compound over time.</p>
    <div style="display: flex; gap: 0.5rem; margin-top: 0.5rem;">
        <span id="graphiti-status-badge" class="badge badge-low">Checking...</span>
        <span id="graphiti-stats" style="color: var(--zerok-text-secondary);"></span>
    </div>
</div>
```

**Step 5: Commit**

```bash
git add server.py index.html
git commit -m "feat(H1): Memory stats, search UI in Intelligence view

- /api/memory/stats endpoint (entity, episode, relationship counts)
- KPI card showing knowledge entities in Intelligence view
- Memory search input with real-time Graphiti query
- Memory + Langfuse status cards in Settings view"
```

---

### Task 10: Integration Testing

**Files:**
- Create: `tools/athena-dashboard/tests/test_graphiti_integration.py`
- Create: `tools/athena-dashboard/tests/test_langfuse_integration.py`

**Step 1: Write Graphiti integration test**

```python
# tools/athena-dashboard/tests/test_graphiti_integration.py
"""H1: Integration tests for Graphiti cross-session memory."""
import pytest
from unittest.mock import patch


def test_ontology_entity_count():
    from graphiti_ontology import ENTITY_TYPES
    assert len(ENTITY_TYPES) == 9


def test_ontology_edge_count():
    from graphiti_ontology import EDGE_TYPES
    assert len(EDGE_TYPES) == 7


def test_ontology_edge_map_count():
    from graphiti_ontology import EDGE_TYPE_MAP
    assert len(EDGE_TYPE_MAP) == 12


@pytest.mark.asyncio
async def test_init_without_password():
    """Graphiti should gracefully disable when NEO4J_PASSWORD is missing."""
    from graphiti_integration import init_graphiti, is_enabled
    with patch.dict("os.environ", {"NEO4J_PASSWORD": ""}, clear=False):
        result = await init_graphiti()
        assert result is False
        assert is_enabled() is False


@pytest.mark.asyncio
async def test_search_when_disabled():
    """search_memory should return empty list when disabled."""
    from graphiti_integration import search_memory
    results = await search_memory("test query")
    assert results == []


@pytest.mark.asyncio
async def test_ingest_when_disabled():
    """ingest_episode should return False when disabled."""
    from graphiti_integration import ingest_episode
    result = await ingest_episode("eng_1", "test", "content")
    assert result is False
```

**Step 2: Write Langfuse integration test**

```python
# tools/athena-dashboard/tests/test_langfuse_integration.py
"""H3: Integration tests for Langfuse observability."""
import pytest
from unittest.mock import patch


@pytest.mark.asyncio
async def test_init_without_secret_key():
    """Langfuse should gracefully disable when secret key is missing."""
    from langfuse_integration import init_langfuse, is_enabled
    with patch.dict("os.environ", {"LANGFUSE_SECRET_KEY": ""}, clear=False):
        result = await init_langfuse()
        assert result is False
        assert is_enabled() is False


@pytest.mark.asyncio
async def test_init_explicitly_disabled():
    """Langfuse should respect ATHENA_LANGFUSE_ENABLED=false."""
    from langfuse_integration import init_langfuse
    with patch.dict("os.environ", {"ATHENA_LANGFUSE_ENABLED": "false"}, clear=False):
        result = await init_langfuse()
        assert result is False


def test_trace_engagement_when_disabled():
    """trace_engagement should yield None when disabled."""
    from langfuse_integration import trace_engagement
    with trace_engagement("eng_1", "target.com") as trace:
        assert trace is None


def test_score_finding_when_disabled():
    """score_finding should not crash when disabled."""
    from langfuse_integration import score_finding
    score_finding("eng_1", "find_1", "HIGH", "HIGH", "EX")
```

**Step 3: Run tests**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-dashboard
source .venv/bin/activate
pip install pytest pytest-asyncio
python3 -m pytest tests/test_graphiti_integration.py tests/test_langfuse_integration.py -v
```

Expected: All tests PASS

**Step 4: Commit**

```bash
git add tests/
git commit -m "test(H1+H3): Integration tests for Graphiti and Langfuse

- Ontology validation (entity, edge, mapping counts)
- Graceful degradation tests (missing config, disabled)
- No-crash tests for disabled state operations"
```

---

## Verification Checklist

After all tasks are complete, verify:

- [ ] `docker compose -f docker/docker-compose.langfuse.yml ps` — all 6 services healthy
- [ ] `curl http://localhost:3000/api/public/health` returns OK
- [ ] ATHENA server starts with both Langfuse and Graphiti active logs
- [ ] ATHENA server starts without Langfuse/Graphiti (graceful degradation)
- [ ] Start a test engagement — traces appear in Langfuse UI (http://localhost:3000)
- [ ] After engagement — `curl /api/memory/stats` shows episodes > 0
- [ ] Memory search returns results: `curl "/api/memory/search?q=apache+vuln"`
- [ ] Intelligence view shows memory KPI card and search works
- [ ] Settings view shows both Langfuse and Graphiti status cards
- [ ] All tests pass: `pytest tests/ -v`

---

## Cost Estimate

| Component | Cost |
|-----------|------|
| Langfuse stack | $0 (self-hosted, local Docker) |
| Graphiti entity extraction | ~$0.01-0.05/engagement (Haiku 4.5 for LLM calls) |
| Graphiti embeddings | ~$0.001/engagement (text-embedding-3-small) |
| Neo4j storage | $0 (existing instance, shared) |
| **Total per engagement** | **~$0.02-0.06 additional** |

---

**Last Updated:** 2026-03-09
**Author:** Vex for ZeroK Labs
