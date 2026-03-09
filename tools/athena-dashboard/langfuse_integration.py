# SPDX-License-Identifier: AGPL-3.0-or-later
"""ATHENA H3: Langfuse LLM Observability Integration"""

import os
import logging
from contextlib import contextmanager
from typing import Optional

logger = logging.getLogger("athena.langfuse")

_langfuse = None
_enabled = False


def is_enabled() -> bool:
    return _enabled


async def init_langfuse() -> bool:
    """Initialize Langfuse. Reads LANGFUSE_PUBLIC_KEY, LANGFUSE_SECRET_KEY, LANGFUSE_BASE_URL.
    Returns True if initialized, False if skipped/failed. Graceful — never crashes."""
    global _langfuse, _enabled

    explicitly_disabled = os.environ.get("ATHENA_LANGFUSE_ENABLED", "").lower() == "false"
    if explicitly_disabled:
        logger.info("Langfuse disabled via ATHENA_LANGFUSE_ENABLED=false")
        return False

    secret_key = os.environ.get("LANGFUSE_SECRET_KEY")
    if not secret_key:
        logger.warning("Langfuse not configured (LANGFUSE_SECRET_KEY missing). Observability disabled.")
        return False

    try:
        from langfuse import get_client
        from opentelemetry.instrumentation.anthropic import AnthropicInstrumentor

        public_key = os.environ.get("LANGFUSE_PUBLIC_KEY", "pk-lf-athena")
        base_url = os.environ.get("LANGFUSE_BASE_URL", "http://localhost:3000")

        os.environ.setdefault("LANGFUSE_PUBLIC_KEY", public_key)
        os.environ.setdefault("LANGFUSE_SECRET_KEY", secret_key)
        os.environ.setdefault("LANGFUSE_BASE_URL", base_url)

        AnthropicInstrumentor().instrument()
        logger.info("AnthropicInstrumentor activated — all Claude calls auto-traced")

        _langfuse = get_client()
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
    """Flush and shutdown. MUST call in FastAPI lifespan teardown."""
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
    """Root trace for an engagement. Yields trace or None if disabled."""
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
        with propagate_attributes(session_id=engagement_id, tags=["engagement", mode]):
            yield trace
        trace.update(output={"status": "completed"})
    except Exception as e:
        logger.error(f"Langfuse trace_engagement error: {e}")
        yield None


@contextmanager
def trace_agent_run(engagement_id: str, agent_code: str, agent_name: str, model: str = "claude-sonnet-4-6"):
    """Span for individual agent execution."""
    if not _enabled or not _langfuse:
        yield None
        return
    try:
        span = _langfuse.start_as_current_observation(
            as_type="span",
            name=f"agent-{agent_code}",
            session_id=engagement_id,
            metadata={"agent_code": agent_code, "agent_name": agent_name, "model": model},
        )
        with span:
            yield span
    except Exception as e:
        logger.error(f"Langfuse trace_agent_run error: {e}")
        yield None


def score_finding(engagement_id: str, finding_id: str, severity: str, confidence: str, agent_code: str):
    """Record finding score for evaluation pipelines."""
    if not _enabled or not _langfuse:
        return
    severity_scores = {"CRITICAL": 1.0, "HIGH": 0.75, "MEDIUM": 0.5, "LOW": 0.25}
    confidence_scores = {"HIGH": 1.0, "MEDIUM": 0.66, "LOW": 0.33, "UNCONFIRMED": 0.0}
    try:
        _langfuse.score(name="finding_severity", value=severity_scores.get(severity, 0.0),
                       comment=f"{severity} finding by {agent_code}", trace_id=engagement_id, observation_id=finding_id)
        _langfuse.score(name="finding_confidence", value=confidence_scores.get(confidence, 0.0),
                       comment=f"{confidence} confidence by {agent_code}", trace_id=engagement_id, observation_id=finding_id)
    except Exception as e:
        logger.error(f"Langfuse score error: {e}")
