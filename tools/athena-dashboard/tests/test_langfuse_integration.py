"""H3: Integration tests for Langfuse observability."""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.mark.asyncio
async def test_init_without_secret_key():
    """Langfuse should gracefully disable when secret key is missing."""
    from langfuse_integration import init_langfuse, is_enabled, shutdown_langfuse
    await shutdown_langfuse()
    old = os.environ.pop("LANGFUSE_SECRET_KEY", None)
    try:
        result = await init_langfuse()
        assert result is False
        assert is_enabled() is False
    finally:
        if old:
            os.environ["LANGFUSE_SECRET_KEY"] = old


@pytest.mark.asyncio
async def test_init_explicitly_disabled():
    """Langfuse should respect ATHENA_LANGFUSE_ENABLED=false."""
    from langfuse_integration import init_langfuse, shutdown_langfuse
    await shutdown_langfuse()
    old = os.environ.get("ATHENA_LANGFUSE_ENABLED")
    os.environ["ATHENA_LANGFUSE_ENABLED"] = "false"
    try:
        result = await init_langfuse()
        assert result is False
    finally:
        if old:
            os.environ["ATHENA_LANGFUSE_ENABLED"] = old
        else:
            os.environ.pop("ATHENA_LANGFUSE_ENABLED", None)


def test_trace_engagement_when_disabled():
    from langfuse_integration import trace_engagement
    with trace_engagement("eng_1", "target.com") as trace:
        assert trace is None


def test_trace_agent_run_when_disabled():
    from langfuse_integration import trace_agent_run
    with trace_agent_run("eng_1", "ST", "Strategy Agent") as span:
        assert span is None


def test_score_finding_when_disabled():
    """score_finding should not crash when disabled."""
    from langfuse_integration import score_finding
    # Should not raise
    score_finding("eng_1", "find_1", "HIGH", "HIGH", "EX")


def test_is_enabled_default_false():
    from langfuse_integration import is_enabled
    # Without explicit init, should be False
    assert is_enabled() is False
