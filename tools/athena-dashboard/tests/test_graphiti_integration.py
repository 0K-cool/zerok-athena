"""H1: Integration tests for Graphiti cross-session memory."""
import pytest
import sys
import os

# Add parent to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_ontology_entity_count():
    from graphiti_ontology import ENTITY_TYPES
    assert len(ENTITY_TYPES) == 9


def test_ontology_edge_count():
    from graphiti_ontology import EDGE_TYPES
    assert len(EDGE_TYPES) == 7


def test_ontology_edge_map_count():
    from graphiti_ontology import EDGE_TYPE_MAP
    assert len(EDGE_TYPE_MAP) == 12


def test_ontology_entity_types_have_docstrings():
    """Docstrings are critical — Graphiti's LLM reads them."""
    from graphiti_ontology import ENTITY_TYPES
    for name, cls in ENTITY_TYPES.items():
        assert cls.__doc__, f"Entity type {name} is missing a docstring"


def test_ontology_edge_types_have_docstrings():
    from graphiti_ontology import EDGE_TYPES
    for name, cls in EDGE_TYPES.items():
        assert cls.__doc__, f"Edge type {name} is missing a docstring"


def test_ontology_all_entity_types_are_pydantic():
    from graphiti_ontology import ENTITY_TYPES
    from pydantic import BaseModel
    for name, cls in ENTITY_TYPES.items():
        assert issubclass(cls, BaseModel), f"{name} is not a Pydantic BaseModel"


def test_ontology_all_edge_types_are_pydantic():
    from graphiti_ontology import EDGE_TYPES
    from pydantic import BaseModel
    for name, cls in EDGE_TYPES.items():
        assert issubclass(cls, BaseModel), f"{name} is not a Pydantic BaseModel"


@pytest.mark.asyncio
async def test_init_without_password():
    """Graphiti should gracefully disable when NEO4J_PASS is missing."""
    from graphiti_integration import init_graphiti, is_enabled, shutdown_graphiti
    # Ensure clean state
    await shutdown_graphiti()
    old = os.environ.pop("NEO4J_PASS", None)
    try:
        result = await init_graphiti()
        assert result is False
        assert is_enabled() is False
    finally:
        if old:
            os.environ["NEO4J_PASS"] = old


@pytest.mark.asyncio
async def test_init_without_anthropic_key():
    """Graphiti should gracefully disable when ANTHROPIC_API_KEY is missing."""
    from graphiti_integration import init_graphiti, is_enabled, shutdown_graphiti
    await shutdown_graphiti()
    old_pw = os.environ.get("NEO4J_PASS")
    old_key = os.environ.pop("ANTHROPIC_API_KEY", None)
    os.environ["NEO4J_PASS"] = "test"
    try:
        result = await init_graphiti()
        assert result is False
        assert is_enabled() is False
    finally:
        os.environ.pop("NEO4J_PASS", None)
        if old_pw:
            os.environ["NEO4J_PASS"] = old_pw
        if old_key:
            os.environ["ANTHROPIC_API_KEY"] = old_key


@pytest.mark.asyncio
async def test_search_when_disabled():
    from graphiti_integration import search_memory
    results = await search_memory("test query")
    assert results == []


@pytest.mark.asyncio
async def test_ingest_when_disabled():
    from graphiti_integration import ingest_episode
    result = await ingest_episode("eng_1", "test", "content")
    assert result is False


@pytest.mark.asyncio
async def test_similar_cases_when_disabled():
    from graphiti_integration import get_similar_cases
    results = await get_similar_cases("Apache", "2.4.49")
    assert results == []
