# SPDX-License-Identifier: AGPL-3.0-or-later
"""
ATHENA H1: Graphiti Cross-Session Temporal Memory

Engagement-aware temporal knowledge graph using Graphiti.
Each engagement gets its own group_id for data isolation
within the shared Neo4j instance.
"""

import os
import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("athena.graphiti")

_graphiti = None
_enabled = False

def is_enabled() -> bool:
    return _enabled

async def init_graphiti() -> bool:
    """Initialize Graphiti with existing Neo4j instance.
    Reads NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD, ANTHROPIC_API_KEY.
    Returns True if initialized, False if skipped/failed."""
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
        llm_client = AnthropicClient(api_key=anthropic_key, model=llm_model)

        _graphiti = Graphiti(
            neo4j_uri=neo4j_uri,
            neo4j_user=neo4j_user,
            neo4j_password=neo4j_password,
            llm_client=llm_client,
        )
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
    engagement_id: str, name: str, content: str,
    source_description: str = "agent output",
    reference_time: Optional[datetime] = None,
) -> bool:
    """Feed an episode into Graphiti for knowledge extraction.
    Fire-and-forget safe — never raises."""
    if not _enabled or not _graphiti:
        return False
    if reference_time is None:
        reference_time = datetime.now(timezone.utc)
    try:
        from graphiti_core.nodes import EpisodeType
        from graphiti_ontology import ENTITY_TYPES, EDGE_TYPES, EDGE_TYPE_MAP

        await _graphiti.add_episode(
            name=name, episode_body=content,
            source=EpisodeType.text, source_description=source_description,
            reference_time=reference_time, group_id=engagement_id,
            entity_types=ENTITY_TYPES, edge_types=EDGE_TYPES,
            edge_type_map=EDGE_TYPE_MAP,
        )
        logger.debug(f"Graphiti episode ingested: {name} -> group={engagement_id}")
        return True
    except Exception as e:
        logger.error(f"Graphiti ingest_episode failed for '{name}': {e}")
        return False

async def search_memory(
    query: str, engagement_ids: Optional[list[str]] = None,
    include_global: bool = False, num_results: int = 10,
) -> list[dict]:
    """Search Graphiti knowledge graph. Returns list of fact dicts."""
    if not _enabled or not _graphiti:
        return []
    try:
        group_ids = list(engagement_ids) if engagement_ids else []
        if include_global:
            group_ids = None
        results = await _graphiti.search(
            query=query, group_ids=group_ids, num_results=num_results,
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

async def get_similar_cases(service_name: str, version: str = "", num_results: int = 5) -> list[dict]:
    """Find similar services from past engagements."""
    query = f"{service_name} {version}".strip() + " vulnerabilities exploits techniques"
    return await search_memory(query=query, include_global=True, num_results=num_results)
