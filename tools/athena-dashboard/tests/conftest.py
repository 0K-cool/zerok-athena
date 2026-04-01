"""API test fixtures for ATHENA dashboard server.

Provides an async test client that runs the FastAPI app in-process
(no real server needed). Uses httpx.AsyncClient with ASGITransport.
"""
import pytest
import pytest_asyncio
import sys
import os

# Add dashboard directory to path so we can import server
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


@pytest_asyncio.fixture
async def client():
    """Async HTTP client for testing the FastAPI app in-process."""
    from httpx import AsyncClient, ASGITransport
    from server import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.fixture
def sample_engagement_id():
    """A known engagement ID for testing."""
    return "eng-test-001"


@pytest.fixture
def sample_finding():
    """A sample finding payload for POST /api/findings."""
    return {
        "title": "SQL Injection in login form",
        "severity": "high",
        "category": "injection",
        "target": "10.1.1.25:3306",
        "agent": "WV",
        "description": "Blind SQLi via username parameter",
        "cvss": 8.1,
        "cve": "CVE-2026-0001",
        "engagement": "eng-test-001",
        "host_ip": "10.1.1.25",
        "service_port": 3306,
    }


@pytest.fixture
def sample_finding_2():
    """A second finding on a different host."""
    return {
        "title": "Default SSH credentials",
        "severity": "critical",
        "category": "authentication",
        "target": "10.1.1.31:22",
        "agent": "EX",
        "description": "SSH login with root:toor",
        "cvss": 9.8,
        "engagement": "eng-test-001",
        "host_ip": "10.1.1.31",
        "service_port": 22,
    }
