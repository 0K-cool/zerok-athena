#!/usr/bin/env python3
"""Seed ATHENA Neo4j with demo engagements and findings.

Idempotent — uses MERGE so re-running is safe.

Usage:
    cd tools/athena-dashboard
    source .venv/bin/activate
    python seed-data.py                                          # Antsle (default)
    NEO4J_URI=bolt://your-internal-kali:7687 python seed-data.py       # Mini-PC
"""

import os
import time

from neo4j import GraphDatabase

NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://your-kali-host:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASS = os.environ.get("NEO4J_PASS", "$NEO4J_PASS")

ENGAGEMENTS = [
    {
        "id": "eng-001", "name": "Acme Corp External",
        "client": "Acme Corp", "scope": "*.acme.com",
        "type": "external", "status": "active",
        "start_date": "2026-02-10", "methodology": "PTES",
    },
    {
        "id": "eng-002", "name": "GlobalBank API",
        "client": "GlobalBank", "scope": "api.globalbank.test",
        "type": "api", "status": "active",
        "start_date": "2026-02-14", "methodology": "PTES",
    },
    {
        "id": "eng-003", "name": "HealthCo Web App",
        "client": "HealthCo", "scope": "portal.healthco.test",
        "type": "webapp", "status": "active",
        "start_date": "2026-02-16", "methodology": "PTES",
    },
]

now = time.time()

FINDINGS = [
    {
        "id": "f-001", "title": "SQL Injection \u2014 admin login bypass",
        "severity": "critical", "category": "Injection",
        "target": "acme.com/admin/login", "agent": "WV",
        "description": "Blind SQL injection in login form allows authentication bypass via UNION-based payload.",
        "cvss": 9.8, "cve": "CVE-2024-1234", "evidence": "sqlmap output",
        "timestamp": now - 3600, "engagement_id": "eng-001",
    },
    {
        "id": "f-002", "title": "RCE via unrestricted file upload",
        "severity": "critical", "category": "File Upload",
        "target": "acme.com/upload", "agent": "EC",
        "description": "Unrestricted file upload endpoint allows uploading PHP web shells, leading to remote code execution.",
        "cvss": 9.6, "cve": None, "evidence": "reverse shell session",
        "timestamp": now - 3200, "engagement_id": "eng-001",
    },
    {
        "id": "f-003", "title": "Stored XSS in comment field",
        "severity": "high", "category": "XSS",
        "target": "acme.com/blog/comments", "agent": "WV",
        "description": "Stored cross-site scripting via unescaped user input in blog comment field.",
        "cvss": 7.5, "cve": None, "evidence": "alert(1) screenshot",
        "timestamp": now - 2800, "engagement_id": "eng-001",
    },
    {
        "id": "f-004", "title": "Missing CSRF tokens on forms",
        "severity": "medium", "category": "CSRF",
        "target": "api.globalbank.test/settings", "agent": "WV",
        "description": "Settings forms lack CSRF protection, enabling cross-site request forgery attacks.",
        "cvss": 5.4, "cve": None, "evidence": "Burp request diff",
        "timestamp": now - 2400, "engagement_id": "eng-002",
    },
    {
        "id": "f-005", "title": "Server version disclosed in headers",
        "severity": "low", "category": "Information Disclosure",
        "target": "api.globalbank.test", "agent": "AR",
        "description": "Server response headers disclose Apache/2.4.52 and PHP/8.1.12 versions.",
        "cvss": 3.1, "cve": None, "evidence": "HTTP headers",
        "timestamp": now - 2000, "engagement_id": "eng-002",
    },
    {
        "id": "f-006", "title": "IDOR \u2014 direct object reference on /api/users/{id}",
        "severity": "high", "category": "Access Control",
        "target": "api.globalbank.test/api/users/", "agent": "WV",
        "description": "Insecure direct object reference allows any authenticated user to access other users' data by iterating IDs.",
        "cvss": 7.1, "cve": None, "evidence": "API response diff",
        "timestamp": now - 1600, "engagement_id": "eng-002",
    },
    {
        "id": "f-007", "title": "Weak password policy allows common passwords",
        "severity": "medium", "category": "Authentication",
        "target": "portal.healthco.test/register", "agent": "AR",
        "description": "Password policy accepts passwords like 'Password1!' that appear in common password lists.",
        "cvss": 5.0, "cve": None, "evidence": "registration test",
        "timestamp": now - 1200, "engagement_id": "eng-003",
    },
    {
        "id": "f-008", "title": "Missing security headers (X-Frame-Options, CSP)",
        "severity": "low", "category": "Configuration",
        "target": "portal.healthco.test", "agent": "AR",
        "description": "Response missing X-Frame-Options, Content-Security-Policy, and X-Content-Type-Options headers.",
        "cvss": 3.0, "cve": None, "evidence": "Header analysis",
        "timestamp": now - 800, "engagement_id": "eng-003",
    },
]


def seed(driver):
    with driver.session() as session:
        # Seed engagements
        for eng in ENGAGEMENTS:
            session.run("""
                MERGE (e:Engagement {id: $id})
                SET e.name = $name, e.client = $client, e.scope = $scope,
                    e.type = $type, e.status = $status,
                    e.start_date = $start_date, e.methodology = $methodology
            """, **eng)
            print(f"  Engagement: {eng['id']} ({eng['name']})")

        # Seed findings with relationships
        for f in FINDINGS:
            session.run("""
                MERGE (f:Finding {id: $id})
                SET f.title = $title, f.severity = $severity,
                    f.category = $category, f.target = $target,
                    f.agent = $agent, f.description = $description,
                    f.cvss = $cvss, f.cve = $cve, f.evidence = $evidence,
                    f.timestamp = $timestamp, f.engagement_id = $engagement_id,
                    f.status = 'open'
                WITH f
                MATCH (e:Engagement {id: $engagement_id})
                MERGE (f)-[:BELONGS_TO]->(e)
            """, **f)
            print(f"  Finding:    {f['id']} ({f['severity']}: {f['title'][:50]})")


def main():
    print(f"\nATHENA Seed Data Migration")
    print(f"{'=' * 40}")
    print(f"  Target: {NEO4J_URI}")
    print()

    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
    driver.verify_connectivity()
    print(f"  Connected to Neo4j")
    print()

    seed(driver)

    # Verify
    with driver.session() as session:
        eng_count = session.run("MATCH (e:Engagement) RETURN count(e) AS c").single()["c"]
        find_count = session.run("MATCH (f:Finding) RETURN count(f) AS c").single()["c"]
        rel_count = session.run("MATCH ()-[r:BELONGS_TO]->() RETURN count(r) AS c").single()["c"]

    print()
    print(f"  Verification:")
    print(f"    Engagements: {eng_count}")
    print(f"    Findings:    {find_count}")
    print(f"    Relations:   {rel_count}")
    print()
    print("  Done!")

    driver.close()


if __name__ == "__main__":
    main()
