#!/usr/bin/env python3
"""Seed ATHENA Neo4j with engagements for Phase D dry run.

Idempotent — uses MERGE so re-running is safe.
Seeds the DryRun-MS2 engagement for Metasploitable2 at 10.1.1.25.
No pre-seeded findings — real findings are created by the orchestrator.

Usage:
    cd tools/athena-dashboard
    source .venv/bin/activate
    python seed-data.py                                          # Antsle (default)
    NEO4J_URI=bolt://172.26.80.76:7687 python seed-data.py       # Mini-PC
"""

import os

from neo4j import GraphDatabase

NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://kali.linux.vkloud.antsle.us:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASS = os.environ.get("NEO4J_PASS", "athena2026")

ENGAGEMENTS = [
    {
        "id": "dryrun-ms2", "name": "DryRun — Metasploitable2",
        "client": "Internal Lab", "scope": "10.1.1.25",
        "type": "external", "status": "active",
        "start_date": "2026-02-23", "methodology": "PTES",
    },
]

# No pre-seeded findings — Phase D dry run creates real findings from tools.
FINDINGS = []


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
