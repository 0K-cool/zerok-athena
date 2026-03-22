# Service/Port Dedup — Double Count (62 vs 31)

**Created:** 2026-03-22
**Status:** Pending fix
**Priority:** MEDIUM — inflates Open Ports KPI

## Problem

Open Ports KPI shows 62 when the target has 31 open ports. AR runs naabu (fast port scan) then nmap (service enumeration) — each creates separate service records in Neo4j for the same ports. The KPI counts all service records without dedup.

## Fix

Same approach as finding dedup — MERGE on `(host_ip, port, protocol)` instead of CREATE. When nmap adds service details to a port already discovered by naabu, it should update the existing record, not create a duplicate.

Check Neo4j Service node creation in server.py — likely uses CREATE or MERGE on unique ID instead of MERGE on `{host, port}`.
