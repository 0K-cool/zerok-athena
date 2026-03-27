# BUG: Finding Dedup V2 — Cross-Path Duplicates + Multi-CVE Splitting

**Date:** March 27, 2026
**Severity:** HIGH — Data quality, report accuracy
**Status:** DOCUMENTED — Next session
**Predecessor:** BUG #1 (bus fingerprint dedup) — partially fixed

## Problem

Dedup V1 (fingerprint MERGE on bus path) reduced findings from ~120 to ~63 on Metasploitable 2, but duplicates persist from three sources:

### Source 1: Multi-CVE Batch Findings
Agents dump multiple CVEs in one finding title:
- "CVE(s) detected: CVE-2011-2523, CVE-2010-2075, CVE-2007-2447, CVE-2012-2122"
- Fingerprint extracts FIRST CVE only → one finding covers 4+ vulns
- Meanwhile, individual CVE findings exist: "CVE-2011-2523: vsftpd 2.3.4 Backdoor"
- These don't merge because titles differ (Tier 5 fallback)

### Source 2: Cross-Path Dedup
Three finding creation paths exist independently:
- `bus-*` IDs → `_bus_to_neo4j()` in agent_session_manager.py → MERGE on {fingerprint, engagement_id}
- `find-*` IDs → `POST /api/findings` in server.py → MERGE on {fingerprint, engagement_id}  
- 8-char hex IDs → EX direct creation → unknown path

Each path MERGEs within itself but creates separate nodes from the others even for the same CVE, because the finding IDs differ.

### Source 3: Missing Target Field
Most bus findings have `target: null`. Without a target, fingerprinting can't extract `host_ip`, falling through to Tier 3 (CVE only) or Tier 5 (title). This reduces dedup accuracy.

## Evidence (eng-eb2adc, March 27, 2026)

CVE-2011-2523 (vsftpd): 4 separate findings
- bus-927ab7840de05fc9: "CVE(s) detected: CVE-2011-2523, CVE-2010-2075..." (batch)
- bus-a9a10c9ab9957b1d: "CVE(s) detected: CVE-2011-2523" (single)
- bus-e9f216c7c4ea4488: "ROOT shell via vsftpd 2.3.4 backdoor CVE-2011-2523" (EX result)
- find-e9725d0c: "CVE-2011-2523: vsftpd 2.3.4 Backdoor — Root Shell" (AR via /api/findings)

CVE-2010-2075 (UnrealIRCd): 5 separate findings
CVE-2007-2447 (Samba): 4 separate findings
CVE-2004-2687 (distccd): 4 separate findings

## Proposed Fix (V2)

### Fix A: Split multi-CVE findings at ingestion
In `finding_pipeline.py` or `_bus_to_neo4j()`:
- Detect titles with multiple CVE-YYYY-NNNN patterns
- Split into individual findings, one per CVE
- Each gets its own fingerprint → proper Tier 1/2/3 dedup

### Fix B: Unified finding creation path
Route ALL findings through a single `create_or_merge_finding()` function:
- `POST /api/findings` calls it
- `_bus_to_neo4j()` calls it
- EX direct creation calls it
- Single MERGE key, single dedup logic

### Fix C: Enforce target field on bus findings
In `POST /api/bus/publish`:
- If no `target` in message, extract from engagement scope
- Use engagement's primary target as default
- Populates host_ip for Tier 1/2 fingerprinting

### Recommended: Fix B + C (unified path + target enforcement)
Fix A is a patch. Fix B is the architectural solution. Fix C improves fingerprint quality.

## Impact
- VF receives duplicates, confirms the same vuln multiple times
- Confirmed Exploit Rate is understated (dedup in exploit-stats catches some but not all)
- Reports would overstate finding count if not manually corrected
- Finding count: ~63 displayed vs ~35-40 truly unique vulnerabilities
