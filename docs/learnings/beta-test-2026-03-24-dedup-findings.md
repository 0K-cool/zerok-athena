# Exploit Count Dedup — Confirmed Exploits Need CVE-Level Dedup

**Date:** March 24, 2026
**Engagement:** eng-088403 (0din Server #3)
**Priority:** HIGH — affects client-facing exploit count

---

## Problem

35 "confirmed exploits" reported but only ~10 unique CVEs. Multiple agents (ST, VF, DA, EX, RP) post findings for the same CVE with different titles, each counting separately in `confirmed_exploits`.

Example: CVE-2004-2687 has 16 findings across 6 agents.

## Current State (BUG-S2-004 partial fix applied)

The exploit-stats endpoint already:
- ✅ Filters out summary/port-discovery titles from `discovered` count
- ✅ Scopes `exploited_unverified` to EX-agent only

But `confirmed_exploits` still counts each Finding node separately — no CVE dedup.

## What Kelvin Wants

**Unique confirmed exploits** — deduped by CVE+host. If CVE-2004-2687 has 16 findings from 6 agents on the same host, it counts as **1 confirmed exploit**, not 16.

## Fix Location

`server.py` — `get_exploit_stats` endpoint

### Neo4j path (primary)
In the Cypher query that counts `confirmed_exploits`:
- Extract CVE from `f.cve` or regex from `f.title`
- Group by CVE + host (or CVE + target)
- Count distinct groups, not individual findings

### In-memory path (fallback)
Same dedup logic in Python after collecting `mem_findings`:

```python
# After counting confirmed findings, dedup by CVE+host
seen_cve_keys = set()
unique_confirmed = 0
for f in confirmed_findings:
    cve = getattr(f, 'cve', '') or ''
    if not cve:
        # Try extracting from title
        import re
        m = re.search(r'CVE-\d{4}-\d+', f.title or '', re.IGNORECASE)
        cve = m.group(0) if m else ''
    host = getattr(f, 'target', '') or getattr(f, 'host_ip', '') or ''
    key = f"{cve}|{host}" if cve else f.fingerprint or f.title[:40]
    if key not in seen_cve_keys:
        seen_cve_keys.add(key)
        unique_confirmed += 1
confirmed = unique_confirmed
```

### Dashboard display
The KPI and gauge should show the deduped count. The per-finding breakdown in the exploit-stats response can still list all findings for drill-down — just the headline count should be unique.

## Impact

| Metric | Current (inflated) | After dedup (estimated) |
|--------|-------------------|------------------------|
| confirmed_exploits | 35 | ~10-12 |
| success_rate | 33.3% | ~10-11% |
| exploited_unverified | 5 | ~3-4 |

The deduped numbers are more honest and client-presentable. 35 "confirmed exploits" on Metasploitable sounds wrong — 10 unique CVEs exploited is accurate and still impressive for 29 minutes.

## Also Affects

- Exploit Rate gauge (denominator is `discovered` which may also have CVE dupes)
- Reports: RP generates report with exploit count — should use deduped value
- Speed optimization: TTFS is fine (first exploit), but "total exploits" in speed report should be unique

## eng-088403 Actual Unique CVEs (10)

1. CVE-2011-2523 — vsftpd 2.3.4 backdoor (root shell)
2. CVE-2004-2687 — distccd RCE (daemon user)
3. CVE-2020-1938 — Tomcat AJP Ghostcat
4. CVE-2010-2075 — UnrealIRCd backdoor
5. CVE-2007-2447 — Samba username map script
6. CVE-2012-1823 — PHP-CGI argument injection
7. CVE-2016-5195 — Dirty COW privilege escalation
8. CVE-2009-2692 — Linux kernel sendpage
9-10. Additional CVEs (check full findings list)

---

**Fix session:** Next ATHENA bug fix pass
**Estimated effort:** MEDIUM — Python post-processing dedup, no Cypher changes needed
