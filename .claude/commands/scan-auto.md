# Automated Modern Recon Pipeline

Execute the modern ProjectDiscovery recon pipeline against: **$ARGUMENTS**

## Pipeline Architecture

```
Phase 1: Passive Recon (zero packets to target)
├── GAU → Discover historical URLs from Wayback/CommonCrawl/OTX
└── Output: passive_urls.txt

Phase 2: Port Discovery (fast sweep)
├── Naabu → Fast SYN scan across target range
└── Output: open_ports.txt (IP:port pairs)

Phase 3: HTTP Probing (filter alive web services)
├── Httpx → Probe discovered ports for HTTP services
├── Flags: -status-code -title -tech-detect -follow-redirects
└── Output: alive_web.txt (URLs with metadata)

Phase 4: Vulnerability Scanning (targeted)
├── Nuclei → Run templates against alive URLs
├── Severity: critical,high,medium
└── Output: vulnerabilities.txt (findings with severity)

Phase 5: Summary
└── Aggregate all results into engagement-ready format
```

## Execution Instructions

### Pre-Flight

1. **Verify authorization** — this runs active scanning tools against the target
2. **Confirm scope** — validate target is in-scope per engagement RoE
3. **Select backend** — choose `kali_internal` (mini-PC, has all tools) or `kali_external` (antsle, has Nuclei/Httpx/GAU but not Naabu/Katana)
4. **Check engagement** — if an active engagement exists, log all commands to ATHENA Monitor

### Backend Selection

| Tool | kali_external | kali_internal |
|------|:---:|:---:|
| GAU | Y | Y |
| Naabu | - | Y |
| Httpx | Y | Y |
| Nuclei | Y | Y |
| Katana | - | Y |

**If using kali_external**: Skip Naabu step, use Nmap for port discovery instead. Skip Katana.
**If using kali_internal**: Full pipeline available.

### Phase 1: Passive URL Discovery (GAU)

**Zero packets to target. Safe to run before authorization confirmation.**

```
Tool: gau_discover
Target: [domain from $ARGUMENTS]
```

Parse the GAU output to extract:
- Unique URLs and paths
- API endpoints (contains `/api/`, `/v1/`, `/graphql`)
- Interesting file extensions (.sql, .bak, .env, .config, .json)
- Admin/management paths (/admin, /dashboard, /manage, /wp-admin)

**Save results** to engagement evidence folder if active engagement exists.

### Phase 2: Port Discovery (Naabu)

**Active scanning — requires authorization.**

```
Tool: naabu_scan (kali_internal only) OR nmap_scan (fallback)
Target: [IP/CIDR/domain from $ARGUMENTS]
Rate: 1000 (default, adjust per RoE)
Additional args: -top-ports 1000
```

**If Naabu unavailable (kali_external)**, use Nmap fallback:
```
Tool: nmap_scan
Target: [from $ARGUMENTS]
Scan type: -sn (host discovery first)
Then: -sV --top-ports 1000 -T4 -Pn --open
```

**Output**: List of IP:port pairs with open ports.

### Phase 3: HTTP Probing (Httpx)

Feed discovered ports into Httpx to identify alive web services.

```
Tool: httpx_probe
Target: [each IP:port pair from Phase 2]
Additional args: -status-code -title -tech-detect -content-length -follow-redirects
```

**Parse output to identify:**
- Web servers and their technologies
- Status codes (focus on 200, 301, 302, 401, 403)
- Page titles (identify default pages, login portals, APIs)
- Tech stack (React, Angular, WordPress, etc.)

**Decision logic:**
- WordPress detected → flag for WPScan
- SPA detected (React/Angular/Vue) → flag for Playwright deep-dive
- API detected → flag for Kiterunner
- Default page/login portal → flag for credential testing

### Phase 4: Vulnerability Scanning (Nuclei)

Run Nuclei templates against all alive web URLs.

```
Tool: nuclei_scan
Target: [alive URLs from Phase 3, one at a time or via file]
Severity: critical,high,medium
Additional args: -rl 50 -bulk-size 25 -c 25
```

**Rate limiting**: `-rl 50` (50 requests/sec) is moderate. Adjust per RoE:
- Conservative: `-rl 10`
- Moderate: `-rl 50`
- Aggressive: `-rl 150` (only if RoE allows)

**Parse findings:**
- Group by severity (Critical → High → Medium)
- Extract CVE references
- Note template IDs for reproducibility
- Flag any findings requiring manual validation

### Phase 5: Results Summary

Present a consolidated summary:

```markdown
## Scan-Auto Results: [TARGET]
**Date**: [timestamp]
**Backend**: kali_internal / kali_external
**Duration**: [total time]

### Passive Recon (GAU)
- Total URLs discovered: [count]
- Unique paths: [count]
- API endpoints found: [count]
- Interesting files: [list]

### Port Discovery
- Live hosts: [count]
- Open ports: [count]
- Top services: [list with counts]

### HTTP Services
- Alive web services: [count]
- Technologies detected: [list]
- Login portals: [list]
- APIs: [list]

### Vulnerabilities (Nuclei)
- Critical: [count]
- High: [count]
- Medium: [count]

### Critical/High Findings
[List each with CVE, target, template ID]

### Recommended Next Steps
- [ ] Manual validation of critical findings (/validate)
- [ ] WPScan on WordPress targets (if any)
- [ ] Kiterunner API discovery (if APIs detected)
- [ ] Playwright deep-dive on SPAs (if detected)
- [ ] Credential testing on login portals (/validate)
```

### Integration with ATHENA Monitor

If an active engagement exists, log all commands:
```python
# Log each phase to ATHENA Monitor database
db.record_command(
    engagement=engagement_name,
    phase="Automated Recon Pipeline",
    command=f"scan-auto {target}",
    tool="scan-auto-pipeline",
    target=target,
    output=summary,
    duration=total_duration
)
```

### Error Handling

- **Tool timeout**: Nuclei can be slow on large targets. If timeout occurs, report partial results.
- **Tool not available**: If a tool is missing on the selected backend, skip that phase and note it.
- **Rate limiting triggered**: If target returns 429s, reduce rate and retry.
- **No results**: If a phase returns zero results, note it and continue to next phase.

### Safety Notes

- **GAU is passive** — safe to run without explicit authorization (no packets to target)
- **Naabu/Httpx/Nuclei are active** — require written authorization
- **Nuclei DAST fuzzing** (XSS, SQLi) is disabled by default — use `-tags dast` to enable if RoE allows
- **All commands logged** — complete audit trail for client reporting
- **Non-destructive** — no exploitation, just detection and enumeration
