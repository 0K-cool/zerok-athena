# Evidence Collection Findings — March 24, 2026 (eng-088403 Live Test)

**Engagement:** 0din Server #3 (eng-088403), Target: 10.1.1.25/32
**Status:** Active during testing

---

## What's Working

- **21 artifacts captured** — evidence IS being collected across multiple agents
- **95% have content** (20/21) — FIX-4 empty content guard working
- **100% descriptive titles** — FIX-EV-005 _generate_evidence_title working
  - "Root shell obtained", "Exploitation — CVE-2004-2687", "Verification — VSFTPD"
- **81% evidence_type tagged** (17/21) — exploitation:8, verification:8, post_exploitation:1
- **Multiple agents contributing** — VF:13, PE:4, EX:2, AR:2

## Remaining Issues (Fix Later)

### ISSUE-1: AR auto-captures have no evidence_type [LOW]
- AR's `nmap_scan` auto-captured artifacts have `evidence_type: None`
- Fix: In the auto-capture path in server.py, default `evidence_type = "reconnaissance"` for AR agent outputs

### ISSUE-2: Screenshots underutilized [MEDIUM]
- Only 1 screenshot in 21 artifacts
- Kali Playwright endpoint confirmed available (POST /api/tools/screenshot returns 405 on GET = route exists)
- VF prefers CLI verification (nmap, ncat, smbclient) over browser-based
- VF manually created evidence file via `curl` multipart upload instead of using screenshot endpoint
- **Fix:** Add explicit screenshot instructions to VF and EX prompts in agent_configs.py:
  ```
  SCREENSHOT EVIDENCE: For web-facing services (HTTP, HTTPS), capture visual proof:
    POST {kali_url}/api/tools/screenshot
    Body: {"url": "http://<target>:<port>", "engagement_id": "{eid}"}
    Take screenshots of: login pages, admin panels, vulnerable pages, exploit output
  ```

### ISSUE-3: PE evidence tagging inconsistent [LOW]
- PE's `/etc/shadow` dump tagged as "exploitation" instead of "post_exploitation"
- Some PE artifacts tagged correctly (post_exploitation:1), others inherit wrong type
- Fix: In sdk_agent.py `_is_post_exploitation_result`, the detection fires correctly but the `evidence_type` parameter at the call site may default to "exploitation" instead of checking agent code

### ISSUE-4: Finding-artifact linkage [MEDIUM]
- Most artifacts link to `find-fbf9e5ba` (a single finding) — stale `_last_finding_id` issue from FIX-EV-002
- VF's manual upload correctly linked to `bus-621585900a688537`
- Fix: SDK evidence capture should match artifacts to findings by CVE/service correlation, not just `_last_finding_id`

### ISSUE-5: Old engagements have generic titles [LOW]
- eng-aadee9 and eng-6d06ef artifacts still show "Exploitation evidence — mcp_kali_external__execute_command"
- These were captured before FIX-EV-005 was deployed
- No action needed — only affects historical data, new engagements generate descriptive titles

## Kali Screenshot Endpoint

Confirmed available at both backends:
- External: `POST http://your-kali-host:5000/api/tools/screenshot`
- Internal: `POST http://your-internal-kali:5000/api/tools/screenshot` (if online)
- Blueprint: `kali-screenshot-endpoints.py` (Flask, Playwright chromium)
- Endpoints: `/api/tools/screenshot` (web page) + `/api/tools/screenshot_terminal` (styled terminal output)

## Summary

Evidence collection pipeline is functional post-fixes. Main gaps are prompt engineering (screenshots, PE tagging) and finding-artifact correlation. Not code bugs — agent behavior improvements.

---

**Priority for next session:**
1. ISSUE-2: Screenshot prompt instructions (MEDIUM — biggest visual impact for reports)
2. ISSUE-4: Finding-artifact correlation (MEDIUM — affects report quality)
3. ISSUE-1: AR evidence_type default (LOW — quick fix)
4. ISSUE-3: PE tagging (LOW — edge case)
