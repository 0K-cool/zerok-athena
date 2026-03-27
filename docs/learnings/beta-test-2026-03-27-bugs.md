# Beta Test Bugs — March 27, 2026

**Engagement:** 0din Server #5 (eng-*), Target: 10.1.1.25/32
**Mode:** Autonomous
**Session:** Post-Sprint Mode + dedup fixes

## Bugs Found

### BUG-VF-001: Confirmed Exploit Rate stays 0% despite VF confirmation
**Severity:** HIGH
**Status:** Not fixed
**Details:** VF confirmed CVE-2011-2523 (vsftpd backdoor, root shell, confidence 0.99) but Confirmed Exploit Rate gauge shows 0%. The "0 confirmed + 0 unverified / 5" text confirms no exploits are counted.
**Root cause:** The PATCH endpoint sets `verified=true` in memory and Neo4j but `exploit-stats` may not be reading it correctly, or VF's PATCH didn't reach the endpoint (msg_type validation may have blocked it first).

### BUG-VF-002: Unknown msg_type "debrief" and "verification"
**Severity:** MEDIUM
**Status:** Not fixed
**Details:** VF sends `msg_type: "debrief"` and `msg_type: "verification"` via /api/messages but these are not in AGENT_COMM_RULES. Messages rejected with 400 error.
**Fix:** Add "debrief" and "verification" to AGENT_COMM_RULES.

### BUG-VF-003: Artifacts API schema mismatch
**Severity:** MEDIUM
**Status:** Not fixed (pre-existing)
**Details:** VF tries to upload screenshot evidence but artifacts API expects `file` field, not `content`. VF has the base64 screenshot but can't upload it.
**Fix:** Either update artifacts API to accept `content` field, or update VF prompt to use correct field name.

### BUG-EX-001: EX not calling /first-shell endpoint
**Severity:** HIGH
**Status:** Not fixed
**Details:** TTFS and MTTE show "—" because EX didn't call POST /api/engagements/{eid}/first-shell after exploiting. VF confirmed the shell but the first-shell endpoint was never called.
**Root cause:** EX may not have the {eid} substitution working, or EX used a different method to report the exploit.

### NOT REGRESSIONS
None of these bugs were caused by today's changes. They are:
- Pre-existing issues (artifacts API, msg_types)
- Agent behavior variations (EX not calling first-shell)
- New agent behaviors not yet accounted for (VF using "debrief" msg_type)
