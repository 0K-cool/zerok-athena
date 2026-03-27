# BUG: Orphaned Credentials — No Host/Service Linkage

**Date:** March 27, 2026
**Severity:** MEDIUM — Data quality in credential tracking
**Status:** DOCUMENTED — Not yet fixed

## Problem

5 out of 39 credentials are orphaned — no host, no agent attribution, no service. They have usernames (msfadmin, tomcat, postgres, root, vnc) but no passwords, no host_ip, no service association.

## Root Cause

DA discovers default credentials in its CVE research and posts them as text in finding titles ("PostgreSQL default creds postgres:postgres") but doesn't use the `msg_type: "credential"` format that properly creates Credential nodes with HARVESTED_FROM edges to Host/Service nodes.

The credential extraction from DA's findings is either:
1. Not parsing the username:password from the title text
2. Not linking to the target host when extracted
3. Creating partial Credential nodes from bus messages without full context

## Impact

- Credential Tracker shows inflated count (39 total but 5 are noise)
- Orphaned credentials can't be used for attack chain analysis (no HARVESTED_FROM edge)
- Reports may include phantom credentials

## Proposed Fix

1. **DA prompt:** When reporting default credentials, use structured format: `{"msg_type": "credential", "username": "...", "password": "...", "host_ip": "...", "service": "...", "port": ...}`
2. **Credential extraction:** Parse `username:password` pairs from finding titles and auto-link to host
3. **Validation:** Reject credential nodes without host_ip (require at minimum host + username)
