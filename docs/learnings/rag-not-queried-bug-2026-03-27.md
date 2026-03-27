# BUG: Agents Not Querying RAG Knowledge Base During Engagements

**Date:** March 27, 2026
**Severity:** MEDIUM — Performance/intelligence gap
**Status:** DOCUMENTED — Not yet fixed

## Problem

During autonomous engagement (0din Server #5, eng-eb2adc), 121 scans were executed using only Kali tools (nmap, nuclei, sqlmap, httpx, etc.). Zero RAG/Knowledge queries were made despite:
- 16 playbooks available in the knowledge base
- RAG system fully operational (mcp-proxy on :8765, verified working)
- `search_kb` MCP tool available to all agents
- `rag_queries` field populated in agent configs with initial context

## Impact

- Agents "reinvent the wheel" instead of leveraging known attack paths
- Slower exploitation — no fast-path lookup for known vulnerabilities
- Past engagement learnings (CEI data) not utilized
- Playbooks with proven exploitation chains ignored
- Higher token/cost usage as agents reason from scratch

## Root Cause

Agent prompts don't actively instruct agents to query RAG during execution. The `rag_queries` config field provides initial context at spawn but doesn't tell agents to proactively search during the engagement.

## Proposed Fix

1. **EX prompt:** "Before attempting any exploit, query the knowledge base: `search_kb('<service> <version> exploit')`. Use known attack paths before trying from scratch."
2. **DA prompt:** "When researching CVEs, check the knowledge base first for existing analysis and PoC details."
3. **VF prompt:** "Query the knowledge base for verification techniques before running tools."
4. **ST prompt:** "Instruct agents to check the knowledge base for relevant playbooks at the start of each phase."
5. **Speed impact:** RAG queries add ~2-3s per call but save 30-60s of agent reasoning time.

## Expected Behavior

Each agent should make 2-5 RAG queries per engagement:
- AR: "nmap scan techniques for <target type>"
- DA: "CVE-XXXX-XXXX exploit details"
- EX: "<service> <version> exploitation playbook"
- VF: "<service> verification methodology"

## Files to Modify

- `agent_configs.py` — Add RAG query instructions to _EX_PROMPT, _DA_PROMPT, _VF_PROMPT, _AR_PROMPT
- Potentially `finding_pipeline.py` — Auto-suggest RAG queries when new services are discovered
