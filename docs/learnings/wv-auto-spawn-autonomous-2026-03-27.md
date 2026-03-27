# IMPROVEMENT: WV Auto-Spawn in Autonomous/Sprint Mode

**Date:** March 27, 2026
**Severity:** LOW — Behavioral enhancement, not a bug
**Status:** DOCUMENTED — Next session

## Current Behavior (Correct)

ST spawns agents based on engagement type:
- **External (network):** AR + DA + EX — no WV
- **Web app:** WV + DA + EX — no AR
- **Full scope:** AR + WV + DA + EX

This is correct for supervised mode — operator chose the type, ST respects it.

## Enhancement

In **autonomous/sprint mode**, ST should have tactical authority to spawn WV when AR discovers HTTP services on a non-web engagement. Rationale: autonomous mode prioritizes maximum coverage with minimum human intervention.

### Rules

| Mode | Engagement Type | AR Finds HTTP | Spawn WV? |
|------|----------------|---------------|-----------|
| Supervised | External | Yes | **No** — stick to SoW |
| Supervised | Web App | n/a | **Yes** — selected by operator |
| Supervised | Full | n/a | **Yes** — selected by operator |
| Autonomous/Sprint | External | Yes | **Yes** — tactical decision |
| Autonomous/Sprint | Web App | n/a | **Yes** |
| Autonomous/Sprint | Full | n/a | **Yes** |

### Real-World Analogy

- **Supervised = client engagement:** Follow the Statement of Work. External means external.
- **Autonomous = lab/CTF:** Go after everything you find. HTTP port = web target.

## Fix

Add ~5 lines to ST prompt in the AGENT DISPATCH section:

```
AUTONOMOUS MODE EXCEPTION: In autonomous/sprint mode, if AR discovers HTTP/HTTPS 
services (ports 80, 443, 8080, 8180, or "http" in service name) on a non-web 
engagement, you MAY spawn WV to perform web vulnerability scanning. In supervised 
mode, only spawn WV if the engagement type includes web app testing.
```

## Files to Modify

- `agent_configs.py` — _ST_PROMPT, near the agent dispatch rules (lines ~437-441)

## Note

Current behavior is NOT a bug. AR doing light web probes (nuclei, httpx) as part 
of recon is normal — AR discovers surface, WV deep-dives OWASP Top 10. The 
enhancement just gives ST permission to escalate in auto mode.
