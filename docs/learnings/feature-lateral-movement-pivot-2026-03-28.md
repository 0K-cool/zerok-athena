# FEATURE: Lateral Movement / Pivot Detection and Execution

**Date:** March 28, 2026
**Priority:** HIGH — Key differentiator for multi-host engagements
**Status:** FEATURE REQUEST
**Triggered by:** First multi-host engagement (eng-beb01b) — PE cracked hashes on .25 but didn't test them on .31

## What a Pivot Looks Like

1. EX/PE compromises Host A (10.1.1.25) → gets root shell
2. PE harvests credentials (shadow hashes, config files, SSH keys)
3. PE cracks hashes or extracts cleartext passwords
4. **PIVOT:** PE tries those credentials against Host B (10.1.1.31) services (SSH, RDP, SMB, MySQL)
5. If password reuse confirmed → lateral movement finding linking Host A → Host B
6. Attack graph shows: Host A → (cred reuse) → Host B

## Mode-Dependent Behavior

| Mode | Pivot Behavior |
|---|---|
| Autonomous/Full | Actively seek pivot opportunities. After cred harvest on any host, auto-test against all other in-scope hosts. |
| Supervised | Detect opportunity, request HITL approval: "Cracked creds from .25. Test against .31 SSH? [Y/N]" |
| Sprint | No pivoting — stop at first shell |
| Healthcare | No pivoting — no exploitation at all |
| CTF/Lab | Full autonomy — pivot freely |

## ST Decision Tree for Pivots

```
After PE harvests credentials from Host A:
1. Check engagement mode
2. If autonomous/CTF: auto-dispatch PE to test creds on all other hosts
3. If supervised: POST /api/approvals requesting pivot approval
4. If sprint/healthcare: skip — not applicable

Pivot dispatch message to PE:
"Test harvested credentials from <Host A> against <Host B>:
 - SSH (port 22): try <username>/<password> pairs
 - Telnet (port 23): try same
 - MySQL (port 3306): try same
 - PostgreSQL (port 5432): try same
 If any succeed: record as LATERAL MOVEMENT finding with source_host and dest_host."
```

## Neo4j Model for Lateral Movement

```cypher
// Lateral movement edge
(src:Host {ip: "10.1.1.25"})-[:LATERAL_MOVE {
    method: "credential_reuse",
    credential: "msfadmin:msfadmin",
    service: "ssh",
    port: 22,
    timestamp: datetime()
}]->(dst:Host {ip: "10.1.1.31"})

// Finding linked to both hosts
(f:Finding {title: "Password Reuse: msfadmin/msfadmin valid on 10.1.1.31 via SSH"})-[:FOUND_ON]->(src)
(f)-[:AFFECTS]->(dst)
```

## Implementation Plan

### Phase 1: ST Pivot Recognition (Prompt)
- ST checks for harvested credentials after PE completes on each host
- ST queries `/api/engagements/{eid}/hosts` for other in-scope hosts
- ST dispatches PE with pivot instructions (mode-dependent)

### Phase 2: PE Credential Reuse Testing (Prompt + Tools)
- PE receives "test creds on Host B" directive
- PE uses hydra/ncrack/medusa for automated credential testing
- PE reports findings with source_host + dest_host metadata

### Phase 3: Attack Graph Visualization
- LATERAL_MOVE edges rendered as orange lines in Attack Graph
- Pivot findings show in both source and destination host sections
- Attack chain auto-detected: Host A → cred harvest → Host B compromise

### Phase 4: Report Integration
- "Lateral Movement" section in technical report
- Cross-host attack paths in executive summary
- Remediation: "Implement unique credentials per host" recommendation

## Files to Modify

- `agent_configs.py` — _ST_PROMPT (pivot recognition), _PE_PROMPT (credential reuse testing)
- `agent_session_manager.py` — mode-dependent pivot gating
- `server.py` — LATERAL_MOVE edge creation, attack path detection
- `index.html` — Attack Graph orange lateral movement lines

## Exfiltration Simulation (Related Feature)

Real kill chain: Initial Access → Exploitation → Post-Exploitation → Lateral Movement → **Data Exfiltration** → Reporting

### Mode-Dependent Exfiltration

| Mode | Exfiltration | Scope |
|---|---|---|
| Autonomous/Full | **Simulate** — prove access, don't extract | List accessible data, screenshot, calculate volume |
| Red Team (future) | **Controlled exfil** — sample records to prove impact | Small sample, documented chain of custody |
| Supervised | **HITL approval** per data type | Operator approves each exfil attempt |
| Healthcare | **NEVER** — ePHI cannot be exfiltrated | Document access path only, no data touched |
| Sprint | No — first shell only | |
| CTF | Yes — capture the flag | |

### Implementation Considerations
- PE identifies accessible data (databases, file shares, S3 buckets)
- PE documents what COULD be exfiltrated without actually doing it
- For Red Team mode: controlled extraction with hash verification
- Finding type: "Data Exfiltration Risk" with volume estimate + access path
