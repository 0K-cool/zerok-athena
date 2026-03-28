# ARCHITECTURE DECISION: Budget Management — Track Don't Kill

**Date:** March 28, 2026
**Decision:** Kelvin approved — budget must never break an engagement
**Status:** IMPLEMENT

## The Decision

Budget management changes from **hard-kill enforcement** to **soft-warning + operator approval**. The budget system tracks costs for billing and visibility but NEVER kills an agent mid-work. The operator (pentester) decides when to stop, not a dollar cap.

## Rationale

- RP stalled 3x on technical report because $8.33 cap killed it mid-generation
- Respawn loops waste MORE money than letting the agent finish
- Per-agent hard caps designed for CTF safety, not client engagements
- A failed deliverable costs more (client trust, rework) than $10 extra in API calls
- Real pentests scale unpredictably — can't pre-set caps for unknown scope

## New Budget Model

### Per-Agent: Track + Warn (No Kill)

| Threshold | Action |
|---|---|
| 50% of estimate | Log info — on track |
| 80% of estimate | Warning to ST + operator notification |
| 100% of estimate | Alert to operator: "RP has exceeded $15 budget. Continue? [Y/auto]" |
| 150% of estimate | Strong alert: "RP at $22.50 (150% of budget). Recommend review." |
| Never | Hard kill — agent decides when it's done |

### Per-Engagement: Soft Cap

| Mode | Cap | Enforcement |
|---|---|---|
| Lab/CTF | $20 | Hard cap — test environments are expendable |
| Client (supervised) | $100 | Soft cap — warn at 80%, operator approves continuation |
| Client (autonomous) | $200 | Soft cap — warn at 80%, auto-continue up to 150%, then pause |
| Sprint | $30 | Hard cap — sprint is time-boxed by design |

### Dynamic Agent Budgets (Estimate, Not Limit)

```python
# Budget ESTIMATE scales with engagement data
base_budget = {
    "ST": 5.00, "AR": 3.00, "WV": 4.00, "DA": 3.00,
    "EX": 5.00, "VF": 3.00, "PE": 3.00, "RP": 8.00
}

# Scale RP with findings — the more findings, the more writing needed
rp_estimate = base_budget["RP"] + (finding_count * 0.15)
# 73 findings → $8 + $10.95 = $18.95 estimate
# 500 findings → $8 + $75 = $83 estimate
```

## Implementation

### Phase 1: Remove Hard Kills (Quick)
- Remove `signal_early_stop` for budget exhaustion
- Change `budget_exhausted` status to `budget_warning`
- RP keeps running past budget estimate
- Log cost tracking continues (for billing)

### Phase 2: Operator Notifications (Medium)
- At 80% budget: WebSocket notification to operator
- At 100%: Dashboard alert with continue/stop option
- At 150%: Escalation alert
- Discord notification for unattended engagements

### Phase 3: Dynamic Estimates (Medium)
- Budget estimate calculated at engagement start based on scope size
- Re-estimated after AR discovers total host/service count
- Dashboard shows "Estimated cost: $X" not "Budget remaining: $Y"

### Phase 4: Billing Integration (Later)
- Per-engagement cost tracking for client invoicing
- Cost breakdown by agent (AR: $3.20, EX: $5.40, RP: $12.00)
- Export to CSV/PDF for napoleontek/VERSANT billing

## What Does NOT Change

- **Cost tracking** — every tool call still logged with estimated cost
- **Engagement-level visibility** — dashboard still shows total cost
- **Lab/CTF hard caps** — test environments keep hard caps (prevent accidental $100 lab runs)
- **Sprint hard caps** — sprint mode is time-boxed, budget cap is a safety net

## Files to Modify

- `agent_session_manager.py` — change `signal_early_stop` from kill to warning
- `server.py` — budget endpoint changes from "exhausted" to "warning"
- `agent_configs.py` — remove `max_cost_usd` hard enforcement, keep as estimates
- `index.html` — budget display changes from "remaining" to "estimated vs actual"
