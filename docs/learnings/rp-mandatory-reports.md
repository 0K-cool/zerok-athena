# RP Mandatory Report Types

**Created:** 2026-03-20
**Status:** Pending implementation
**Priority:** MEDIUM

## Problem

RP doesn't always generate a Remediation Roadmap report. First engagement run produced only 2 reports (Executive Summary + Technical Report). Re-engagement produced 3.

## Required Reports

RP should ALWAYS generate these reports when findings exist:

| Report | Condition | Audience |
|--------|-----------|----------|
| **Executive Summary** | Always (if findings > 0) | Leadership, non-technical stakeholders |
| **Technical Report** | Always (if findings > 0) | Security team, engineers |
| **Remediation Roadmap** | When confirmed exploits exist | IT/dev team — prioritized fixes with effort estimates |

## Fix

Update `_RP_PROMPT` in `agent_configs.py` to make Remediation Roadmap mandatory when `confirmed_exploits > 0`. The roadmap should include:

- Prioritized remediation actions (Critical → High → Medium → Low)
- Effort estimates per fix
- Dependencies between fixes
- Quick wins vs long-term improvements
- Timeline recommendations (Today / This Week / This Month / This Quarter)

## Context

- First run (Gym website): 2 reports (no roadmap)
- Re-engagement (Gym website): 3 reports (roadmap appeared — likely because PE ran and more exploits confirmed)
- Roadmap should not depend on PE running — confirmed exploits alone should trigger it
