# 0K ATHENA — Product Roadmap

**Product:** 0K ATHENA (AI-Autonomous Penetration Testing Platform)
**Company:** ZeroK Labs
**Created:** February 26, 2026
**Status:** Phase 1 (Consultant) — Active Development

---

## Vision

ATHENA is AI-driven adversary simulation that maps real attack paths, not just vulnerabilities. It runs full PTES methodology using Claude Agent SDK with real Kali Linux tool execution, produces compliance-mapped reports, and tracks everything in a Neo4j attack graph.

**Tagline:** "AI-driven adversary simulation that maps real attack paths, not just vulnerabilities."

---

## Current State (February 2026)

### What Works Today
- Full dashboard (FastAPI + WebSocket + single-page HTML, dual themes)
- Claude Agent SDK integration with 5 specialized agents by PTES phase
- 21-tool registry (extensible via JSON config, hot-reloadable)
- Dual Kali backends (external Antsle cloud + internal mini-PC via ZeroTier)
- Neo4j attack graph with force-directed kill chain visualization
- HITL approval workflow for destructive operations (sqlmap, metasploit, hydra, etc.)
- Config-driven compliance frameworks (22 frameworks across 7 industry categories)
- Real engagement validated: 18 findings, 409 events, 203 tool calls, full report generation
- Evidence capture (screenshots, command output, HTTP pairs linked to findings)
- SoW/RoE upload with regex-based scope extraction

### Completed Phases
| Phase | Description | Date | Commit |
|-------|-------------|------|--------|
| A | UI/UX — 23 features, dual themes, all views | Feb 21, 2026 | `3d86ab0` |
| B | Neo4j wiring, dual-backend, seed data | Feb 23, 2026 | `9309041` |
| C | Agent integration, 21-tool registry | Feb 23, 2026 | `d7d8a8d` |
| E | Real Claude Code Agent Teams | Feb 24, 2026 | `3ca289b` |
| F | Claude Agent SDK replaces subprocess | Feb 25, 2026 | `b13a0dd` |

### Key Files
- Dashboard: `tools/athena-dashboard/` (server.py, index.html)
- Agent SDK: `tools/athena-dashboard/sdk_agent.py`
- Tool registry: `tools/athena-dashboard/tool-registry.json`
- Compliance config: `tools/athena-dashboard/config/frameworks.yml`
- Agent definitions: `.claude/agents/athena-{recon,vuln,exploit,postexploit,report}.md`

---

## Product Tiers

### Tier 1: Consultant (Current)
**Target:** Solo pentest consultants (like the author)
**Price:** Free (internal tool)
**Goal:** Validate platform works end-to-end on real targets

### Tier 2: Pro
**Target:** Small pentest firms and independent consultants (2-10 people)
**Price:** Per-engagement or monthly subscription (TBD)
**Goal:** First paying customers, product-market fit

### Tier 3: Enterprise
**Target:** Enterprise security teams running internal pentests
**Price:** Annual license + support (TBD)
**Goal:** Scalable recurring revenue

---

## Roadmap

### Phase 1: Consultant (Now — Q1 2026)

**Status:** Active

| Item | Status | Notes |
|------|--------|-------|
| Full PTES pipeline (5 agents) | Done | Recon, Vuln, Exploit, PostExploit, Report |
| Claude Agent SDK integration | Done | `query()` + `resume` pattern |
| 21-tool Kali registry | Done | JSON config, hot-reload |
| Neo4j attack graph | Done | Force-directed visualization |
| HITL approval workflow | Done | Blocking for destructive tools |
| Compliance framework config | Done | 22 frameworks, 7 industries, YAML-driven |
| AI security frameworks | Done | OWASP LLM/Agentic, ATLAS, NIST AI RMF, EU AI Act |
| Evidence capture system | In Progress | Screenshots + command output + HTTP pairs |
| Beta testing (full engagement runs) | Done | ACME GYM, 18 findings, $13.86 |
| Bug fixes from beta | Done | BUG-021b through BUG-030 |
| Report generation via API | Done | AI writes to correct dir + registers via POST |
| End-to-end dry run (Juice Shop) | Pending | Validate SDK mode against controlled target |
| Engagement portfolio | Pending | 3+ successful engagements as proof points |

**Exit criteria:** 3 successful real engagements, all major bugs fixed, reports are client-presentable.

---

### Phase 2: Pro (Q2-Q3 2026)

**Goal:** First external users. Package for sale.

#### Authentication & Multi-User
- [ ] Dashboard authentication (login page, session management)
- [ ] Operator roles: Admin (full), Operator (run engagements), Viewer (read-only)
- [ ] SSO-ready architecture (OAuth2/OIDC prep)
- [ ] Audit trail (who did what, when)

#### Report Productization
- [ ] PDF report generation (not just Markdown)
- [ ] Customer branding on reports (logo, colors, contact info)
- [ ] Report templates: Technical, Executive Summary, Remediation Roadmap
- [ ] Compliance framework mapping section auto-generated per engagement industry
- [ ] Report review/approval workflow (Draft → Review → Final)

#### Compliance Framework Management
- [ ] Per-customer `frameworks.yml` overlay (base from ZeroK + customer custom)
- [ ] Admin UI for framework management (enable/disable, add custom frameworks)
- [ ] Framework update channel (ZeroK Labs pushes version updates to customers)
- [ ] Custom framework import (upload YAML/JSON with framework definitions)

#### Engagement Improvements
- [ ] Engagement templates (pre-configured for common targets: web app, API, cloud, network)
- [ ] Scope validation (target reachability check before starting)
- [ ] Cost estimation (predict API cost based on scope complexity)
- [ ] Engagement scheduling (start at specific time)
- [ ] Multi-engagement isolation (concurrent engagements on different targets)

#### Tool Registry
- [ ] Tool registry admin UI (add/edit/delete tools from browser)
- [ ] Custom tool definitions (customers add their own tools)
- [ ] Tool health monitoring (check backend availability before engagement)

#### Infrastructure
- [ ] Docker deployment option (single `docker compose up`)
- [ ] Configuration wizard (first-run setup)
- [ ] Backup/restore for Neo4j data
- [ ] Health check endpoint (`/health`)

**Exit criteria:** 5 paying customers, Docker deployment working, PDF reports shipping.

---

### Phase 3: Enterprise (Q4 2026 — 2027)

**Goal:** Scalable product with enterprise features.

#### Integrations
- [ ] Jira bi-directional sync (findings → tickets, status updates back)
- [ ] ServiceNow integration
- [ ] Slack/Discord/Teams notifications for findings and approvals
- [ ] Webhook API for custom integrations
- [ ] SIEM integration (findings as security events)

#### Advanced AI Features
- [ ] Auto-fix code generation (AI generates PRs for each finding, human approval gate)
- [ ] Continuous pentesting (scheduled daily/weekly/monthly automated runs)
- [ ] Re-verification (1-click re-run exploit against fixed target to confirm remediation)
- [ ] Attack path analysis (AI suggests most impactful attack chains)
- [ ] Finding deduplication across engagements (same vuln on same target = same finding)

#### Compliance & Governance
- [ ] PCI DSS 11.4 attestation support (AI + human review hybrid)
- [ ] SOC 2 audit evidence generation
- [ ] HIPAA security assessment mapping
- [ ] Compliance dashboard (framework coverage across all engagements)
- [ ] Finding lifecycle management (Open → Assigned → Fixed → Verified → Closed)

#### Scale & Operations
- [ ] RBAC with team isolation
- [ ] White-label option (fully rebrandable)
- [ ] Managed Kali backend option (ZeroK-hosted, customer doesn't manage infrastructure)
- [ ] API access (programmatic engagement creation, finding export)
- [ ] Multi-tenant architecture (shared infrastructure, isolated data)
- [ ] SLA-backed support tiers

**Exit criteria:** $5K MRR, 3+ enterprise customers, continuous pentest working.

---

## Competitive Positioning

### Market Landscape (Feb 2026)

| Competitor | Type | Pricing | Differentiator |
|-----------|------|---------|---------------|
| NodeZero (Horizon3.ai) | Autonomous pentest | Enterprise ($$$) | Docker agent, unlimited tests |
| Pentera | Continuous security validation | Enterprise ($$$) | Pentera Resolve (auto-remediation) |
| Picus | BAS (attack simulation) | Enterprise ($$) | Threat-intel-led |
| Cobalt | Pentest-as-a-Service | Per-test ($) | Best Jira integration |
| XBOW | AI autonomous pentest | Early stage | Research-focused |

### ATHENA Differentiators
1. **End-to-end find → fix → verify** — No competitor generates fix code
2. **Config-driven compliance** — YAML, not hardcoded. Customers extend it.
3. **AI + Human hybrid** — Addresses PCI DSS attestation gap
4. **Real tool execution** — Actual Kali tools, not simulations
5. **Transparent AI reasoning** — Full agent thinking visible in dashboard
6. **Affordable** — Solo consultant pricing → enterprise, not enterprise-only
7. **Self-hosted option** — Customer controls their data and infrastructure

### Gaps (Competitors Have, We Don't Yet)
- Docker single-command deployment (NodeZero has this)
- 100+ tool integrations (Pentera Resolve)
- PDF/branded reports (all competitors)
- Continuous/scheduled pentesting (NodeZero, Pentera)
- Jira integration (Cobalt standard since 2020)

---

## Architecture for Commercialization

### Current (Consultant)
```
Mac → ATHENA Dashboard (localhost:8080)
        ├── Claude Agent SDK (5 agents)
        ├── Neo4j (Antsle cloud)
        ├── Kali External (Antsle)
        └── Kali Internal (Mini-PC, ZeroTier)
```

### Target (Pro/Enterprise)
```
Customer Environment
├── ATHENA Dashboard (Docker or self-hosted)
│   ├── Auth Layer (OAuth2/OIDC)
│   ├── Claude Agent SDK (customer API key)
│   ├── Neo4j (local or cloud-hosted)
│   ├── Compliance Config (base + customer overlay)
│   └── Report Engine (PDF + branding)
├── Kali Backend(s) (customer-managed or ZeroK-hosted)
└── Integrations (Jira, Slack, SIEM, webhooks)

ZeroK Labs (SaaS layer)
├── Framework Update Channel (push new versions)
├── Tool Registry Updates (new tools, parsers)
├── License Management
└── Support Portal
```

### Key Architecture Decisions for Commercialization
1. **Config-driven everything** — frameworks.yml, tool-registry.json, themes. No code changes for customization.
2. **Docker-first deployment** — `docker compose up` with environment variables for config.
3. **Customer API key** — Customer provides their own Anthropic API key (ATHENA doesn't proxy AI calls).
4. **Base + overlay config pattern** — ZeroK pushes base frameworks.yml, customer overlays custom frameworks without losing upstream updates.
5. **Self-hosted by default** — Customer data never leaves their infrastructure. Managed option for those who want it.

---

## Revenue Model

### Phase 2 (Pro)
| Model | Price (est.) | Notes |
|-------|-------------|-------|
| Per-engagement | $50-200/engagement | Pay-as-you-go, API cost pass-through |
| Monthly subscription | $500-1,500/month | Unlimited engagements, support included |
| Annual | $5,000-15,000/year | Discount for commitment |

### Phase 3 (Enterprise)
| Model | Price (est.) | Notes |
|-------|-------------|-------|
| Team license | $25,000-75,000/year | Per-team, RBAC, integrations |
| Enterprise | $100,000+/year | Multi-team, white-label, managed infra, SLA |
| VERSANT consulting | $200-350/hour | Setup, customization, training |

### Revenue Streams
1. **License fees** — Platform access (primary)
2. **Framework packs** — Industry-specific compliance bundles (AI Security, Healthcare, Financial)
3. **Managed services** — ZeroK-hosted Kali backends, Neo4j cloud
4. **VERSANT consulting** — Done-for-you setup, custom framework development, training
5. **Tool marketplace** (future) — Third-party tool integrations

---

## Success Metrics

### 6 Months (August 2026)
- [ ] 3+ portfolio engagements completed
- [ ] Docker deployment working
- [ ] PDF report generation shipping
- [ ] Authentication implemented
- [ ] First external user (beta)
- [ ] Landing page on 0k.cool

### 12 Months (February 2027)
- [ ] 10 paying customers
- [ ] Jira integration live
- [ ] Continuous pentesting available
- [ ] $2K MRR
- [ ] VERSANT using ATHENA for all engagements

### 24 Months (February 2028)
- [ ] 50+ customers
- [ ] Enterprise tier with 3+ enterprise customers
- [ ] Auto-fix code generation shipping
- [ ] $10K MRR
- [ ] Brand recognition in pentest community

---

## Key Risks

| Risk | Mitigation |
|------|-----------|
| Anthropic API pricing increases | Support multiple LLM backends (OpenAI, local models) |
| Competitor ships similar product | Speed to market + compliance differentiator + consulting cross-sell |
| Tool execution liability | Clear Terms of Service, customer-provided authorization, audit trail |
| AI hallucination in reports | Strawberry verification, human review workflow, evidence-linked findings |
| Customer data security | Self-hosted default, no data leaves customer infra, audit trail |

---

## Notes

- Build for yourself first, validate it works, then scale out
- Consulting (VERSANT) funds product development (ZeroK Labs)
- Compliance framework config is a competitive moat — build it deeper
- The AI + Human hybrid model is not a limitation, it's the product (PCI DSS attestation requires it)
- Every bug fix from real engagements makes the product better

---

*"AI-driven adversary simulation that maps real attack paths, not just vulnerabilities."* 🦖⚡
