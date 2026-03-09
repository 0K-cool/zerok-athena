# ATHENA Gap Closure Roadmap — Path to Best-in-Class
**Date:** 2026-03-08
**Author:** Vex Intelligence Platform
**Classification:** Internal strategic planning — ZeroK Labs
**Goal:** Close every competitive gap exposed by PentAGI, Shannon, XBOW, and NodeZero

---

## Executive Summary

PentAGI (v1.2.0, 9.2K GitHub stars, MIT) is the most architecturally ambitious open-source AI pentest platform. After thorough codebase audit, ATHENA has **4 true gaps** (not 8 as initially assessed) — 3 claimed gaps were already implemented (exploit DB search, deterministic validation, compliance reports).

ATHENA already leads in: dual-backend, HITL scope enforcement, PTES methodology, CTF benchmarks, bilateral agent comms, per-agent cost caps, 7-source CVE/exploit pipeline (vs PentAGI's single Sploitus), and independent exploit validation (athena-verify with 9 evidence types).

**Strategic principle:** ATHENA will be open-sourced under AGPL v3 with a commercial dual-license option from ZeroK Labs. Dependencies must be AGPL-compatible (MIT, Apache 2.0, GPL, AGPL are all compatible).

---

## Licensing Audit — Commercial Safety

Every dependency ATHENA uses or adopts must be **AGPL-compatible** (permissive licenses and GPL-family are compatible; SSPL and BSL are not).

| Component | License | AGPL Compatible? | Action |
|-----------|---------|------------------|--------|
| **Graphiti** (getzep) | Apache 2.0 | ✅ YES | Adopt for cross-session memory |
| **Langfuse** | MIT | ✅ YES | Adopt for LLM observability |
| **Vulners API** | Official ToS, API key | ✅ YES | Adopt for exploit search (NOT Sploitus) |
| **Neo4j Community** | GPL v3 | ✅ YES | GPL is compatible with AGPL |
| **FalkorDB** | SSPL v1 | ❌ NO | SSPL is NOT compatible with AGPL |
| **Memgraph** | BSL v1.1 | ❌ NO | BSL is NOT compatible with AGPL |
| **Claude Agent SDK** | MIT | ✅ YES | Continue using |
| **Shannon** | AGPL v3 | ⚠️ Same license | Study only, zero code (clean-room) |
| **PentAGI source** | MIT (source) + EULA (images) | ✅ Source OK | Can study architecture, not fork/redistribute images |
| **FastAPI** | MIT | ✅ YES | Continue using |
| **Python** | PSF License | ✅ YES | Continue using |
| **Apache AGE** | Apache 2.0 | ✅ YES | Alternative graph DB if needed |

**Key finding:** Neo4j CE (GPL) is fully compatible with AGPL. Since ATHENA itself will be AGPL, the GPL "copyleft" obligation is satisfied — both require source distribution. **No licensing conflict.**

**Graph DB decision: Neo4j CE is cleared.** No need for expensive Enterprise license or alternatives. GPL + AGPL = compatible copyleft. This removes the biggest licensing blocker from the original roadmap.

### ATHENA Licensing Strategy — AGPL + Commercial Dual-License

**Model:** Same approach as MongoDB, Neo4j, Grafana, MinIO.

```
┌─────────────────────────────────────────────┐
│           ATHENA Source Code                 │
│              (AGPL v3)                      │
├──────────────────┬──────────────────────────┤
│  Community Use   │   Commercial License     │
│  (Free, AGPL)    │   (Paid, from ZeroK Labs)│
├──────────────────┼──────────────────────────┤
│  Must publish    │  No source disclosure    │
│  modifications   │  required                │
│  if served over  │                          │
│  network         │  Private modifications   │
│                  │  allowed                 │
│  Internal use    │                          │
│  = no obligation │  Enterprise support      │
│                  │  included                │
└──────────────────┴──────────────────────────┘
```

**Why enterprises pay:**
1. **AGPL network clause** — running ATHENA as a service requires publishing ALL modifications (including internal integrations with SIEM, AD, ticketing systems)
2. **Legal compliance** — most enterprises (Google, banks, MSSPs) have blanket "no AGPL" policies
3. **Confidentiality** — customizations may expose internal architecture
4. **Support** — commercial license includes ZeroK Labs enterprise support

**Revenue streams:**
- Hosted SaaS (ZeroK Labs managed ATHENA)
- Commercial license (on-prem without AGPL obligations)
- Premium features (advanced reporting, multi-tenant, SSO, compliance modules)
- Support contracts and training
- VERSANT consulting services (using ATHENA as the platform)

**CLA requirement:** All contributors must sign a Contributor License Agreement (CLA) granting ZeroK Labs the right to dual-license. Without this, external contributions under AGPL would prevent commercial relicensing.

**Implementation:**
1. Add `LICENSE` file (AGPL v3) to ATHENA repo root
2. Add `LICENSE-COMMERCIAL.md` with terms overview and contact
3. Add CLA bot to GitHub (e.g., CLA Assistant)
4. Update README with license section and dual-license explanation
5. Add SPDX headers to all source files: `SPDX-License-Identifier: AGPL-3.0-or-later`

---

## Phase Plan

### Phase H: Cross-Session Contextual Memory (Graphiti)
**Priority:** HIGHEST | **Effort:** 2-3 weeks | **Impact:** Game-changing
**Inspiration:** PentAGI's Graphiti temporal knowledge graph

**What it gives us:**
- Engagements compound — "last time on Apache 2.4 behind Cloudflare, this bypass worked"
- Temporal reasoning — track how attack surface changed during multi-day engagement
- Semantic search over past engagement context, not just statistics
- CEI analytics + Graphiti contextual memory = complete learning system

**Architecture:**
```
Current:  Agent → Neo4j (findings, attack graph) → CEI (analytics)
Proposed: Agent → Neo4j (findings) → Graphiti (temporal memory) → CEI (analytics)
                                         ↑
                                    Episodes fed from:
                                    - Tool outputs (nmap, sqlmap results)
                                    - Agent reasoning chains
                                    - Findings with full context
                                    - Operator decisions (HITL approvals)
```

**Implementation:**
1. Add `graphiti-core` to requirements.txt
2. Define ATHENA pentest ontology (Pydantic entity/edge types):
   - Entities: Target, Service, Vulnerability, CVE, Tool, Technique, Credential, Finding
   - Edges: EXPOSES, EXPLOITS, RUNS_ON, MITIGATES, CHAINS_TO (all temporal)
3. Run Graphiti as FastAPI sidecar (vxcontrol pattern) OR embed directly in server.py
4. Feed episodes from: tool outputs, agent turns, findings, HITL decisions
5. ST (Strategy Agent) queries Graphiti for similar past cases before planning
6. AR (Recon Agent) queries for known services/vulns on similar targets

**PentAGI reference:** `vxcontrol/pentagi-graphiti` (FastAPI wrapper), `vxcontrol/pentagi-taxonomy` (YAML ontology with codegen)

**Decision needed:** Embed in server.py (simpler) vs. sidecar service (cleaner isolation)?

---

### Phase H2: Vulners API (Enhancement — Additional Exploit Source)
**Priority:** LOW | **Effort:** 3-5 days | **Impact:** Incremental enrichment
**Status:** ENHANCEMENT, not a gap — ATHENA already has 7 exploit/CVE sources

**ATHENA's existing CVE/exploit pipeline (already implemented):**

| Source | Tool | Method |
|--------|------|--------|
| NVD/NIST | `nvd_cve_search` | Direct REST API |
| AttackerKB (Rapid7) | `attackerkb_lookup` | Direct API + Bearer auth |
| Exploit-DB | `searchsploit_search` | Local SearchSploit + web |
| GitHub PoCs | `github_exploit_search` | GitHub API v3 |
| PacketStorm | `packetstorm_search` | HTTP + HTML parsing |
| Metasploit | `msf_search` / `msf_search_keyword` | Module search |
| Web research | `WebSearch` + `WebFetch` | Claude tools (fallback/supplementary) |

**What Vulners would add:**
- Unified exploit aggregator (combines Exploit-DB, PacketStorm, Metasploit, and more)
- Exploit maturity classification (`poc/weaponized/metasploit`)
- Official Python SDK (`pip install vulners`)

**Verdict:** Nice-to-have, not blocking. Current 7-source pipeline is already more comprehensive than PentAGI's single Sploitus integration. Defer unless a specific engagement reveals coverage gaps.

---

### Phase H3: Production LLM Observability (Langfuse)
**Priority:** HIGH | **Effort:** 1-2 weeks | **Impact:** Enterprise-grade monitoring

**What it gives us:**
- Per-agent token usage, cost, and latency tracking
- Trace every agent turn: model completions + tool calls + MCP calls
- Cost per engagement (actual, not estimated)
- Prompt version management (A/B test agent prompts)
- Evaluation pipelines (score agent quality over time)

**Architecture:**
```
Agent SDK → AnthropicInstrumentor (OTEL) → Langfuse Collector
                                                ↓
                                          ClickHouse (traces)
                                          Redis (queue)
                                          MinIO (blob storage)
                                          PostgreSQL (metadata)
                                                ↓
                                          Langfuse UI (dashboard)
```

**Implementation:**
1. Add to docker-compose: Langfuse web + worker + ClickHouse + Redis + MinIO + PostgreSQL
2. `pip install langfuse openinference-instrumentation-anthropic opentelemetry-sdk`
3. Add `AnthropicInstrumentor().instrument()` at server startup
4. Configure OTEL exporter pointing at local Langfuse instance
5. Add `langfuse.flush()` to FastAPI shutdown hook
6. All Claude Agent SDK calls auto-traced (zero code changes to agent logic)

**Dedicated cookbook exists:** `langfuse/langfuse-docs/cookbook/integration_claude_agent_sdk.ipynb`

**Replaces:** Current basic WebSocket event timeline with full observability stack
**Complements:** PAI's existing observability framework (token-usage.jsonl, traces)

---

### Phase H4: Multi-LLM Provider Support
**Priority:** MEDIUM-HIGH | **Effort:** 2-3 weeks | **Impact:** Cost flexibility, no lock-in

**What it gives us:**
- Per-agent model selection (reasoning model for ST, cheap model for installer)
- Local Ollama option for zero API cost (training/demo environments)
- Provider failover (if Anthropic is down, fall back to OpenAI)
- Customer choice — enterprises may mandate specific providers

**Architecture options:**

**Option A: LiteLLM Proxy (PentAGI's approach)**
```
Agent SDK → LiteLLM → Claude/GPT/Gemini/Ollama
                ↓
          Unified OpenAI-compatible API
          Per-model routing rules
          Fallback chains
          Rate limit handling
```

**Option B: Native multi-provider in agent configs**
```python
AGENT_MODELS = {
    "orchestrator": {"provider": "anthropic", "model": "claude-sonnet-4-6"},
    "pentester": {"provider": "anthropic", "model": "claude-haiku-4-5"},
    "searcher": {"provider": "openai", "model": "gpt-4.1-mini"},
    "installer": {"provider": "ollama", "model": "qwen3-32b"},
}
```

**Decision needed:** LiteLLM proxy (cleanest, but adds infra) vs. native provider abstraction?

**Note:** Claude Agent SDK is Anthropic-only. Multi-LLM means some agents use Agent SDK (for tool use), others use raw API calls. Need to design the abstraction carefully.

---

### Phase H5: Authentication + Multi-User
**Priority:** MEDIUM | **Effort:** 1-2 weeks | **Impact:** Production/team readiness

**Implementation:**
- FastAPI + OAuth2 (GitHub + Google providers)
- JWT tokens for API access
- Role-based access: admin, operator, viewer
- Per-user engagement isolation
- Audit log per user action

**Why now:** Required before any beta testing with external users or team deployment.

---

### Phase H6: Docker Compose Deployment
**Priority:** LOW (but easy win) | **Effort:** 3-5 days | **Impact:** Professional onboarding

**Implementation:**
- `docker-compose.yml` with all services (dashboard, Neo4j/FalkorDB, Graphiti, Langfuse stack)
- `.env.example` with all configuration options
- `Dockerfile` for ATHENA server
- TUI installer script (interactive setup wizard)
- Health check endpoints for all services
- Documentation: one-command setup guide

---

### Phase I1: White-Box Source Analysis (SC Agent Deep Pipeline)
**Priority:** HIGH | **Effort:** 3-4 weeks | **Impact:** Shannon-class code analysis

**What it gives us:**
- Read source code → identify vulnerabilities → generate exploits
- Shannon pattern: white-box analysis informs black-box testing
- SC agent gets full static analysis pipeline (Semgrep, CodeQL, custom rules)

**Architecture:**
```
SC Agent: Source code → Semgrep/CodeQL → AI triage → Exploit hypothesis
    ↓
EX Agent: Hypothesis → Targeted exploitation → Validation
    ↓
VF Agent: Verify exploit works → Evidence package
```

**This is Phase H from the original roadmap.** Shannon (AGPL) is the reference but we can't use their code — clean-room implementation using Semgrep (LGPL, safe) + CodeQL (free for open-source, check commercial terms).

---

### Phase I2: Compliance-Ready Report Formats (Enhancement)
**Priority:** MEDIUM | **Effort:** 1-2 weeks | **Impact:** Client deliverable polish
**Status:** ENHANCEMENT — `athena-report` agent already generates full PTES reports with risk scoring, MITRE ATT&CK mapping, detection gap analysis, and remediation roadmaps

**What exists:** Markdown reports at `reports/{engagement_id}/athena-report-{date}.md` with executive summary, findings, attack chains, evidence manifests, and SHA-256 validation

**What this phase adds:**
- PDF output via VERSANT docs skill (Pandoc + LaTeX pipeline, VERSANT-branded)
- Compliance framework mappings (OWASP Top 10, NIST CSF, PCI DSS 11.4, SOC 2 Type II)
- HTML interactive report (filterable findings, expandable evidence)
- JSON machine-readable format (for SIEM/GRC integration)

---

### ~~Phase I3: Deterministic Validation Layer~~ — ALREADY IMPLEMENTED
**Status:** ✅ EXISTS — `athena-verify` agent (VF) provides XBOW-style independent validation

**What ATHENA already has:**
- **"Finder is not verifier" principle** — independent VF agent replays exploits
- **9 evidence types:** HTTP response delta, status code change, timing delta (3+ runs), unique strings, command output format, OOB callbacks, file content match, auth state change, SQL error strings
- **Confidence scoring:** HIGH (3+ evidence types), MEDIUM (2), LOW (1), UNCONFIRMED (0), FALSE_POSITIVE
- **Baseline-first:** Every validation starts with a clean baseline request
- **EvidencePackage nodes** persisted to Neo4j with structured proof
- **Safety:** No novel payloads (replay only), no data exfiltration

**Potential enhancement (LOW priority):** Add canary token deployment for controlled test environments (pre-plant tokens, check for trigger). But the current multi-evidence approach already provides deterministic validation without requiring canary infrastructure.

---

### Phase I4: Independent Benchmarks
**Priority:** MEDIUM | **Effort:** 1-2 weeks | **Impact:** Marketing credibility

**Benchmarks to run:**
- XBOW 104-challenge benchmark (Shannon scored 96.15%)
- GOAD (Game of Active Directory) — NodeZero's benchmark
- Custom ATHENA benchmark suite (based on Phase F CTF runner)
- HackTheBox/TryHackMe retired machines

**Output:** Public benchmark results page on zeroklabs.ai

---

### Phase L0: Licensing Setup (AGPL + Commercial Dual-License)
**Priority:** HIGH (do before public release) | **Effort:** 3-5 days | **Impact:** Legal foundation

**Decision (2026-03-08):** ATHENA will be released under **AGPL v3** with a **commercial dual-license** from ZeroK Labs.

**Graph DB licensing — RESOLVED:** Neo4j CE (GPL v3) is fully compatible with AGPL v3. Both are copyleft — GPL's source disclosure obligation is satisfied by AGPL's even stronger network clause. **No Neo4j Enterprise license needed.**

**Tasks:**
1. Add `LICENSE` file (AGPL v3 full text) to repo root
2. Add `LICENSE-COMMERCIAL.md` — terms overview, pricing tiers, contact info
3. Add SPDX headers to all source files: `SPDX-License-Identifier: AGPL-3.0-or-later`
4. Set up CLA bot on GitHub (CLA Assistant or similar) — required so ZeroK Labs retains dual-license rights
5. Update README with license section explaining AGPL + commercial option
6. Add `CONTRIBUTING.md` referencing CLA requirement
7. Review all dependencies for AGPL compatibility (see audit table above — all clear)

**Dependency compatibility summary:**
- ✅ Neo4j CE (GPL) — copyleft compatible with AGPL
- ✅ Graphiti (Apache 2.0) — permissive, always compatible
- ✅ Langfuse (MIT) — permissive, always compatible
- ✅ Claude Agent SDK (MIT) — permissive, always compatible
- ✅ FastAPI (MIT) — permissive, always compatible
- ❌ FalkorDB (SSPL) / Memgraph (BSL) — NOT compatible, but we don't need them

---

## Implementation Sequence

```
## TRUE GAPS (require new implementation):
Phase H1: Graphiti cross-session memory (HIGHEST priority)
Phase H3: Langfuse observability (can parallel with H1)
    ↓
Phase H4: Multi-LLM support (after H3 — Langfuse traces inform model selection)
Phase I1: White-box source analysis (SC agent pipeline)
    ↓
Phase H5: Authentication (after H1/H3 — infrastructure stable)
Phase H6: Docker Compose (after H1-H5 — package everything)

## ENHANCEMENTS (existing features, adding polish):
Phase H2: Vulners API (additional exploit source — LOW priority)
Phase I2: Compliance report formats (PDF/HTML/JSON output — MEDIUM)
Phase I4: Benchmarks (XBOW + GOAD — MEDIUM, do before public release)

## ALREADY DONE (removed from roadmap):
Phase I3: Deterministic validation — athena-verify agent exists ✅
Exploit DB search — 7-source CVE/exploit pipeline exists ✅
Compliance reports — athena-report agent exists ✅

## BEFORE PUBLIC RELEASE:
Phase L0: AGPL licensing setup
Phase I4: Benchmarks (prove it works)
```

**Estimated total:** 2-3 months for true gaps + enhancements (down from 4-6 months — 3 phases removed)
**MVP (H1 + H3):** 3-5 weeks — cross-session memory + LLM observability = biggest competitive leap

---

## ATHENA After Gap Closure — Competitive Position

| Capability | ATHENA (Current) | ATHENA (Post-Roadmap) | PentAGI | XBOW | NodeZero |
|-----------|-----------------|----------------------|---------|------|----------|
| Agent count | 21 roles / 5 teams | 21+ | 13 | 2-tier | Graph-driven |
| Cross-session memory | ❌ (CEI stats only) | ✅ Graphiti temporal | ✅ | Unknown | ❌ |
| Exploit DB search | ✅ 7 sources (NVD, AttackerKB, ExploitDB, GitHub, PacketStorm, Metasploit, WebSearch) | ✅ + Vulners | ✅ Sploitus (1 source) | Internal | Unknown |
| LLM observability | Basic events | ✅ Langfuse | ✅ Langfuse | Internal | Internal |
| Multi-LLM | Claude only | ✅ Multi-provider | ✅ 10+ | Unknown | N/A |
| Dual-backend | ✅ | ✅ | ❌ | ❌ | ❌ |
| HITL scope enforcement | ✅ | ✅ | ❌ | ✅ (network) | ❌ |
| PTES methodology | ✅ | ✅ | ❌ | ❌ | ❌ |
| White-box analysis | ❌ | ✅ SC pipeline | ❌ | ❌ | ❌ |
| Deterministic validation | ✅ athena-verify (9 evidence types, confidence scoring) | ✅ + canary tokens | ❌ | ✅ | ❌ |
| Compliance reports | ✅ athena-report (PTES, MITRE, risk scoring) | ✅ + PDF/HTML/JSON formats | ❌ | ❌ | ✅ |
| Benchmarks | CTF runner | ✅ XBOW + GOAD | ❌ | ✅ | ✅ |
| Internet research | ✅ Direct APIs + WebSearch/WebFetch | ✅ | ✅ | Unknown | ❌ |
| Auth + multi-user | ❌ | ✅ OAuth + RBAC | Basic | Enterprise | Enterprise |
| Docker deployment | Manual | ✅ Compose + TUI | ✅ | SaaS | SaaS |
| License | Private | Commercial-safe | MIT + EULA | Proprietary | Proprietary |
| Tool count | 57 | 57+ | Kali suite | Unknown | Unknown |
| Cost per test | ~$2-5 API | ~$1-5 (multi-LLM) | $0-5 (Ollama→API) | $4K+ | Subscription |
| CTF benchmark | ✅ XBOW runner | ✅ + results published | ❌ | ✅ | ✅ |

**After this roadmap, ATHENA would be the only platform with ALL of:**
- Full-spectrum tools (web + network + AD + cloud + containers)
- Dual-backend (external + internal)
- HITL scope enforcement with bilateral comms
- Cross-session temporal memory (Graphiti)
- Autonomous exploit search (Vulners)
- Enterprise observability (Langfuse)
- White-box + black-box analysis
- Deterministic validation
- PTES methodology
- Compliance-ready reports
- Multi-LLM provider support
- Independent benchmark results

No competitor — open-source or commercial — has all of these today.

---

**Next step:** Kelvin approves this roadmap → Use `superpowers:writing-plans` to create implementation plans for each phase → Execute via `superpowers:subagent-driven-development`

---

**Last Updated:** 2026-03-08
**Author:** Vex 🦖⚡ for ZeroK Labs
