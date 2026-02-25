# ATHENA Phase F: Autonomous Intelligence

**Status:** Planning
**Author:** Vex 🦖⚡ + Kelvin
**Date:** February 25, 2026
**Goal:** Transform ATHENA from automated scanner with reasoning into autonomous pentest intelligence that can compete in CTFs and the commercial market.

---

## Strategic Context

### Where ATHENA Stands (Phase E Complete)
- 7 real Claude Code agents (recon, vuln, exploit, verify, postexploit, cleanup, report)
- 37 Kali tools across dual backends (Antsle cloud + mini-PC)
- Neo4j attack graph with engagement persistence
- HITL approval flow for dangerous operations
- Dashboard with real-time agent monitoring, PTES matrix, attack chains

### Competitive Intelligence
- **XBOW:** $117M funded, #1 HackerOne US, ~85% on their 104-challenge web benchmark. Three-role architecture: Coordinator → Sandbox Agents → Validation Agent. The validation layer is their moat.
- **MAPTA (open-source):** 76.9% on XBOW benchmark, $0.117/challenge median cost. Coordinator + sandbox + validator pattern.
- **ZeroPath:** MCTSr validation, found 19 critical zero-days in Netflix/Hulu/Salesforce. $3.67/assessment.
- **Key insight:** The market has bifurcated — tools that produce verified PoC exploits vs tools that produce advisory reports. Only PoC-verified tools command premium pricing.

### Research-Backed Architecture Principles
1. **Specialization > Generalism** — HPTSA paper: 550% efficiency with hierarchy + specialized agents vs single LLM (arXiv:2406.01637)
2. **Validation is the moat** — XBOW and ZeroPath both built their differentiation on verified PoC reproduction
3. **Early-stopping saves cost** — MAPTA data: >40 tool calls or >$0.30 without convergence = stop and pivot (r=-0.661 correlation)
4. **Web >> Pwn for current AI** — Crypto and web exploitation are strongest; binary exploitation remains unsolved at scale
5. **Dynamic reasoning > Static patterns** — ToT/ReAct reasoning about application state finds what pattern matching can't

---

## Phase F Architecture

### F1: Strategy Agent ("Red Team Lead")
**Priority: CRITICAL | Effort: 1-2 weeks | Impact: HIGH**

The biggest force multiplier. A dedicated adversarial reasoning agent that thinks like an experienced red team lead.

**What it does:**
- Reviews all findings holistically after each agent phase completes
- Identifies the highest-value attack paths (not just severity — exploitability × impact × chaining potential)
- Dynamically reassigns agents based on discoveries ("Recon found an internal API — redirect App Security agent there")
- Maintains adversarial mental model: "If I were an attacker, what would I do next?"
- Makes go/no-go decisions for exploitation attempts based on risk/reward

**Implementation:**
```
agents/athena-strategy.md
├── Model: opus (requires deep reasoning)
├── Tools: Neo4j read, dashboard API read, SendMessage to all agents
├── Pattern: Runs after each phase gate, before next phase starts
├── Input: Full Neo4j graph state + all findings + engagement scope
├── Output: Updated attack plan, agent task assignments, priority targets
└── Trigger: phase_complete events
```

**Agent prompt core:**
```
You are the Red Team Lead for this engagement. Think like an experienced
adversary — a nation-state operator with unlimited patience and creativity.

After reviewing the current findings and attack surface:
1. What attack paths have the highest probability of full compromise?
2. What has the team missed? What would a human pentester check next?
3. Are there any chaining opportunities (finding A + finding B = critical impact)?
4. Should we pivot to a different target/service based on what we've learned?
5. Rate each open finding: exploit now, investigate further, or deprioritize.

Your output is the attack plan for the next phase.
```

**Neo4j Integration:**
- Reads: Host, Service, Finding, Vulnerability, AttackPath, Credential nodes
- Writes: StrategyDecision nodes with reasoning, priority scores, and agent assignments
- Queries: "What is the shortest path from initial access to domain admin?" via graph traversal

---

### F2: Bilateral Agent Communication
**Priority: HIGH | Effort: 1-2 weeks | Impact: HIGH**

Replace hub-and-spoke with event-driven messaging. Agents notify each other directly when discoveries change the attack surface.

**Current state (hub-and-spoke):**
```
Recon → Orchestrator → Vuln → Orchestrator → Exploit
```

**Target state (bilateral + strategy):**
```
Recon ──→ Vuln (direct: "Found internal API on :8443")
Recon ──→ Strategy (direct: "Attack surface larger than expected")
Vuln  ──→ Exploit (direct: "SQLi confirmed, here's the injection point")
Exploit → Verify (direct: "Got RCE, need independent verification")
Strategy ←──── All (receives all major findings for holistic reasoning)
```

**Implementation using Claude Code Agent Teams:**
- Agent Teams already supports bilateral messaging via `SendMessage` tool
- Each agent gets teammate names in their prompt: `Your teammates: recon, vuln, exploit, verify, strategy`
- Message protocol:
  ```json
  {
    "from": "recon",
    "to": "vuln",
    "type": "discovery",
    "priority": "high",
    "content": "Internal API found at https://target:8443/api/v2 — no auth required",
    "neo4j_ref": "node-id-123"
  }
  ```
- Dashboard renders bilateral messages as arrows between agent chips in the timeline

**Communication Rules:**
| Event | Who Notifies | Who |
|-------|-------------|-----|
| New host/service discovered | Recon | Vuln + Strategy |
| Vulnerability confirmed | Vuln | Exploit + Strategy |
| Credential harvested | Exploit | PostExploit + Strategy |
| Exploit verified with PoC | Verify | Strategy + Report |
| New attack path identified | Strategy | Relevant agents |
| Lateral movement opportunity | PostExploit | Strategy |

---

### F3: Validation Pipeline ("The Moat")
**Priority: CRITICAL | Effort: 2-3 weeks | Impact: HIGHEST**

This is what separates real tools from advisory generators. Every finding must be independently verified with a working PoC.

**Architecture (inspired by XBOW + ZeroPath):**
```
Finding Discovered (any agent)
    │
    ▼
┌─────────────────────────┐
│  athena-verify (exists)  │
│  ─────────────────────  │
│  1. Independent re-test  │  ← Different tool/technique than discovery
│  2. PoC generation       │  ← Working exploit script/curl command
│  3. Evidence capture     │  ← Screenshot, response, stack trace
│  4. Impact assessment    │  ← What can attacker actually do?
│  5. Reproducibility test │  ← Run PoC 3x to confirm consistency
│  6. Confidence scoring   │  ← CONFIRMED / LIKELY / UNVERIFIED
└─────────────────────────┘
    │
    ▼
Neo4j: Finding node updated with:
  - verified: true/false
  - poc_script: "sqlmap -u ... --dump"
  - evidence_package: {screenshot, response, trace}
  - confidence: 0.0-1.0
  - impact_demonstrated: "Full database dump achieved"
```

**Verification methods by vulnerability type:**
| Vuln Type | Verification Method |
|-----------|-------------------|
| SQLi | sqlmap with --technique different from discovery; extract 1 row as proof |
| XSS | Inject unique canary, verify in response/DOM |
| RCE | Execute `id` or `whoami`, capture output |
| Auth Bypass | Access protected resource, prove authorization failure |
| SSRF | Request to Burp Collaborator / internal metadata endpoint |
| File Read | Read `/etc/passwd` or known file, verify contents |
| IDOR | Access another user's resource, compare responses |

**PoC Output Format:**
```markdown
## PoC: SQL Injection — Authentication Bypass
**Target:** https://target/api/Users/login
**Severity:** CRITICAL | **Confidence:** 0.95 | **Verified:** 3/3 attempts

### Reproduction Steps
1. Send POST to /api/Users/login
2. Body: {"email": "' OR 1=1--", "password": "x"}
3. Observe: 200 OK with valid JWT token

### Evidence
- HTTP Request/Response: [attached]
- JWT decoded: {"role": "admin", "email": "admin@juice.sh"}
- Verified access to /api/Users (all user data exposed)

### One-liner
curl -X POST https://target/api/Users/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"'"'"' OR 1=1--","password":"x"}'

### Impact
Full authentication bypass → admin access → all user PII exposed
```

---

### F4: CTF Mode
**Priority: HIGH | Effort: 2-3 weeks | Impact: HIGH**

Specialized mode for jeopardy-style CTF competitions. Different from pentest mode — focused on flag capture with time pressure.

**Architecture:**
```
/athena-ctf <url> --category web --time-limit 30m
    │
    ▼
Strategy Agent (CTF-specialized prompt)
    │
    ├── Web Challenges: SQLi, XSS, SSTI, SSRF, command injection, deserialization
    ├── Crypto: Cipher analysis, parameter recovery, known attacks
    ├── Forensics: File analysis, metadata, steganography
    ├── Reverse: Static analysis, decompilation, pattern matching
    └── Misc: OSINT, encoding, scripting puzzles
```

**CTF-specific features:**
1. **Flag detection** — Regex patterns for common flag formats (`flag{...}`, `CTF{...}`, `picoCTF{...}`)
2. **Time-boxed attempts** — Early-stopping: if >40 tool calls without progress, pivot strategy
3. **Category-specific agents** — Specialized prompts per CTF category (web agent knows SSTI payloads, crypto agent knows RSA attacks)
4. **Challenge classification** — Auto-detect challenge type from description/files
5. **Hint integration** — If hints are released, Strategy Agent incorporates them
6. **Parallel solving** — Multiple challenges simultaneously via Agent Teams

**Target benchmarks:**
| Benchmark | Target Score | Timeline |
|-----------|-------------|----------|
| OWASP Juice Shop (all challenges) | 80%+ | Month 1 |
| PicoCTF 2024 (web category) | 70%+ | Month 2 |
| HTB Easy-Medium boxes | 60%+ | Month 3 |
| XBOW 104-challenge benchmark | 50%+ | Month 4 |

**First proving ground:** OWASP Juice Shop — you already have it deployed as a test target at `web01.your-cloud-domain:3030`. Perfect for iterating.

---

### F5: Cost Optimization & Early-Stopping
**Priority: MEDIUM | Effort: 1 week | Impact: MEDIUM**

Based on MAPTA research: strong inverse correlation between resource consumption and success. Failed attempts cost 5x more than successful ones.

**Implementation:**
```python
# In orchestrator — per-agent cost tracking
class AgentBudget:
    tool_calls: int = 0
    estimated_cost: float = 0.0
    max_tool_calls: int = 40        # MAPTA heuristic
    max_cost: float = 0.50          # Per-agent budget

    def should_stop(self) -> bool:
        return self.tool_calls > self.max_tool_calls or \
               self.estimated_cost > self.max_cost

    def on_stop(self):
        # Notify Strategy Agent: "Agent X exhausted budget without findings"
        # Strategy decides: increase budget, pivot, or abandon this path
```

**Budget allocation by agent:**
| Agent | Tool Call Limit | Cost Limit | Rationale |
|-------|----------------|------------|-----------|
| Recon | 60 | $0.75 | Needs broad scanning |
| Vuln | 40 | $0.50 | Standard |
| Exploit | 30 | $1.00 | Higher per-call cost (Opus) |
| Verify | 20 | $0.30 | Focused re-testing |
| PostExploit | 40 | $0.50 | Depends on access level |
| Strategy | 10 | $0.50 | Pure reasoning, few tools |
| Report | 15 | $0.75 | Writing-heavy (Opus) |

**Dashboard integration:**
- Per-agent cost badge on agent chips
- Total engagement cost in KPI bar
- Budget exhaustion warnings in timeline

---

### F6: Attack Chain Reasoning via Neo4j
**Priority: HIGH | Effort: 2 weeks | Impact: HIGH**

Use the graph database not just for storage, but for adversarial reasoning about multi-step attack paths.

**New Cypher queries for Strategy Agent:**
```cypher
// Shortest path from initial access to sensitive data
MATCH path = shortestPath(
  (entry:Host {access_level: 'initial'})-[*]-(target:Service {contains_pii: true})
)
RETURN path

// What can we reach from compromised host?
MATCH (h:Host {compromised: true})-[:CONNECTS_TO]->(s:Service)
WHERE NOT s.tested = true
RETURN s

// Chain findings into attack narrative
MATCH (f1:Finding)-[:ENABLES]->(f2:Finding)
WHERE f1.engagement_id = $eid
RETURN f1.title, f2.title, f1.severity, f2.severity

// Lateral movement opportunities
MATCH (h1:Host {compromised: true})-[:NETWORK_ACCESS]->(h2:Host)
WHERE NOT h2.compromised
RETURN h2, h2.services
```

**New relationship types:**
- `ENABLES` — Finding A enables exploitation of Finding B
- `PIVOTS_TO` — Compromised Host A can reach Host B
- `ESCALATES_TO` — Low-priv access escalates to higher privilege
- `EXPOSES` — Service exposes sensitive data or functionality

**Strategy Agent uses these queries to:**
1. Find non-obvious attack chains (SQLi → admin panel → file upload → RCE)
2. Identify lateral movement paths across hosts
3. Calculate "blast radius" of each finding
4. Prioritize exploitation order for maximum impact

---

## Implementation Roadmap

### Month 1: Foundation (Weeks 1-4)
| Week | Focus | Deliverable |
|------|-------|-------------|
| 1 | F1: Strategy Agent | `athena-strategy.md` agent definition, Neo4j integration |
| 2 | F2: Bilateral Comms | Agent Teams messaging protocol, dashboard message rendering |
| 3 | F3: Validation Pipeline | Enhanced `athena-verify` with PoC generation, evidence capture |
| 4 | Integration + Testing | End-to-end run against Juice Shop with all Phase F features |

### Month 2: CTF Capability (Weeks 5-8)
| Week | Focus | Deliverable |
|------|-------|-------------|
| 5 | F4: CTF Mode skeleton | `/athena-ctf` skill, challenge classification, flag detection |
| 6 | F4: Web CTF agents | Specialized prompts for SQLi, XSS, SSTI, SSRF, command injection |
| 7 | F5: Cost optimization | Per-agent budgets, early-stopping, dashboard cost tracking |
| 8 | Juice Shop full run | Benchmark: target 80%+ challenges solved autonomously |

### Month 3: Graph Intelligence (Weeks 9-12)
| Week | Focus | Deliverable |
|------|-------|-------------|
| 9 | F6: Attack chain queries | New relationship types, Cypher query library for Strategy Agent |
| 10 | F6: Multi-host reasoning | Lateral movement detection, pivot recommendations |
| 11 | CTF competition prep | PicoCTF or HTB challenge runs, measure and iterate |
| 12 | Benchmark + publish | Run XBOW benchmark subset, document results for ZeroK Labs |

---

## Success Metrics

| Metric | Phase E (Current) | Phase F Target |
|--------|-------------------|----------------|
| Agent communication | Hub-and-spoke | Bilateral mesh + Strategy |
| Finding verification | Manual review | Automated PoC for 80%+ findings |
| Attack chain depth | 2 steps (SQLi → admin) | 4+ steps with lateral movement |
| CTF solve rate (web) | Not tested | 70%+ on PicoCTF web |
| Cost per engagement | Untracked | <$5 for standard web app |
| Time to first finding | ~10 min | <5 min |
| False positive rate | Unknown | <10% (verified findings only) |

---

## Architecture Diagram (Phase F)

```
                    ┌──────────────────┐
                    │  STRATEGY AGENT  │  ← Red Team Lead (Opus)
                    │  (adversarial    │     Reviews all findings
                    │   reasoning)     │     Directs team dynamically
                    └────────┬─────────┘
                             │ bilateral messaging
          ┌──────────────────┼──────────────────┐
          │                  │                  │
    ┌─────┴─────┐     ┌─────┴─────┐     ┌─────┴─────┐
    │   RECON   │────▶│   VULN    │────▶│  EXPLOIT  │
    │ PO,AR,JS  │     │ CV,WV,AP  │     │ EC,EX,AT  │
    └───────────┘     └───────────┘     └─────┬─────┘
                                              │
                                        ┌─────┴─────┐
                                        │  VERIFY   │  ← The Moat
                                        │ Independent│     PoC generation
                                        │ validation │     Evidence capture
                                        └─────┬─────┘
                                              │
                    ┌─────────────────────────┼───────────┐
                    │                         │           │
              ┌─────┴─────┐           ┌──────┴────┐ ┌────┴─────┐
              │ POST-EXPL │           │  CLEANUP  │ │  REPORT  │
              │  PE, LM   │           │    CL     │ │  RP, DV  │
              └───────────┘           └───────────┘ └──────────┘
                    │
                    ▼
              ┌───────────┐
              │  NEO4J    │  ← Attack graph reasoning
              │  Graph    │     Shortest paths, pivots,
              │  Engine   │     chain detection, blast radius
              └───────────┘
```

---

## Risk & Mitigations

| Risk | Mitigation |
|------|-----------|
| Strategy Agent adds latency | Async — runs in parallel while next phase preps |
| Bilateral messaging is noisy | Rate limit: max 5 messages per agent per phase |
| PoC generation creates real damage | All exploit verification in HITL-approved sandbox only |
| CTF mode triggers AUP | Explicit authorization framing, controlled targets only |
| Cost explosion with Opus agents | Per-agent budgets with early-stopping (F5) |
| Agent Teams limitations (no nested teams) | Strategy Agent IS the team lead, not a separate layer |

---

## Dependencies

- [x] Phase E complete (7 agents, tool registry, HITL, Neo4j)
- [x] Kali backends verified (external + internal healthy)
- [x] Claude Code Agent Teams enabled (`CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS=1`)
- [x] OWASP Juice Shop deployed (`web01.your-cloud-domain:3030`)
- [ ] Agent Teams bilateral messaging tested (need proof-of-concept)
- [ ] Neo4j relationship types extended (ENABLES, PIVOTS_TO, ESCALATES_TO)

---

## The 0K ATHENA Vision

Phase F transforms ATHENA from "automated tools with AI reasoning" into "autonomous adversarial intelligence." The Strategy Agent is the brain, bilateral communication is the nervous system, the Validation Pipeline is the credibility, and CTF Mode is the proving ground.

After Phase F, ATHENA will:
1. **Think adversarially** — Not just scan, but reason about attack paths like a red team lead
2. **Verify everything** — Every finding comes with a working PoC (the XBOW/ZeroPath moat)
3. **Compete measurably** — CTF benchmarks prove capability to clients and the market
4. **Scale efficiently** — Cost-optimized per-agent budgets with early-stopping

**This is how a solo builder competes with $117M-funded teams: by building the scaffolding so that each model upgrade multiplies capability automatically.**

---

*0K ATHENA — Offense. Defense. Intel. End-to-end.* 🦖⚡
