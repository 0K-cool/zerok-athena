# ATHENA Speed Optimization Plan

**Date:** March 24, 2026
**Author:** Kelvin Lomboy + Vex
**Status:** PLANNING
**Priority:** HIGH — Product differentiator + realistic adversary simulation

---

## Why Speed Matters

### Threat Landscape (2026)

Real-world AI-powered adversaries are operating at machine speed:

| Metric | Real Adversary | Source |
|--------|---------------|--------|
| Fastest breakout (compromise → lateral) | **27 seconds** | CrowdStrike 2026 GTR |
| Average eCrime breakout | **29 minutes** | CrowdStrike 2026 GTR |
| Fastest 25% full lifecycle (access → exfil) | **72 minutes** | Unit 42 2026 IR |
| YoY speed increase | **4x faster** | Unit 42 2026 IR |
| Mean time to exfiltrate | **30 min** (was 9 days in 2021) | Aggregated |

**State-sponsored AI attack documented:** Chinese campaign used Claude Code autonomously — 80-90% of tactical operations executed without human intervention. Targeted ~30 global organizations.

### ATHENA Current Performance (eng-aadee9 baseline)

| Metric | Current | Target | Gap |
|--------|---------|--------|-----|
| MTTE (Mean Time to Exploit) | 42m 55s | < 5 min | ~8.5x |
| Time to First Shell | Unknown (not measured) | < 2 min | Not tracked |
| Full engagement duration | 1h 33m | < 30 min | ~3x |
| Agent parallelism | Sequential (mostly) | 3-5 concurrent | Significant |

### Competitive Landscape

| Tool | Approach | Speed Claim |
|------|----------|-------------|
| **XBOW** | Autonomous offensive, Microsoft partnership | "Continuous" — no engagement window |
| **PentestGPT** | Multi-agent LLM, 12.1K GitHub stars | Per-phase agents, research-grade |
| **xOffense** | Knowledge-enhanced LLMs | arXiv Sep 2025 |
| **VulnBot** | Multi-agent collaborative | Research |
| **PentestAgent** | LLM agents, ASIA CCS '25 | Academic |
| **ATHENA** | Claude SDK + real Kali tools + Neo4j | 42m MTTE (current) |

---

## Optimization Strategy

### Phase 1: Measure (Week 1)

Before optimizing, add instrumentation.

#### New KPIs to Track

1. **Time to First Shell (TTFS)** — Engagement start → first confirmed RCE/shell access
   - This is the metric CrowdStrike uses ("breakout time")
   - Display alongside MTTE in KPI bar
   - Store on Engagement node: `first_shell_at` timestamp

2. **Phase Transition Times** — Time spent in each PTES phase
   - Pre-Engagement → Intel Gathering: how long?
   - Intel Gathering → Exploitation: how long?
   - Exploitation → First Shell: how long?
   - Track bottlenecks per phase

3. **Agent Utilization** — Percentage of time each agent is actively working vs waiting
   - Idle time = optimization opportunity
   - Track via agent status WebSocket messages

4. **Tool Execution Latency** — Per-tool round-trip time
   - Kali tool call → result received
   - Identify slow tools (nmap full scan vs targeted scan)
   - Track via existing Langfuse integration

#### Implementation
- Add `first_shell_at` property to Engagement node in Neo4j
- EX agent: when first shell/RCE is confirmed, POST to `/api/engagements/{eid}/first-shell`
- Dashboard: add TTFS KPI card next to MTTE
- Phase timing: log phase transitions with timestamps to Neo4j

---

### Phase 2: Sprint Mode (Week 2)

New engagement mode: **Sprint** — race to first shell using the highest-probability attack path.

#### Sprint Mode Behavior

```
Normal Mode (current):
  AR (full recon) → DA (full analysis) → EX (all vulns) → VF (all confirms) → RP

Sprint Mode (new):
  AR (fast scan) → EX (top 3 vulns) → VF (first shell only) → STOP
  └── Parallel: DA analyzes while EX exploits
```

#### Key Differences from Normal Mode

| Aspect | Normal Mode | Sprint Mode |
|--------|-------------|-------------|
| Recon scope | Full nmap + naabu + httpx | naabu (ports only) + top-20 nmap scripts |
| Analysis | All services analyzed | Top 3 by CVSS only |
| Exploitation | All exploitable vulns | First 3 highest-probability only |
| Verification | All exploits verified | First shell only, then stop |
| Post-exploitation | Full PE + credential harvest | Skip entirely |
| Reporting | Full PTES report | One-page speed report |
| Goal | Comprehensive assessment | "Can we get a shell in < 2 minutes?" |

#### Sprint Mode Configuration

```yaml
# In athena-config.yaml or engagement creation
mode: sprint
sprint:
  recon_timeout: 30s        # Max time for initial recon
  max_exploit_attempts: 3   # Try top 3 only
  stop_on_first_shell: true # Stop after first confirmed shell
  skip_post_exploitation: true
  skip_verification: true   # First shell IS the verification
  target_ttfs: 120s         # Target: 2 minutes
```

#### Sprint Mode Agent Strategy

ST (Strategy) prompt modifications for Sprint:
1. "Your goal is SPEED. Get a shell as fast as possible."
2. "Do NOT wait for full recon. Start exploitation after first 10 ports discovered."
3. "Prioritize known-vulnerable services: vsftpd 2.3.4, Tomcat default creds, MS17-010, CVE-2024-xxxx"
4. "Run AR and EX in PARALLEL — don't wait for AR to finish"
5. "Stop the engagement the moment EX confirms a shell"

---

### Phase 3: Parallel Execution (Week 3)

Currently agents are mostly sequential. Real attackers parallelize.

#### Parallelization Opportunities

1. **AR + EX overlap** — Start exploitation on discovered services while recon continues
   - AR discovers port 21 (vsftpd) → immediately spawn EX for vsftpd
   - AR continues scanning remaining ports
   - Don't wait for full port scan

2. **Multiple EX instances** — Exploit 3-5 services simultaneously
   - EX-1: vsftpd backdoor
   - EX-2: Tomcat default creds
   - EX-3: MySQL no-password root
   - First one to shell wins

3. **VF parallel batches** — Verify 2-3 exploits simultaneously
   - Batch nmap NSE scripts: `nmap -p 21,445,8080 --script <all-relevant>`
   - Don't verify one port at a time

4. **DA + EX pipeline** — DA feeds EX in real-time
   - DA finds CVE → immediately queue for EX
   - Don't wait for DA to finish analyzing all services

#### Implementation Approach

Option A: Multiple concurrent agent sessions (resource-intensive)
- Spawn 3 EX sessions simultaneously
- Requires host resource check (FR-S2-002 from bug report)
- M1 Air: max 4-5 concurrent agents

Option B: Single EX with parallel tool calls (lighter)
- EX sends multiple Kali tool requests via asyncio
- Kali backend handles them in parallel
- Less host resource pressure

Option C: Hybrid (recommended)
- Sprint Mode: Option B (single EX, parallel tools)
- Normal Mode: Option A when host resources allow

---

### Phase 4: Intelligence-Driven Speed (Week 4)

Use ATHENA's knowledge base to skip unnecessary steps.

#### Known-Vuln Fast Path

Maintain a "fast exploit" database:
```yaml
# docs/knowledge/fast-exploits.yml
fast_exploits:
  - service: "vsftpd 2.3.4"
    exploit: "exploit/unix/ftp/vsftpd_234_backdoor"
    ttfs: "< 5s"
    reliability: "100%"

  - service: "Tomcat/7 default"
    exploit: "auxiliary/scanner/http/tomcat_mgr_login"
    ttfs: "< 10s"
    reliability: "95%"

  - service: "MS17-010"
    exploit: "exploit/windows/smb/ms17_010_eternalblue"
    ttfs: "< 15s"
    reliability: "90%"
```

When AR identifies a known-vulnerable service, EX skips DA entirely and goes straight to the fast exploit. This is how real attackers work — they have playbooks for known vulns.

#### RAG-Accelerated Exploitation

Current flow: AR finds vuln → DA searches CVE databases → EX writes exploit
Fast flow: AR finds vuln → RAG lookup in fast-exploit DB → EX executes immediately

The 16 playbooks in `docs/playbooks/` already cover common attack patterns. Make them machine-readable for instant lookup.

---

### Phase 5: Benchmark & Report (Week 5)

#### Speed Benchmarks

Run ATHENA in Sprint Mode against standardized targets:

| Target | Difficulty | Expected TTFS |
|--------|-----------|---------------|
| Metasploitable 2 | Easy | < 30 seconds |
| DVWA | Easy | < 1 minute |
| HackTheBox Easy | Medium | < 5 minutes |
| HackTheBox Medium | Hard | < 15 minutes |
| Real client (hardened) | Realistic | < 30 minutes |

#### Speed Report Card

New report type generated after Sprint Mode:

```
═══════════════════════════════════════
   ATHENA SPEED ASSESSMENT REPORT
═══════════════════════════════════════

Target: 10.1.1.25 (Metasploitable 2)
Mode: Sprint
Date: 2026-03-24

TIME TO FIRST SHELL: 00:00:27
──────────────────────────────
  Recon:        0:00:08 (naabu fast scan)
  Analysis:     0:00:04 (vsftpd 2.3.4 identified)
  Exploitation: 0:00:15 (backdoor shell confirmed)

ATTACK PATH:
  naabu → port 21 open → vsftpd 2.3.4 banner →
  exploit/unix/ftp/vsftpd_234_backdoor → root shell

BENCHMARK COMPARISON:
  CrowdStrike fastest: 27 seconds
  ATHENA Sprint:       27 seconds  ✅ MATCH
  Your MTTD (detect):  ???

  ⚠️  If your team can't detect and respond
     in under 27 seconds, this attack succeeds.

RECOMMENDATION:
  Deploy EDR with < 10s detection latency
  Enable automated containment (isolate on first shell)
  Monitor vsftpd 2.3.4 — immediate patch required
═══════════════════════════════════════
```

This report is the **sales weapon** — show a client their system was owned in 27 seconds, then offer the remediation engagement.

---

## Marketing Angle

### Blog Post: "Can Your Defenses Survive a 27-Second Breakout?"

1. Open with CrowdStrike's 27-second stat
2. "We built an AI pentesting platform that simulates real adversary speed"
3. Run Sprint Mode against Metasploitable, show the timeline
4. Compare to traditional pentest (2-week engagement vs 27 seconds)
5. Close with: "If AI attackers can breach you in 27 seconds, your annual pentest isn't enough"

### Client Pitch

"CrowdStrike documented a 27-second breakout time. We can simulate that against your infrastructure and tell you exactly where you'd fail — and how to fix it."

**Tier 1 add-on:** Sprint Assessment ($3-5K, half-day engagement)
**Deliverable:** Speed Report Card showing time-to-shell for each network segment

---

## Implementation Priority

| Phase | Effort | Impact | Timeline |
|-------|--------|--------|----------|
| 1. Measure (TTFS KPI) | LOW | HIGH | Week 1 |
| 2. Sprint Mode | MEDIUM | HIGH | Week 2 |
| 3. Parallel Execution | HIGH | HIGH | Week 3 |
| 4. Intelligence-Driven | MEDIUM | MEDIUM | Week 4 |
| 5. Benchmark & Report | LOW | HIGH (marketing) | Week 5 |

**Phase 1 is the minimum viable optimization** — just measuring TTFS changes how clients think about security. The rest builds on it.

---

## Dependencies

- Bug fixes first (SYSTEMIC ✅, MTTE ✅, Invalid Date ✅, Coverage ✅)
- FR-S2-002 (parallel agents) from bug report — directly feeds Phase 3
- FR-S2-003 (ST override authority) — ST needs to force-stop for Sprint Mode
- BUG-003 (CR timeout) — CR must stay alive for operator feedback during Sprint

---

## Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|-----------|
| Sprint Mode misses vulns | Client has false sense of security | Always recommend Normal Mode for comprehensive assessment; Sprint is supplemental |
| Parallel agents crash host | Engagement fails mid-test | Resource check at start (FR-S2-002), adaptive throttling |
| Speed benchmarks vary by network | Inconsistent results | Standardize on local targets for benchmarks, real targets for assessments |
| Competitors announce similar | Reduced differentiation | Ship first, iterate fast |

---

## References

- CrowdStrike 2026 Global Threat Report (Feb 24, 2026)
- Palo Alto Unit 42 2026 Global IR Report (Feb 2026)
- IBM 2026 X-Force Threat Intelligence Index (Feb 25, 2026)
- Anthropic: Disrupting the First AI-Orchestrated Cyber Espionage Campaign (Nov 2025)
- arXiv:2512.09882 — AI Agents vs Cybersecurity Professionals in Real-World Pentesting
- ATHENA bug report: FR-S2-002 (parallel agents), FR-S2-003 (ST override)

---

**"If AI attackers operate at machine speed, your pentest must simulate machine speed."** 🦖⚡
