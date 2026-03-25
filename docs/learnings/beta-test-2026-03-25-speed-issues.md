# Speed Issues — March 25, 2026 (eng-bacf26 restart)

**Engagement:** 0din Server #4 (restarted), Target: 10.1.1.25/32 (Metasploitable 2)
**Duration:** ~15 min, 0 confirmed exploits, MTTE never populated

---

## Problem

EX agent stuck on vsftpd port 6200 shell — spent most of the engagement retrying one target instead of moving to easier ones. ST redirected EX to ingreslock (1524) and rlogin (513) but EX was slow to pivot. VF couldn't verify because EX hadn't confirmed anything.

Previous engagement (eng-088403, same target) had first exploit at ~6 min and 10 unique CVEs in 29 min. This run: 0 confirmed in 15 min.

## Root Cause: EX Sequential, Single-Target Focus

EX tries one exploit at a time, sequentially. If it gets stuck (shell doesn't respond, connection drops, payload fails), it keeps retrying instead of moving on. No timeout per exploit attempt. No parallel exploitation.

## What Speed Optimization Needs (Priority Order)

### 1. Exploit Attempt Timeout
- Max 60 seconds per exploit attempt
- If no shell/response in 60s → mark as "stalled" → move to next target
- ST should enforce this via the CVE Registry (status: "stalled")

### 2. Known-Vuln Fast Path
- Metasploitable services have KNOWN exploits that work 100% of the time
- EX should check a fast-exploit database before trying complex exploitation
- Ingreslock (port 1524) = `nc <target> 1524` → instant root. No Metasploit needed.
- rlogin (port 513) = `rlogin -l root <target>` → instant root. No exploit needed.
- EX is trying Metasploit for everything when simple commands work faster

### 3. Parallel Exploitation
- EX should attempt 2-3 exploits simultaneously
- First one to confirm shell → register in CVE Registry → others skip
- Resource-aware: check host CPU/memory before spawning parallel agents

### 4. Machine Resource Awareness
- ATHENA's speed depends on the host machine running the agents
- M1 Air (8GB): max 4-5 concurrent agents, sequential EX
- M1/M2 Pro (32GB): 6-8 concurrent agents, parallel EX possible
- ST should check resources at engagement start and adapt strategy

### 5. Sprint Mode
- New engagement mode: race to first shell in < 2 min
- Skip full recon, go straight to known-vuln fast path
- Stop after first confirmed shell
- Speed Report Card showing TTFS (Time to First Shell)

## Evidence That Speed Optimization Will Help

| Engagement | Target | MTTE | Confirmed | Duration | Notes |
|------------|--------|------|-----------|----------|-------|
| eng-088403 (#3) | Metasploitable 2 | 6m 23s | 38 | 39 min | After neo4j_exec fix |
| eng-bacf26 (#4 restart) | Metasploitable 2 | — | 0 | 15+ min | EX stuck on vsftpd |

Same target, dramatically different results. The difference: EX's first attempt succeeded in #3 but got stuck in #4. Speed optimization (timeouts + parallel + fast path) would prevent this.

## Next Session Priority

1. Speed Optimization Phase 1: TTFS KPI + exploit attempt timeout
2. Speed Optimization Phase 2: Sprint Mode + known-vuln fast path
3. Speed Optimization Phase 3: Parallel EX + resource awareness

**Reference:** `docs/plans/2026-03-24-speed-optimization-plan.md`
