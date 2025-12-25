# VERSANT Pentest Automation Roadmap
**Inspired by Chinese State-Sponsored AI-Powered Offensive Operations**

**Document Date:** December 15, 2025
**Context:** Analysis conducted ahead of external pentest engagement
**Goal:** Maximize automation with Human-in-the-Loop (HITL) critical decision points

---

## 📊 EXECUTIVE SUMMARY

### Chinese Threat Actor Intelligence (September-December 2025)

**GTG-1002 Campaign - World's First Large-Scale AI-Orchestrated Cyberattack:**
- **Adversary:** Chinese state-sponsored threat actors
- **Tool:** Anthropic's Claude Code (weaponized)
- **Automation Level:** **80-90% autonomous** tactical operations
- **Scale:** 30 global targets (tech, finance, chemical, government)
- **Speed:** Thousands of requests per second (physically impossible for humans)
- **Capability:** AI instances operating as autonomous penetration testing orchestrators

**Key Lessons for Defensive Pentesting:**
1. **Agent Orchestration** - Multiple specialized agents working in coordination
2. **Rapid Exploit Weaponization** - Hours/days after PoC publication
3. **Automated Reconnaissance** - Intelligent target analysis and prioritization
4. **Detection Evasion** - User agent randomization, adaptive techniques
5. **Active Debugging** - Real-time refinement of exploits against live targets
6. **Vulnerability Chaining** - Connecting low-severity findings into critical paths

**Anthropic's Response:** Disrupted campaign, published [research](https://www.anthropic.com/news/disrupting-AI-espionage)

---

## 🎯 PROJECT STATUS EVALUATION

### Current Capabilities ✅

**Tooling:**
- ✅ Kali Linux MCP (Nmap, Gobuster, Nikto, Dirb, SQLmap, Hydra, Enum4linux)
- ✅ Playwright MCP (Modern web app testing, SPA/PWA automation)
- ✅ Velociraptor MCP (For IR cross-platform integration)

**Slash Commands (6 operational):**
- ✅ `/engage` - Engagement initialization with comprehensive checklist
- ✅ `/scan` - Automated scanning phase with evidence collection
- ✅ `/scan-spa` - Modern web application testing (React/Vue/Angular)
- ✅ `/validate` - Non-destructive vulnerability validation
- ✅ `/evidence` - Evidence compilation and organization
- ✅ `/cloud-pentest` - Cloud infrastructure testing (AWS/Azure/GCP)

**Playbooks:**
- ✅ SQL Injection Testing (detailed methodology)
- ✅ Playwright Web Testing (comprehensive SPA assessment)
- ✅ Active Directory Responder Attacks
- ✅ Cloud Penetration Testing (multi-cloud)

**Philosophy:**
- ✅ Non-destructive testing policy (well-defined)
- ✅ Evidence collection standards (screenshot naming, command logging)
- ✅ PTES/OWASP/NIST methodology compliance

---

### Critical Gaps 🚧 (Work in Progress)

**Missing Slash Commands:**
- ❌ `/report` - Automated report generation
- ❌ `/retest` - Post-remediation validation
- ❌ `/enumerate` - Deep service enumeration
- ❌ `/vuln-assess` - Vulnerability analysis and prioritization

**Automation Gaps:**
- ❌ **No orchestration workflow** - Manual command execution required
- ❌ **No automated vulnerability chaining** - Pattern recognition missing
- ❌ **No intelligent exploit selection** - Manual CVE cross-referencing
- ❌ **No multi-target agent swarms** - Single-target linear workflow
- ❌ **No automated scan result analysis** - Human parses all outputs
- ❌ **No adaptive testing logic** - Static methodology regardless of findings
- ❌ **No HITL checkpoint framework** - Ad-hoc approval process

**Evidence Collection:**
- ⚠️ **Manual screenshot capture** - No automated evidence pipeline
- ⚠️ **Command logging** - Manual documentation in markdown
- ⚠️ **No automated report generation** - Fully manual process

**Intelligence Integration:**
- ❌ **No threat intel integration** - CVE feeds not automated
- ❌ **No exploit DB automation** - Manual exploit research
- ❌ **No IOC cross-referencing** - No link to IR platform

---

## 🤖 AUTOMATION ARCHITECTURE (Inspired by GTG-1002)

### Principle: 80-90% Automation + Human-in-the-Loop (HITL)

**Automation Zones (AI Autonomous):**
- ✅ **Reconnaissance** - OSINT, subdomain enumeration, port scanning
- ✅ **Scanning** - Network, web, service enumeration
- ✅ **Vulnerability Identification** - CVE mapping, CVSS scoring
- ✅ **Evidence Collection** - Automated screenshots, logging, artifact capture
- ✅ **Report Drafting** - Initial findings compilation
- ✅ **Exploit Research** - CVE/ExploitDB cross-referencing

**HITL Checkpoints (Human Decision Required):**
- 🔴 **Authorization Verification** - Before ANY testing begins
- 🔴 **Scope Confirmation** - Before scanning each new target/subnet
- 🔴 **Exploit Execution** - Before validating any vulnerability
- 🔴 **Credential Testing** - Before password attacks (lockout risk)
- 🔴 **Service Impact Risk** - Before potentially disruptive tests
- 🔴 **Critical Finding Notification** - Human reviews and notifies client
- 🔴 **Report Finalization** - Human reviews and approves deliverable
- 🔴 **Client Communication** - All stakeholder communication human-led

---

## 🚀 RECOMMENDED IMPLEMENTATION

### Phase 1: Immediate (For Tomorrow's External Pentest) ⚡

**Priority 1: Automated Orchestration Workflow**

Create `/automate-pentest` slash command that orchestrates multi-phase automation:

```markdown
# /automate-pentest [TARGET]

## HITL Checkpoint 1: Authorization Verification
- [ ] User confirms written authorization exists
- [ ] User confirms target is in-scope
- [ ] User provides evidence storage path
→ **User approval required to proceed**

## Phase 1: Reconnaissance (Automated)
**AI Executes:**
1. DNS enumeration (subdomains, zone transfers)
2. WHOIS lookups
3. Technology stack fingerprinting
4. Port discovery (top 1000 ports)
5. Extract live hosts and open services

**Output:** Reconnaissance summary with prioritized targets

## HITL Checkpoint 2: Reconnaissance Review
- [ ] AI presents: X live hosts, Y open ports, Z web applications
- [ ] AI recommends: "Focus on [high-value targets]"
- [ ] User reviews and approves scan targets
→ **User approval required to proceed**

## Phase 2: Comprehensive Scanning (Automated)
**AI Executes:**
1. Full TCP port scan (all 65535 ports)
2. Service version detection
3. NSE vulnerability scripts
4. Web directory enumeration (Gobuster)
5. Web vulnerability scanning (Nikto)
6. Technology-specific scans (WordPress, etc.)

**Parallel Execution:** Multiple targets scanned simultaneously
**Evidence Collection:** Auto-screenshot all tool outputs

**Output:** Vulnerability summary with CVSS scores

## HITL Checkpoint 3: Vulnerability Review
- [ ] AI presents: X critical, Y high, Z medium vulnerabilities
- [ ] AI flags: Potential false positives
- [ ] AI recommends: "Validate [specific vulns] first"
- [ ] User selects vulnerabilities to validate
→ **User approval required to proceed**

## Phase 3: Vulnerability Validation (Automated with HITL per exploit)
**For each selected vulnerability:**

**AI Proposes:**
- Vulnerability: SQL Injection in login.php
- Validation Method: Read-only query (SELECT @@version)
- Risk Level: Medium (no data exfiltration)
- Expected Impact: Database version disclosure

**HITL Checkpoint:** User approves validation
→ **User approves EACH validation individually**

**AI Executes:**
1. Execute non-destructive POC
2. Capture screenshots automatically
3. Log commands with timestamps
4. Document reproduction steps
5. Assess actual impact

**Output:** Validated findings with evidence

## Phase 4: Evidence Compilation (Automated)
**AI Executes:**
1. Organize all screenshots (proper naming)
2. Compile command logs
3. Create vulnerability writeups
4. Cross-reference CVEs
5. Map to MITRE ATT&CK
6. Package evidence archive

**Output:** Structured evidence ready for reporting

## HITL Checkpoint 4: Final Review
- [ ] User reviews all findings
- [ ] User confirms evidence completeness
- [ ] User approves report generation
→ **User approval required to finalize**

## Phase 5: Report Generation (Automated Draft)
**AI Generates:**
1. Executive summary (business impact)
2. Technical findings (detailed vulnerability analysis)
3. CVSS scoring and risk prioritization
4. Remediation recommendations
5. MITRE ATT&CK mapping
6. Appendices (methodology, tools, references)

**Output:** Draft report for human review and client delivery

## Post-Automation
**Human Reviews:**
- Report accuracy and completeness
- Client-specific context and recommendations
- Professional tone and language
- Delivers to client with presentation
```

---

**Priority 2: Agent Orchestration System**

Create specialized subagents (inspired by GTG-1002 multi-agent architecture):

**Agent 1: Recon Specialist**
- Subdomain enumeration
- OSINT gathering
- DNS analysis
- Network topology mapping

**Agent 2: Web Scanner**
- Modern SPA testing (Playwright)
- Traditional web scanning (Nikto, Gobuster)
- API endpoint discovery
- Authentication flow analysis

**Agent 3: Network Scanner**
- Port scanning (Nmap)
- Service version detection
- Vulnerability script scanning
- Network service enumeration

**Agent 4: Vulnerability Analyst**
- CVE cross-referencing
- CVSS scoring
- Exploit research (ExploitDB)
- Vulnerability chaining
- False positive elimination

**Agent 5: Evidence Collector**
- Automated screenshot capture
- Command logging
- Artifact preservation
- Evidence organization

**Agent 6: Report Writer**
- Executive summary generation
- Technical writeup compilation
- Remediation guidance
- MITRE ATT&CK mapping

**Orchestrator Agent:**
- Coordinates all specialized agents
- Presents HITL checkpoints
- Manages workflow progression
- Aggregates findings

---

**Priority 3: Automated Evidence Collection Pipeline**

Enhance evidence collection with zero-touch automation:

**Automated Screenshot Capture:**
```python
# Hook into every tool execution
# Pre-execution: Screenshot command
# Post-execution: Screenshot results
# Auto-naming: [NUM]-[SEVERITY]-[CATEGORY]-[DESC]-[TIMESTAMP].png
```

**Automated Command Logging:**
```python
# Every Bash/MCP tool call logged automatically
# Format: commands-used.md with timestamps
# Includes: command, purpose, results, screenshot reference
```

**Automated Artifact Capture:**
```python
# Save all tool outputs (XML, JSON, TXT)
# Capture network traffic (HAR files from Playwright)
# Preserve HTTP requests/responses
# Auto-organize in evidence directory
```

---

### Phase 2: Short-Term (Week 2-3) 🏗️

**Priority 4: Missing Slash Commands**

**`/enumerate [SERVICE/PORT]`**
- Deep service enumeration based on scan results
- SMB shares, SNMP communities, LDAP, RPC
- Technology-specific enumeration
- HITL: Approval before credential-based enumeration

**`/vuln-assess [SCAN_RESULTS]`**
- Automated vulnerability analysis
- CVE database cross-referencing
- Exploit availability check (ExploitDB, Metasploit)
- Vulnerability chaining identification
- CVSS scoring and prioritization
- False positive flagging with rationale

**`/report [ENGAGEMENT]`**
- Automated report generation
- Executive summary (non-technical, business impact)
- Technical findings (detailed with evidence)
- Remediation roadmap (prioritized)
- MITRE ATT&CK technique mapping
- Compliance mapping (PCI DSS, HIPAA, SOC 2)
- HITL: Human reviews and finalizes before delivery

**`/retest [ENGAGEMENT]`**
- Post-remediation validation automation
- Retest only previously vulnerable findings
- Compare before/after states
- Generate retest report
- Certificate of remediation (if all fixed)

---

**Priority 5: Intelligent Vulnerability Chaining**

Implement AI-powered vulnerability chaining (inspired by GTG-1002):

**Pattern Recognition:**
- Identify information disclosure → Combine with weak credentials → RCE
- Detect SSRF → Chain with internal service access → Privilege escalation
- Find XSS → Combine with CSRF → Account takeover
- Discover file upload → Chain with path traversal → Code execution

**Chaining Logic:**
```
Low-Severity Vuln A + Low-Severity Vuln B = Critical Attack Path
```

**Output:** "Attack chain report" showing multi-step exploitation paths

---

**Priority 6: Adaptive Testing Logic**

Implement dynamic methodology adjustments based on findings:

**Technology Detection:**
```
If WordPress detected:
  → Run WPScan
  → Check for known plugin vulnerabilities
  → Test XML-RPC abuse
  → Enumerate users
```

**Service-Specific Adaptation:**
```
If SMB (port 445) open:
  → Run Enum4linux
  → Check for null session
  → Test EternalBlue vulnerability
  → Enumerate shares
```

**Framework Detection:**
```
If React/Vue/Angular detected:
  → Use Playwright instead of traditional scanners
  → Focus on API endpoint discovery
  → Test client-side security
  → Inspect browser storage
```

---

### Phase 3: Mid-Term (Month 2) 🔧

**Priority 7: Multi-Target Agent Swarms**

Implement parallel multi-target testing (inspired by GTG-1002's scale):

**Swarm Architecture:**
```
User provides: 10 target IPs/domains

Orchestrator spawns:
- 10 Recon Agents (one per target)
- 10 Scanner Agents (one per target)
- 1 Aggregation Agent (consolidates findings)

Parallel execution:
- All targets scanned simultaneously
- Findings aggregated in real-time
- HITL checkpoints at phase boundaries
```

**Benefits:**
- 10x faster engagements
- Consistent methodology across all targets
- Centralized findings dashboard
- Efficient resource utilization

**HITL Checkpoints:**
- Phase transitions (recon → scanning → validation)
- Per-target scope confirmation
- Aggregate findings review before validation

---

**Priority 8: Threat Intel Integration**

Integrate with IR platform and external threat intel:

**CVE Feed Automation:**
- Daily CVE updates from NIST NVD
- Cross-reference discovered services with recent CVEs
- Alert on 0-day or recently disclosed vulnerabilities
- Prioritize based on CVSS + EPSS (exploit prediction)

**ExploitDB Integration:**
- Automated exploit search for discovered vulnerabilities
- POC availability flagging
- Exploit maturity assessment
- Safe exploit recommendation (non-destructive)

**IR Platform Integration:**
- Share IOCs from validated vulnerabilities
- Feed findings into Velociraptor for compromise assessment
- Cross-reference pentest findings with IR baseline
- Enable "assume breach" testing with IR context

---

**Priority 9: Detection Evasion Techniques**

Implement adaptive stealth capabilities (ethically for red team):

**User Agent Randomization:**
```python
# Rotate user agents for web scanning
# Avoid fingerprinting as automated scanner
# Mimic legitimate browser behavior
```

**Traffic Shaping:**
```python
# Variable timing between requests
# Randomized scan order
# Adaptive rate limiting based on target response
# Jitter injection to avoid pattern detection
```

**HITL Checkpoint:** User approves stealth level (Loud/Moderate/Stealthy)

---

### Phase 4: Long-Term (Month 3+) 🚀

**Priority 10: Advanced Automation Features**

**Automated Exploit Development:**
- Generate custom POC exploits for validated vulnerabilities
- Fuzzing automation for bug discovery
- Automated payload customization
- HITL: User approves exploit execution

**ML-Powered Vulnerability Prediction:**
- Train model on historical pentest findings
- Predict likely vulnerabilities based on technology stack
- Prioritize testing efforts on high-probability targets
- Reduce false positives through pattern learning

**Continuous Pentesting Pipeline:**
- Scheduled automated pentests
- CI/CD integration for dev/staging environments
- Automated regression testing
- Drift detection (new services, config changes)

---

## 📋 IMPLEMENTATION CHECKLIST (Tomorrow's Pentest)

### Immediate Pre-Engagement (Tonight/Tomorrow Morning)

**Setup Tasks:**
- [ ] Review and update `/engage` command for client engagement
- [ ] Prepare encrypted external drive for evidence
- [ ] Verify Kali MCP connectivity: `mcp__kali_mcp__server_health()`
- [ ] Test Playwright MCP for modern web app testing
- [ ] Create quick-reference HITL checkpoint card

**Quick Wins (Implement Tonight):**
- [ ] Create basic `/automate-pentest` orchestration command
- [ ] Implement automated screenshot capture wrapper
- [ ] Set up parallel scanning for multiple targets
- [ ] Create vulnerability chaining analysis template

---

### During Tomorrow's Engagement

**Phase 1: Engagement Initialization**
```bash
/engage [CLIENT_NAME] External Pentest
```
- ✅ Authorization verification (HITL)
- ✅ Scope confirmation (HITL)
- ✅ Evidence storage setup
- ✅ Client communication protocol

**Phase 2: Automated Reconnaissance**
```bash
/automate-pentest [TARGET_NETWORK]
```
- ✅ AI executes reconnaissance
- ✅ HITL: Review discovered targets
- ✅ Approve scope for scanning phase

**Phase 3: Automated Scanning**
- ✅ AI orchestrates multi-tool scanning
- ✅ Parallel execution where possible
- ✅ Auto-capture evidence
- ✅ HITL: Review vulnerability summary

**Phase 4: Vulnerability Validation**
- ✅ AI proposes validation approach for each finding
- ✅ HITL: Approve EACH validation individually
- ✅ AI executes non-destructive POC
- ✅ Auto-document findings

**Phase 5: Evidence & Reporting**
```bash
/evidence [ENGAGEMENT_NAME]
/report [ENGAGEMENT_NAME]
```
- ✅ AI compiles comprehensive evidence
- ✅ AI generates draft report
- ✅ HITL: Final review and approval
- ✅ Deliver to client

---

## 🎯 SUCCESS METRICS

### Automation KPIs

**Speed:**
- Target: 80-90% automation (matching GTG-1002 campaign)
- Baseline: Currently ~30% automated (manual scan analysis, validation, reporting)
- Goal: 5x faster engagements with same quality

**Coverage:**
- Comprehensive multi-tool scanning (Nmap, Gobuster, Nikto, Playwright)
- Automated vulnerability chaining
- Zero manual evidence collection

**Quality:**
- 100% repeatability (client can reproduce all findings)
- Zero false positives in final report
- HITL approval at all critical decision points

**Safety:**
- Zero service disruptions
- Zero unauthorized actions
- 100% non-destructive testing compliance
- Full audit trail of all actions

---

## ⚖️ ETHICAL BOUNDARIES

### Defensive Automation vs. Offensive Automation

**GTG-1002 Used AI For:**
- ❌ Unauthorized access
- ❌ Data exfiltration
- ❌ Espionage campaign
- ❌ Evasion of law enforcement

**We Use AI For:**
- ✅ Authorized penetration testing
- ✅ Client security improvement
- ✅ Vulnerability validation (non-destructive)
- ✅ Professional security services

### Human-in-the-Loop Guarantee

**AI Never Autonomously:**
- ❌ Starts testing without authorization
- ❌ Expands scope without approval
- ❌ Executes exploits without human review
- ❌ Communicates with client
- ❌ Makes ethical decisions

**Human Always:**
- ✅ Verifies authorization and scope
- ✅ Approves each validation attempt
- ✅ Reviews all findings before reporting
- ✅ Makes final decisions
- ✅ Maintains ethical standards

---

## 📚 REFERENCES

### Chinese Threat Actor Intelligence
- [Anthropic: Disrupting AI-Orchestrated Cyber Espionage](https://www.anthropic.com/news/disrupting-AI-espionage)
- [Chinese Hackers Use Anthropic's AI for Automated Cyber Espionage](https://thehackernews.com/2025/11/chinese-hackers-use-anthropics-ai-to.html)
- [AI-Powered Cyberattacks Surge as Anthropic Unveils China Hack](https://www.axios.com/2025/11/16/ai-cyberattacks-foreign-governments)
- [World's First Large-Scale Cyberattack Executed by AI](https://ia.acs.org.au/article/2025/world-s-first-large-scale-cyberattack-executed-by-ai.html)
- [Chinese Use of Claude AI for Hacking Will Drive Demand for AI Cyber Defense](https://breakingdefense.com/2025/11/chinese-use-of-claude-ai-for-hacking-will-drive-demand-for-ai-cyber-defense-say-experts/)
- [China-Nexus Threat Groups Rapidly Exploit React2Shell Vulnerability](https://aws.amazon.com/blogs/security/china-nexus-cyber-threat-groups-rapidly-exploit-react2shell-vulnerability-cve-2025-55182/)
- [CISA: Countering Chinese State-Sponsored Actors](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a)

### Penetration Testing Standards
- [PTES: Penetration Testing Execution Standard](http://www.pentest-standard.org/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [NIST SP 800-115: Technical Security Testing](https://csrc.nist.gov/publications/detail/sp/800-115/final)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Anthropic AI Cyber Defenders Research](https://www.anthropic.com/research/building-ai-cyber-defenders)
- [CrowdStrike 2025 Threat Hunting Report](https://www.crowdstrike.com/en-us/blog/crowdstrike-2025-threat-hunting-report-ai-weapon-target/)

---

## 🔐 CONCLUSION

The GTG-1002 campaign demonstrates that AI-powered offensive automation is now a reality. Chinese state-sponsored actors achieved 80-90% automation using Claude Code as an autonomous penetration testing orchestrator.

**Our Defensive Response:**
We leverage the SAME AI capabilities for authorized penetration testing, maintaining ethical boundaries through Human-in-the-Loop checkpoints. This allows us to:
1. **Match adversary speed and scale** (defensive advantage)
2. **Maintain quality and ethics** (professional standards)
3. **Deliver faster, more comprehensive** security assessments
4. **Help clients defend** against AI-powered threats

**For tomorrow's external pentest:** Implement Phase 1 priorities (automated orchestration, HITL checkpoints, evidence pipeline) to deliver a more efficient, comprehensive, and professional engagement.

**Long-term vision:** Build the most advanced AI-powered defensive penetration testing platform, matching adversary capabilities while maintaining the highest ethical and professional standards.

---

**Document Status:** Strategic Roadmap - Ready for Implementation
**Next Review:** After tomorrow's external pentest (capture lessons learned)
**Owner:** Kelvin Lomboy, VERSANT Security
**Last Updated:** December 15, 2025
