# ATHENA - AI-Powered Penetration Testing Platform

**Automated Tactical Hacking and Exploitation Network Architecture**

ATHENA is a multi-agent AI penetration testing platform that coordinates specialized agents to conduct authorized security assessments. Built on the Claude Agent SDK, it combines autonomous AI capabilities with human-in-the-loop (HITL) safety gates — adapting its autonomy level to the engagement context.

> **AI + Human oversight > AI alone** — Inspired by [Anthropic's AI Cyber Defenders](https://www.anthropic.com/research/building-ai-cyber-defenders)

---

## Key Features

- **Multi-Agent AI Team** — 6 specialized agents (Strategy, Recon, Vuln Scanner, Exploitation, Verification, Reporting) coordinate through a shared knowledge graph
- **Tiered Autonomy** — CTF/Lab mode (full autonomy) vs Client mode (HITL gates) vs Client Auto (client-approved automation)
- **Cross-Engagement Intelligence (CEI)** — Learns from past engagements. Agents skip known dead-ends and prioritize proven techniques
- **Bilateral Communication** — Agents coordinate through Neo4j + real-time messaging, not just sequential handoffs
- **Real-Time Dashboard** — Single-page web UI with agent LEDs, live event feed, HITL approval modals, and scope management
- **Dual Kali Backends** — External (cloud) + Internal (on-premise via ZeroTier) with 50+ offensive tools
- **PTES Methodology** — Full 7-phase penetration testing execution standard with phase gating
- **One-Command Startup** — `./start.sh` handles everything including Docker services

---

## Tiered Autonomy Model

ATHENA adapts its safety behavior to the engagement context:

| Mode | Novel Tools | Exploitation | HITL Gates | Use Case |
|------|-----------|-------------|-----------|----------|
| **CTF / Lab** | Full autonomy — notify ST | Full autonomy — notify ST | None | Practice, CTFs, training labs |
| **Client** (default) | ST evaluates → HITL approval | ST evaluates → HITL approval | Exploitation, scope expansion, novel tools | Healthcare, production, compliance |
| **Client Auto** | Full autonomy | Full autonomy | None | Client opts into full automation |

**Why this matters:** Most AI pentest tools are either fully manual (HITL on every action) or fully autonomous (no guardrails). ATHENA's tiered model lets you run wide-open in a lab, then flip to compliance-ready for a hospital — same platform, same agents, different risk profile.

### Novel Technique Protocol

Worker agents (AR, WV, EX, VF) aren't limited to predefined MCP tools. They can use any of Kali's hundreds of open-source tools via `execute_command`:

- **CTF/Lab**: Use freely. Just notify ST for strategy coordination.
- **Client**: Message ST with rationale → ST evaluates risk → HITL approval popup → proceed or denied.

---

## Multi-Agent Architecture

```
┌─────────────────────────────────────────────────────┐
│                    OPERATOR (You)                     │
│         Dashboard + HITL Approvals + Commands         │
└──────────────────────┬──────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────┐
│              Agent Session Manager                    │
│     Spawns sessions, routes messages, manages HITL    │
└──┬────┬────┬────┬────┬────┬─────────────────────────┘
   │    │    │    │    │    │
   ▼    ▼    ▼    ▼    ▼    ▼
  ST   AR   WV   EX   VF   RP
```

| Agent | Role | Model | Phase |
|-------|------|-------|-------|
| **ST** (Strategy) | Red Team Lead — coordinates attack plan, requests workers, evaluates novel tool requests | Opus | All |
| **AR** (Active Recon) | Port scanning, service enumeration, host discovery | Sonnet | 2 |
| **WV** (Web Vuln Scanner) | Vulnerability scanning, directory brute-forcing, template-based detection | Sonnet | 4 |
| **EX** (Exploitation) | Exploit confirmed vulnerabilities, prove impact | Opus | 5 |
| **VF** (Verification) | Independent verification using different tools — no false positives get through | Sonnet | 4 |
| **RP** (Reporting) | Generate technical, executive, and remediation reports | Opus | 7 |

### How Agents Communicate

- **Neo4j Knowledge Graph** — Shared state: hosts, services, findings, credentials, attack chains
- **Bilateral Messaging** — Direct agent-to-agent messages via dashboard API (`/api/messages`)
- **ST Coordination** — Workers report to ST; ST decides next moves and requests new agents
- **HITL Approvals** — Modal-based approve/reject for exploitation and scope expansion

---

## Cross-Engagement Intelligence (CEI)

ATHENA remembers. Past engagement data persists in Neo4j and is injected into agent context:

- **TechniqueRecords** — Which tools/techniques worked against which services
- **FalsePositiveRecords** — Known false positives to skip
- **Experience Briefs** — Data-driven summaries from past engagements injected into agent prompts

Agents prioritize techniques with high success rates and skip known dead-ends.

---

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+ (for Playwright MCP)
- Neo4j database (bolt connection)
- Kali Linux backend(s) running the MCP server
- Claude Agent SDK (`pip install claude-agent-sdk`)

### 1. Start ATHENA

```bash
cd tools/athena-dashboard
./start.sh
```

This handles everything:
- Detects and validates Neo4j connection
- Checks Kali backend availability (external + internal)
- Auto-starts Langfuse Docker stack (if configured)
- Initializes Graphiti memory layer
- Launches the dashboard on **http://localhost:8080**

### 2. Create an Engagement

In the dashboard sidebar, click **New Engagement** and provide:
- **Name** — Engagement identifier
- **Target** — IP, CIDR, or URL
- **Type** — `web_app`, `external`, `internal`, or `all`

### 3. Engage AI

Click **Engage AI** to start the multi-agent team. ST (Strategy Agent) activates first, analyzes the target, and spawns worker agents as needed.

### 4. Monitor & Approve

- Watch the **live event feed** for agent activity
- **HITL approval popups** appear for exploitation and scope expansion (client mode)
- Use the **command box** to direct agents: "Focus on the admin panel" or "Skip port 8080"
- **Pause/Resume/Stop** controls for engagement management

---

## Dashboard

The ATHENA dashboard is a single-page web application optimized for desktop and tablet:

- **Agent LEDs** — Real-time status indicators for each agent (idle/running/completed)
- **PTES Phase Bar** — Visual progress through penetration testing phases
- **Live Event Feed** — Scrolling feed of agent actions, tool calls, findings, and strategy decisions
- **Settings** — Configure Neo4j, Graphiti, Langfuse, and Kali backends
- **Intelligence** — View and manage cross-engagement intelligence data
- **Findings/Vulnerabilities** — Organized by severity with CVSS scores
- **Attack Graph** — Visual attack chain representation (Neo4j-powered)
- **Reports** — Generated technical, executive, and remediation reports

---

## Kali Linux Integration

### Dual Backend Architecture

| Backend | URL | Purpose | Tools |
|---------|-----|---------|-------|
| **External** | `your-kali-host:5000` | Cloud-based pentesting | 50+ tools |
| **Internal** | `your-internal-kali:5000` (ZeroTier) | On-premise pentesting | ProjectDiscovery + AD tools |

### Available Tools (23 MCP tools)

**Reconnaissance:** nmap, naabu, httpx, whatweb, eyewitness
**Web Scanning:** nikto, nuclei, gobuster, dirb, katana, kiterunner, gau, wpscan
**Exploitation:** sqlmap, metasploit, hydra, john, crackmapexec
**Utility:** execute_command (any Kali tool), server_health, s3scanner, responder, enum4linux

---

## Configuration

### MCP Servers (`.mcp.json`)

```json
{
  "mcpServers": {
    "kali_external": { "command": "python", "args": ["mcp_server.py", "--server", "http://kali:5000/"] },
    "kali_internal": { "command": "python", "args": ["mcp_server.py", "--server", "http://your-internal-kali:5000/"] },
    "athena-neo4j": { "command": "python", "args": ["server.py"] },
    "athena-knowledge-base": { "command": "python", "args": ["vex_kb_server.py"] },
    "playwright": { "command": "npx", "args": ["@playwright/mcp@latest", "--headless"] }
  }
}
```

### Environment Variables

Neo4j and Kali backend configuration is managed through the dashboard Settings page or environment variables:

```bash
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASS=your-password
```

---

## Observability

### Langfuse Integration (Optional)

ATHENA supports Langfuse for LLM tracing, cost tracking, and prompt analytics:

```bash
# Auto-started by start.sh if configured
docker compose -f langfuse/docker-compose.yml up -d
```

### Graphiti Memory (Optional)

Temporal knowledge graph for cross-session memory. Agents can query past findings and learn from experience.

---

## Testing Methodology

### PTES Phases

1. **Pre-engagement** — Authorization, scope, rules of engagement
2. **Reconnaissance** — Active scanning, service enumeration (AR agent)
3. **Threat Modeling** — Attack surface analysis (ST agent)
4. **Vulnerability Analysis** — Scanning and detection (WV agent)
5. **Exploitation** — Prove impact with HITL approval (EX agent)
6. **Post-Exploitation** — Verify and validate findings (VF agent)
7. **Reporting** — Professional deliverables (RP agent)

### Compliance Support

- **PCI DSS v4.0** — Payment card industry
- **HIPAA** — Healthcare compliance
- **SOC 2** — Trust services criteria
- **GDPR** — Data protection

---

## Non-Destructive Testing Policy

### Approved Methods
- Read-only database queries (`SELECT`)
- Safe command execution (`whoami`, `id`, `hostname`)
- Benign XSS payloads (alert boxes)
- Authentication bypass with immediate logout
- File upload testing with harmless files

### Prohibited Actions
- Data exfiltration or downloading sensitive information
- Creating, modifying, or deleting production data
- Installing backdoors or persistent access
- Denial of service attacks
- Lateral movement beyond proof-of-concept

---

## Project Structure

```
ATHENA/
├── tools/athena-dashboard/     # Dashboard + Agent Session Manager
│   ├── start.sh                # One-command startup
│   ├── server.py               # FastAPI backend (~10K lines)
│   ├── index.html              # Single-page dashboard (~15K lines)
│   ├── agent_session_manager.py # Multi-agent orchestration
│   ├── agent_configs.py        # Agent roles, prompts, tool access
│   ├── sdk_agent.py            # Claude Agent SDK wrapper
│   ├── graphiti_integration.py # Cross-session memory
│   └── langfuse_integration.py # LLM observability
├── mcp-servers/                # Custom MCP servers
│   └── neo4j-mcp/              # Neo4j knowledge graph MCP
├── playbooks/                  # Attack methodology playbooks
├── engagements/                # Client engagement data
├── intel/                      # Target intelligence
├── .claude/                    # Claude Code configuration
│   ├── commands/               # Slash commands
│   └── settings.json           # Permission configuration
├── CLAUDE.md                   # Agent system prompt + methodology
├── .mcp.json                   # MCP server configuration
└── README.md                   # This file
```

---

## License

**AGPL v3 + Commercial Dual License**

Open source under AGPL v3 for individual and non-commercial use. Commercial licensing available for enterprise deployments.

---

## Disclaimer

This framework is designed for **authorized penetration testing only**. Unauthorized access to computer systems is illegal. Always obtain explicit written authorization before conducting any security testing. Users of this framework are solely responsible for ensuring all testing activities are legal and authorized.

---

**Platform**: ATHENA - AI-Powered Penetration Testing
**Status**: Production
**Version**: 2.0
**Last Updated**: 2026-03-10
**Maintained By**: ZeroK Labs

---

*Professional penetration testing requires authorization, ethical boundaries, non-destructive validation, and comprehensive evidence collection.*
