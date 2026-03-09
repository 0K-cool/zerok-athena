# ATHENA Kali Containerization — Distribution Vision

**Date:** 2026-03-09
**Author:** Vex Intelligence Platform
**Classification:** Internal strategic planning — ZeroK Labs
**Status:** Vision document — implementation deferred to post-H1/H3

---

## Problem Statement

ATHENA currently relies on two Kali Linux backends (external on Antsle, internal on Mini-PC via ZeroTier) with manually installed tools and Flask API servers. This works for Kelvin's personal use but doesn't scale for distribution:

- New users must provision and configure two Kali boxes from scratch
- 57 tools must be installed manually on each backend
- Flask API server must be deployed and configured
- Network connectivity (ZeroTier, firewall rules) is manual
- No self-service backend management in the dashboard

---

## Vision

**One Docker image, two modes, zero manual setup.**

```
┌─────────────────────────────────────────────────────────┐
│                    ATHENA Dashboard                      │
│              (client laptop or cloud VM)                 │
│                                                          │
│    Settings → Backends                                   │
│    ┌─────────────────────────────────────────────┐       │
│    │ External Kali    ● Connected   29/29 tools  │       │
│    │ https://kali-ext.example.com:5000           │       │
│    │ [Test] [Edit] [Remove]                      │       │
│    │                                             │       │
│    │ Internal Kali    ● Connected   35/35 tools  │       │
│    │ http://10.0.1.50:5000 (via WireGuard)       │       │
│    │ [Test] [Edit] [Remove]                      │       │
│    │                                             │       │
│    │ [+ Add Backend]                             │       │
│    └─────────────────────────────────────────────┘       │
└──────────────┬────────────────────────┬──────────────────┘
               │                        │
               ▼                        ▼
     ┌──────────────────┐    ┌──────────────────┐
     │  athena-kali      │    │  athena-kali      │
     │  MODE=external    │    │  MODE=internal    │
     │  (Cloud VPS)      │    │  (Client LAN)     │
     │                   │    │                   │
     │  29 ext tools     │    │  35 int tools     │
     │  Flask API :5000  │    │  Flask API :5000  │
     │                   │    │  + WireGuard      │
     └──────────────────┘    └──────────────────┘
               │                        │
               ▼                        ▼
        Internet-facing          Client internal
        targets                  network targets
```

---

## Architecture

### Single Docker Image: `athena-kali`

One image built from `kalilinux/kali-rolling` with all tools pre-installed. Mode selected at runtime via environment variable.

```dockerfile
FROM kalilinux/kali-rolling

# Install all 57 tools (shared + mode-specific)
# Shared: nmap, gobuster, nikto, sqlmap, nuclei, ffuf, etc.
# Internal-only: responder, crackmapexec, impacket, bloodhound, etc.
# External-only: subfinder, amass, theHarvester, etc.

ENV ATHENA_BACKEND_MODE=external
ENV ATHENA_DASHBOARD_URL=http://localhost:8080
ENV ATHENA_BACKEND_NAME=kali-external
ENV ATHENA_BACKEND_PORT=5000

# Flask API server
COPY kali-server/ /opt/athena/
EXPOSE 5000

# Health check
HEALTHCHECK CMD curl -f http://localhost:5000/health || exit 1

ENTRYPOINT ["/opt/athena/entrypoint.sh"]
```

**entrypoint.sh logic:**
1. Start Flask API server on `:5000`
2. Run tool health checks (verify all tools present)
3. If `ATHENA_DASHBOARD_URL` set, POST `/api/backends/register` to register self
4. If `ATHENA_BACKEND_MODE=internal`, start WireGuard/Tailscale tunnel

### Registration-Based Discovery

Kali containers self-register with ATHENA on startup:

```
POST /api/backends/register
{
    "name": "kali-external-1",
    "mode": "external",
    "url": "https://kali-ext.example.com:5000",
    "tools": ["nmap", "gobuster", "sqlmap", ...],
    "tool_count": 29,
    "version": "1.0.0"
}
```

ATHENA responds with:
```json
{
    "status": "registered",
    "backend_id": "be_abc123",
    "heartbeat_interval": 30
}
```

Backends send heartbeats every 30s. If 3 heartbeats missed, ATHENA marks backend as offline.

**Benefits:**
- No hardcoded backend URLs in config
- Spin up additional Kali containers and ATHENA auto-discovers them
- Scale horizontally: 3 external Kali containers for parallel scanning
- Dashboard shows live backend status without polling

### VPN/Tunnel for Internal Backends

Internal Kali containers need to reach ATHENA through the client's network. Options:

| Tunnel | Pros | Cons |
|--------|------|------|
| **WireGuard** | Fast, lightweight, built into Linux kernel | Manual key exchange |
| **Tailscale** | Zero-config, NAT traversal, ACLs | Depends on Tailscale coordination server |
| **ZeroTier** | Current setup, works well | Another dependency |
| **Reverse SSH** | Simplest, no extra software | Less reliable, no UDP |

**Recommendation:** Tailscale as default (easiest for clients), WireGuard as fallback (no external dependency). Both can be pre-configured in the container.

---

## Deployment Scenarios

### Scenario 1: VERSANT-Managed (Full Service)

Kelvin hosts everything. Client just connects.

```
Kelvin's infra:
  - ATHENA Dashboard (Antsle or cloud)
  - External Kali (cloud VPS)
  - Neo4j + Langfuse + Graphiti

Client provides:
  - Target scope and authorization
  - Internal Kali placement (if internal test)
```

**Cost to Kelvin:** ~$30-50/mo (VPS + storage)
**Cost to client:** Engagement fee only

### Scenario 2: Client Self-Hosted (On-Prem)

Client runs everything in their own environment.

```bash
# One command to start ATHENA + External Kali + Neo4j + Langfuse
git clone https://github.com/0K-cool/zerok-athena
cd zerok-athena
docker compose up -d

# For internal testing, deploy internal Kali on client LAN
docker run -d --name athena-kali-internal \
    -e ATHENA_BACKEND_MODE=internal \
    -e ATHENA_DASHBOARD_URL=http://athena-server:8080 \
    --network host \
    zeroklabs/athena-kali:latest
```

**Cost to client:** Infrastructure only (Docker host)

### Scenario 3: Hybrid (Most Likely for Consulting)

Kelvin manages ATHENA + external. Client hosts internal Kali.

```
Kelvin's cloud:
  - ATHENA Dashboard
  - External Kali container
  - Neo4j + Langfuse

Client's network:
  - Internal Kali container (Mini-PC or VM)
  - Tailscale tunnel back to ATHENA
```

### Scenario 4: Client Has Existing Kali

Least likely but supported. Provide an installer script:

```bash
# On client's existing Kali box
curl -sSL https://install.zeroklabs.ai/athena-backend | bash

# Installs: Flask API server, missing tools, tool-registry.json
# Registers with ATHENA dashboard automatically
```

---

## Dashboard Configuration UI

### Settings > Backends

```
┌─ Backend Management ─────────────────────────────────────┐
│                                                           │
│  ┌─ kali-external-1 ─────────────────────────────────┐   │
│  │ ● Connected     Mode: External     29/29 tools     │   │
│  │ URL: https://kali-ext.do.example.com:5000          │   │
│  │ Uptime: 14d 3h    Last heartbeat: 5s ago           │   │
│  │ [Test Connection] [View Tools] [Edit] [Remove]     │   │
│  └────────────────────────────────────────────────────┘   │
│                                                           │
│  ┌─ kali-internal-1 ─────────────────────────────────┐   │
│  │ ● Connected     Mode: Internal     35/35 tools     │   │
│  │ URL: http://100.64.0.5:5000 (Tailscale)            │   │
│  │ Uptime: 2h 15m    Last heartbeat: 12s ago          │   │
│  │ [Test Connection] [View Tools] [Edit] [Remove]     │   │
│  └────────────────────────────────────────────────────┘   │
│                                                           │
│  ┌─ Add Backend ─────────────────────────────────────┐   │
│  │ Option A: Auto-register (run container with URL)   │   │
│  │ Option B: Manual add (enter URL + test)            │   │
│  └────────────────────────────────────────────────────┘   │
│                                                           │
│  Scaling: Add more backends for parallel scanning.        │
│  Each engagement auto-selects backends by target type.    │
└───────────────────────────────────────────────────────────┘
```

### Backend Health Dashboard

```
┌─ Backend Health ─────────────────────────────────────────┐
│                                                           │
│  Tool Coverage:                                           │
│    External: ████████████████████████████░ 29/29 (100%)   │
│    Internal: █████████████████████████████████░ 35/35     │
│                                                           │
│  Response Time (p95):                                     │
│    External: 45ms  ● Healthy                              │
│    Internal: 120ms ● Healthy (via tunnel)                 │
│                                                           │
│  Recent Errors: 0 in last 24h                             │
└───────────────────────────────────────────────────────────┘
```

---

## API Endpoints (New)

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/backends` | GET | List all registered backends with health |
| `/api/backends/register` | POST | Backend self-registration |
| `/api/backends/{id}` | PUT | Update backend config |
| `/api/backends/{id}` | DELETE | Remove backend |
| `/api/backends/{id}/health` | GET | Backend health + tool inventory |
| `/api/backends/{id}/heartbeat` | POST | Heartbeat from backend |
| `/api/backends/{id}/tools` | GET | List tools on this backend |

---

## Tool Registry per Backend

Each Kali container carries its own `tool-registry.json` and reports available tools on registration. ATHENA merges tool registries across backends:

```
ATHENA tool registry (merged):
  nmap        → available on: [external, internal]
  sqlmap      → available on: [external, internal]
  responder   → available on: [internal only]
  subfinder   → available on: [external only]
  crackmapexec → available on: [internal only]
```

Agent orchestrator uses this to route tool calls to the correct backend automatically.

---

## Docker Image Size Considerations

| Component | Estimated Size |
|-----------|---------------|
| `kalilinux/kali-rolling` base | ~300MB |
| 57 tools installed | ~2-4GB |
| Flask API + configs | ~10MB |
| **Total image** | **~3-5GB** |

Optimization strategies:
- Multi-stage build (build deps in one stage, copy binaries)
- Separate "lite" image with top 20 tools (~1.5GB) vs "full" with all 57
- Layer caching so updates only pull changed tool layers

---

## Security Considerations

| Risk | Mitigation |
|------|-----------|
| Kali container has offensive tools | Network isolation, no internet access unless needed for target |
| API server exposed | mTLS between ATHENA and backends, API key auth |
| Internal container on client LAN | Scope-locked — only scans authorized targets, HITL gates |
| Credentials in container | No hardcoded creds — injected via env vars or 1Password |
| Tool output exfiltration | All results flow through ATHENA dashboard (auditable) |
| Container escape | Run with `--cap-drop=ALL`, add only needed capabilities |

---

## Implementation Sequence

```
Phase H1+H3 (Current): Memory + Observability
    ↓
Phase H-Kali: Kali Containerization
    Task 1: Dockerfile (base image + 57 tools + Flask API)
    Task 2: entrypoint.sh (mode selection, registration, tunnel)
    Task 3: /api/backends/* endpoints in server.py
    Task 4: Settings > Backends UI in index.html
    Task 5: Backend health monitoring + heartbeat
    Task 6: docker-compose.yml (ATHENA + Neo4j + Langfuse + External Kali)
    ↓
Phase H6: Full Docker Compose Deployment
    One command: docker compose up → everything runs
    ↓
Phase L0: AGPL Licensing
    ↓
Public Release
```

**Estimated effort for H-Kali:** 2-3 weeks
**Dependencies:** None — can start anytime after H1+H3

---

## Success Criteria

- [ ] `docker compose up` starts ATHENA + External Kali + Neo4j in < 2 minutes
- [ ] External Kali auto-registers and shows in Settings > Backends
- [ ] Internal Kali container connects via Tailscale tunnel
- [ ] Tool health: 57/57 tools pass health check
- [ ] Backend failover: if external goes down, ATHENA shows offline status (no crash)
- [ ] New backend added via `docker run` auto-appears in dashboard
- [ ] Image size < 5GB (full) or < 2GB (lite)

---

**Last Updated:** 2026-03-09
**Author:** Vex for ZeroK Labs
