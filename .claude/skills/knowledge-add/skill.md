---
name: knowledge-add
category: knowledge
description: Add playbooks, knowledge documents, or bulk reference material to ATHENA's knowledge base. Validates structure, assigns to agents, triggers RAG indexing, and verifies workspace accessibility. Designed for manual input and future COEUS integration.
---

# ATHENA Knowledge Add

Add knowledge to ATHENA's attack intelligence pipeline.

## Usage

```
/knowledge-add <type> [source]
```

**Types:**
- `playbook` — Attack methodology guide assigned to specific agents
- `knowledge` — Reference material indexed into RAG (not agent-assigned)
- `bulk` — Import multiple files from a directory or URL list

**Examples:**
```
/knowledge-add playbook                    # Interactive — guided creation
/knowledge-add playbook ./my-playbook.md   # From existing file
/knowledge-add knowledge ./reference.md    # Add reference doc
/knowledge-add bulk ./new-techniques/      # Import directory
```

## Workflow

### Step 1: Determine Content Type

Ask if not provided:
- **Playbook** → Goes to `playbooks/` or `docs/playbooks/`, assigned to agents, brief-injected
- **Knowledge** → Goes to `docs/knowledge/`, RAG-indexed only, no agent assignment
- **Bulk** → Multiple files, each classified as playbook or knowledge

### Step 2: Determine Destination

**For playbooks:**
- Focused technique guide (<50KB expected) → `playbooks/`
- Comprehensive methodology (50KB+) → `docs/playbooks/`
- Ask: "Is this a focused technique guide or a comprehensive methodology?"

**For knowledge docs:**
- Always → `docs/knowledge/`
- Naming: `YYYY-MM-DD-<descriptive-name>.md`

### Step 3: Validate Structure (Playbooks Only)

**CRITICAL: First 40 lines are the knowledge brief.** Check that lines 1-40 contain:

1. Title (`# [Name] Playbook`)
2. Overview section (1-2 sentences)
3. MITRE ATT&CK mapping (Tactic + Technique)
4. Start of methodology or key techniques

If missing, restructure before saving. The brief is what agents see in their system prompt — it MUST be information-dense.

**Validate no single line exceeds 200 chars** (long lines get truncated in prompts).

### Step 4: Agent Assignment (Playbooks Only)

Ask which agents should receive this playbook:
- **AR** (Active Recon) — recon, port scanning, service enumeration
- **WV** (Web Vuln Scanner) — web app testing, injection, XSS
- **EX** (Exploitation) — exploitation, credential attacks, privesc
- **VF** (Verification) — exploit verification, validation
- **RP** (Reporting) — report generation

Can assign to multiple agents. Update `AGENT_ROLES` in `agent_configs.py:553-651` — add the path to the agent's `playbooks` tuple.

### Step 5: Verify Workspace Accessibility

Check that the playbook's path prefix directory is in `WorkspaceManager.SYMLINK_TARGETS` (agent_session_manager.py:71).

Current targets: `["CLAUDE.md", ".claude", "playbooks", "docs", "intel", "mcp-servers"]`

- Path starts with `playbooks/` → covered
- Path starts with `docs/` → covered
- Path starts with anything else → MUST add to SYMLINK_TARGETS

### Step 6: RAG Indexing

Trigger re-index of the new file:
```
Use mcp__athena-knowledge-base__index_document with the file path
```

The RAG config (`.vex-rag.yml`) auto-indexes `docs/` and `playbooks/` on git commits, but manual indexing ensures immediate availability.

### Step 7: Update CLAUDE.md Knowledge Section

Add the new playbook/knowledge doc to the appropriate section in CLAUDE.md:
- `### Attack Playbooks (docs/playbooks/)` — line 139
- `### Root Playbooks (playbooks/)` — line 144
- `### Reference Knowledge (docs/knowledge/)` — line 133

### Step 8: Verification Checklist

Before marking complete:
- [ ] File saved to correct directory
- [ ] First 40 lines contain title, overview, MITRE mapping (playbooks)
- [ ] Agent assignment updated in `agent_configs.py` (playbooks)
- [ ] Path resolves via SYMLINK_TARGETS
- [ ] RAG indexed (manual trigger)
- [ ] CLAUDE.md knowledge section updated
- [ ] Commit changes

## COEUS Integration Interface (Future)

When COEUS (Threat Intelligence Platform) is built, it will call this skill programmatically:

```python
# COEUS → ATHENA knowledge pipeline (future)
{
    "type": "playbook",           # or "knowledge"
    "title": "APT29 Cloud Exploitation",
    "content": "...",             # Full markdown content
    "mitre_attack": ["T1078", "T1552.004"],
    "agents": ["EX", "AR"],      # Target agents
    "source": "coeus-threat-model-2026-03-15",
    "auto_index": true
}
```

The skill should work identically whether invoked by a human (`/knowledge-add`) or by COEUS passing structured input. The steps are the same — validate, save, assign, index.

## Red Flags

- **Never skip the 40-line brief validation** — agents without a good brief waste tool calls re-reading
- **Never add a playbook path that doesn't resolve in agent workspaces** — check SYMLINK_TARGETS
- **Never forget RAG indexing** — unindexed content is invisible to ST agent (which uses RAG, not playbooks)
- **Don't duplicate existing content** — check RAG first for similar topics before adding
