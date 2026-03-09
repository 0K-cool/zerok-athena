# ATHENA Knowledge Add Skill — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Create a `/knowledge-add` skill for ATHENA that provides a guided workflow for adding playbooks and knowledge documents, with validation, agent assignment, and RAG indexing — designed for future COEUS integration.

**Architecture:** The skill lives in ATHENA (standalone for distribution) with a thin PAI wrapper (`/athena-knowledge-add`) for Vex convenience. It handles three content types: playbooks (agent-assigned), knowledge docs (RAG-only reference), and bulk imports. All content follows a front-loaded structure (first 40 lines = knowledge brief) and is validated against workspace symlink targets before completion.

**Tech Stack:** Markdown skill files, Python validation script, vex-rag MCP for indexing, existing agent_configs.py for agent assignment.

---

## Context for Implementer

### How ATHENA Knowledge Works (3 Layers)

1. **Knowledge Brief (CEI-1):** `_build_knowledge_brief()` in `agent_session_manager.py:819-857` reads the first 40 lines of each playbook and injects them into the agent's system prompt. This is automatic — agents can't skip it.

2. **Prompt Instruction:** Agents get "MANDATORY READING — Read these playbooks BEFORE starting work" with full file paths listed. Agents use the Read tool to load the full content.

3. **Workspace Symlinks:** `WorkspaceManager` (line 71) symlinks these directories into agent workspaces: `["CLAUDE.md", ".claude", "playbooks", "docs", "intel", "mcp-servers"]`. Playbook paths in agent configs MUST resolve via these symlinks.

### Content Locations

| Type | Directory | Purpose | RAG Indexed |
|------|-----------|---------|-------------|
| Structured playbooks | `docs/playbooks/` | Large methodology guides (60-100KB) | Yes |
| Root playbooks | `playbooks/` | Focused technique guides (16-33KB) | Yes |
| Knowledge docs | `docs/knowledge/` | Reference material (curated external) | Yes |
| Research | `docs/research/` | Competitive intel, analysis | Yes |

### Agent → Playbook Assignments (agent_configs.py:553-651)

| Agent | Playbooks |
|-------|-----------|
| ST | None (reads via RAG as needed) |
| AR | `docs/playbooks/c2-and-network-services.md` |
| WV | `docs/playbooks/web-application-attacks.md`, `playbooks/sql-injection-testing.md` |
| EX | `docs/playbooks/credential-attacks.md`, `docs/playbooks/lotl-and-privilege-escalation.md`, `playbooks/cve-exploit-research-workflow.md` |
| VF | None |
| RP | None |

### RAG Config (.vex-rag.yml)

Auto-indexes: `docs/`, `playbooks/`, `README.md`, `CLAUDE.md`
Extensions: `.md`, `.pdf`, `.txt`
MCP tool for manual indexing: `mcp__athena-knowledge-base__index_document`

### Playbook Structure Convention (from existing playbooks)

```markdown
# [Title] Playbook

## Overview
[1-2 sentence description of what this covers]

## MITRE ATT&CK Mapping
- **Tactic**: [TA####]
- **Technique**: [T####]

## OWASP Reference (if web-related)
- **OWASP Top 10**: [A##:####]
- **CWE**: [CWE-##]

---

## Testing Methodology

### Phase 1: [First Phase]
[Key techniques, tools, commands]
...
```

The first 40 lines MUST contain: title, overview, MITRE mapping, and start of methodology. This is what gets injected into agent prompts.

---

## Task 1: Create ATHENA `/knowledge-add` Skill

**Files:**
- Create: `.claude/skills/knowledge-add/skill.md`

**Step 1: Write the skill file**

```markdown
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

1. ✅ Title (`# [Name] Playbook`)
2. ✅ Overview section (1-2 sentences)
3. ✅ MITRE ATT&CK mapping (Tactic + Technique)
4. ✅ Start of methodology or key techniques

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

- Path starts with `playbooks/` → ✅ covered
- Path starts with `docs/` → ✅ covered
- Path starts with anything else → ❌ MUST add to SYMLINK_TARGETS

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
```

**Step 2: Commit**

```bash
git add .claude/skills/knowledge-add/skill.md
git commit -m "feat: Add /knowledge-add skill for playbook and knowledge management"
```

---

## Task 2: Create PAI Wrapper Skill (`/athena-knowledge-add`)

**Files:**
- Create: `/Users/kelvinlomboy/Personal_AI_Infrastructure/.claude/skills/athena-knowledge-add/skill.md`

**Step 1: Write the PAI wrapper skill**

```markdown
---
name: athena-knowledge-add
category: pentesting
description: Add playbooks and knowledge to ATHENA's attack intelligence pipeline from any Vex session. Thin wrapper that resolves ATHENA's path and delegates to the core /knowledge-add workflow.
---

# ATHENA Knowledge Add (Vex Wrapper)

Add knowledge to ATHENA from any Vex session without switching to the ATHENA repo.

## Usage

```
/athena-knowledge-add <type> [source]
```

**Types:** `playbook`, `knowledge`, `bulk`

## How This Works

This is a convenience wrapper. It:
1. Resolves ATHENA root: `/Users/kelvinlomboy/VERSANT/Projects/ATHENA/`
2. Follows the same workflow as ATHENA's `/knowledge-add` skill
3. Handles file operations at the ATHENA path
4. Triggers RAG re-index via `mcp__athena-knowledge-base__index_document`

## Workflow

### Step 1: Resolve ATHENA Root

```
ATHENA_ROOT=/Users/kelvinlomboy/VERSANT/Projects/ATHENA
```

Verify it exists. If not, error: "ATHENA not found at expected path."

### Step 2: Follow Core Workflow

Execute the same steps as ATHENA's `/knowledge-add`:

1. **Determine type** (playbook/knowledge/bulk)
2. **Determine destination** within ATHENA_ROOT
3. **Validate structure** (40-line brief for playbooks)
4. **Agent assignment** (update `agent_configs.py`)
5. **Verify SYMLINK_TARGETS** accessibility
6. **RAG index** the new file
7. **Update ATHENA's CLAUDE.md** knowledge section
8. **Commit** changes in ATHENA repo

### Step 3: Cross-Reference

After adding to ATHENA, check if this knowledge is also relevant to PAI:
- Threat intel → Consider adding to PAI's RAG via `mcp__vex-knowledge-base__index_document`
- Security techniques → May inform PAI's defense-in-depth layers

## Key Paths (ATHENA)

| Content | Path |
|---------|------|
| Focused playbooks | `$ATHENA_ROOT/playbooks/` |
| Methodology guides | `$ATHENA_ROOT/docs/playbooks/` |
| Knowledge docs | `$ATHENA_ROOT/docs/knowledge/` |
| Agent configs | `$ATHENA_ROOT/tools/athena-dashboard/agent_configs.py` |
| Session manager | `$ATHENA_ROOT/tools/athena-dashboard/agent_session_manager.py` |
| RAG config | `$ATHENA_ROOT/.vex-rag.yml` |
```

**Step 2: Commit**

```bash
git add .claude/skills/athena-knowledge-add/skill.md
git commit -m "feat: Add /athena-knowledge-add wrapper skill for Vex"
```

---

## Task 3: Add Validation Script

**Files:**
- Create: `tools/athena-dashboard/validate_playbook.py`

**Step 1: Write the validation script**

This script validates playbook structure before ingestion. Can be called by the skill or by COEUS programmatically.

```python
#!/usr/bin/env python3
"""Validate ATHENA playbook structure for knowledge brief compatibility.

Checks that the first 40 lines contain required sections and that
the file follows ATHENA playbook conventions.

Usage:
    python validate_playbook.py <path_to_playbook.md>
    python validate_playbook.py --json <path>  # Machine-readable output
"""

import argparse
import json
import re
import sys
from pathlib import Path


def validate_playbook(path: Path) -> dict:
    """Validate a playbook file and return results.

    Returns:
        dict with keys: valid (bool), errors (list), warnings (list), brief_lines (int)
    """
    errors = []
    warnings = []

    if not path.exists():
        return {"valid": False, "errors": [f"File not found: {path}"], "warnings": [], "brief_lines": 0}

    if path.suffix not in (".md", ".txt"):
        errors.append(f"Unsupported format: {path.suffix} (expected .md or .txt)")

    content = path.read_text(encoding="utf-8")
    lines = content.splitlines()

    if len(lines) < 10:
        errors.append(f"Playbook too short ({len(lines)} lines). Minimum 10 lines expected.")
        return {"valid": False, "errors": errors, "warnings": warnings, "brief_lines": len(lines)}

    # Check first 40 lines (knowledge brief zone)
    brief = "\n".join(lines[:40])

    # Required: Title
    if not re.search(r"^#\s+.+", lines[0]):
        errors.append("Line 1 must be a markdown title (# Title)")

    # Required: Overview section
    if not re.search(r"(?i)overview|summary|description|introduction", brief):
        errors.append("First 40 lines must contain an Overview/Summary section")

    # Required: MITRE ATT&CK mapping
    if not re.search(r"(?i)mitre|att&ck|TA\d{4}|T\d{4}", brief):
        warnings.append("No MITRE ATT&CK mapping found in first 40 lines (recommended)")

    # Warning: Long lines
    long_lines = [i + 1 for i, line in enumerate(lines[:40]) if len(line) > 200]
    if long_lines:
        warnings.append(f"Lines exceed 200 chars (may truncate in prompts): {long_lines}")

    # Warning: Brief too sparse
    non_empty = sum(1 for line in lines[:40] if line.strip())
    if non_empty < 15:
        warnings.append(f"Brief zone sparse ({non_empty}/40 non-empty lines). Front-load key content.")

    # Check for methodology/phases
    if not re.search(r"(?i)phase|step|methodology|procedure|workflow", brief):
        warnings.append("No methodology structure found in first 40 lines")

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
        "brief_lines": min(len(lines), 40),
    }


def main():
    parser = argparse.ArgumentParser(description="Validate ATHENA playbook structure")
    parser.add_argument("path", type=Path, help="Path to playbook file")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    result = validate_playbook(args.path)

    if args.json:
        print(json.dumps(result, indent=2))
        sys.exit(0 if result["valid"] else 1)

    # Human-readable output
    status = "✅ VALID" if result["valid"] else "❌ INVALID"
    print(f"\n  Playbook Validation: {status}")
    print(f"  File: {args.path}")
    print(f"  Brief lines: {result['brief_lines']}/40\n")

    if result["errors"]:
        print("  Errors:")
        for e in result["errors"]:
            print(f"    ❌ {e}")

    if result["warnings"]:
        print("  Warnings:")
        for w in result["warnings"]:
            print(f"    ⚠️  {w}")

    if result["valid"] and not result["warnings"]:
        print("  No issues found.\n")

    sys.exit(0 if result["valid"] else 1)


if __name__ == "__main__":
    main()
```

**Step 2: Run validation against existing playbooks to verify**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA
python tools/athena-dashboard/validate_playbook.py playbooks/sql-injection-testing.md
python tools/athena-dashboard/validate_playbook.py docs/playbooks/web-application-attacks.md
python tools/athena-dashboard/validate_playbook.py --json playbooks/cve-exploit-research-workflow.md
```

Expected: All existing playbooks should pass validation.

**Step 3: Commit**

```bash
git add tools/athena-dashboard/validate_playbook.py
git commit -m "feat: Add playbook validation script for knowledge-add pipeline"
```

---

## Task 4: Update ATHENA CLAUDE.md with Skill Reference

**Files:**
- Modify: `CLAUDE.md` (add skill to available skills section)

**Step 1: Add /knowledge-add to the skills/commands section**

Find the section that documents available skills/commands and add:

```markdown
### Knowledge Management
- `/knowledge-add` — Add playbooks, knowledge docs, or bulk imports to ATHENA's knowledge base
  - Validates playbook structure (40-line brief, MITRE mapping)
  - Assigns playbooks to agents (AR, WV, EX, VF, RP)
  - Triggers RAG re-indexing
  - Verifies workspace symlink accessibility
```

**Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: Add /knowledge-add skill to CLAUDE.md"
```

---

## Task 5: Update PAI CLAUDE.md with Wrapper Skill

**Files:**
- Modify: `/Users/kelvinlomboy/Personal_AI_Infrastructure/CLAUDE.md`

**Step 1: Add /athena-knowledge-add to the skills list**

In the `## Available Skills` section, under **Professional**, add `athena-knowledge-add` to the list.

**Step 2: Commit (in PAI repo)**

```bash
cd /Users/kelvinlomboy/Personal_AI_Infrastructure
git add CLAUDE.md
git commit -m "docs: Add /athena-knowledge-add skill reference"
```

---

## Summary

| Task | What | Where |
|------|------|-------|
| 1 | Core `/knowledge-add` skill | ATHENA `.claude/skills/` |
| 2 | PAI wrapper `/athena-knowledge-add` | PAI `.claude/skills/` |
| 3 | Validation script | ATHENA `tools/athena-dashboard/` |
| 4 | ATHENA CLAUDE.md update | ATHENA root |
| 5 | PAI CLAUDE.md update | PAI root |

**COEUS future integration point:** The skill accepts structured input (type, content, MITRE mapping, agent targets). When COEUS generates playbooks from threat models, it passes the same structure — no skill changes needed, just a programmatic caller.
