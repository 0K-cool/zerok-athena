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
    status = "VALID" if result["valid"] else "INVALID"
    print(f"\n  Playbook Validation: {status}")
    print(f"  File: {args.path}")
    print(f"  Brief lines: {result['brief_lines']}/40\n")

    if result["errors"]:
        print("  Errors:")
        for e in result["errors"]:
            print(f"    ERROR: {e}")

    if result["warnings"]:
        print("  Warnings:")
        for w in result["warnings"]:
            print(f"    WARNING: {w}")

    if result["valid"] and not result["warnings"]:
        print("  No issues found.\n")

    sys.exit(0 if result["valid"] else 1)


if __name__ == "__main__":
    main()
