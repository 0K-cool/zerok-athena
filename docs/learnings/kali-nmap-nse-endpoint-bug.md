# Kali nmap_scan Endpoint Doesn't Pass NSE Scripts Correctly

**Created:** 2026-03-22
**Status:** Pending fix
**Priority:** HIGH — blocks VF from confirming exploits via NSE scripts

## Problem

VF calls `mcp__kali_external__nmap_scan` with NSE script arguments (e.g., `--script=ftp-vsftpd-backdoor`), but the dedicated `/api/tools/nmap` endpoint either strips or malforms the script arguments. Nmap runs but doesn't execute NSE scripts, returning basic port info only.

Error seen in VF: `NSE: failed to initialize the script engine`

## Evidence

- Generic `/api/command` with `nmap --script=default -p 21 10.1.1.25` → **works** (returns NSE output)
- Dedicated `/api/tools/nmap` with `scripts: "ftp-vsftpd-backdoor"` → **no NSE output** (basic scan only)
- VF via MCP → `failed to initialize the script engine` error

## Impact

VF can't use nmap NSE scripts to verify vulnerabilities (vsftpd backdoor, UnrealIRCd, Samba). Falls back to manual verification (nc, curl) which is slower and less reliable.

## Fix

Check the Kali API's `/api/tools/nmap` endpoint — how it constructs the nmap command from the `scripts` parameter. The `additional_args` field in `tool-registry.json` may need to pass `--script` correctly.

## Workaround

VF can use `execute_command` to run nmap directly with full control over arguments. The generic command endpoint works correctly.
