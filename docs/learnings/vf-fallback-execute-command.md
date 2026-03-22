# VF Should Fall Back to execute_command When Dedicated Tools Fail

**Created:** 2026-03-22
**Status:** Pending fix
**Priority:** MEDIUM — VF gets stuck on broken tools instead of adapting

## Problem

VF's nmap_scan tool failed (NSE engine error) but VF didn't fall back to `execute_command` to run nmap directly. VF has `execute_command` in its approved tools but doesn't know to use it as a fallback.

## Fix

Add to `_VF_PROMPT` in `agent_configs.py`:

"TOOL RESILIENCE: If a dedicated tool (nmap_scan, nuclei_scan, etc.) fails or returns an error, fall back to execute_command and run the same command directly. Example: if nmap_scan fails with NSE errors, run: execute_command with command='nmap --script=ftp-vsftpd-backdoor -p 21 TARGET'. execute_command gives you full control over arguments."

## Applies To

All agents, not just VF. Any agent that uses dedicated Kali tools should know about the execute_command fallback. Consider adding this to the shared base prompt section.
