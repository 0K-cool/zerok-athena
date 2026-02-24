"""
Tool output parsers for ATHENA agents.

Imports existing parsers from bridge.py and adds parsers for tools not
covered there (nmap, gobuster, nikto, sqlmap, gau, wpscan, netexec).

Each parser extracts structured data from tool stdout/stderr so agents
can write results to Neo4j and broadcast findings to the dashboard.
"""

import json
import re
import sys
from pathlib import Path
from typing import Optional

# Import bridge.py parsers from mcp-servers directory
_bridge_dir = Path(__file__).resolve().parent.parent.parent / "mcp-servers" / "kali-neo4j-bridge"
if str(_bridge_dir) not in sys.path:
    sys.path.insert(0, str(_bridge_dir))

try:
    from bridge import (
        parse_naabu_results,
        parse_nuclei_results,
        parse_httpx_results,
        validate_scope,
    )
except ImportError:
    # Fallback: define minimal versions if bridge.py not found
    def parse_naabu_results(raw_output: str, engagement_id: str) -> list[dict]:
        records = []
        for line in raw_output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            if line.startswith("{"):
                try:
                    obj = json.loads(line)
                    records.append({"ip": obj.get("ip", ""), "port": int(obj.get("port", 0)), "protocol": "tcp"})
                except (json.JSONDecodeError, ValueError):
                    continue
            elif ":" in line:
                parts = line.rsplit(":", 1)
                if len(parts) == 2 and parts[1].isdigit():
                    records.append({"ip": parts[0], "port": int(parts[1]), "protocol": "tcp"})
        return records

    def parse_nuclei_results(raw_output: str, engagement_id: str) -> list[dict]:
        vulns = []
        for line in raw_output.strip().split("\n"):
            if not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
                info = obj.get("info", {})
                vulns.append({
                    "name": info.get("name", obj.get("template-id", "")),
                    "severity": info.get("severity", "info").upper(),
                    "host": obj.get("host", ""),
                    "matched_at": obj.get("matched-at", ""),
                    "template_id": obj.get("template-id", ""),
                    "cve_id": ",".join(info.get("classification", {}).get("cve-id", [])),
                    "cvss_score": info.get("classification", {}).get("cvss-score", 0),
                    "description": info.get("description", ""),
                })
            except json.JSONDecodeError:
                continue
        return vulns

    def parse_httpx_results(raw_output: str, engagement_id: str) -> list[dict]:
        urls = []
        for line in raw_output.strip().split("\n"):
            if not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
                urls.append({
                    "url": obj.get("url", ""),
                    "status_code": obj.get("status_code", 0),
                    "title": obj.get("title", ""),
                    "tech": obj.get("tech", []),
                    "content_type": obj.get("content_type", ""),
                    "host": obj.get("host", ""),
                    "port": obj.get("port", 0),
                })
            except json.JSONDecodeError:
                continue
        return urls

    def validate_scope(target: str, scope: dict) -> bool:
        import ipaddress
        exclusions = scope.get("exclusions", [])
        if target in exclusions:
            return False
        for allowed in scope.get("targets", []):
            if target == allowed:
                return True
            try:
                if ipaddress.ip_address(target) in ipaddress.ip_network(allowed, strict=False):
                    return True
            except ValueError:
                pass
            if allowed.startswith("*.") and target.endswith(allowed[1:]):
                return True
        return False


# ── New Parsers ──

def parse_nmap_output(stdout: str) -> dict:
    """Parse nmap text output into structured host/service data.

    Returns:
        {
            "hosts": [
                {
                    "ip": "10.0.0.5",
                    "hostname": "web-01",
                    "status": "up",
                    "ports": [
                        {"port": 80, "state": "open", "service": "http", "version": "Apache 2.4.58"}
                    ]
                }
            ],
            "summary": "156 hosts up, 847 ports open"
        }
    """
    hosts = []
    current_host = None

    for line in stdout.split("\n"):
        line = line.strip()

        # Host line: "Nmap scan report for hostname (IP)" or "Nmap scan report for IP"
        host_match = re.match(
            r"Nmap scan report for (?:(\S+)\s+\()?(\d+\.\d+\.\d+\.\d+)\)?",
            line,
        )
        if host_match:
            if current_host:
                hosts.append(current_host)
            hostname = host_match.group(1) or ""
            ip = host_match.group(2)
            current_host = {"ip": ip, "hostname": hostname, "status": "up", "ports": []}
            continue

        # Port line: "80/tcp   open  http     Apache httpd 2.4.58"
        port_match = re.match(
            r"(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)\s*(.*)",
            line,
        )
        if port_match and current_host:
            current_host["ports"].append({
                "port": int(port_match.group(1)),
                "protocol": port_match.group(2),
                "state": port_match.group(3),
                "service": port_match.group(4),
                "version": port_match.group(5).strip(),
            })
            continue

        # Host up line: "Host is up (0.0012s latency)."
        if line.startswith("Host is up") and current_host:
            current_host["status"] = "up"

    if current_host:
        hosts.append(current_host)

    # Summary line
    summary = ""
    summary_match = re.search(r"Nmap done:.*", stdout)
    if summary_match:
        summary = summary_match.group(0)

    return {"hosts": hosts, "summary": summary}


def parse_gobuster_output(stdout: str) -> list[dict]:
    """Parse gobuster dir output into discovered paths.

    Returns:
        [{"path": "/admin", "status": 403, "size": 162}, ...]
    """
    paths = []
    for line in stdout.split("\n"):
        line = line.strip()
        # Gobuster output: "/admin                (Status: 403) [Size: 162]"
        match = re.match(
            r"(/\S*)\s+\(Status:\s*(\d+)\)\s*(?:\[Size:\s*(\d+)\])?",
            line,
        )
        if match:
            paths.append({
                "path": match.group(1),
                "status": int(match.group(2)),
                "size": int(match.group(3)) if match.group(3) else 0,
            })
    return paths


def parse_nikto_output(stdout: str) -> list[dict]:
    """Parse nikto text output into findings.

    Returns:
        [{"finding": "Directory indexing found", "path": "/admin/", "osvdb": "3268"}, ...]
    """
    findings = []
    for line in stdout.split("\n"):
        line = line.strip()
        if not line.startswith("+"):
            continue
        # Skip info lines
        if any(line.startswith(f"+ {prefix}") for prefix in ["Target", "Server:", "Start", "End", "-"]):
            continue

        finding = {"finding": line.lstrip("+ "), "path": "", "osvdb": ""}

        # Extract OSVDB reference
        osvdb_match = re.search(r"OSVDB-(\d+)", line)
        if osvdb_match:
            finding["osvdb"] = osvdb_match.group(1)

        # Extract path
        path_match = re.search(r"(/\S+):", line)
        if path_match:
            finding["path"] = path_match.group(1)

        findings.append(finding)
    return findings


def parse_sqlmap_output(stdout: str) -> dict:
    """Parse sqlmap output for injection confirmation.

    Returns:
        {
            "injectable": True/False,
            "parameter": "username",
            "technique": "boolean-based blind",
            "dbms": "MySQL >= 8.0",
            "databases": ["acme_portal", "information_schema"],
            "details": "..."
        }
    """
    result = {
        "injectable": False,
        "parameter": "",
        "technique": "",
        "dbms": "",
        "databases": [],
        "details": "",
    }

    for line in stdout.split("\n"):
        line = line.strip()

        # Injectable parameter
        inject_match = re.search(
            r"parameter '(\w+)' (?:appears to be|is) '(.+?)' injectable",
            line, re.IGNORECASE,
        )
        if inject_match:
            result["injectable"] = True
            result["parameter"] = inject_match.group(1)
            result["technique"] = inject_match.group(2)

        # DBMS
        dbms_match = re.search(r"back-end DBMS:\s*(.+)", line, re.IGNORECASE)
        if dbms_match:
            result["dbms"] = dbms_match.group(1).strip()

        # Databases
        if line.startswith("[*] ") and result["injectable"]:
            db_name = line[4:].strip()
            if db_name and not db_name.startswith("starting") and not db_name.startswith("shutting"):
                result["databases"].append(db_name)

    # Build details summary
    if result["injectable"]:
        parts = [f"Parameter '{result['parameter']}' is {result['technique']} injectable"]
        if result["dbms"]:
            parts.append(f"DBMS: {result['dbms']}")
        if result["databases"]:
            parts.append(f"Databases: {', '.join(result['databases'])}")
        result["details"] = ". ".join(parts)

    return result


def parse_gau_output(stdout: str) -> list[str]:
    """Parse gau output into URL list.

    Returns:
        ["https://example.com/admin", "https://example.com/api/v1", ...]
    """
    urls = []
    for line in stdout.strip().split("\n"):
        line = line.strip()
        if line and (line.startswith("http://") or line.startswith("https://")):
            urls.append(line)
    return urls


def parse_wpscan_output(stdout: str) -> list[dict]:
    """Parse wpscan output into findings.

    Returns:
        [{"type": "vulnerability", "title": "...", "reference": "CVE-...", "severity": "high"}, ...]
    """
    findings = []
    current_finding = None

    for line in stdout.split("\n"):
        line = line.strip()

        # Vulnerability header: "[!] Title: WordPress < 6.5 - SQL Injection"
        vuln_match = re.match(r"\[!\]\s+Title:\s+(.+)", line)
        if vuln_match:
            if current_finding:
                findings.append(current_finding)
            current_finding = {
                "type": "vulnerability",
                "title": vuln_match.group(1),
                "reference": "",
                "severity": "medium",
            }
            continue

        # Reference lines
        if current_finding:
            cve_match = re.search(r"(CVE-\d{4}-\d+)", line)
            if cve_match:
                current_finding["reference"] = cve_match.group(1)

        # Severity from fixed string
        if current_finding and "critical" in line.lower():
            current_finding["severity"] = "critical"
        elif current_finding and "high" in line.lower():
            current_finding["severity"] = "high"

        # Info findings: "[i] ..." or "[+] ..."
        info_match = re.match(r"\[([i+])\]\s+(.+)", line)
        if info_match and not current_finding:
            findings.append({
                "type": "info",
                "title": info_match.group(2),
                "reference": "",
                "severity": "info",
            })

    if current_finding:
        findings.append(current_finding)

    return findings


def parse_netexec_output(stdout: str) -> list[dict]:
    """Parse NetExec (nxc) output into results.

    Returns:
        [{"host": "10.0.0.5", "port": 445, "status": "Pwn3d!", "info": "..."}, ...]
    """
    results = []
    for line in stdout.split("\n"):
        line = line.strip()
        if not line:
            continue

        # NXC output: "SMB  10.0.0.5  445  HOSTNAME  [*] Windows 10.0 Build 19041"
        nxc_match = re.match(
            r"(\w+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\S+)\s+\[([*+!-])\]\s+(.*)",
            line,
        )
        if nxc_match:
            marker = nxc_match.group(5)
            results.append({
                "protocol": nxc_match.group(1),
                "host": nxc_match.group(2),
                "port": int(nxc_match.group(3)),
                "hostname": nxc_match.group(4),
                "status": "pwned" if marker == "+" else ("error" if marker == "-" else "info"),
                "info": nxc_match.group(6),
            })

    return results


def parse_subfinder_output(stdout: str) -> list[str]:
    """Parse subfinder output into subdomain list.

    Returns:
        ["sub1.example.com", "sub2.example.com", ...]
    """
    subdomains = []
    for line in stdout.strip().split("\n"):
        line = line.strip()
        if line and "." in line and not line.startswith("["):
            subdomains.append(line)
    return subdomains


def parse_whatweb_output(stdout: str) -> list[dict]:
    """Parse whatweb JSON output into technology fingerprints.

    Returns:
        [{"url": "...", "technologies": ["Apache", "PHP"], "status": 200}, ...]
    """
    results = []
    for line in stdout.strip().split("\n"):
        if not line.startswith("[") and not line.startswith("{"):
            continue
        try:
            # WhatWeb JSON output is a JSON array per line
            data = json.loads(line)
            if isinstance(data, list):
                for item in data:
                    results.append({
                        "url": item.get("target", ""),
                        "status": item.get("http_status", 0),
                        "technologies": [
                            p.get("string", [p.get("name", "")])
                            for p in item.get("plugins", {}).values()
                            if isinstance(p, dict)
                        ],
                    })
            elif isinstance(data, dict):
                results.append({
                    "url": data.get("target", ""),
                    "status": data.get("http_status", 0),
                    "technologies": list(data.get("plugins", {}).keys()),
                })
        except json.JSONDecodeError:
            continue
    return results


# ── Enrichment Parsers ──

def parse_searchsploit_json(stdout: str) -> list[dict]:
    """Parse searchsploit -j JSON output into exploit list.

    Input:  searchsploit --cve <id> -j
    Output: [{"title": "...", "edb_id": "49757", "type": "remote",
              "platform": "unix", "path": "...", "source": "exploitdb"}, ...]
    """
    results = []
    # searchsploit -j wraps output in a JSON object
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        # Try to extract JSON from mixed output (searchsploit may prepend text)
        json_start = stdout.find("{")
        if json_start == -1:
            return results
        try:
            data = json.loads(stdout[json_start:])
        except json.JSONDecodeError:
            return results

    for exploit in data.get("RESULTS_EXPLOIT", []):
        results.append({
            "title": exploit.get("Title", ""),
            "edb_id": str(exploit.get("EDB-ID", "")),
            "type": exploit.get("Type", ""),
            "platform": exploit.get("Platform", ""),
            "path": exploit.get("Path", ""),
            "source": "exploitdb",
        })
    return results


def parse_msf_search_output(stdout: str) -> list[dict]:
    """Parse msfconsole 'search cve:...' table output into module list.

    Input:  msfconsole -q -x 'search cve:2011-2523; exit'
    Output: [{"module_path": "exploit/unix/ftp/vsftpd_234_backdoor",
              "module_type": "exploit", "rank": "excellent", "check": False,
              "description": "VSFTPD v2.3.4 Backdoor", "source": "metasploit"}, ...]
    """
    results = []

    # Rank ordering for comparison
    rank_order = {
        "excellent": 5, "great": 4, "good": 3,
        "normal": 2, "average": 1, "low": 0, "manual": -1,
    }

    for line in stdout.split("\n"):
        line = line.strip()
        # Match table rows like:
        #   0  exploit/unix/ftp/vsftpd_234_backdoor  2011-07-03  excellent  No  VSFTPD v2.3.4 Backdoor
        match = re.match(
            r"\d+\s+"                        # row number
            r"(\S+)\s+"                      # module path
            r"(\d{4}-\d{2}-\d{2})?\s*"       # optional disclosure date
            r"(excellent|great|good|normal|average|low|manual)\s+"  # rank
            r"(Yes|No)\s+"                   # check support
            r"(.+)",                         # description
            line,
        )
        if match:
            module_path = match.group(1)
            # Extract module type from path (e.g. exploit/, auxiliary/, post/)
            module_type = module_path.split("/")[0] if "/" in module_path else "unknown"
            results.append({
                "module_path": module_path,
                "module_type": module_type,
                "rank": match.group(3),
                "rank_score": rank_order.get(match.group(3), 0),
                "check": match.group(4) == "Yes",
                "description": match.group(5).strip(),
                "disclosure_date": match.group(2) or "",
                "source": "metasploit",
            })

    # Sort by rank descending (best modules first)
    results.sort(key=lambda m: m.get("rank_score", 0), reverse=True)
    return results


def parse_attackerkb_response(stdout: str) -> Optional[dict]:
    """Parse AttackerKB API /v1/topics response into intelligence summary.

    Input:  curl JSON from https://api.attackerkb.com/v1/topics?name=CVE-...
    Output: {"cve_id": "CVE-2021-44228", "attacker_value": 5,
             "exploitability": 5, "name": "CVE-2021-44228 (Log4Shell)",
             "rapid7_analysis": True, "source": "attackerkb"}
             or None if no matching topic found.

    API response format (v1, flat structure — no "attributes" wrapper):
        {"data": [{"name": "CVE-2021-44228 (Log4Shell)",
                   "score": {"attackerValue": 5, "exploitability": 5},
                   "rapid7Analysis": "...", "tags": [...], ...}]}
    """
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        # Try extracting JSON from mixed curl output
        json_start = stdout.find("{")
        if json_start == -1:
            return None
        try:
            data = json.loads(stdout[json_start:])
        except json.JSONDecodeError:
            return None

    topics = data.get("data", [])
    if not topics:
        return None

    # Take the first (best match) topic — flat structure (no "attributes" nesting)
    topic = topics[0]
    if not isinstance(topic, dict):
        return None

    # Handle both flat (current API) and nested ("attributes") formats
    attrs = topic.get("attributes", topic)

    score = attrs.get("score", {}) or {}

    return {
        "cve_id": attrs.get("name", ""),
        "name": attrs.get("name", ""),
        "attacker_value": score.get("attackerValue", 0),
        "exploitability": score.get("exploitability", 0),
        "rapid7_analysis": attrs.get("rapid7Analysis") is not None,
        "source": "attackerkb",
    }


# ── Severity Helpers ──

def severity_from_cvss(cvss: float) -> str:
    """Map CVSS score to severity string."""
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    if cvss >= 0.1:
        return "low"
    return "info"


def extract_cves(text: str) -> list[str]:
    """Extract CVE IDs from any text."""
    return list(set(re.findall(r"CVE-\d{4}-\d{4,}", text)))


# ── Phase E: Web App Testing Parsers ──

def parse_ffuf(stdout: str) -> dict:
    """Parse ffuf JSON output into discovered paths.

    Returns:
        {
            "results": [{"url": "...", "status": 200, "length": 1234, "words": 100}],
            "count": 42
        }
    """
    results = []
    # ffuf -of json wraps results in a JSON object
    try:
        data = json.loads(stdout)
        for item in data.get("results", []):
            results.append({
                "url": item.get("url", ""),
                "status": item.get("status", 0),
                "length": item.get("length", 0),
                "words": item.get("words", 0),
                "input": item.get("input", {}).get("FUZZ", ""),
            })
    except json.JSONDecodeError:
        # Try reading from output file content (sometimes ffuf writes to file)
        for line in stdout.strip().split("\n"):
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                item = json.loads(line)
                results.append({
                    "url": item.get("url", ""),
                    "status": item.get("status", 0),
                    "length": item.get("length", 0),
                    "words": item.get("words", 0),
                    "input": item.get("input", {}).get("FUZZ", ""),
                })
            except json.JSONDecodeError:
                continue
    return {"results": results, "count": len(results)}


def parse_dalfox(stdout: str) -> list[dict]:
    """Parse dalfox JSON output into XSS findings.

    Returns:
        [{"type": "verified", "poc": "...", "param": "q", "payload": "...", "severity": "high"}]
    """
    findings = []
    for line in stdout.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        if line.startswith("{"):
            try:
                item = json.loads(line)
                findings.append({
                    "type": item.get("type", ""),
                    "poc": item.get("poc", item.get("proof_of_concept", "")),
                    "param": item.get("param", item.get("parameter", "")),
                    "payload": item.get("payload", ""),
                    "severity": item.get("severity", "medium"),
                    "message": item.get("message", item.get("msg", "")),
                })
            except json.JSONDecodeError:
                continue
        elif "[POC]" in line or "[V]" in line:
            # Text mode fallback: "[POC][V] http://target/path?q=<script>..."
            findings.append({
                "type": "verified",
                "poc": line,
                "param": "",
                "payload": line,
                "severity": "high",
                "message": line,
            })
    return findings


def parse_commix(stdout: str) -> dict:
    """Parse commix output for command injection results.

    Returns:
        {
            "injectable": True/False,
            "technique": "classic",
            "parameter": "id",
            "os": "Linux",
            "details": "..."
        }
    """
    result = {
        "injectable": False,
        "technique": "",
        "parameter": "",
        "os": "",
        "details": "",
    }

    for line in stdout.split("\n"):
        line = line.strip()

        if "is injectable" in line.lower() or "command injection" in line.lower():
            result["injectable"] = True

        param_match = re.search(
            r"parameter\s+['\"]?(\w+)['\"]?\s+(?:is|appears)\s+injectable",
            line, re.IGNORECASE,
        )
        if param_match:
            result["injectable"] = True
            result["parameter"] = param_match.group(1)

        tech_match = re.search(
            r"technique:\s*(\S+)", line, re.IGNORECASE,
        )
        if tech_match:
            result["technique"] = tech_match.group(1)

        os_match = re.search(
            r"operating system:\s*(.+)", line, re.IGNORECASE,
        )
        if os_match:
            result["os"] = os_match.group(1).strip()

    if result["injectable"]:
        parts = []
        if result["parameter"]:
            parts.append(f"Parameter '{result['parameter']}' is injectable")
        if result["technique"]:
            parts.append(f"Technique: {result['technique']}")
        if result["os"]:
            parts.append(f"OS: {result['os']}")
        result["details"] = ". ".join(parts) if parts else "Command injection confirmed"

    return result


def parse_arjun(stdout: str) -> dict:
    """Parse arjun JSON output into discovered parameters.

    Returns:
        {
            "url": "http://target/endpoint",
            "params": ["id", "debug", "admin"],
            "count": 3
        }
    """
    result = {"url": "", "params": [], "count": 0}

    # Arjun -oJ writes JSON
    try:
        data = json.loads(stdout)
        # arjun output format: {"url": {params: [...]}}
        if isinstance(data, dict):
            for url, params in data.items():
                if url.startswith("http"):
                    result["url"] = url
                    if isinstance(params, list):
                        result["params"] = params
                    elif isinstance(params, dict):
                        result["params"] = list(params.keys())
                    break
    except json.JSONDecodeError:
        # Try text output: "[param_name]" lines
        for line in stdout.strip().split("\n"):
            line = line.strip()
            param_match = re.match(r"\[(\w+)\]", line)
            if param_match:
                result["params"].append(param_match.group(1))
            # Also handle "URL: http://..." line
            url_match = re.match(r"URL:\s*(https?://\S+)", line)
            if url_match:
                result["url"] = url_match.group(1)

    result["count"] = len(result["params"])
    return result


def parse_feroxbuster(stdout: str) -> list[dict]:
    """Parse feroxbuster JSON output into discovered paths.

    Returns:
        [{"url": "...", "status": 200, "content_length": 1234, "lines": 50, "words": 200}]
    """
    results = []
    for line in stdout.strip().split("\n"):
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
            results.append({
                "url": item.get("url", ""),
                "status": item.get("status", 0),
                "content_length": item.get("content_length", item.get("length", 0)),
                "lines": item.get("line_count", item.get("lines", 0)),
                "words": item.get("word_count", item.get("words", 0)),
            })
        except json.JSONDecodeError:
            continue
    return results


def parse_curl(stdout: str) -> dict:
    """Parse curl -D- output into structured HTTP response.

    Returns:
        {
            "status_code": 200,
            "status_line": "HTTP/1.1 200 OK",
            "headers": {"Content-Type": "application/json", ...},
            "body": "...",
            "body_json": {...} or None
        }
    """
    result = {
        "status_code": 0,
        "status_line": "",
        "headers": {},
        "body": "",
        "body_json": None,
    }

    # Split headers and body (separated by \r\n\r\n or \n\n)
    parts = re.split(r"\r?\n\r?\n", stdout, maxsplit=1)
    header_section = parts[0] if parts else ""
    body = parts[1] if len(parts) > 1 else ""

    # Parse status line
    for line in header_section.split("\n"):
        line = line.strip()
        status_match = re.match(r"(HTTP/[\d.]+\s+(\d+)\s+.*)", line)
        if status_match:
            result["status_line"] = status_match.group(1)
            result["status_code"] = int(status_match.group(2))
            continue
        # Parse headers
        header_match = re.match(r"([^:]+):\s*(.*)", line)
        if header_match:
            result["headers"][header_match.group(1).strip()] = header_match.group(2).strip()

    result["body"] = body

    # Try to parse body as JSON
    if body.strip():
        try:
            result["body_json"] = json.loads(body.strip())
        except json.JSONDecodeError:
            pass

    return result


def parse_js_analysis(source: str) -> dict:
    """Extract API endpoints, secrets, and config from JavaScript source code.

    Returns:
        {
            "endpoints": ["/api/Users", "/rest/products", ...],
            "secrets": ["apiKey=...", ...],
            "admin_routes": ["/admin", ...],
            "websocket_endpoints": ["ws://...", ...],
            "auth_mechanisms": ["JWT", "Bearer", ...]
        }
    """
    # Cap input size to avoid regex catastrophe on huge vendor bundles
    MAX_JS_SIZE = 512_000  # 512KB — app code is at the start/end, not deep in vendor deps
    if len(source) > MAX_JS_SIZE:
        # Analyze first and last 256KB (app code often split around vendor code)
        source = source[:MAX_JS_SIZE // 2] + source[-(MAX_JS_SIZE // 2):]

    result = {
        "endpoints": [],
        "secrets": [],
        "admin_routes": [],
        "websocket_endpoints": [],
        "auth_mechanisms": [],
    }

    # API endpoint patterns
    api_patterns = [
        r"""['"`](/api/\w[\w/\-]*)['"`]""",
        r"""['"`](/rest/\w[\w/\-]*)['"`]""",
        r"""['"`](/v[0-9]+/\w[\w/\-]*)['"`]""",
        r"""['"`](/graphql\w*)['"`]""",
        r"""url:\s*['"`](/[\w/\-]+)['"`]""",
        r"""endpoint:\s*['"`](/[\w/\-]+)['"`]""",
        r"""path:\s*['"`](/[\w/\-]+)['"`]""",
    ]
    seen_endpoints = set()
    for pattern in api_patterns:
        for m in re.finditer(pattern, source):
            ep = m.group(1)
            if ep not in seen_endpoints and len(ep) > 2:
                seen_endpoints.add(ep)
                result["endpoints"].append(ep)

    # Secret/API key patterns
    secret_patterns = [
        r"""(?:api[_-]?key|apikey|api_secret|secret_key|access_token)\s*[:=]\s*['"`]([^'"`\s]{8,})['"`]""",
        r"""(?:AWS_ACCESS_KEY_ID|aws_secret)\s*[:=]\s*['"`]([^'"`\s]{16,})['"`]""",
        r"""(?:Bearer|Basic)\s+([A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+)""",
    ]
    for pattern in secret_patterns:
        for m in re.finditer(pattern, source, re.IGNORECASE):
            result["secrets"].append(m.group(0)[:100])

    # Admin routes
    admin_patterns = [
        r"""['"`](/admin[\w/\-]*)['"`]""",
        r"""['"`](/dashboard[\w/\-]*)['"`]""",
        r"""['"`](/manage[\w/\-]*)['"`]""",
        r"""['"`](/internal[\w/\-]*)['"`]""",
    ]
    for pattern in admin_patterns:
        for m in re.finditer(pattern, source, re.IGNORECASE):
            route = m.group(1)
            if route not in result["admin_routes"]:
                result["admin_routes"].append(route)

    # WebSocket endpoints
    ws_patterns = [
        r"""(wss?://[^\s'"`]+)""",
        r"""new\s+WebSocket\s*\(\s*['"`]([^'"`]+)['"`]""",
    ]
    for pattern in ws_patterns:
        for m in re.finditer(pattern, source):
            result["websocket_endpoints"].append(m.group(1))

    # Auth mechanisms
    if re.search(r'\bjwt\b|jsonwebtoken|jose', source, re.IGNORECASE):
        result["auth_mechanisms"].append("JWT")
    if re.search(r'Bearer\s', source):
        result["auth_mechanisms"].append("Bearer")
    if re.search(r'\.cookie|set-cookie|session', source, re.IGNORECASE):
        result["auth_mechanisms"].append("Cookie/Session")
    if re.search(r'oauth|openid', source, re.IGNORECASE):
        result["auth_mechanisms"].append("OAuth")

    return result
