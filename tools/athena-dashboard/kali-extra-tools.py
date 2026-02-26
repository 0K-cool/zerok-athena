#!/usr/bin/env python3
"""
ATHENA Kali Extra Tools Blueprint
Additional tool endpoints to align Kali External (Antsle) with Kali Internal (Mini-PC).
Tools: naabu, nuclei, httpx, katana, gau, responder, crackmapexec,
       eyewitness, whatweb, kiterunner, s3scanner, brutus, titus,
       fingerprintx, interactsh, cvemap, dnsx, uncover, chisel,
       impacket, theHarvester, prowler, pacu, trivy, zaproxy, kill-all
"""

import logging
import os
import subprocess
from flask import Blueprint, request, jsonify

logger = logging.getLogger(__name__)

extra_tools_bp = Blueprint("extra_tools", __name__)

# Track active processes for kill-all
_active_processes = set()


def execute_command(command, timeout=300):
    """Execute a shell command and return the result."""
    import threading
    logger.info(f"Executing: {command}")
    try:
        process = subprocess.Popen(
            command, shell=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1
        )
        _active_processes.add(process)
        stdout_data = ""
        stderr_data = ""

        def read_stdout():
            nonlocal stdout_data
            for line in iter(process.stdout.readline, ""):
                stdout_data += line

        def read_stderr():
            nonlocal stderr_data
            for line in iter(process.stderr.readline, ""):
                stderr_data += line

        t1 = threading.Thread(target=read_stdout, daemon=True)
        t2 = threading.Thread(target=read_stderr, daemon=True)
        t1.start()
        t2.start()
        timed_out = False
        try:
            return_code = process.wait(timeout=timeout)
            t1.join()
            t2.join()
        except subprocess.TimeoutExpired:
            timed_out = True
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
            return_code = -1
        _active_processes.discard(process)
        success = True if timed_out and (stdout_data or stderr_data) else (return_code == 0)
        return {
            "stdout": stdout_data, "stderr": stderr_data,
            "return_code": return_code, "success": success,
            "timed_out": timed_out,
            "partial_results": timed_out and bool(stdout_data or stderr_data)
        }
    except Exception as e:
        return {
            "stdout": "", "stderr": f"Error: {str(e)}",
            "return_code": -1, "success": False,
            "timed_out": False, "partial_results": False
        }


@extra_tools_bp.route("/api/kill-all", methods=["POST"])
def kill_all():
    """Kill all active processes started by tool endpoints."""
    killed = 0
    for proc in list(_active_processes):
        try:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                killed += 1
        except Exception as e:
            logger.warning(f"Failed to kill process {proc.pid}: {e}")
        _active_processes.discard(proc)
    logger.info(f"kill-all: terminated {killed} active process(es)")
    return jsonify({"killed": killed})


@extra_tools_bp.route("/api/tools/naabu", methods=["POST"])
def naabu():
    """Port scanning with naabu (ProjectDiscovery)."""
    params = request.json
    target = params.get("target", "")
    if not target:
        return jsonify({"error": "Target parameter is required"}), 400
    ports = params.get("ports", "")
    additional_args = params.get("additional_args", "")
    cmd = f"naabu -host {target}"
    if ports:
        cmd += f" -p {ports}"
    if additional_args:
        cmd += f" {additional_args}"
    return jsonify(execute_command(cmd))


@extra_tools_bp.route("/api/tools/nuclei", methods=["POST"])
def nuclei():
    """Vulnerability scanning with nuclei (ProjectDiscovery)."""
    params = request.json
    target = params.get("target", "")
    if not target:
        return jsonify({"error": "Target parameter is required"}), 400
    templates = params.get("templates", "")
    severity = params.get("severity", "")
    additional_args = params.get("additional_args", "")
    cmd = f"nuclei -u {target}"
    if templates:
        cmd += f" -t {templates}"
    if severity:
        cmd += f" -severity {severity}"
    if additional_args:
        cmd += f" {additional_args}"
    return jsonify(execute_command(cmd))


@extra_tools_bp.route("/api/tools/httpx", methods=["POST"])
def httpx():
    """HTTP probing with httpx (ProjectDiscovery)."""
    params = request.json
    target = params.get("target", "")
    if not target:
        return jsonify({"error": "Target parameter is required"}), 400
    additional_args = params.get("additional_args", "-sc -title -tech-detect")
    cmd = f"echo {target} | httpx {additional_args}"
    return jsonify(execute_command(cmd))


@extra_tools_bp.route("/api/tools/katana", methods=["POST"])
def katana():
    """Web crawling with katana (ProjectDiscovery)."""
    params = request.json
    target = params.get("target", "")
    if not target:
        return jsonify({"error": "Target parameter is required"}), 400
    depth = params.get("depth", "2")
    additional_args = params.get("additional_args", "")
    cmd = f"katana -u {target} -d {depth}"
    if additional_args:
        cmd += f" {additional_args}"
    return jsonify(execute_command(cmd))


@extra_tools_bp.route("/api/tools/gau", methods=["POST"])
def gau():
    """URL discovery with GetAllURLs (gau)."""
    params = request.json
    target = params.get("target", "")
    if not target:
        return jsonify({"error": "Target parameter is required"}), 400
    additional_args = params.get("additional_args", "")
    cmd = f"echo {target} | gau"
    if additional_args:
        cmd += f" {additional_args}"
    return jsonify(execute_command(cmd))


@extra_tools_bp.route("/api/tools/responder", methods=["POST"])
def responder():
    """LLMNR/NBT-NS poisoning with Responder."""
    params = request.json
    interface = params.get("interface", "")
    if not interface:
        return jsonify({"error": "Interface parameter is required"}), 400
    analyze_only = params.get("analyze_only", True)
    additional_args = params.get("additional_args", "")
    cmd = f"responder -I {interface}"
    if analyze_only:
        cmd += " -A"
    if additional_args:
        cmd += f" {additional_args}"
    return jsonify(execute_command(cmd))


@extra_tools_bp.route("/api/tools/crackmapexec", methods=["POST"])
def crackmapexec():
    """Network pentesting with CrackMapExec."""
    params = request.json
    target = params.get("target", "")
    protocol = params.get("protocol", "smb")
    if not target:
        return jsonify({"error": "Target parameter is required"}), 400
    additional_args = params.get("additional_args", "")
    cmd = f"crackmapexec {protocol} {target}"
    if additional_args:
        cmd += f" {additional_args}"
    return jsonify(execute_command(cmd))


@extra_tools_bp.route("/api/tools/eyewitness", methods=["POST"])
def eyewitness():
    """Web screenshot/recon with EyeWitness."""
    params = request.json
    target_file = params.get("target_file", "")
    target_url = params.get("target_url", "")
    if not target_file and not target_url:
        return jsonify({"error": "target_file or target_url is required"}), 400
    output_dir = params.get("output_dir", "/tmp/eyewitness_output")
    additional_args = params.get("additional_args", "")
    if target_file:
        cmd = f"eyewitness -f {target_file} -d {output_dir} --no-prompt"
    else:
        cmd = f"eyewitness --single {target_url} -d {output_dir} --no-prompt"
    if additional_args:
        cmd += f" {additional_args}"
    return jsonify(execute_command(cmd))


@extra_tools_bp.route("/api/tools/whatweb", methods=["POST"])
def whatweb():
    """Web fingerprinting with WhatWeb."""
    params = request.json
    target = params.get("target", "")
    if not target:
        return jsonify({"error": "Target parameter is required"}), 400
    additional_args = params.get("additional_args", "-v")
    cmd = f"whatweb {additional_args} {target}"
    return jsonify(execute_command(cmd))


@extra_tools_bp.route("/api/tools/kiterunner", methods=["POST"])
def kiterunner():
    """API endpoint discovery with Kiterunner."""
    params = request.json
    target = params.get("target", "")
    if not target:
        return jsonify({"error": "Target parameter is required"}), 400
    wordlist = params.get("wordlist", "")
    additional_args = params.get("additional_args", "")
    cmd = f"kiterunner scan {target}"
    if wordlist:
        cmd += f" -w {wordlist}"
    if additional_args:
        cmd += f" {additional_args}"
    return jsonify(execute_command(cmd))


@extra_tools_bp.route("/api/tools/s3scanner", methods=["POST"])
def s3scanner():
    """S3 bucket enumeration with s3scanner."""
    params = request.json
    bucket = params.get("bucket", "")
    if not bucket:
        return jsonify({"error": "Bucket parameter is required"}), 400
    additional_args = params.get("additional_args", "")
    cmd = f"s3scanner scan --bucket {bucket}"
    if additional_args:
        cmd += f" {additional_args}"
    return jsonify(execute_command(cmd))


@extra_tools_bp.route("/api/tools/brutus", methods=["POST"])
def brutus():
    """Credential testing with Brutus (Praetorian) — 23 protocols, embedded SSH bad keys."""
    params = request.json
    target = params.get("target", "")
    protocol = params.get("protocol", "")
    if not target:
        return jsonify({"error": "Target parameter is required (host:port)"}), 400
    if not protocol:
        return jsonify({"error": "Protocol parameter is required (ssh, smb, mysql, etc.)"}), 400
    usernames = params.get("usernames", "root,admin")
    passwords = params.get("passwords", "")
    password_file = params.get("password_file", "")
    key_file = params.get("key_file", "")
    spray = params.get("spray", False)
    badkeys = params.get("badkeys", True)
    additional_args = params.get("additional_args", "")
    cmd = f"brutus --target {target} --protocol {protocol} -u {usernames} --json -q"
    if passwords:
        cmd += f" -p {passwords}"
    if password_file:
        cmd += f" -P {password_file}"
    if key_file:
        cmd += f" -k {key_file}"
    if spray:
        cmd += " --spray"
    if not badkeys:
        cmd += " --no-badkeys"
    if additional_args:
        cmd += f" {additional_args}"
    return jsonify(execute_command(cmd, timeout=600))


@extra_tools_bp.route("/api/tools/brutus-pipeline", methods=["POST"])
def brutus_pipeline():
    """Brutus pipeline mode: naabu → fingerprintx → brutus (auto credential testing)."""
    params = request.json
    target = params.get("target", "")
    if not target:
        return jsonify({"error": "Target parameter is required (host or CIDR)"}), 400
    ports = params.get("ports", "")
    usernames = params.get("usernames", "root,admin")
    passwords = params.get("passwords", "")
    additional_args = params.get("additional_args", "")
    cmd = f"naabu -host {target} -silent"
    if ports:
        cmd += f" -p {ports}"
    cmd += f" | fingerprintx --json | brutus --fingerprintx -u {usernames} --json -q"
    if passwords:
        cmd += f" -p {passwords}"
    if additional_args:
        cmd += f" {additional_args}"
    return jsonify(execute_command(cmd, timeout=900))


@extra_tools_bp.route("/api/tools/titus", methods=["POST"])
def titus():
    """Secret scanning with Titus (Praetorian) — 450+ rules, live validation."""
    params = request.json
    target_path = params.get("target_path", "")
    if not target_path:
        return jsonify({"error": "target_path parameter is required"}), 400
    git_mode = params.get("git", False)
    validate = params.get("validate", False)
    extract = params.get("extract", "")
    output_format = params.get("format", "json")
    additional_args = params.get("additional_args", "")
    cmd = f"titus scan {target_path} --format {output_format}"
    if git_mode:
        cmd += " --git"
    if validate:
        cmd += " --validate"
    if extract:
        cmd += f" --extract {extract}"
    if additional_args:
        cmd += f" {additional_args}"
    return jsonify(execute_command(cmd, timeout=600))


@extra_tools_bp.route("/api/tools/fingerprintx", methods=["POST"])
def fingerprintx():
    """Service fingerprinting with fingerprintx (Praetorian)."""
    params = request.json
    target = params.get("target", "")
    if not target:
        return jsonify({"error": "Target parameter is required (host:port)"}), 400
    additional_args = params.get("additional_args", "")
    cmd = f"echo {target} | fingerprintx --json"
    if additional_args:
        cmd += f" {additional_args}"
    return jsonify(execute_command(cmd))


# ==================== NEW TOOLS (Feb 2026) ====================


@extra_tools_bp.route("/api/tools/interactsh", methods=["POST"])
def interactsh():
    """OOB interaction server with interactsh (ProjectDiscovery) — blind SSRF/SQLi/XSS detection."""
    params = request.json
    poll_interval = params.get("poll_interval", 5)
    token = params.get("token", "")
    additional_args = params.get("additional_args", "")
    cmd = f"interactsh-client -poll-interval {poll_interval} -json -nc"
    if token:
        cmd += f" -token {token}"
    if additional_args:
        cmd += f" {additional_args}"
    timeout = params.get("timeout", 120)
    return jsonify(execute_command(cmd, timeout=timeout))


@extra_tools_bp.route("/api/tools/cvemap", methods=["POST"])
def cvemap():
    """CVE intelligence lookup with cvemap (ProjectDiscovery) — EPSS, KEV, PoC status."""
    params = request.json
    cve_id = params.get("cve_id", "")
    keyword = params.get("keyword", "")
    severity = params.get("severity", "")
    if not cve_id and not keyword:
        return jsonify({"error": "cve_id or keyword parameter is required"}), 400
    additional_args = params.get("additional_args", "")
    cmd = "cvemap -json"
    if cve_id:
        cmd += f" -id {cve_id}"
    if keyword:
        cmd += f" -search {keyword}"
    if severity:
        cmd += f" -severity {severity}"
    if additional_args:
        cmd += f" {additional_args}"
    return jsonify(execute_command(cmd))


@extra_tools_bp.route("/api/tools/dnsx", methods=["POST"])
def dnsx():
    """DNS resolution and enumeration with dnsx (ProjectDiscovery)."""
    params = request.json
    target = params.get("target", "")
    if not target:
        return jsonify({"error": "Target parameter is required (domain or subdomain)"}), 400
    record_type = params.get("record_type", "")
    wordlist = params.get("wordlist", "")
    additional_args = params.get("additional_args", "")
    cmd = f"echo {target} | dnsx -json -resp"
    if record_type:
        cmd += f" -{record_type}"
    if wordlist:
        cmd += f" -w {wordlist}"
    if additional_args:
        cmd += f" {additional_args}"
    return jsonify(execute_command(cmd))


@extra_tools_bp.route("/api/tools/uncover", methods=["POST"])
def uncover():
    """Internet scanner aggregation with uncover (ProjectDiscovery) — Shodan/Censys/FOFA."""
    params = request.json
    query = params.get("query", "")
    if not query:
        return jsonify({"error": "Query parameter is required"}), 400
    engine = params.get("engine", "shodan")
    limit = params.get("limit", 100)
    additional_args = params.get("additional_args", "")
    cmd = f"uncover -q '{query}' -e {engine} -l {limit} -json"
    if additional_args:
        cmd += f" {additional_args}"
    return jsonify(execute_command(cmd))


@extra_tools_bp.route("/api/tools/chisel", methods=["POST"])
def chisel():
    """HTTP tunneling/pivoting with Chisel — reverse port forwarding and SOCKS proxy."""
    params = request.json
    mode = params.get("mode", "client")
    server_addr = params.get("server", "")
    remote = params.get("remote", "")
    port = params.get("port", "8888")
    additional_args = params.get("additional_args", "")
    if mode == "server":
        cmd = f"chisel server --port {port} --reverse"
    elif mode == "client":
        if not server_addr:
            return jsonify({"error": "Server address required for client mode"}), 400
        cmd = f"chisel client {server_addr}"
        if remote:
            cmd += f" {remote}"
        else:
            cmd += " R:socks"
    else:
        return jsonify({"error": "Mode must be 'server' or 'client'"}), 400
    if additional_args:
        cmd += f" {additional_args}"
    return jsonify(execute_command(cmd, timeout=600))


@extra_tools_bp.route("/api/tools/impacket", methods=["POST"])
def impacket():
    """Active Directory attacks with Impacket (Fortra) — secretsdump, GetUserSPNs, psexec, etc."""
    params = request.json
    script = params.get("script", "")
    target = params.get("target", "")
    if not script:
        return jsonify({"error": "Script parameter is required (e.g. secretsdump, GetUserSPNs, psexec)"}), 400
    if not target:
        return jsonify({"error": "Target parameter is required"}), 400
    username = params.get("username", "")
    password = params.get("password", "")
    domain = params.get("domain", "")
    hashes = params.get("hashes", "")
    additional_args = params.get("additional_args", "")
    cmd = f"impacket-{script}"
    if domain and username and password:
        cmd += f" {domain}/{username}:{password}@{target}"
    elif domain and username and hashes:
        cmd += f" {domain}/{username}@{target} -hashes {hashes}"
    elif username and password:
        cmd += f" {username}:{password}@{target}"
    elif username:
        cmd += f" {username}@{target}"
    else:
        cmd += f" {target}"
    if additional_args:
        cmd += f" {additional_args}"
    return jsonify(execute_command(cmd, timeout=300))


@extra_tools_bp.route("/api/tools/theharvester", methods=["POST"])
def theharvester():
    """OSINT reconnaissance with theHarvester — emails, subdomains, IPs from public sources."""
    params = request.json
    domain = params.get("domain", "")
    if not domain:
        return jsonify({"error": "Domain parameter is required"}), 400
    source = params.get("source", "all")
    limit = params.get("limit", 200)
    additional_args = params.get("additional_args", "")
    cmd = f"theHarvester -d {domain} -b {source} -l {limit}"
    if additional_args:
        cmd += f" {additional_args}"
    return jsonify(execute_command(cmd, timeout=300))


@extra_tools_bp.route("/api/tools/prowler", methods=["POST"])
def prowler():
    """Cloud security posture assessment with Prowler — AWS/GCP/Azure/K8s compliance."""
    params = request.json
    provider = params.get("provider", "aws")
    checks = params.get("checks", "")
    severity = params.get("severity", "")
    compliance = params.get("compliance", "")
    additional_args = params.get("additional_args", "")
    cmd = f"prowler {provider} -M json"
    if checks:
        cmd += f" -c {checks}"
    if severity:
        cmd += f" --severity {severity}"
    if compliance:
        cmd += f" --compliance {compliance}"
    if additional_args:
        cmd += f" {additional_args}"
    return jsonify(execute_command(cmd, timeout=1800))


@extra_tools_bp.route("/api/tools/pacu", methods=["POST"])
def pacu():
    """AWS exploitation with Pacu (Rhino Security Labs) — IAM escalation, data exfil, persistence."""
    params = request.json
    module = params.get("module", "")
    if not module:
        return jsonify({"error": "Module parameter is required (e.g. iam__enum_permissions, s3__download_bucket)"}), 400
    module_args = params.get("module_args", "")
    additional_args = params.get("additional_args", "")
    cmd = f"pacu --module {module}"
    if module_args:
        cmd += f" --module-args '{module_args}'"
    if additional_args:
        cmd += f" {additional_args}"
    return jsonify(execute_command(cmd, timeout=600))


@extra_tools_bp.route("/api/tools/trivy", methods=["POST"])
def trivy():
    """Container/filesystem/IaC vulnerability scanning with Trivy (Aqua Security)."""
    params = request.json
    target = params.get("target", "")
    scan_type = params.get("scan_type", "fs")
    if not target:
        return jsonify({"error": "Target parameter is required (image, path, or repo URL)"}), 400
    severity = params.get("severity", "CRITICAL,HIGH")
    output_format = params.get("format", "json")
    scanners = params.get("scanners", "vuln,secret,misconfig")
    additional_args = params.get("additional_args", "")
    cmd = f"trivy {scan_type} {target} --format {output_format} --severity {severity} --scanners {scanners}"
    if additional_args:
        cmd += f" {additional_args}"
    return jsonify(execute_command(cmd, timeout=600))


@extra_tools_bp.route("/api/tools/zaproxy", methods=["POST"])
def zaproxy():
    """DAST web scanning with ZAP (Checkmarx) — authenticated scanning, spidering, active scan."""
    params = request.json
    target = params.get("target", "")
    if not target:
        return jsonify({"error": "Target URL parameter is required"}), 400
    scan_type = params.get("scan_type", "baseline")
    additional_args = params.get("additional_args", "")
    if scan_type == "baseline":
        cmd = f"zaproxy -cmd -quickurl {target} -quickout /tmp/zap-report.json"
    elif scan_type == "full":
        cmd = f"zaproxy -cmd -quickurl {target} -quickprogress -quickout /tmp/zap-report.json"
    elif scan_type == "api":
        api_def = params.get("api_definition", "")
        cmd = f"zaproxy -cmd -quickurl {target} -quickout /tmp/zap-report.json"
        if api_def:
            cmd += f" -openapiurl {api_def}"
    else:
        cmd = f"zaproxy -cmd -quickurl {target} -quickout /tmp/zap-report.json"
    if additional_args:
        cmd += f" {additional_args}"
    return jsonify(execute_command(cmd, timeout=1800))
