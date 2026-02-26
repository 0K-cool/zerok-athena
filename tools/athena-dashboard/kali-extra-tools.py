#!/usr/bin/env python3
"""
ATHENA Kali Extra Tools Blueprint
Additional tool endpoints to align Kali External (Antsle) with Kali Internal (Mini-PC).
Tools: naabu, nuclei, httpx, katana, gau, responder, crackmapexec,
       eyewitness, whatweb, kiterunner, s3scanner, brutus, titus,
       fingerprintx, kill-all
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
