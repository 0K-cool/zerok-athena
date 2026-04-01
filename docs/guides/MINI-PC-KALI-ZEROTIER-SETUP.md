# Mini-PC Kali Linux + ZeroTier Setup Guide
# ATHENA Internal Pentest Backend

**Version:** 1.1
**Date:** 2026-02-17
**Author:** VERSANT Security Team
**Purpose:** Configure a dedicated mini-PC as the Kali Linux execution backend for ATHENA

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Fill-In Reference](#fill-in-reference)
- [Section 1: Kali Linux Installation](#section-1-kali-linux-installation)
  - [1.1 Download Kali ISO](#11-download-kali-iso)
  - [1.2 Create Bootable USB](#12-create-bootable-usb)
  - [1.3 Installation Steps](#13-installation-steps)
  - [1.4 Post-Install: Update and Upgrade](#14-post-install-update-and-upgrade)
  - [1.5 Create Non-Root User and Configure sudo](#15-create-non-root-user-and-configure-sudo)
- [Section 2: ZeroTier Installation and Configuration](#section-2-zerotier-installation-and-configuration)
  - [2.1 Install ZeroTier](#21-install-zerotier)
  - [2.2 Join Your Network](#22-join-your-network)
  - [2.3 Authorize the Device](#23-authorize-the-device)
  - [2.4 Verify Connectivity](#24-verify-connectivity)
  - [2.5 Enable ZeroTier on Boot](#25-enable-zerotier-on-boot)
  - [2.6 Firewall Rules for ZeroTier Interface](#26-firewall-rules-for-zerotier-interface)
  - [2.7 Test Connectivity from Mac](#27-test-connectivity-from-mac)
- [Section 3: Kali MCP Server Setup](#section-3-kali-mcp-server-setup)
  - [3.1 Architecture Clarification](#31-architecture-clarification)
  - [3.2 Deploy the Kali Tools API Server](#32-deploy-the-kali-tools-api-server)
  - [3.3 Configure API Key](#33-configure-api-key)
  - [3.4 Identify Your ZeroTier IP for Binding](#34-identify-your-zerotier-ip-for-binding)
  - [3.5 Create systemd Service](#35-create-systemd-service)
  - [3.6 Verify the API Server is Running](#36-verify-the-api-server-is-running)
  - [3.7 Open Port 5000 on Firewall](#37-open-port-5000-on-firewall-zerotier-interface-only)
- [Section 4: ATHENA Integration](#section-4-athena-integration)
  - [4.1 Dual-Backend MCP Configuration](#41-dual-backend-mcp-configuration)
  - [4.2 API Key Authentication](#42-api-key-authentication)
  - [4.2 Restart ATHENA / Claude Code](#42-restart-athena--claude-code)
  - [4.3 Test Connectivity](#43-test-connectivity)
  - [4.4 Verify Individual Tools](#44-verify-individual-tools)
  - [4.5 Network Position: Why the Mini-PC Works](#45-network-position-why-the-mini-pc-works-for-internal-pentests)
- [Section 5: Security Hardening](#section-5-security-hardening)
  - [5.1 SSH Hardening](#51-ssh-hardening)
  - [5.2 Firewall: Complete UFW Configuration](#52-firewall-complete-ufw-configuration)
  - [5.3 Fail2ban for SSH](#53-fail2ban-for-ssh)
  - [5.4 Disk Encryption (LUKS)](#54-disk-encryption-luks)
  - [5.5 Regular Updates](#55-regular-updates)
  - [5.6 Health Check Script](#56-health-check-script)
- [Section 6: Operational Procedures](#section-6-operational-procedures)
  - [6.1 Pre-Engagement Checklist](#61-pre-engagement-checklist)
  - [6.2 Starting and Stopping the API Server](#62-starting-and-stopping-the-kali-mcp-api-server)
  - [6.3 Updating Tools and Signatures](#63-updating-tools-and-signatures)
  - [6.4 Evidence Collection from Remote Mini-PC](#64-evidence-collection-from-remote-mini-pc)
  - [6.5 Backup Procedures](#65-backup-procedures)
- [Section 7: Troubleshooting](#section-7-troubleshooting)
  - [7.1 ZeroTier Connection Issues](#71-zerotier-connection-issues)
  - [7.2 Kali MCP Server Not Responding](#72-kali-mcp-server-not-responding)
  - [7.3 Tool-Specific Issues](#73-tool-specific-issues)
  - [7.4 Network Connectivity to Targets](#74-network-connectivity-from-mini-pc-to-targets)
- [Reference: Key Addresses and Ports](#reference-key-addresses-and-ports)
- [Reference: Quick Command Cheat Sheet](#reference-quick-command-cheat-sheet)

---

## Architecture Overview

ATHENA operates a **dual-box architecture** — two Kali backends for different engagement types:

| Box | Role | URL | Network Position |
|-----|------|-----|-----------------|
| **Antsle** (existing) | External pentesting | `http://your-kali-host:5000/` | Cloud/VPS — reaches targets from the internet |
| **Mini-PC** (new) | Internal pentesting | `http://[ZEROTIER_IP]:5000/` | On-site — sits on client's internal network |

```
                              ┌──────────────────────────┐
                              │  Antsle - Kali Linux     │
                     ┌───────>│  your-kali-host    │───> External Targets
                     │        │  port 5000 (Flask API)   │    (internet-facing)
                     │        └──────────────────────────┘
[Mac - ATHENA]       │
     |               │
 .mcp.json           │ ATHENA routes by
 mcp_server.py ──────┤ engagement type
 (FastMCP client)    │
     |               │        ┌──────────────────────────┐
  ATHENA             └───────>│  Mini-PC - Kali Linux    │
                              │  ZeroTier VPN            │───> Internal Targets
                              │  port 5000 (Flask API)   │    (client LAN)
                              └──────────────────────────┘
```

**How it works:**
- `mcp_server.py` on your Mac is a **client proxy** — it speaks MCP to ATHENA and makes HTTP calls to the active Kali backend
- Both Kali boxes run a **Flask API server** on port 5000 that actually executes tools (nmap, gobuster, metasploit, etc.)
- The **antsle** is cloud-hosted and always reachable — used for external engagements (internet-facing targets)
- The **mini-PC** connects via ZeroTier VPN and is physically deployed on-site at client networks for internal assessments
- ATHENA's `.mcp.json` is configured to point at the correct backend for the current engagement type (see Section 4)

**This guide covers the mini-PC setup only.** The antsle box is already operational.

---

## Fill-In Reference

Before starting, collect these values and substitute throughout the guide:

| Placeholder | Description | Your Value |
|-------------|-------------|------------|
| `[ZEROTIER_NETWORK_ID]` | 16-character network ID from my.zerotier.com | |
| `[ZEROTIER_IP]` | ZeroTier-assigned IP for the mini-PC (e.g., 10.147.x.x) | |
| `[MINI_PC_HOSTNAME]` | Hostname you assign (e.g., `kali-athena`) | |
| `[SSH_PORT]` | Non-standard SSH port (e.g., 2222) | |
| `[PENTEST_USER]` | Non-root user for daily operations | |
| `[API_KEY]` | 64-char random string for Flask API auth | |

Generate the API key now and save it somewhere safe:

```bash
# Run this on your Mac now
python3 -c "import secrets; print(secrets.token_hex(32))"
```

---

## Section 1: Kali Linux Installation

### 1.1 Download Kali ISO

Download the **Installer** version (not live), 64-bit:

```
https://www.kali.org/get-kali/#kali-installer-images
```

Select: **Kali Linux 64-Bit (Installer)** - the `kali-linux-2025.x-installer-amd64.iso`

Verify the SHA256 hash before proceeding:

```bash
# On Mac
shasum -a 256 kali-linux-2025.x-installer-amd64.iso
# Compare against the hash on https://www.kali.org/get-kali/
```

### 1.2 Create Bootable USB

**Option A: balenaEtcher (recommended for simplicity)**

1. Download balenaEtcher: https://www.balena.io/etcher/
2. Flash the ISO to a USB drive (8GB minimum)
3. Select the ISO, select the USB drive, click Flash

**Option B: dd (command line)**

```bash
# On Mac - identify your USB drive first
diskutil list

# Flash (replace diskN with your USB disk number - DOUBLE CHECK THIS)
diskutil unmountDisk /dev/diskN
sudo dd if=kali-linux-2025.x-installer-amd64.iso of=/dev/rdiskN bs=4m status=progress
sync
```

### 1.3 Installation Steps

Boot the mini-PC from USB (typically F12 or F2 for boot menu).

Select **Graphical Install** from the Kali boot menu.

**Walk through the installer:**

1. **Language/Location/Keyboard** - set to your preference

2. **Hostname** - set to `[MINI_PC_HOSTNAME]` (e.g., `kali-athena`)

3. **Domain name** - leave blank or use `local`

4. **Root password** - set a strong password, store in 1Password as `Kali [MINI_PC_HOSTNAME] root`

5. **Create non-root user** - create `[PENTEST_USER]` here with a strong password

6. **Partition disks** - select **Guided - use entire disk and set up encrypted LVM**
   - This enables full-disk encryption (LUKS) automatically
   - **Encryption passphrase** - store in 1Password as `Kali [MINI_PC_HOSTNAME] LUKS`
   - Use separate /home partition: **No** (keep it simple for a dedicated tool machine)

7. **Software selection** - keep the defaults:
   - `[x]` Kali desktop environment
   - `[x]` top10 (Kali's top 10 tools)
   - `[x]` default (standard tool collection)
   - Optionally add: `large` for the full toolset

8. **GRUB bootloader** - install to the primary drive, yes

9. Reboot. Enter LUKS passphrase at boot.

### 1.4 Post-Install: Update and Upgrade

On first login as root or via sudo:

```bash
# Update package lists and upgrade everything
sudo apt update && sudo apt full-upgrade -y

# Reboot if kernel was updated
sudo reboot
```

After reboot, install common essentials that may be missing:

```bash
sudo apt install -y \
    curl wget git vim tmux htop \
    net-tools dnsutils whois \
    python3-pip python3-venv \
    ufw fail2ban \
    nmap gobuster dirb nikto sqlmap \
    metasploit-framework \
    hydra john wpscan enum4linux \
    wordlists

# Decompress rockyou if not already done
sudo gunzip /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true
```

### 1.5 Create Non-Root User and Configure sudo

If you did not create a non-root user during install:

```bash
# Create user
sudo useradd -m -s /bin/bash [PENTEST_USER]
sudo passwd [PENTEST_USER]

# Add to sudo group
sudo usermod -aG sudo [PENTEST_USER]

# Verify
su - [PENTEST_USER]
sudo whoami
# Should return: root
```

For tool operations that require root (nmap raw sockets, etc.), grant specific capabilities rather than running everything as root:

```bash
# Allow nmap to run without root (uses capabilities instead)
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap
```

---

## Section 2: ZeroTier Installation and Configuration

### 2.1 Install ZeroTier

```bash
curl -s https://install.zerotier.com | sudo bash
```

This installs the ZeroTier daemon and `zerotier-cli`. Verify:

```bash
sudo systemctl status zerotier-one
# Should show: active (running)
```

### 2.2 Join Your Network

```bash
sudo zerotier-cli join [ZEROTIER_NETWORK_ID]
```

Expected output: `200 join OK`

### 2.3 Authorize the Device

1. Go to https://my.zerotier.com/network/[ZEROTIER_NETWORK_ID]
2. Scroll to **Members**
3. Find the new node (shows by ZeroTier node ID)
4. Check the **Auth** checkbox to authorize it
5. Set a name: `kali-athena` or `[MINI_PC_HOSTNAME]`
6. Note the **Managed IP** assigned - this is `[ZEROTIER_IP]`

### 2.4 Verify Connectivity

On the mini-PC:

```bash
sudo zerotier-cli listnetworks
```

Expected output shows your network with status `OK` and the assigned IP:

```
200 listnetworks [ZEROTIER_NETWORK_ID] kali-internal [ZEROTIER_IP]/... ztXXXXXXXX OK PRIVATE
```

### 2.5 Enable ZeroTier on Boot

```bash
sudo systemctl enable zerotier-one
sudo systemctl is-enabled zerotier-one
# Should return: enabled
```

### 2.6 Firewall Rules for ZeroTier Interface

Identify the ZeroTier interface name:

```bash
ip link show | grep zt
# Note the interface name, typically: ztXXXXXXXX
ZEROTIER_IFACE=$(ip link show | grep -oP 'zt\w+' | head -1)
echo "ZeroTier interface: $ZEROTIER_IFACE"
```

Allow traffic on the ZeroTier interface:

```bash
# Enable ufw if not already active
sudo ufw --force enable

# Allow all traffic on ZeroTier interface (VPN tunnel - internal only)
sudo ufw allow in on $ZEROTIER_IFACE
sudo ufw allow out on $ZEROTIER_IFACE

# Allow established connections
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Check status
sudo ufw status verbose
```

### 2.7 Test Connectivity from Mac

From your Mac terminal (after the mini-PC is authorized and connected):

```bash
ping [ZEROTIER_IP]
# Should get responses

# Test SSH (after SSH is configured in Section 5)
ssh [PENTEST_USER]@[ZEROTIER_IP] -p [SSH_PORT]
```

---

## Section 3: Kali MCP Server Setup

### 3.1 Architecture Clarification

The MCP setup has **two components**:

| Component | Runs On | Purpose |
|-----------|---------|---------|
| `mcp_server.py` | Your Mac | FastMCP client proxy - bridges ATHENA to the Kali HTTP API |
| `kali-tools-api` | Mini-PC (Kali) | Flask HTTP API that actually executes pentest tools |

The component you need to deploy to the mini-PC is the **Flask API server**, not the `mcp_server.py`. The `mcp_server.py` stays on your Mac and gets updated to point to the new ZeroTier IP.

The Flask API server source is in the same repository as `mcp_server.py`. Check if there's an `api_server.py` or `server.py` alongside it:

```bash
# On your Mac
ls /Users/kelvinlomboy/VERSANT/MCPs/mcp-kali-linux-main/
```

If the repository only contains `mcp_server.py`, the Flask backend may need to be sourced separately. The upstream project referenced in the code is `https://github.com/whit3rabbit0/project_astro`. Check that repo for the server-side component.

### 3.2 Deploy the Kali Tools API Server

**Option A: Clone from the upstream repository**

```bash
# On the mini-PC
sudo apt install -y git python3-pip python3-venv

# Clone the project (check for the Flask API server component)
cd /opt
sudo git clone https://github.com/whit3rabbit0/project_astro kali-tools-api
cd kali-tools-api

# Or clone whatever repo contains the Flask server
# If you have the server code locally, copy it over:
# scp -P [SSH_PORT] /path/to/api_server.py [PENTEST_USER]@[ZEROTIER_IP]:/opt/kali-tools-api/
```

**Option B: Create a minimal Flask API server**

If the upstream repo does not have the server component separately, create one that matches the expected API endpoints that `mcp_server.py` calls:

```bash
# On the mini-PC
sudo mkdir -p /opt/kali-tools-api
sudo chown [PENTEST_USER]:[PENTEST_USER] /opt/kali-tools-api
cd /opt/kali-tools-api

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

pip install flask requests
```

Create `/opt/kali-tools-api/app.py`:

```python
#!/usr/bin/env python3
"""
Kali Tools API Server
Flask backend that executes pentest tools for ATHENA via kali-mcp.
Binds to ZeroTier interface only.
"""

import subprocess
import shlex
import os
import logging
from flask import Flask, request, jsonify
from functools import wraps

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Authentication
API_KEY = os.environ.get("KALI_API_KEY", "")
if not API_KEY:
    raise RuntimeError("KALI_API_KEY environment variable is required")


def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-API-Key") or request.args.get("api_key")
        if not key or key != API_KEY:
            return jsonify({"error": "Unauthorized", "success": False}), 401
        return f(*args, **kwargs)
    return decorated


def run_command(cmd_list, timeout=300):
    """Execute a command safely using a list (no shell=True)."""
    try:
        result = subprocess.run(
            cmd_list,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return {
            "success": True,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": f"Command timed out after {timeout}s"}
    except FileNotFoundError as e:
        return {"success": False, "error": f"Tool not found: {e}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.route("/health", methods=["GET"])
def health():
    tools = ["nmap", "gobuster", "dirb", "nikto", "sqlmap", "hydra", "john", "wpscan", "enum4linux"]
    tools_status = {}
    for tool in tools:
        result = subprocess.run(["which", tool], capture_output=True)
        tools_status[tool] = result.returncode == 0
    all_available = all(tools_status.values())
    return jsonify({
        "status": "healthy",
        "all_essential_tools_available": all_available,
        "tools_status": tools_status
    })


@app.route("/api/command", methods=["POST"])
@require_api_key
def execute_command():
    data = request.get_json()
    command = data.get("command", "")
    if not command:
        return jsonify({"error": "No command provided", "success": False}), 400
    # Use shlex.split for safe tokenization - still no shell=True
    try:
        cmd_list = shlex.split(command)
    except ValueError as e:
        return jsonify({"error": f"Invalid command: {e}", "success": False}), 400
    return jsonify(run_command(cmd_list))


@app.route("/api/tools/nmap", methods=["POST"])
@require_api_key
def nmap():
    data = request.get_json()
    target = data.get("target", "")
    scan_type = data.get("scan_type", "-sV")
    ports = data.get("ports", "")
    additional_args = data.get("additional_args", "")

    cmd = ["nmap"] + shlex.split(scan_type)
    if ports:
        cmd += ["-p", ports]
    if additional_args:
        cmd += shlex.split(additional_args)
    cmd += [target, "-oN", "-"]
    return jsonify(run_command(cmd))


@app.route("/api/tools/gobuster", methods=["POST"])
@require_api_key
def gobuster():
    data = request.get_json()
    cmd = ["gobuster", data.get("mode", "dir"),
           "-u", data.get("url", ""),
           "-w", data.get("wordlist", "/usr/share/wordlists/dirb/common.txt")]
    if data.get("additional_args"):
        cmd += shlex.split(data["additional_args"])
    return jsonify(run_command(cmd))


@app.route("/api/tools/dirb", methods=["POST"])
@require_api_key
def dirb():
    data = request.get_json()
    cmd = ["dirb", data.get("url", ""), data.get("wordlist", "/usr/share/wordlists/dirb/common.txt")]
    if data.get("additional_args"):
        cmd += shlex.split(data["additional_args"])
    return jsonify(run_command(cmd))


@app.route("/api/tools/nikto", methods=["POST"])
@require_api_key
def nikto():
    data = request.get_json()
    cmd = ["nikto", "-h", data.get("target", "")]
    if data.get("additional_args"):
        cmd += shlex.split(data["additional_args"])
    return jsonify(run_command(cmd, timeout=600))


@app.route("/api/tools/sqlmap", methods=["POST"])
@require_api_key
def sqlmap():
    data = request.get_json()
    cmd = ["sqlmap", "-u", data.get("url", ""), "--batch"]
    if data.get("data"):
        cmd += ["--data", data["data"]]
    if data.get("additional_args"):
        cmd += shlex.split(data["additional_args"])
    return jsonify(run_command(cmd, timeout=600))


@app.route("/api/tools/metasploit", methods=["POST"])
@require_api_key
def metasploit():
    data = request.get_json()
    module = data.get("module", "")
    options = data.get("options", {})
    rc_lines = [f"use {module}"]
    for k, v in options.items():
        rc_lines.append(f"set {k} {v}")
    rc_lines.append("run")
    rc_lines.append("exit")
    rc_content = "\n".join(rc_lines)

    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.rc', delete=False) as f:
        f.write(rc_content)
        rc_path = f.name

    result = run_command(["msfconsole", "-q", "-r", rc_path], timeout=600)
    os.unlink(rc_path)
    return jsonify(result)


@app.route("/api/tools/hydra", methods=["POST"])
@require_api_key
def hydra():
    data = request.get_json()
    cmd = ["hydra"]
    if data.get("username"):
        cmd += ["-l", data["username"]]
    elif data.get("username_file"):
        cmd += ["-L", data["username_file"]]
    if data.get("password"):
        cmd += ["-p", data["password"]]
    elif data.get("password_file"):
        cmd += ["-P", data["password_file"]]
    if data.get("additional_args"):
        cmd += shlex.split(data["additional_args"])
    cmd += [data.get("target", ""), data.get("service", "")]
    return jsonify(run_command(cmd, timeout=600))


@app.route("/api/tools/john", methods=["POST"])
@require_api_key
def john():
    data = request.get_json()
    cmd = ["john", data.get("hash_file", ""),
           f"--wordlist={data.get('wordlist', '/usr/share/wordlists/rockyou.txt')}"]
    if data.get("format"):
        cmd.append(f"--format={data['format']}")
    if data.get("additional_args"):
        cmd += shlex.split(data["additional_args"])
    return jsonify(run_command(cmd, timeout=3600))


@app.route("/api/tools/wpscan", methods=["POST"])
@require_api_key
def wpscan():
    data = request.get_json()
    cmd = ["wpscan", "--url", data.get("url", "")]
    if data.get("additional_args"):
        cmd += shlex.split(data["additional_args"])
    return jsonify(run_command(cmd, timeout=300))


@app.route("/api/tools/enum4linux", methods=["POST"])
@require_api_key
def enum4linux():
    data = request.get_json()
    cmd = ["enum4linux"] + shlex.split(data.get("additional_args", "-a")) + [data.get("target", "")]
    return jsonify(run_command(cmd, timeout=300))


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0", help="Bind address")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()
    app.run(host=args.host, port=args.port, debug=False)
```

### 3.3 Configure API Key

Store the API key in an environment file (not hardcoded):

```bash
# On the mini-PC
sudo mkdir -p /etc/kali-tools-api
sudo tee /etc/kali-tools-api/env << 'EOF'
KALI_API_KEY=[API_KEY]
EOF
sudo chmod 600 /etc/kali-tools-api/env
sudo chown root:root /etc/kali-tools-api/env
```

### 3.4 Identify Your ZeroTier IP for Binding

```bash
# Get ZeroTier IP
ip addr show $(ip link show | grep -oP 'zt\w+' | head -1) | grep -oP '10\.\d+\.\d+\.\d+'
# Note this as [ZEROTIER_IP]
```

### 3.5 Create systemd Service

The service should bind only to the ZeroTier interface, not expose port 5000 to the entire local network:

Create `/etc/systemd/system/kali-tools-api.service`:

```bash
sudo tee /etc/systemd/system/kali-tools-api.service << 'EOF'
[Unit]
Description=Kali Tools API Server (ATHENA Backend)
After=network.target zerotier-one.service
Wants=zerotier-one.service

[Service]
Type=simple
User=[PENTEST_USER]
Group=[PENTEST_USER]
WorkingDirectory=/opt/kali-tools-api
EnvironmentFile=/etc/kali-tools-api/env
ExecStart=/opt/kali-tools-api/venv/bin/python app.py --host [ZEROTIER_IP] --port 5000
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF
```

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable kali-tools-api
sudo systemctl start kali-tools-api
sudo systemctl status kali-tools-api
```

### 3.6 Verify the API Server is Running

```bash
# On the mini-PC - test locally first
curl http://[ZEROTIER_IP]:5000/health
# Expected: {"status":"healthy","all_essential_tools_available":true,...}

# Check it's only listening on ZeroTier IP, not 0.0.0.0
ss -tlnp | grep 5000
# Should show: [ZEROTIER_IP]:5000 not 0.0.0.0:5000
```

### 3.7 Open Port 5000 on Firewall (ZeroTier Interface Only)

```bash
ZEROTIER_IFACE=$(ip link show | grep -oP 'zt\w+' | head -1)
sudo ufw allow in on $ZEROTIER_IFACE to any port 5000 proto tcp
sudo ufw reload
sudo ufw status
```

---

## Section 4: ATHENA Integration

### 4.1 Dual-Backend MCP Configuration

ATHENA uses a dual-backend architecture. Both Kali boxes stay configured in `.mcp.json` — you switch the active backend based on engagement type.

Edit `/Users/kelvinlomboy/VERSANT/Projects/ATHENA/.mcp.json`:

```json
{
  "mcpServers": {
    "kali_external": {
      "command": "/Users/kelvinlomboy/VERSANT/MCPs/kali-linux-mcp-venv/bin/python",
      "args": [
        "/Users/kelvinlomboy/VERSANT/MCPs/mcp-kali-linux-main/mcp_server.py",
        "--server",
        "http://your-kali-host:5000/"
      ],
      "env": {
        "KALI_API_KEY": "[ANTSLE_API_KEY]"
      }
    },
    "kali_internal": {
      "command": "/Users/kelvinlomboy/VERSANT/MCPs/kali-linux-mcp-venv/bin/python",
      "args": [
        "/Users/kelvinlomboy/VERSANT/MCPs/mcp-kali-linux-main/mcp_server.py",
        "--server",
        "http://[ZEROTIER_IP]:5000/"
      ],
      "env": {
        "KALI_API_KEY": "[MINI_PC_API_KEY]"
      }
    }
  }
}
```

**Switching backends:**
- **External engagement:** Use `kali_external` tools (routes to antsle)
- **Internal engagement:** Use `kali_internal` tools (routes to mini-PC via ZeroTier)
- Both can be active simultaneously if running parallel engagements
- To disable one: comment it out or remove from `.mcp.json` and restart Claude Code

**Tool naming convention:** With both backends active, ATHENA will see two sets of tools:
- `mcp__kali_external__nmap_scan` — runs on antsle (external)
- `mcp__kali_internal__nmap_scan` — runs on mini-PC (internal)

This makes it explicit which box is executing each command during engagements.

### 4.2 API Key Authentication

Both backends should use API key authentication. The current `mcp_server.py` does not send an API key header by default. Update `mcp_server.py` to pass the key:

```python
# Add to KaliToolsClient.__init__
self.api_key = os.environ.get("KALI_API_KEY", "")

# Add header to safe_get and safe_post requests:
headers = {"X-API-Key": self.api_key} if self.api_key else {}
response = requests.get(url, params=params, timeout=self.timeout, headers=headers)
```

**Store API keys in 1Password:**
- `op://Private/Kali Antsle API Key/credential` — for the antsle box
- `op://Private/Kali Mini-PC API Key/credential` — for the mini-PC

Generate unique keys for each box:
```bash
python3 -c "import secrets; print('Antsle:', secrets.token_hex(32))"
python3 -c "import secrets; print('Mini-PC:', secrets.token_hex(32))"
```

### 4.2 Restart ATHENA / Claude Code

After updating `.mcp.json`, fully restart Claude Code for the MCP config change to take effect. `/mcp reconnect` will NOT re-read the file.

```bash
# Exit Claude Code completely, then reopen ATHENA project
exit
claude --project /Users/kelvinlomboy/VERSANT/Projects/ATHENA
```

### 4.3 Test Connectivity

In ATHENA, use the MCP tool:

```
server_health()
```

Expected response:
```json
{
  "status": "healthy",
  "all_essential_tools_available": true,
  "tools_status": {
    "nmap": true,
    "gobuster": true,
    "dirb": true,
    "nikto": true,
    "sqlmap": true,
    "hydra": true,
    "john": true,
    "wpscan": true,
    "enum4linux": true
  }
}
```

### 4.4 Verify Individual Tools

Run these from ATHENA to confirm each tool works end-to-end:

```
# Test nmap - scan the mini-PC itself
nmap_scan(target="[ZEROTIER_IP]", scan_type="-sV", ports="22,5000")

# Test gobuster - requires a running web server as target
gobuster_scan(url="http://[TEST_TARGET]/", mode="dir")

# Test nikto
nikto_scan(target="http://[TEST_TARGET]/")
```

### 4.5 Network Position: Why the Mini-PC Works for Internal Pentests

The mini-PC is physically connected to the client's internal network during an engagement. This means:

- nmap scans reach internal targets **directly** over LAN (fast, no NAT)
- Metasploit payloads connect to the mini-PC's **local IP** (the one on the client network, not ZeroTier)
- ATHENA on your Mac sends commands via ZeroTier, which arrive at the mini-PC, which then operates on the local network

For Metasploit handlers, set LHOST to the mini-PC's **local interface IP** (not ZeroTier IP), so reverse shells reach it directly:

```
metasploit_run(
  module="exploit/multi/handler",
  options={"LHOST": "192.168.x.x", "LPORT": "4444", "PAYLOAD": "linux/x64/meterpreter/reverse_tcp"}
)
```

---

## Section 5: Security Hardening

### 5.1 SSH Hardening

Generate SSH key pair on your Mac:

```bash
ssh-keygen -t ed25519 -C "athena-kali-minipc" -f ~/.ssh/athena_kali
```

Copy public key to the mini-PC:

```bash
ssh-copy-id -i ~/.ssh/athena_kali.pub [PENTEST_USER]@[ZEROTIER_IP]
```

Harden SSH on the mini-PC. Edit `/etc/ssh/sshd_config`:

```bash
sudo tee /etc/ssh/sshd_config.d/hardened.conf << 'EOF'
# Non-standard port
Port [SSH_PORT]

# Key auth only
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PermitRootLogin no
PermitEmptyPasswords no

# Connection limits
MaxAuthTries 3
MaxSessions 5
LoginGraceTime 30

# Disable unused features
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PrintLastLog yes

# Allowed users only
AllowUsers [PENTEST_USER]
EOF

sudo systemctl restart sshd
```

Update firewall to allow SSH only on ZeroTier interface:

```bash
ZEROTIER_IFACE=$(ip link show | grep -oP 'zt\w+' | head -1)

# Remove any default SSH allow rules
sudo ufw delete allow ssh 2>/dev/null
sudo ufw delete allow 22/tcp 2>/dev/null

# Allow SSH only via ZeroTier
sudo ufw allow in on $ZEROTIER_IFACE to any port [SSH_PORT] proto tcp
sudo ufw reload
```

Test before closing existing session:

```bash
# In a NEW terminal on your Mac
ssh -i ~/.ssh/athena_kali -p [SSH_PORT] [PENTEST_USER]@[ZEROTIER_IP]
```

Add SSH config entry on your Mac for convenience. Add to `~/.ssh/config`:

```
Host kali-athena
    HostName [ZEROTIER_IP]
    User [PENTEST_USER]
    Port [SSH_PORT]
    IdentityFile ~/.ssh/athena_kali
    ServerAliveInterval 60
```

Then connect with: `ssh kali-athena`

### 5.2 Firewall: Complete UFW Configuration

```bash
# Reset and configure from scratch
sudo ufw --force reset
sudo ufw default deny incoming
sudo ufw default allow outgoing

ZEROTIER_IFACE=$(ip link show | grep -oP 'zt\w+' | head -1)

# Allow all ZeroTier traffic (SSH + API)
sudo ufw allow in on $ZEROTIER_IFACE to any port [SSH_PORT] proto tcp comment "SSH via ZeroTier"
sudo ufw allow in on $ZEROTIER_IFACE to any port 5000 proto tcp comment "Kali API via ZeroTier"

# Enable
sudo ufw --force enable
sudo ufw status verbose
```

Verify port 5000 is NOT reachable from the local network (only via ZeroTier):

```bash
# From a device on the same local network as the mini-PC (not via ZeroTier):
# This should fail/timeout:
curl http://[LOCAL_IP_OF_MINIPC]:5000/health  # should not respond
```

### 5.3 Fail2ban for SSH

```bash
sudo apt install -y fail2ban

sudo tee /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = [SSH_PORT]
logpath = %(sshd_log)s
backend = %(sshd_backend)s
EOF

sudo systemctl enable fail2ban
sudo systemctl restart fail2ban
sudo fail2ban-client status sshd
```

### 5.4 Disk Encryption (LUKS)

Disk encryption is configured during installation (Section 1.3). Verify LUKS is active:

```bash
sudo cryptsetup status $(lsblk -o NAME,TYPE | grep crypt | awk '{print $1}' | head -1)
# Should show: type: LUKS2, cipher: aes-xts-plain64
```

**LUKS passphrase is required at every boot.** This is expected behavior - the machine is offline until you enter it (either physically at keyboard or via remote KVM if available).

### 5.5 Regular Updates

Set up automatic security updates:

```bash
sudo apt install -y unattended-upgrades apt-listchanges

sudo tee /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

# Configure to update Kali security feed
sudo dpkg-reconfigure -plow unattended-upgrades
```

For tool signatures specifically (metasploit modules, nikto plugins, wpscan db):

```bash
sudo tee /etc/cron.weekly/update-pentest-tools << 'EOF'
#!/bin/bash
# Update pentest tool signatures weekly
msfdb reinit &>/dev/null
msfupdate &>/dev/null
nikto -update &>/dev/null
wpscan --update &>/dev/null
EOF
sudo chmod +x /etc/cron.weekly/update-pentest-tools
```

### 5.6 Health Check Script

Create `/opt/kali-tools-api/health-check.sh`:

```bash
sudo tee /opt/kali-tools-api/health-check.sh << 'EOF'
#!/bin/bash
# Kali ATHENA Backend Health Check
# Run: ./health-check.sh | tee /var/log/kali-health.log

ZEROTIER_IP=$(ip addr show $(ip link show | grep -oP 'zt\w+' | head -1) 2>/dev/null | grep -oP '10\.\d+\.\d+\.\d+' | head -1)
API_URL="http://${ZEROTIER_IP}:5000"

echo "=== Kali ATHENA Health Check $(date) ==="
echo ""

# ZeroTier status
echo "[ZeroTier]"
sudo zerotier-cli listnetworks 2>/dev/null | grep -v "^200" || echo "  ERROR: ZeroTier not connected"

echo ""
echo "[API Server]"
curl -s "${API_URL}/health" 2>/dev/null | python3 -m json.tool || echo "  ERROR: API server not responding"

echo ""
echo "[Services]"
for svc in zerotier-one kali-tools-api sshd fail2ban; do
    status=$(systemctl is-active $svc 2>/dev/null)
    echo "  $svc: $status"
done

echo ""
echo "[Disk Usage]"
df -h / | tail -1

echo ""
echo "[Memory]"
free -h | grep Mem
EOF

sudo chmod +x /opt/kali-tools-api/health-check.sh
```

---

## Section 6: Operational Procedures

### 6.1 Pre-Engagement Checklist

Before any pentest engagement:

```
[ ] Written authorization obtained and on file
[ ] Scope document defines target IPs/ranges (nothing beyond this list)
[ ] ZeroTier connected: sudo zerotier-cli listnetworks
[ ] API server running: curl http://[ZEROTIER_IP]:5000/health
[ ] ATHENA connectivity: server_health() returns healthy
[ ] Mini-PC on client network: ping [FIRST_TARGET_IP]
[ ] Engagement folder created on Mac: output/client-work/[CLIENT]/
[ ] Time window confirmed with client (avoid business-critical hours)
[ ] Emergency contact for client IT available
```

### 6.2 Starting and Stopping the Kali MCP API Server

```bash
# Start
sudo systemctl start kali-tools-api

# Stop
sudo systemctl stop kali-tools-api

# Restart (after config changes)
sudo systemctl restart kali-tools-api

# Check status and recent logs
sudo systemctl status kali-tools-api
sudo journalctl -u kali-tools-api -n 50 --no-pager
```

The service starts automatically on boot if enabled. For engagements where you want manual control:

```bash
sudo systemctl disable kali-tools-api  # Remove auto-start
sudo systemctl enable kali-tools-api   # Restore auto-start
```

### 6.3 Updating Tools and Signatures

```bash
# Full system update (run before major engagements)
sudo apt update && sudo apt full-upgrade -y

# Metasploit framework update
sudo msfupdate

# WPScan database
wpscan --update

# Nikto plugins
nikto -update

# OpenVAS/GVM feeds (if installed)
# sudo gvm-feed-update
```

### 6.4 Evidence Collection from Remote Mini-PC

All tool outputs from ATHENA's MCP calls are returned directly to your Mac in the ATHENA session. For additional evidence collected on the mini-PC directly:

```bash
# On Mac - pull files from mini-PC over ZeroTier/SSH
scp -P [SSH_PORT] -i ~/.ssh/athena_kali \
    [PENTEST_USER]@[ZEROTIER_IP]:/home/[PENTEST_USER]/engagement-output/* \
    /Users/kelvinlomboy/output/client-work/[CLIENT]/03-scanning/

# Or use rsync for directory sync
rsync -avz -e "ssh -p [SSH_PORT] -i ~/.ssh/athena_kali" \
    [PENTEST_USER]@[ZEROTIER_IP]:/home/[PENTEST_USER]/engagement-output/ \
    /Users/kelvinlomboy/output/client-work/[CLIENT]/
```

For ongoing output capture during a session, use tmux with logging on the mini-PC:

```bash
# On mini-PC - start logged tmux session
tmux new-session -s engagement -d
tmux pipe-pane -t engagement -o 'cat >> /home/[PENTEST_USER]/engagement-output/session.log'
```

### 6.5 Backup Procedures

The mini-PC should be considered **ephemeral** - tools and configuration are reproducible from this guide. Client evidence and reports belong on your Mac in `output/client-work/` (gitignored, backed up separately).

For the Kali box configuration backup:

```bash
# On Mac - pull config files
ssh kali-athena "sudo tar czf /tmp/kali-config-backup.tar.gz /etc/kali-tools-api /etc/ssh/sshd_config.d /etc/fail2ban/jail.local /opt/kali-tools-api/app.py"
scp -P [SSH_PORT] -i ~/.ssh/athena_kali [PENTEST_USER]@[ZEROTIER_IP]:/tmp/kali-config-backup.tar.gz \
    /Users/kelvinlomboy/output/personal/kali-minipc-backup-$(date +%Y%m%d).tar.gz
```

---

## Section 7: Troubleshooting

### 7.1 ZeroTier Connection Issues

**Symptom:** `ping [ZEROTIER_IP]` fails from Mac

```bash
# On mini-PC - check ZeroTier status
sudo zerotier-cli status
# Should show: 200 info [NODE_ID] ONLINE

sudo zerotier-cli listnetworks
# Should show status: OK (not REQUESTING_CONFIGURATION or ACCESS_DENIED)

# If ACCESS_DENIED - the device is not authorized in ZeroTier Central
# Go to https://my.zerotier.com/network/[ZEROTIER_NETWORK_ID] and authorize it

# Restart ZeroTier daemon
sudo systemctl restart zerotier-one

# Check ZeroTier interface exists
ip link show | grep zt

# Check ZeroTier has its IP
ip addr show $(ip link show | grep -oP 'zt\w+' | head -1)
```

**Symptom:** ZeroTier shows OK but ping still fails

```bash
# Check firewall is not blocking
sudo ufw status verbose

# Temporarily allow all (diagnostic only, revert after)
sudo ufw allow from any to any
ping [ZEROTIER_IP]  # from Mac
sudo ufw delete allow from any to any  # revert immediately

# If this fixed it, check the specific ZeroTier interface rule
```

### 7.2 Kali MCP Server Not Responding

**Symptom:** `server_health()` in ATHENA returns error or connection refused

```bash
# On mini-PC - check service
sudo systemctl status kali-tools-api
sudo journalctl -u kali-tools-api -n 30 --no-pager

# Verify it's listening on ZeroTier IP
ss -tlnp | grep 5000

# Test locally on the mini-PC
curl http://[ZEROTIER_IP]:5000/health

# If not listening - check the ZEROTIER_IP in the systemd unit matches current IP
# ZeroTier IPs can change if you reset the network
ip addr show $(ip link show | grep -oP 'zt\w+' | head -1) | grep inet
```

**Symptom:** Service starts but health check fails from Mac

```bash
# Test with curl from Mac
curl http://[ZEROTIER_IP]:5000/health

# Check firewall allows port 5000 on ZeroTier interface
sudo ufw status verbose | grep 5000

# Verify the API is not bound to 127.0.0.1 only
ss -tlnp | grep 5000
# Should show [ZEROTIER_IP]:5000, not 127.0.0.1:5000
```

**Symptom:** ATHENA MCP reconnect doesn't pick up .mcp.json changes

This is a known Claude Code limitation. The MCP cache is not re-read on `/mcp reconnect`. You must fully exit and reopen Claude Code.

### 7.3 Tool-Specific Issues

**Metasploit: database not connected**

```bash
# Initialize metasploit database
sudo msfdb init

# Start PostgreSQL if not running
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Verify database connection
msfconsole -q -x "db_status; exit"
# Should show: Connected to msf. Connection type: postgresql.
```

**Nmap: permission denied for SYN scans**

```bash
# Capability approach (preferred over running as root)
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap

# Or run nmap as root for raw socket scans
# The API server runs as [PENTEST_USER] - for SYN scans you may need to
# adjust the service to run nmap with sudo:
# In /etc/sudoers.d/kali-api:
echo "[PENTEST_USER] ALL=(ALL) NOPASSWD: /usr/bin/nmap" | sudo tee /etc/sudoers.d/kali-api
# Then in the API, prefix nmap commands with 'sudo'
```

**WPScan: API token required for full results**

```bash
# Register at https://wpscan.com/register (free tier: 25 API calls/day)
# Then:
wpscan --api-token [WPSCAN_API_TOKEN] --url http://target/
# Store token in 1Password as: WPScan API Token
```

**gobuster/dirb: wordlist not found**

```bash
# Check wordlists are installed
ls /usr/share/wordlists/
ls /usr/share/wordlists/dirb/

# If missing
sudo apt install -y wordlists
sudo gunzip /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true
```

### 7.4 Network Connectivity from Mini-PC to Targets

**Symptom:** nmap scans return no results or `host down` for targets that are up

```bash
# Verify mini-PC can reach the target network
ping [TARGET_IP]

# Check which interface the route uses
ip route get [TARGET_IP]
# Should use the local LAN interface, not ZeroTier

# Verify local LAN interface has an IP on the client's subnet
ip addr show
# Look for the LAN interface (eth0, enp3s0, etc.)
```

**Symptom:** Metasploit reverse shells not connecting back

The mini-PC has two network interfaces: ZeroTier (for ATHENA control) and the local LAN (for reaching targets). For reverse shells, set LHOST to the **LAN IP**, not the ZeroTier IP:

```bash
# Find LAN IP on the mini-PC
ip addr show eth0  # or enp3s0, ens18, etc.
# Note the inet address - this is what you set for LHOST in metasploit
```

---

## Reference: Key Addresses and Ports

| Service | Interface | Port | Notes |
|---------|-----------|------|-------|
| SSH | ZeroTier only | [SSH_PORT] | Key auth, fail2ban protected |
| Kali Tools API | ZeroTier only | 5000 | API key required |
| Nessus (if installed) | localhost only | 8834 | Access via SSH tunnel |
| OpenVAS (if installed) | localhost only | 9392 | Access via SSH tunnel |

**Access Nessus/OpenVAS remotely via SSH tunnel:**

```bash
# On Mac - forward local port to mini-PC's localhost
ssh -L 8834:localhost:8834 -p [SSH_PORT] -i ~/.ssh/athena_kali [PENTEST_USER]@[ZEROTIER_IP]
# Then open https://localhost:8834 in browser
```

---

## Reference: Quick Command Cheat Sheet

```bash
# === On Mini-PC ===

# ZeroTier
sudo zerotier-cli status
sudo zerotier-cli listnetworks
sudo systemctl restart zerotier-one

# API Server
sudo systemctl status kali-tools-api
sudo journalctl -u kali-tools-api -f
sudo systemctl restart kali-tools-api

# Health check
/opt/kali-tools-api/health-check.sh

# Update tools
sudo apt update && sudo apt full-upgrade -y
sudo msfupdate
wpscan --update

# === On Mac ===

# SSH to mini-PC
ssh kali-athena

# Test API from Mac
curl http://[ZEROTIER_IP]:5000/health

# Pull evidence
scp -P [SSH_PORT] -i ~/.ssh/athena_kali [PENTEST_USER]@[ZEROTIER_IP]:/path/to/file ./

# ATHENA .mcp.json location
# /Users/kelvinlomboy/VERSANT/Projects/ATHENA/.mcp.json
```

---

**Guide Version:** 1.0
**Tested against:** mcp-kali-linux-main (mcp_server.py as found in ATHENA project)
**ZeroTier version:** 1.12.x
**Kali Linux version:** 2025.x
