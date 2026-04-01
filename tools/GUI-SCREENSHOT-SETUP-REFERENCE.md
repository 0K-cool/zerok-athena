# GUI Screenshot Capabilities - Future Reference

**Status**: Currently using headless mode (Option A)
**Date**: December 15, 2025
**Note**: This document contains research for enabling GUI-based automated screenshots if needed in future engagements

---

## Current Configuration (Active)

**Playwright MCP**: Headless mode
- Screenshots work perfectly in headless mode
- Stealth advantage for pentesting
- Consistent, automated screenshots

**Kali Linux MCP**: Headless server
- Remote execution via API
- Manual screenshots from local Mac for critical evidence

---

## Future Option 1: Playwright Headed Mode

### Enable GUI for Playwright

**Edit `.mcp.json`** and remove `--headless` flag:

```json
"playwright": {
  "command": "npx",
  "args": [
    "@playwright/mcp@latest",
    "--browser", "chromium",
    // Remove "--headless" line to enable GUI
    "--viewport-size", "1920x1080",
    "--timeout-action", "10000"
  ]
}
```

**Benefits**:
- Visual browser window during testing
- Real-time debugging
- See JavaScript execution live

**Drawbacks**:
- Higher detection risk (websites can detect headed mode)
- Requires display on local machine
- Slightly slower execution
- Minor pixel differences in screenshots (2-5px due to scrollbar rendering)

**Use Cases**:
- Debugging complex JavaScript applications
- Visual verification of exploit chains
- Client demonstrations

**References**:
- [Understanding Headless vs. Headed Modes in Playwright](https://dev.to/johnnyv5g/understanding-headless-vs-headed-modes-in-playwright-a-guide-for-qa-automation-engineers-sdets-4h7e)
- [Headed vs Headless Mode in Playwright](https://www.hashstudioz.com/blog/headed-vs-headless-mode-in-playwright/)

---

## Future Option 2: Kali Linux GUI with Xvfb (Virtual Display)

### Setup X Virtual Frame Buffer on Kali Server

**Best for**: Automated GUI screenshots without VNC complexity

**Installation** (on Kali server):
```bash
# SSH to Kali server
ssh kali@your-kali-host

# Install Xvfb
sudo apt update
sudo apt install xvfb xfonts-base xfonts-75dpi xfonts-100dpi

# Install screenshot tools
sudo apt install imagemagick scrot
```

**Usage**:
```bash
# Run Firefox with virtual display and take screenshot
xvfb-run -a --server-args="-screen 0 1920x1080x24" firefox --screenshot=output.png https://target.com

# Or use ImageMagick import with virtual display
DISPLAY=:99 xvfb-run -a import -window root screenshot.png

# For web-based tools with GUI
xvfb-run -a burpsuite &
```

**Integration with Kali MCP**:
```python
# Modify mcp_server.py to prefix commands with xvfb-run
command = f"xvfb-run -a --server-args='-screen 0 1920x1080x24' {original_command}"
```

**Benefits**:
- No VNC server needed
- Fully automated screenshots
- Works with GUI tools (Burp Suite, OWASP ZAP)
- Headless server remains headless

**Drawbacks**:
- No visual feedback during testing
- Requires Kali server modification

---

## Future Option 3: VNC Server on Kali (Full GUI Access)

### Setup VNC for Visual Access to Kali

**Installation** (on Kali server):
```bash
# Install x11vnc
sudo apt install x11vnc

# Start VNC server (one-time)
x11vnc -display :0 -forever -shared -bg -o /var/log/x11vnc.log

# Or persistent service:
sudo systemctl enable x11vnc
sudo systemctl start x11vnc
```

**Access from Mac**:
```bash
# Using built-in VNC client
open vnc://your-kali-host:5900

# Or use Screen Sharing app
# Finder → Go → Connect to Server → vnc://your-kali-host
```

**Security Enhancement**:
```bash
# Run VNC over SSH tunnel (recommended)
ssh -L 5900:localhost:5900 kali@your-kali-host
# Then connect to vnc://localhost:5900
```

**Benefits**:
- Full visual access to Kali desktop
- Real-time tool execution monitoring
- Interactive debugging
- Use GUI tools directly

**Drawbacks**:
- Network overhead
- Requires VNC client
- Security considerations (use SSH tunnel)

**References**:
- [VNC Penetration Testing](https://www.hackingarticles.in/vnc-penetration-testing/)
- [Kali tightvnc tool](https://www.kali.org/tools/tightvnc/)

---

## Future Option 4: noVNC (Browser-Based GUI)

### Official Kali Recommendation for Remote Access

**Installation** (on Kali server):
```bash
# Install noVNC and dependencies
sudo apt install novnc x11vnc websockify

# Start x11vnc
x11vnc -display :0 -localhost -forever

# Start noVNC websocket proxy
websockify --web=/usr/share/novnc/ 6080 localhost:5900
```

**Access**:
```
Open browser: http://your-kali-host:6080/vnc.html
```

**Benefits**:
- No client software needed
- HTML5 browser-based access
- Official Kali 2025.4 method
- Works on any device with browser

**Drawbacks**:
- Requires port 6080 open
- Additional service to maintain
- Bandwidth considerations

**References**:
- [Kali In The Browser (noVNC) | Official Docs](https://www.kali.org/docs/general-use/novnc-kali-in-browser/)
- [Kali Linux 2025.4 Updates](https://www.archyde.com/kali-linux-2025-4-new-tools-enhanced-security/)

---

## Future Option 5: Scrying (Automated Screenshot Tool)

### Purpose-Built Pentesting Screenshot Tool

**What it does**:
- Automated RDP, Web, and VNC screenshot collection
- Mass screenshot capture for multiple targets
- Evidence organization for reporting

**Installation**:
```bash
# On Kali server
sudo apt install scrying

# Or from source
git clone https://github.com/nccgroup/scrying
cd scrying
pip install -r requirements.txt
```

**Usage**:
```bash
# Web screenshots
scrying --web -t targets.txt -o screenshots/

# With credentials
scrying --rdp -t rdp_targets.txt -u user -p pass
```

**References**:
- [Scrying Tool for Screenshots](https://kalilinuxtutorials.com/scrying/)

---

## Screenshot Quality Comparison

| Method | Quality | Automation | Stealth | Complexity |
|--------|---------|------------|---------|------------|
| **Playwright Headless** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| Playwright Headed | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ |
| Kali + Xvfb | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ |
| Kali + VNC | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐ |
| Kali + noVNC | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐ |
| Scrying | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ |
| Manual (Local Mac) | ⭐⭐⭐⭐⭐ | ⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |

---

## Recommended Approach by Engagement Type

**Standard External Pentest** (like ACME_CORP):
- ✅ Playwright headless
- ✅ Manual screenshots from local machine
- ⚠️ Minimal complexity, maximum stealth

**Red Team / Adversary Simulation**:
- ✅ Playwright headless (stealth priority)
- ✅ Kali + Xvfb (GUI tools without VNC)
- ⚠️ Stealth over visibility

**Web Application Deep Dive**:
- ✅ Playwright headed (debugging complex JS)
- ✅ Manual screenshots for evidence
- ⚠️ Visual debugging valuable

**Large-Scale Asset Discovery**:
- ✅ Scrying (mass screenshots)
- ✅ Automated collection
- ⚠️ Volume over granularity

**Internal Pentest with Network Access**:
- ✅ Kali + VNC or noVNC
- ✅ Interactive GUI tools
- ⚠️ Security of environment allows

---

## Implementation Checklist

If enabling GUI screenshots in future:

### Playwright Headed Mode
- [ ] Edit `.mcp.json` - remove `--headless` flag
- [ ] Restart Claude Code
- [ ] Test screenshot capability
- [ ] Verify display works on local machine

### Kali Xvfb
- [ ] SSH to Kali server
- [ ] Install Xvfb: `sudo apt install xvfb imagemagick`
- [ ] Test: `xvfb-run -a import -window root test.png`
- [ ] Modify Kali MCP server if needed
- [ ] Test screenshot automation

### Kali VNC
- [ ] Install x11vnc on Kali server
- [ ] Configure SSH tunnel for security
- [ ] Start VNC service
- [ ] Connect from Mac VNC client
- [ ] Test screenshot workflow

### Kali noVNC
- [ ] Install novnc and websockify
- [ ] Start x11vnc and websockify
- [ ] Open firewall port 6080 (if needed)
- [ ] Access via browser
- [ ] Test screenshot capability

---

## Current Decision (Option A)

**Active Configuration**:
- ✅ Playwright MCP: Headless (optimal for screenshots)
- ✅ Kali Linux MCP: Headless API server
- ✅ Manual screenshots: Local Mac browser for critical evidence

**Rationale**:
- Professional pentesting standard
- Maximum stealth and automation
- Screenshot quality identical to headed mode
- Minimal complexity and detection risk
- Faster execution

**When to Revisit**:
- Client requests visual demonstrations
- Complex JavaScript debugging needed
- GUI-only tools required (Burp Suite, ZAP)
- Red team engagement with visual requirements
- Large-scale automated screenshot needs

---

**Document Created**: December 15, 2025
**Last Updated**: December 15, 2025
**Status**: Reference Only - Not Currently Implemented
**Current Approach**: Option A (Headless + Manual Screenshots)
