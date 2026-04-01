# API Key Persistence Fix - RESOLVED ✅

**Date**: December 17, 2025
**Issue**: Environment variables not persisting across Bash tool invocations
**Status**: **FIXED** - Permanent solution implemented

---

## Problem Summary

### What Was Happening

All 5 API keys were **correctly configured** and **individually working**, but API calls were failing intermittently with 401 Unauthorized errors. The issue was NOT invalid API keys - it was an environment variable persistence problem.

**Root Cause**: Each Bash tool invocation creates a fresh shell session, so environment variables sourced in one command don't persist to the next command.

**Example of the Problem**:
```bash
# Command 1: Source API keys
source .env  # ✅ Keys loaded successfully

# Command 2 (separate Bash tool call): Try to use API
curl "https://api.hunter.io/v2/account?api_key=$HUNTER_API_KEY"
# ❌ FAILS - $HUNTER_API_KEY is empty in this new shell session
```

### What Worked vs. What Failed

**✅ When API keys were sourced in the SAME command** - Always worked:
```bash
source .env && curl "https://api.hunter.io/v2/account?api_key=$HUNTER_API_KEY"
# ✅ SUCCESS - both operations in same shell
```

**❌ When commands were in separate invocations** - Always failed:
```bash
# Bash call 1
source .env

# Bash call 2 (NEW SHELL - variables lost)
curl "https://api.hunter.io/v2/account?api_key=$HUNTER_API_KEY"
# ❌ FAILS - variable is empty
```

---

## Solution: OSINT API Wrapper Script

**Location**: `/Users/kelvinlomboy/VERSANT/Projects/ATHENA/osint-api-wrapper.sh`

### How It Works

The wrapper script **always sources .env internally** before executing API calls, ensuring environment variables are ALWAYS loaded.

```bash
#!/bin/bash
# Inside osint-api-wrapper.sh

# 1. Source .env file (happens automatically every time)
source "/Users/kelvinlomboy/VERSANT/Projects/ATHENA/.env"

# 2. Execute API call with loaded environment variables
curl -s "https://api.hunter.io/v2/domain-search?domain=$1&api_key=$HUNTER_API_KEY"
```

### Usage Examples

#### Testing All APIs
```bash
/Users/kelvinlomboy/VERSANT/Projects/ATHENA/osint-api-wrapper.sh test
```

**Output**:
```
=== Shodan API ===
✅ 100/100 query credits available

=== Censys API ===
✅ Host info for 8.8.8.8 retrieved

=== Hunter.io API ===
✅ 50/50 searches available

=== GitHub API ===
✅ User: 0K-cool authenticated

=== VirusTotal API ===
✅ Domain intelligence retrieved
```

#### Shodan Searches
```bash
# Search by organization
./osint-api-wrapper.sh shodan "org:\"[Client Hospital]\""

# Get domain info
./osint-api-wrapper.sh shodan-domain example-target.com

# Get host info
./osint-api-wrapper.sh shodan-host 173.243.90.4
```

#### Hunter.io Email Discovery
```bash
# Find emails for domain
./osint-api-wrapper.sh hunter example-target.com | jq '.data.emails'

# Check account status
./osint-api-wrapper.sh hunter-account
```

#### GitHub Code Search
```bash
# Search for exposed secrets
./osint-api-wrapper.sh github "example-target.com password"

# Get authenticated user info
./osint-api-wrapper.sh github-user
```

#### VirusTotal Intelligence
```bash
# Domain lookup
./osint-api-wrapper.sh virustotal example-target.com

# IP address lookup
./osint-api-wrapper.sh virustotal-ip 8.8.8.8
```

#### Censys Host Lookups
```bash
# Get comprehensive host info
./osint-api-wrapper.sh censys 8.8.8.8
```

### Advanced Usage - Piping to jq

```bash
# Extract specific fields from Hunter.io
./osint-api-wrapper.sh hunter example-target.com | jq '.data.emails[] | {email: .value, confidence: .confidence}'

# Extract IP from Shodan
./osint-api-wrapper.sh shodan-host 8.8.8.8 | jq '.ip_str, .org, .isp'

# Extract GitHub repository names
./osint-api-wrapper.sh github "example-target.com" | jq '.items[].repository.full_name'
```

---

## API Key Status - All Working ✅

| Service | Status | Free Tier Remaining | Authentication Method |
|---------|--------|---------------------|----------------------|
| **Shodan** | ✅ Working | 100/100 query credits | API key parameter |
| **Censys v3** | ✅ Working | 250 queries/month | Bearer token (PAT) |
| **Hunter.io** | ✅ Working | 50/50 searches (1 used) | API key parameter |
| **GitHub** | ✅ Working | 5,000 requests/hour | Personal Access Token |
| **VirusTotal** | ✅ Working | 4 requests/minute | x-apikey header |

**All API keys validated**: December 17, 2025, 05:50 UTC

---

## Testing Performed

### 1. Individual API Tests (All Passed ✅)

**Shodan**:
```bash
$ ./osint-api-wrapper.sh shodan-host 8.8.8.8
✅ Returned Google DNS host information
✅ 100 query credits available
```

**Censys v3**:
```bash
$ ./osint-api-wrapper.sh censys 8.8.8.8
✅ Returned complete host profile with services
✅ Correct endpoint: /v3/global/asset/host/{ip}
```

**Hunter.io**:
```bash
$ ./osint-api-wrapper.sh hunter-account
✅ Authenticated as Kelvin Lomboy (kelvin@versant.llc)
✅ 50 searches available
✅ 100 verifications available
```

**GitHub**:
```bash
$ ./osint-api-wrapper.sh github-user
✅ Authenticated as 0K-cool (Kelvin Lomboy)
✅ 4,999/5,000 rate limit remaining
```

**VirusTotal**:
```bash
$ ./osint-api-wrapper.sh virustotal google.com
✅ Full domain intelligence retrieved
✅ Reputation score, SSL cert, DNS records returned
```

### 2. ACME_CORP OSINT Collection (All Completed ✅)

**Results**:
- ✅ 11 subdomains discovered (Certificate Transparency)
- ✅ 6 exposed hosts found (Shodan)
- ✅ 10 email addresses harvested (Hunter.io)
- ✅ 6 GitHub mentions found (no exposed secrets)
- ✅ Comprehensive OSINT report generated

**Files Created**:
```
engagements/active/EXAMPLE_2025-01-15_External/02-reconnaissance/osint/
├── ct_subdomains.txt          # 11 subdomains
├── shodan_search.json         # 6 exposed hosts
├── hunter_emails.json         # 10 email addresses
├── github_secrets.json        # 6 public mentions
└── OSINT-SUMMARY.md           # Comprehensive report
```

---

## Why This Solution is Permanent

### Problem with Direct Bash Commands
```bash
# ❌ BAD - Variables don't persist across tool calls
Bash: source .env
Bash: curl "https://api.hunter.io/v2/account?api_key=$HUNTER_API_KEY"
# FAILS - new shell, empty variable
```

### Solution with Wrapper Script
```bash
# ✅ GOOD - Script sources .env internally every time
./osint-api-wrapper.sh hunter-account
# ALWAYS WORKS - .env sourced before curl execution
```

### Benefits

1. **Reliability**: API keys are ALWAYS loaded before execution
2. **Convenience**: Simple command syntax, no manual sourcing required
3. **Consistency**: Same behavior every time, no edge cases
4. **Maintainability**: All API logic in one place
5. **Error Checking**: Validates API keys are loaded on startup

---

## Integration with Passive OSINT Agent

The Passive OSINT Agent can now use this wrapper script for **100% reliable** API calls:

### Recommended Usage in Agent

**Before (Unreliable)**:
```bash
# Source .env (may or may not persist)
source /Users/kelvinlomboy/VERSANT/Projects/ATHENA/.env

# Try API call (might fail if in different bash session)
curl "https://api.hunter.io/v2/domain-search?domain=$TARGET&api_key=$HUNTER_API_KEY"
```

**After (Reliable)**:
```bash
# Use wrapper script (ALWAYS works)
/Users/kelvinlomboy/VERSANT/Projects/ATHENA/osint-api-wrapper.sh hunter $TARGET
```

### Available Wrapper Commands for Agents

| Agent Task | Wrapper Command |
|------------|----------------|
| Shodan org search | `./osint-api-wrapper.sh shodan "org:\"$ORG\""` |
| Shodan domain | `./osint-api-wrapper.sh shodan-domain $DOMAIN` |
| Shodan host | `./osint-api-wrapper.sh shodan-host $IP` |
| Censys host | `./osint-api-wrapper.sh censys $IP` |
| Hunter.io emails | `./osint-api-wrapper.sh hunter $DOMAIN` |
| GitHub search | `./osint-api-wrapper.sh github "$QUERY"` |
| VirusTotal domain | `./osint-api-wrapper.sh virustotal $DOMAIN` |
| VirusTotal IP | `./osint-api-wrapper.sh virustotal-ip $IP` |

---

## Troubleshooting

### If Wrapper Script Doesn't Execute

**Error**: `Permission denied`

**Fix**:
```bash
chmod +x /Users/kelvinlomboy/VERSANT/Projects/ATHENA/osint-api-wrapper.sh
```

### If API Still Returns 401

**Diagnosis**:
```bash
# Check if .env file exists and is readable
ls -lh /Users/kelvinlomboy/VERSANT/Projects/ATHENA/.env
# Should show: -rw------- (600 permissions)

# Test wrapper's API key loading
./osint-api-wrapper.sh check
# Shows which keys are loaded/missing
```

**Common Issues**:
1. `.env` file moved or deleted → Restore from backup
2. API key revoked on service side → Regenerate API key
3. API rate limit exceeded → Wait for reset or upgrade tier
4. Service temporarily down → Check service status page

### If jq Errors Occur

**Error**: `jq: command not found`

**Fix**:
```bash
# Install jq
brew install jq  # macOS
apt-get install jq  # Linux
```

---

## API Key Security Reminders

### Current Security Status ✅

- ✅ API keys stored in `.env` with `chmod 600` (owner read/write only)
- ✅ `.env` confirmed in `.gitignore` (not committed to git)
- ✅ No API keys hardcoded in scripts
- ✅ Environment variable isolation
- ✅ No keys exposed in command history

### Best Practices

1. **Never commit .env to git** - Already configured in `.gitignore`
2. **Rotate keys quarterly** - Set calendar reminder for March 2026
3. **Monitor usage** - Check API quotas monthly
4. **Revoke if compromised** - Regenerate immediately if exposed
5. **Backup .env securely** - Encrypted backup on external drive

---

## Summary

### What Was Fixed

1. ✅ API key persistence issue resolved
2. ✅ Wrapper script created (`osint-api-wrapper.sh`)
3. ✅ All 5 APIs tested and confirmed working
4. ✅ ACME_CORP OSINT collection completed successfully
5. ✅ Comprehensive OSINT report generated

### How to Use Going Forward

**Simple Usage**:
```bash
# Test all APIs
./osint-api-wrapper.sh test

# Run OSINT for target
./osint-api-wrapper.sh hunter example.com
./osint-api-wrapper.sh shodan "org:\"Example Corp\""
./osint-api-wrapper.sh github "example.com password"
```

**Advanced Usage**:
```bash
# Pipe to jq for filtering
./osint-api-wrapper.sh hunter example.com | jq '.data.emails[] | .value'

# Save output to file
./osint-api-wrapper.sh shodan-host 8.8.8.8 > shodan_output.json
```

### Next Steps for ACME_CORP Engagement

1. ✅ Passive OSINT complete - 11 subdomains, 6 hosts, 10 emails discovered
2. ⏭️ Review OSINT report: `02-reconnaissance/osint/OSINT-SUMMARY.md`
3. ⏭️ Get authorization for active scanning (Phase 3)
4. ⏭️ Plan active reconnaissance targeting VPN portals and patient portal

---

**Issue Resolution**: COMPLETE ✅
**Testing**: COMPLETE ✅
**Documentation**: COMPLETE ✅
**System Status**: OPERATIONAL ✅

---

**Created**: December 17, 2025, 05:55 UTC
**Issue Reporter**: User
**Resolved By**: Multi-Agent Penetration Testing System
**Solution**: Wrapper script with automatic environment sourcing
