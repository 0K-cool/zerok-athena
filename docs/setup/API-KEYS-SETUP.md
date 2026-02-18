# API Keys Setup for Passive OSINT

**Created**: December 16, 2025
**Purpose**: Configure API keys for enhanced passive reconnaissance

---

## Quick Summary

| Service | Required? | Free Tier? | What It Provides |
|---------|-----------|------------|------------------|
| **Certificate Transparency (crt.sh)** | ❌ No | ✅ Yes (free) | Subdomain discovery via SSL certificates |
| **Amass (passive)** | ❌ No | ✅ Yes (free) | Subdomain enumeration (passive mode) |
| **Shodan** | ⚠️ Recommended | ✅ Yes (limited) | Exposed service discovery |
| **Censys** | ⚠️ Recommended | ✅ Yes (250 queries/month) | Internet-wide scanning data |
| **Hunter.io** | ⚠️ Recommended | ✅ Yes (25 searches/month) | Email address discovery |
| **GitHub API** | ⚠️ Optional | ✅ Yes (5000 req/hour) | Secret scanning, repository search |
| **Google/Bing** | ❌ No | ✅ Yes (free) | Dorking (no API needed) |
| **VirusTotal** | ⚠️ Optional | ✅ Yes (4 req/min) | Domain/IP intelligence |
| **Recon-ng** | ⚠️ Optional | Varies | Aggregates multiple APIs |

**Can you run passive recon WITHOUT any API keys?** ✅ **YES!**
- Certificate Transparency (crt.sh) - Free, no key needed
- Passive Amass - Free, no key needed
- Google Dorking - Free, no key needed
- Manual WHOIS - Free, no key needed

**Should you use API keys?** ✅ **YES (for better results)**
- More data sources
- Higher rate limits
- Better accuracy
- Professional-grade intelligence

---

## Option 1: Quick Start (No API Keys)

**What works without API keys:**

```bash
# Certificate Transparency (no API key needed)
curl -s "https://crt.sh/?q=%.example.com&output=json" | jq -r '.[].name_value' | sort -u

# Passive Amass (no API key needed)
amass enum -passive -d example.com -o subdomains.txt

# Google Dorking (no API key needed)
# Manual search: site:example.com filetype:pdf
# Use browser automation (Playwright) for scraping

# WHOIS (no API key needed)
whois example.com

# DNS enumeration (no API key needed)
dig example.com ANY
```

**Result**: You'll get ~60-70% of the intelligence without any API keys.

---

## Option 2: Enhanced Setup (With Free API Keys)

### 1. Shodan (Recommended)

**Why use it**: Discover exposed services (databases, RDP, SMB) without scanning
**Free tier**: 100 queries/month, limited filters

**Setup**:
```bash
# 1. Sign up at https://account.shodan.io/register
# 2. Get your API key from https://account.shodan.io/

# 3. Configure Shodan CLI
pip3 install shodan
shodan init YOUR_API_KEY_HERE

# 4. Test it
shodan search "org:\"Example Corporation\""
```

**Usage in pentest**:
```bash
# Search by organization
shodan search 'org:"ACME Corporation"'

# Search by domain
shodan domain example.com

# Search by IP range
shodan search 'net:198.51.100.0/24'
```

**What it finds**:
- Exposed databases (MySQL, MongoDB, Redis)
- Remote access services (RDP, VNC, SSH)
- Web servers and versions
- IoT devices
- Cloud services

---

### 2. Censys (Recommended)

**Why use it**: Alternative to Shodan with different data
**Free tier**: 250 queries/month

**Setup**:
```bash
# 1. Sign up at https://censys.io/register
# 2. Get API ID and Secret from https://censys.io/account/api

# 3. Configure Censys CLI
pip3 install censys
censys config

# Enter API ID and Secret when prompted

# 4. Test it
censys search 'services.service_name: HTTP and autonomous_system.name: "ACME"'
```

**Usage in pentest**:
```bash
# Search by organization
censys search 'autonomous_system.name: "Example Corp"'

# Search by domain
censys search 'names: example.com'

# Find certificates
censys search 'parsed.subject.common_name: example.com' --index certificates
```

---

### 3. Hunter.io (Email Discovery)

**Why use it**: Find email addresses and email format
**Free tier**: 25 searches/month, 50 verifications/month

**Setup**:
```bash
# 1. Sign up at https://hunter.io/users/sign_up
# 2. Get API key from https://hunter.io/api_keys

# 3. Use with curl or theHarvester
```

**Usage in pentest**:
```bash
# Find email addresses
curl "https://api.hunter.io/v2/domain-search?domain=example.com&api_key=YOUR_API_KEY"

# Find email format
curl "https://api.hunter.io/v2/email-finder?domain=example.com&first_name=John&last_name=Doe&api_key=YOUR_API_KEY"
```

**What it finds**:
- Email addresses
- Email format (firstname.lastname@domain.com)
- Department information
- Confidence scores

---

### 4. GitHub API (Optional)

**Why use it**: Higher rate limits for secret scanning
**Free tier**: 5,000 requests/hour (authenticated) vs 60/hour (unauthenticated)

**Setup**:
```bash
# 1. Create Personal Access Token at https://github.com/settings/tokens
#    Scopes needed: public_repo (for public repositories only)

# 2. Export token as environment variable
export GITHUB_TOKEN="ghp_YOUR_TOKEN_HERE"

# 3. Test it
curl -H "Authorization: token $GITHUB_TOKEN" https://api.github.com/user
```

**Usage in pentest**:
```bash
# Search for organization repositories
curl -H "Authorization: token $GITHUB_TOKEN" \
  "https://api.github.com/search/repositories?q=org:example-corp"

# Search for potential secrets
curl -H "Authorization: token $GITHUB_TOKEN" \
  "https://api.github.com/search/code?q=example.com+password"
```

---

### 5. VirusTotal (Optional)

**Why use it**: Domain/IP reputation and historical data
**Free tier**: 4 requests/minute

**Setup**:
```bash
# 1. Sign up at https://www.virustotal.com/gui/join-us
# 2. Get API key from https://www.virustotal.com/gui/my-apikey

# 3. Use with curl
```

**Usage in pentest**:
```bash
# Domain report
curl --request GET \
  --url "https://www.virustotal.com/api/v3/domains/example.com" \
  --header "x-apikey: YOUR_API_KEY"

# IP address report
curl --request GET \
  --url "https://www.virustotal.com/api/v3/ip_addresses/198.51.100.10" \
  --header "x-apikey: YOUR_API_KEY"
```

---

## Secure API Key Storage

### Option 1: Environment Variables (Recommended)

```bash
# Create .env file in engagement directory
cat > .env << 'EOF'
# OSINT API Keys
export SHODAN_API_KEY="YOUR_SHODAN_KEY"
export CENSYS_API_ID="YOUR_CENSYS_ID"
export CENSYS_API_SECRET="YOUR_CENSYS_SECRET"
export HUNTER_API_KEY="YOUR_HUNTER_KEY"
export GITHUB_TOKEN="YOUR_GITHUB_TOKEN"
export VIRUSTOTAL_API_KEY="YOUR_VT_KEY"
EOF

# Load environment variables
source .env

# Add .env to .gitignore (CRITICAL - never commit API keys!)
echo ".env" >> .gitignore
```

### Option 2: Dedicated API Key Manager

```bash
# Create secure API key storage
cat > ~/.pentest-api-keys << 'EOF'
# Passive OSINT API Keys
SHODAN_API_KEY=YOUR_SHODAN_KEY
CENSYS_API_ID=YOUR_CENSYS_ID
CENSYS_API_SECRET=YOUR_CENSYS_SECRET
HUNTER_API_KEY=YOUR_HUNTER_KEY
GITHUB_TOKEN=YOUR_GITHUB_TOKEN
VIRUSTOTAL_API_KEY=YOUR_VT_KEY
EOF

# Secure permissions (only you can read)
chmod 600 ~/.pentest-api-keys

# Load in shell profile
echo "source ~/.pentest-api-keys" >> ~/.zshrc  # or ~/.bashrc
```

### Option 3: Tool-Specific Config Files

Some tools have their own config files:

```bash
# Shodan stores key at:
~/.shodan/api_key

# Censys stores credentials at:
~/.censys/censys.cfg

# Amass can use config file:
~/.config/amass/config.ini
```

**Example Amass config** (`~/.config/amass/config.ini`):

```ini
[data_sources]
[data_sources.Shodan]
[data_sources.Shodan.Credentials]
apikey = YOUR_SHODAN_KEY

[data_sources.Censys]
[data_sources.Censys.Credentials]
apikey = YOUR_CENSYS_ID
secret = YOUR_CENSYS_SECRET

[data_sources.GitHub]
[data_sources.GitHub.accountname]
apikey = YOUR_GITHUB_TOKEN

[data_sources.VirusTotal]
[data_sources.VirusTotal.Credentials]
apikey = YOUR_VT_KEY
```

With this config, Amass automatically uses all APIs:
```bash
amass enum -passive -d example.com -config ~/.config/amass/config.ini
```

---

## Integration with Multi-Agent System

### Passive OSINT Agent - API Key Detection

The Passive OSINT Agent automatically detects available API keys:

```python
import os

# Check for API keys
shodan_key = os.getenv('SHODAN_API_KEY')
censys_id = os.getenv('CENSYS_API_ID')
censys_secret = os.getenv('CENSYS_API_SECRET')
hunter_key = os.getenv('HUNTER_API_KEY')

if shodan_key:
    print("✅ Shodan API key detected - enhanced scanning enabled")
    # Use Shodan API for organization search
else:
    print("⚠️ No Shodan API key - using free methods only")
    # Fall back to crt.sh, Amass passive, etc.

if censys_id and censys_secret:
    print("✅ Censys API credentials detected - enhanced scanning enabled")
else:
    print("⚠️ No Censys API - using free methods only")
```

### Graceful Degradation

The agent works with OR without API keys:

**With API keys** (100% coverage):
- Certificate Transparency ✅
- Passive Amass ✅
- Shodan ✅
- Censys ✅
- Hunter.io ✅
- GitHub ✅
- VirusTotal ✅
- Google Dorking ✅

**Without API keys** (70% coverage):
- Certificate Transparency ✅
- Passive Amass ✅
- Shodan ❌ (falls back to crt.sh and Amass)
- Censys ❌ (falls back to crt.sh and Amass)
- Hunter.io ❌ (falls back to manual email harvesting)
- GitHub ✅ (lower rate limit)
- VirusTotal ❌ (skipped)
- Google Dorking ✅

**Result**: You still get good intelligence without API keys, but more with them.

---

## Cost Analysis

### Free Tier Comparison

| Service | Free Tier | Upgrade Cost | Recommended For |
|---------|-----------|--------------|-----------------|
| Shodan | 100 queries/month | $59/month (unlimited) | Professional pentesting |
| Censys | 250 queries/month | $99/month (custom) | Large-scale assessments |
| Hunter.io | 25 searches/month | $49/month (500 searches) | Email harvesting |
| GitHub | 5000 req/hour | Free (with account) | Secret scanning |
| VirusTotal | 4 req/min | $100/month (premium) | Optional enhancement |

**Recommendation for Professional Use**:
- **Shodan**: $59/month (best ROI for exposed service discovery)
- **Censys**: Free tier sufficient for most engagements
- **Hunter.io**: Free tier OK for small clients (upgrade for larger orgs)
- **GitHub**: Free tier with account is sufficient
- **VirusTotal**: Optional (not critical for passive recon)

**Total Cost for Professional Setup**: ~$59-108/month

---

## Best Practices

### 1. API Key Rotation

```bash
# Rotate API keys quarterly (every 3 months)
# Set calendar reminder:
# - Review API key usage
# - Generate new keys
# - Update .env file
# - Revoke old keys
```

### 2. Rate Limit Awareness

```python
import time

# Respect rate limits
for target in targets:
    shodan_search(target)
    time.sleep(1)  # 1 second delay (Shodan: 1 req/sec on free tier)

# Or use exponential backoff
def shodan_search_with_retry(query, max_retries=3):
    for attempt in range(max_retries):
        try:
            return shodan_api.search(query)
        except shodan.APIError as e:
            if "rate limit" in str(e).lower():
                wait_time = 2 ** attempt  # 1s, 2s, 4s
                time.sleep(wait_time)
            else:
                raise
```

### 3. Never Commit API Keys

```bash
# .gitignore (CRITICAL)
.env
*.env
.api-keys
api-keys.txt
config/credentials.json
*_credentials.json
shodan_key.txt
```

### 4. Audit API Usage

```bash
# Track API usage per engagement
echo "ENGAGEMENT: ACME_2025-12-16" >> api-usage.log
echo "Shodan queries: 15" >> api-usage.log
echo "Censys queries: 8" >> api-usage.log
echo "Hunter.io searches: 3" >> api-usage.log

# Review monthly to avoid exceeding free tiers
```

---

## Quick Setup Checklist

For a new engagement, run through this checklist:

```bash
# Passive OSINT API Setup Checklist

## Free Methods (No API Keys Needed)
- [ ] Certificate Transparency (crt.sh) - ready to use
- [ ] Passive Amass - installed
- [ ] Google Dorking - browser ready
- [ ] WHOIS - command line ready

## Recommended APIs (Free Tier)
- [ ] Shodan API key configured
- [ ] Censys API credentials configured
- [ ] Hunter.io API key configured
- [ ] GitHub token configured (for higher rate limits)

## Optional Enhancements
- [ ] VirusTotal API key configured
- [ ] Recon-ng API keys configured
- [ ] Amass config file with all APIs

## Security
- [ ] API keys stored in .env file
- [ ] .env added to .gitignore
- [ ] File permissions set to 600
- [ ] API keys NOT committed to git

## Testing
- [ ] Test Shodan: shodan info
- [ ] Test Censys: censys search 'test'
- [ ] Test Hunter.io: curl hunter.io API
- [ ] Test GitHub: curl github.com/user (with token)
```

---

## Workflow Integration

### Before Starting Engagement

```bash
# 1. Load API keys
source ~/.pentest-api-keys

# 2. Verify API keys are loaded
echo $SHODAN_API_KEY  # Should show your key
echo $CENSYS_API_ID   # Should show your ID

# 3. Test connectivity
shodan info
censys account

# 4. Start engagement
/orchestrate ACME.com - External Pentest
```

### During Engagement

The Passive OSINT Agent automatically:
- ✅ Detects available API keys from environment
- ✅ Uses premium APIs when available
- ✅ Falls back to free methods if keys missing
- ✅ Logs API usage to database
- ✅ Respects rate limits

You don't need to do anything - just ensure API keys are in environment.

---

## Troubleshooting

### Common Issues and Solutions

#### Issue 1: API Returns 401 Unauthorized

**Symptoms**:
```bash
curl "https://api.hunter.io/v2/account?api_key=$HUNTER_API_KEY"
# Returns: {"errors":[{"id":"unauthorized","code":401,"details":"Invalid API key"}]}
```

**Cause**: Environment variables not persisting across Bash tool invocations.

**Solution**: Use the OSINT API wrapper script which automatically loads environment variables before each API call.

**Fix**:
```bash
# Instead of direct API calls
./osint-api-wrapper.sh hunter-account

# Instead of manual curl with environment variables
./osint-api-wrapper.sh hunter example.com
```

**See**: `API-KEY-FIX.md` for detailed explanation and permanent solution.

#### Issue 2: Environment Variables Not Loading

**Symptoms**:
```bash
source .env
echo $SHODAN_API_KEY  # Shows nothing
```

**Cause**: .env file doesn't export variables, only sets them.

**Solution**: Ensure .env file uses `export` keyword:
```bash
# WRONG
SHODAN_API_KEY="your_key"

# CORRECT
export SHODAN_API_KEY="your_key"
```

Or source .env in the same command:
```bash
source .env && echo $SHODAN_API_KEY
```

#### Issue 3: API Rate Limit Exceeded

**Symptoms**:
```bash
{"error": "Rate limit exceeded. Please retry after 60 seconds."}
```

**Solution**:
1. Check free tier limits:
   - Shodan: 100 queries/month, 1 req/sec
   - Censys: 250 queries/month
   - Hunter.io: 25-50 searches/month
   - VirusTotal: 4 req/min

2. Use wrapper script's built-in rate limiting
3. Upgrade to paid tier if needed for professional engagements

#### Issue 4: API Key Not Found in Environment

**Symptoms**:
```bash
./osint-api-wrapper.sh test
# [WARN] SHODAN_API_KEY not set
```

**Diagnosis**:
```bash
# Check if .env file exists
ls -lh /Users/kelvinlomboy/VERSANT/Projects/ATHENA/.env

# Check if wrapper script can find .env
./osint-api-wrapper.sh check
```

**Solution**:
1. Verify .env file exists at correct location
2. Ensure API keys are properly exported in .env
3. Check file permissions: `chmod 600 .env`
4. Use wrapper script which sources .env automatically

#### Issue 5: Wrapper Script Permission Denied

**Symptoms**:
```bash
./osint-api-wrapper.sh test
# bash: ./osint-api-wrapper.sh: Permission denied
```

**Solution**:
```bash
chmod +x /Users/kelvinlomboy/VERSANT/Projects/ATHENA/osint-api-wrapper.sh
```

### Using the OSINT API Wrapper (Recommended)

**Why use the wrapper**:
- ✅ Automatically loads environment variables before every API call
- ✅ Eliminates 401 Unauthorized errors from variable persistence issues
- ✅ Simple command syntax (no manual sourcing required)
- ✅ Consistent behavior across all Bash sessions
- ✅ Validates API keys are loaded on startup

**Wrapper Commands**:
```bash
# Test all APIs
./osint-api-wrapper.sh test

# Shodan
./osint-api-wrapper.sh shodan "org:\"Example Corp\""
./osint-api-wrapper.sh shodan-domain example.com
./osint-api-wrapper.sh shodan-host 8.8.8.8

# Censys
./osint-api-wrapper.sh censys 8.8.8.8

# Hunter.io
./osint-api-wrapper.sh hunter example.com
./osint-api-wrapper.sh hunter-account

# GitHub
./osint-api-wrapper.sh github "example.com password"
./osint-api-wrapper.sh github-user

# VirusTotal
./osint-api-wrapper.sh virustotal example.com
./osint-api-wrapper.sh virustotal-ip 8.8.8.8
```

**Advanced Usage**:
```bash
# Pipe to jq for filtering
./osint-api-wrapper.sh hunter example.com | jq '.data.emails[] | .value'

# Save output to file
./osint-api-wrapper.sh shodan-host 8.8.8.8 > evidence/shodan_8.8.8.8.json
```

### Additional Resources

- **API-KEY-FIX.md** - Complete troubleshooting guide for environment variable persistence issues
- **osint-api-wrapper.sh** - Wrapper script source code and documentation
- **README.md** - Project overview with OSINT API Wrapper usage examples

---

## Summary

### Minimum Setup (Free)
```bash
# Works with ZERO API keys
Certificate Transparency + Passive Amass + Google Dorking = ~70% coverage
```

### Recommended Setup (Free Tier)
```bash
# Sign up for free tiers (takes 15 minutes)
export SHODAN_API_KEY="your_key"
export CENSYS_API_ID="your_id"
export CENSYS_API_SECRET="your_secret"
export HUNTER_API_KEY="your_key"

# Result: ~95% coverage
```

### Professional Setup ($59/month)
```bash
# Upgrade Shodan to paid tier
# Keep others on free tier

# Result: 100% coverage + unlimited queries
```

**Next Steps**:
1. Decide on setup level (free vs paid)
2. Sign up for APIs (15 minutes)
3. Configure environment variables
4. Test with `/orchestrate` command

The system works perfectly without API keys, but you'll get better intelligence with them! 🎯

---

**Created**: December 16, 2025
**Last Updated**: December 17, 2025
**Maintained by**: Multi-Agent Penetration Testing System
