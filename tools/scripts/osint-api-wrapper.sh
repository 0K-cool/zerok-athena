#!/bin/bash
#
# OSINT API Wrapper Script
# Purpose: Ensures API keys are ALWAYS loaded before execution
# Fixes: Environment variable persistence issues across Bash sessions
#
# Created: December 17, 2025
# Issue: Bash tool calls don't persist environment variables between invocations
# Solution: Always source .env before executing API commands
#
# Usage:
#   ./osint-api-wrapper.sh shodan "org:\"Example Corp\""
#   ./osint-api-wrapper.sh hunter example.com
#   ./osint-api-wrapper.sh github "example.com password"
#   ./osint-api-wrapper.sh virustotal example.com
#   ./osint-api-wrapper.sh censys 8.8.8.8
#

# Configuration
PENTEST_ROOT="/Users/kelvinlomboy/VERSANT/Projects/ATHENA"
ENV_FILE="$PENTEST_ROOT/.env"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check if .env file exists
if [ ! -f "$ENV_FILE" ]; then
    error ".env file not found at: $ENV_FILE"
    error "Please create .env file with API keys first"
    exit 1
fi

# Source the .env file to load API keys
source "$ENV_FILE"
info "API keys loaded from: $ENV_FILE"

# Verify critical API keys are loaded
check_api_keys() {
    local missing_keys=0

    if [ -z "$SHODAN_API_KEY" ]; then
        warn "SHODAN_API_KEY not set"
        ((missing_keys++))
    fi

    if [ -z "$CENSYS_API_TOKEN" ]; then
        warn "CENSYS_API_TOKEN not set"
        ((missing_keys++))
    fi

    if [ -z "$HUNTER_API_KEY" ]; then
        warn "HUNTER_API_KEY not set"
        ((missing_keys++))
    fi

    if [ -z "$GITHUB_TOKEN" ]; then
        warn "GITHUB_TOKEN not set"
        ((missing_keys++))
    fi

    if [ -z "$VIRUSTOTAL_API_KEY" ]; then
        warn "VIRUSTOTAL_API_KEY not set"
        ((missing_keys++))
    fi

    if [ $missing_keys -gt 0 ]; then
        warn "$missing_keys API key(s) not configured"
        warn "Some OSINT functions may not work"
    else
        info "All 5 API keys loaded successfully ✓"
    fi
}

# Shodan API wrapper
shodan_search() {
    local query="$1"
    info "Shodan Search: $query"
    curl -s "https://api.shodan.io/shodan/host/search?key=$SHODAN_API_KEY&query=$query"
}

shodan_domain() {
    local domain="$1"
    info "Shodan Domain: $domain"
    curl -s "https://api.shodan.io/dns/domain/$domain?key=$SHODAN_API_KEY"
}

shodan_host() {
    local ip="$1"
    info "Shodan Host: $ip"
    curl -s "https://api.shodan.io/shodan/host/$ip?key=$SHODAN_API_KEY"
}

# Censys API wrapper
censys_host() {
    local ip="$1"
    info "Censys Host: $ip"
    curl -s "https://api.platform.censys.io/v3/global/asset/host/$ip" \
        -H "Authorization: Bearer $CENSYS_API_TOKEN" \
        -H "Accept: application/vnd.censys.api.v3.host.v1+json"
}

# Hunter.io API wrapper
hunter_domain() {
    local domain="$1"
    info "Hunter.io Domain Search: $domain"
    curl -s "https://api.hunter.io/v2/domain-search?domain=$domain&api_key=$HUNTER_API_KEY"
}

hunter_account() {
    info "Hunter.io Account Info"
    curl -s "https://api.hunter.io/v2/account?api_key=$HUNTER_API_KEY"
}

# GitHub API wrapper
github_search() {
    local query="$1"
    info "GitHub Code Search: $query"
    curl -s -H "Authorization: token $GITHUB_TOKEN" \
        "https://api.github.com/search/code?q=$query"
}

github_user() {
    info "GitHub User Info"
    curl -s -H "Authorization: token $GITHUB_TOKEN" \
        "https://api.github.com/user"
}

# VirusTotal API wrapper
virustotal_domain() {
    local domain="$1"
    info "VirusTotal Domain: $domain"
    curl -s "https://www.virustotal.com/api/v3/domains/$domain" \
        -H "x-apikey: $VIRUSTOTAL_API_KEY"
}

virustotal_ip() {
    local ip="$1"
    info "VirusTotal IP: $ip"
    curl -s "https://www.virustotal.com/api/v3/ip_addresses/$ip" \
        -H "x-apikey: $VIRUSTOTAL_API_KEY"
}

# Test all APIs
test_all_apis() {
    info "Testing all OSINT APIs..."
    echo ""

    echo "=== Shodan API ==="
    curl -s "https://api.shodan.io/api-info?key=$SHODAN_API_KEY" | jq '.' 2>/dev/null || echo "FAILED"
    echo ""

    echo "=== Censys API ==="
    censys_host "8.8.8.8" | jq '.result.ip' 2>/dev/null || echo "FAILED"
    echo ""

    echo "=== Hunter.io API ==="
    hunter_account | jq '.data.email' 2>/dev/null || echo "FAILED"
    echo ""

    echo "=== GitHub API ==="
    github_user | jq '.login' 2>/dev/null || echo "FAILED"
    echo ""

    echo "=== VirusTotal API ==="
    virustotal_domain "google.com" | jq '.data.id' 2>/dev/null || echo "FAILED"
    echo ""
}

# Display usage
usage() {
    cat << EOF
Usage: $0 <service> <query> [output_file]

Services:
  shodan <query>           - Search Shodan by query
  shodan-domain <domain>   - Get Shodan domain info
  shodan-host <ip>         - Get Shodan host info

  censys <ip>              - Get Censys host info

  hunter <domain>          - Search emails for domain
  hunter-account           - Get Hunter.io account info

  github <query>           - Search GitHub code
  github-user              - Get GitHub user info

  virustotal <domain>      - Get VirusTotal domain info
  virustotal-ip <ip>       - Get VirusTotal IP info

  test                     - Test all APIs
  check                    - Check API key status

Examples:
  $0 shodan "org:\\"Bella Vista Hospital\\""
  $0 hunter bvhpr.org
  $0 github "bvhpr.org password"
  $0 censys 8.8.8.8
  $0 virustotal bvhpr.org

Output can be piped to jq for formatting:
  $0 hunter bvhpr.org | jq '.data.emails'

EOF
    exit 1
}

# Main command router
if [ $# -lt 1 ]; then
    usage
fi

SERVICE="$1"
QUERY="$2"

case "$SERVICE" in
    shodan)
        shodan_search "$QUERY"
        ;;
    shodan-domain)
        shodan_domain "$QUERY"
        ;;
    shodan-host)
        shodan_host "$QUERY"
        ;;
    censys)
        censys_host "$QUERY"
        ;;
    hunter)
        hunter_domain "$QUERY"
        ;;
    hunter-account)
        hunter_account
        ;;
    github)
        github_search "$QUERY"
        ;;
    github-user)
        github_user
        ;;
    virustotal)
        virustotal_domain "$QUERY"
        ;;
    virustotal-ip)
        virustotal_ip "$QUERY"
        ;;
    test)
        test_all_apis
        ;;
    check)
        check_api_keys
        ;;
    *)
        error "Unknown service: $SERVICE"
        usage
        ;;
esac
