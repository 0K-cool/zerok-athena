#!/bin/bash
# Load API Keys for Penetration Testing - OSINT Tools
# Created: 2025-12-16
# Usage: source load-api-keys.sh

# Color codes for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Loading Penetration Testing API Keys...${NC}"

# Load environment variables from .env file
if [ -f "/Users/kelvinlomboy/VERSANT/Projects/Pentest/.env" ]; then
    source /Users/kelvinlomboy/VERSANT/Projects/Pentest/.env
    echo -e "${GREEN}✅ API keys loaded from .env file${NC}"
else
    echo -e "${YELLOW}⚠️  .env file not found!${NC}"
    exit 1
fi

# Verify keys are loaded
echo ""
echo -e "${GREEN}Verifying API keys...${NC}"

if [ -n "$SHODAN_API_KEY" ]; then
    echo -e "${GREEN}✅ Shodan API key loaded${NC}"
else
    echo -e "${YELLOW}⚠️  Shodan API key missing${NC}"
fi

if [ -n "$CENSYS_API_TOKEN" ]; then
    echo -e "${GREEN}✅ Censys API token loaded${NC}"
else
    echo -e "${YELLOW}⚠️  Censys API token missing${NC}"
fi

if [ -n "$HUNTER_API_KEY" ]; then
    echo -e "${GREEN}✅ Hunter.io API key loaded${NC}"
else
    echo -e "${YELLOW}⚠️  Hunter.io API key missing${NC}"
fi

if [ -n "$GITHUB_TOKEN" ]; then
    echo -e "${GREEN}✅ GitHub token loaded${NC}"
else
    echo -e "${YELLOW}⚠️  GitHub token missing${NC}"
fi

if [ -n "$VIRUSTOTAL_API_KEY" ]; then
    echo -e "${GREEN}✅ VirusTotal API key loaded${NC}"
else
    echo -e "${YELLOW}⚠️  VirusTotal API key missing${NC}"
fi

echo ""
echo -e "${GREEN}API keys ready for passive OSINT reconnaissance!${NC}"
echo -e "${YELLOW}Use /orchestrate or /recon commands to start testing${NC}"
