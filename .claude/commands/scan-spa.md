# Scan Single Page Application (SPA)

Execute comprehensive security testing of modern JavaScript-heavy Single Page Applications using Playwright browser automation.

## Usage

```
/scan-spa <TARGET_URL> [OPTIONS]
```

## Arguments

- `<TARGET_URL>` (required): The base URL of the SPA to test (e.g., https://app.example.com)
- `[OPTIONS]` (optional): Additional testing flags
  - `--auth`: Include authentication flow testing
  - `--full`: Comprehensive scan including all test vectors
  - `--quick`: Fast reconnaissance only

## What This Command Does

This command performs automated security testing specifically designed for Single Page Applications (React, Vue, Angular, Svelte) that traditional scanners cannot effectively assess.

### Phase 1: Technology Detection & Reconnaissance
1. Navigate to target URL using Playwright
2. Identify JavaScript framework (React/Vue/Angular/Svelte)
3. Extract framework version information
4. Capture landing page screenshot
5. Analyze page source for sensitive information

### Phase 2: Route Discovery
1. Extract client-side routes from JavaScript bundles
2. Map out navigation structure
3. Identify authenticated vs unauthenticated routes
4. Document API endpoints from network traffic

### Phase 3: API Endpoint Enumeration
1. Monitor all network requests during navigation
2. Capture REST API endpoints
3. Identify GraphQL endpoints
4. Document WebSocket connections
5. Save network traffic as HAR file

### Phase 4: Authentication Flow Analysis (if --auth flag used)
1. Locate login page/modal
2. Test login flow with provided credentials
3. Capture authentication tokens
4. Analyze token storage (localStorage, sessionStorage, cookies)
5. Test token security (httpOnly, Secure flags)
6. Verify session expiration behavior

### Phase 5: Client-Side Security Testing
1. **Storage Inspection:**
   - Extract localStorage contents
   - Extract sessionStorage contents
   - Capture cookies
   - Identify sensitive data exposure

2. **JavaScript Analysis:**
   - Search for hardcoded API keys
   - Identify debug endpoints
   - Find sensitive comments
   - Document client-side validation

3. **Basic XSS Testing:**
   - Discover input fields
   - Test with benign XSS payloads
   - Verify output encoding

### Phase 6: Evidence Collection
1. Generate comprehensive report in engagement folder
2. Save all screenshots to evidence/screenshots/
3. Export network logs to evidence/logs/
4. Document findings in markdown format
5. Create reproduction steps for each finding

## Output Structure

```
[ENGAGEMENT_FOLDER]/
├── 03-scanning/playwright-spa-scan/
│   ├── 00-scan-summary.md
│   ├── technology-stack.json
│   ├── routes-discovered.json
│   ├── api-endpoints.json
│   └── network-traffic.har
│
└── 08-evidence/
    ├── screenshots/
    │   ├── playwright-001-landing-page.png
    │   ├── playwright-002-authenticated-dashboard.png
    │   └── playwright-003-[finding].png
    │
    ├── logs/
    │   └── playwright-network-traffic.har
    │
    └── artifacts/
        ├── storage-dump.json
        ├── cookies.json
        └── api-endpoints.json
```

## Examples

### Basic SPA Scan
```
/scan-spa https://app.example.com
```

### Scan with Authentication
```
/scan-spa https://portal.example.com --auth
```
*(Will prompt for credentials)*

### Full Comprehensive Scan
```
/scan-spa https://dashboard.example.com --full
```

### Quick Reconnaissance
```
/scan-spa https://webapp.example.com --quick
```

## Prerequisites

- ✅ Written authorization for testing
- ✅ Target URL is in-scope per engagement agreement
- ✅ Playwright MCP server is running
- ✅ Active engagement folder exists (created via /engage)

## Safety & Non-Destructive Testing

This command follows VERSANT non-destructive testing policy:
- ✅ Read-only operations (no data modification)
- ✅ Benign XSS payloads (alert boxes only)
- ✅ Safe commands only (whoami, id, hostname)
- ✅ Immediate logout after authentication testing
- ✅ No data exfiltration
- ✅ No destructive exploits
- ✅ Rate limiting to avoid service impact

## Integration with Existing Workflow

### Recommended Usage Pattern

```bash
# Step 1: Start engagement
/engage AcmeCorp External Pentest

# Step 2: Traditional network scan
/scan 203.0.113.0/24

# Step 3: If web app is SPA/modern framework
/scan-spa https://app.acmecorp.com --auth

# Step 4: Validate findings
/validate [discovered vulnerabilities]

# Step 5: Compile evidence
/evidence AcmeCorp_2025-12-02_External
```

## When to Use /scan-spa vs /scan

**Use `/scan-spa` for:**
- React, Vue, Angular, Svelte applications
- Single Page Applications (SPAs)
- Progressive Web Apps (PWAs)
- JavaScript-heavy applications
- Applications with client-side routing
- Modern web frameworks

**Use `/scan` (traditional) for:**
- Static websites
- Server-rendered applications (PHP, ASP.NET, Django)
- Legacy web applications
- Simple HTML/CSS sites
- CMS platforms (WordPress, Joomla)

**Use BOTH for:**
- Hybrid applications (server-rendered with SPA sections)
- Comprehensive coverage
- Client-specific full assessment engagements

## Playwright Testing Capabilities

### What Playwright Can Test (vs Traditional Scanners)

| Test Type | Traditional Scanners | Playwright |
|-----------|---------------------|-----------|
| JavaScript Rendering | ❌ Limited | ✅ Full execution |
| Dynamic Content | ❌ Surface only | ✅ Complete |
| SPA Routes | ❌ Invisible | ✅ Discovered |
| Authenticated Areas | ❌ Manual | ✅ Automated |
| API Endpoints | ❌ Limited | ✅ Complete capture |
| WebSockets | ❌ No | ✅ Full testing |
| Client Storage | ❌ No access | ✅ Full inspection |
| Browser Console | ❌ No | ✅ Error capture |

## Command Implementation

This command will:
1. Verify active engagement exists
2. Confirm authorization for target
3. Initialize Playwright browser context
4. Execute automated SPA testing workflow
5. Collect comprehensive evidence
6. Generate detailed scan report
7. Update engagement tracking

## Troubleshooting

### "Target not responding"
- Verify URL is accessible
- Check for WAF/rate limiting
- Try with `--quick` flag first

### "Cannot detect framework"
- May be custom framework or vanilla JS
- Run traditional `/scan` instead
- Manual analysis may be required

### "Authentication failed"
- Verify credentials are correct
- Check for CAPTCHA on login
- May require manual authentication setup

### "Timeout errors"
- Increase timeout in command
- Check target application performance
- May indicate application issues

## Related Documentation

- **Playbook:** `playbooks/playwright-web-testing.md` - Complete Playwright testing guide
- **Traditional Scan:** `/scan` - For non-SPA applications
- **Validation:** `/validate` - Non-destructive POC testing
- **Evidence:** `/evidence` - Compile all findings

## Report Output

After scan completion, generates:

**Executive Summary:**
- Target URL and technology stack
- Number of routes discovered
- Number of API endpoints found
- Critical findings summary
- Recommended next steps

**Technical Details:**
- Framework and version
- Complete route map
- API endpoint documentation
- Authentication mechanism analysis
- Client-side security issues
- Storage security analysis

**Evidence Package:**
- Screenshots (timestamped)
- Network traffic logs (HAR)
- Storage dumps (JSON)
- Reproduction steps (Markdown)

## Security Considerations

### Authorization Verification
Before scanning:
1. Verify written authorization exists
2. Confirm target is in-scope
3. Check Rules of Engagement
4. Have emergency contact available

### Service Impact
- Uses rate limiting to prevent service degradation
- Monitors for errors and stops if detected
- Can run during off-hours if requested
- Alerts on any service disruption

### Data Protection
- No sensitive data exfiltration
- Evidence encrypted at rest
- Sanitized before reporting
- Secure deletion after retention period

## Next Steps After Scan

1. **Review Findings:** Analyze scan results in engagement folder
2. **Prioritize:** Rank vulnerabilities by severity (Critical → Low)
3. **Validate:** Use `/validate` for non-destructive POC
4. **Document:** Update engagement tracking
5. **Report:** Include findings in client deliverable

---

**Remember:** Always verify authorization before testing. This command performs active security testing and should only be used on authorized targets within approved scope.

**Version:** 1.0
**Last Updated:** 2025-12-02
**Maintained By:** VERSANT Security Team
