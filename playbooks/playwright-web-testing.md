# Playwright Web Application Testing Playbook

## Overview

This playbook provides comprehensive guidance for using **Playwright MCP** to test modern web applications during authorized penetration testing engagements. Playwright enables browser automation for testing JavaScript-heavy applications, Single Page Applications (SPAs), and complex authenticated workflows that traditional scanners cannot effectively assess.

---

## Why Playwright for Penetration Testing?

### The Modern Web Challenge

**Traditional Scanners See:**
- Static HTML shell
- Limited JavaScript execution
- Basic form discovery
- Surface-level vulnerabilities

**Modern Web Reality:**
- React/Vue/Angular SPAs
- Dynamic content loaded via AJAX/fetch
- WebSocket real-time features
- Complex authentication (OAuth, SAML, MFA)
- Client-side routing
- GraphQL APIs
- Progressive Web Apps (PWAs)

### Playwright Advantages

| Capability | Traditional Scanners | Playwright MCP |
|------------|---------------------|----------------|
| **JavaScript Rendering** | ❌ Limited | ✅ Full browser execution |
| **SPA Testing** | ❌ Sees shell only | ✅ Complete application |
| **Authentication** | ❌ Manual setup | ✅ Automated login flows |
| **Network Capture** | ❌ No | ✅ All requests/responses |
| **Browser Storage** | ❌ No access | ✅ Cookies, localStorage, sessionStorage |
| **Screenshots** | ❌ Manual | ✅ Automated evidence |
| **WebSockets** | ❌ No | ✅ Full testing |
| **Multi-Browser** | ❌ Single | ✅ Chromium, Firefox, WebKit |

---

## Integration with VERSANT Workflow

### Phase 3: Scanning & Enumeration

**Enhanced Workflow:**
```
1. Network Scanning (Nmap)
   └── Identify open web ports (80, 443, 8080, etc.)

2. Technology Detection
   └── Determine if target is SPA/modern framework

3a. Traditional Web App → Nikto, Gobuster, Dirb
3b. Modern Web App → Playwright MCP ✨
   ├── Automated navigation
   ├── JavaScript rendering
   ├── Route discovery
   └── API endpoint enumeration

4. Combine findings for complete coverage
```

### Phase 5: Exploitation Validation (Non-Destructive)

**Playwright-Enhanced Testing:**
- Automated XSS payload injection across all inputs
- CSRF token validation testing
- Session management testing
- Authentication bypass validation
- Authorization flaw testing (IDOR, privilege escalation)
- Client-side validation bypass

### Phase 6: Evidence Collection

**Automated Evidence Capture:**
- Screenshots with full context (URL, timestamp, network state)
- Video recordings of complex attack chains
- Network traffic logs (HAR files)
- Browser console errors
- Cookie and storage inspection
- DOM manipulation evidence

---

## Available Playwright MCP Tools

### Navigation & Interaction

**`mcp__playwright__playwright_navigate`**
- Navigate to target URLs
- Handle redirects and authentication
- Wait for page load completion

**`mcp__playwright__playwright_click`**
- Click buttons, links, elements
- Trigger JavaScript events
- Navigate through application flows

**`mcp__playwright__playwright_fill`**
- Fill form inputs with test data
- Submit payloads for vulnerability testing
- Automate multi-step forms

### Content & Analysis

**`mcp__playwright__playwright_screenshot`**
- Capture full-page screenshots
- Element-specific screenshots
- Automated evidence collection

**`mcp__playwright__playwright_evaluate`**
- Execute JavaScript in browser context
- Inspect DOM for vulnerabilities
- Extract data from client-side storage
- Test client-side security controls

**`mcp__playwright__playwright_content`**
- Extract page content after JS rendering
- Analyze dynamically loaded content
- Discover hidden API endpoints

### Advanced Features

**Network Interception**
- Capture all HTTP requests/responses
- Modify requests on the fly
- Test API security
- Identify sensitive data exposure

**Browser Context Management**
- Maintain authenticated sessions
- Test different user roles
- Simulate multiple users
- Isolate test scenarios

---

## Testing Methodologies

### 1. Single Page Application (SPA) Reconnaissance

**Objective:** Map out the complete SPA structure and identify attack surface

**Procedure:**
```
1. Technology Detection
   - Navigate to target with Playwright
   - Inspect page source and network requests
   - Identify framework (React, Vue, Angular, Svelte)
   - Document version information

2. Route Discovery
   - Extract client-side routes from JavaScript bundles
   - Identify authenticated vs unauthenticated routes
   - Map out navigation structure
   - Document API endpoints

3. Authentication Flow Analysis
   - Automate login process
   - Capture authentication tokens (JWT, session cookies)
   - Test token storage (localStorage vs httpOnly cookies)
   - Identify authentication mechanisms (OAuth, SAML, custom)

4. API Endpoint Enumeration
   - Monitor network traffic during navigation
   - Document all API endpoints
   - Identify GraphQL endpoints
   - Capture API request/response patterns
```

**Evidence Collection:**
```
evidence/screenshots/playwright-001-spa-landing-page.png
evidence/screenshots/playwright-002-authenticated-dashboard.png
evidence/logs/playwright-network-traffic.har
evidence/artifacts/playwright-api-endpoints.json
```

### 2. Cross-Site Scripting (XSS) Testing

**Objective:** Systematically test all input vectors for XSS vulnerabilities

**Non-Destructive Payloads:**
```javascript
// Basic alert with unique identifier
<script>alert('XSS-PENTEST-2025-12-02')</script>

// Event handler
<img src=x onerror=alert('XSS-PENTEST')>

// DOM-based XSS detection
<img src=x onerror=console.log('XSS-PENTEST')>
```

**Procedure:**
```
1. Input Discovery
   - Use Playwright to navigate through all forms
   - Identify all input fields (text, textarea, search, etc.)
   - Document hidden inputs and dynamic fields

2. Automated Payload Injection
   - For each input field:
     a. Fill with XSS payload using playwright_fill
     b. Submit form using playwright_click
     c. Check if payload executed using playwright_evaluate
     d. Screenshot if vulnerability confirmed

3. Context Analysis
   - Reflected XSS: Check immediate response
   - Stored XSS: Navigate to where input is displayed
   - DOM-based XSS: Analyze client-side JavaScript

4. Evidence Capture
   - Screenshot showing payload execution
   - Network logs showing payload in request
   - Browser console showing alert/error
   - DOM inspection showing injected code
```

**Evidence Naming:**
```
001-HIGH-XSS-reflected-search-field-20251202-143022.png
001-HIGH-XSS-reflected-network-log-20251202-143022.json
001-HIGH-XSS-reflected-console-20251202-143022.txt
```

### 3. Authentication & Authorization Testing

**Objective:** Test authentication mechanisms and role-based access controls

**Procedure:**

**A. Authentication Bypass Testing**
```
1. Session Token Analysis
   - Capture session tokens using Playwright
   - Test token storage security (httpOnly, Secure flags)
   - Analyze token expiration behavior
   - Test token regeneration on privilege change

2. Multi-Factor Authentication (MFA) Testing
   - Automate primary authentication
   - Test MFA bypass techniques (NON-DESTRUCTIVE)
   - Verify MFA on all sensitive actions
   - Test remember-me functionality

3. Password Reset Flow
   - Automate password reset request
   - Capture reset tokens from network logs
   - Test token predictability
   - Verify token expiration
```

**B. Authorization Testing (RBAC)**
```
1. Create multiple user contexts in Playwright
   - User Context 1: Regular user
   - User Context 2: Admin user
   - User Context 3: Unauthenticated

2. For each privilege level:
   - Navigate to all routes
   - Attempt to access admin functions
   - Document which endpoints are accessible
   - Screenshot unauthorized access if found

3. Insecure Direct Object Reference (IDOR)
   - Identify object IDs in URLs or API requests
   - Test sequential ID enumeration
   - Attempt to access other users' resources
   - Capture evidence of unauthorized access
```

**Evidence:**
```
002-CRITICAL-AUTH-BYPASS-admin-panel-20251202-144512.png
002-CRITICAL-AUTH-BYPASS-network-request-20251202-144512.json
003-HIGH-IDOR-user-profile-access-20251202-145022.png
```

### 4. Cross-Site Request Forgery (CSRF) Testing

**Objective:** Validate CSRF token implementation on sensitive actions

**Procedure:**
```
1. Token Discovery
   - Navigate to sensitive forms (profile update, password change)
   - Use playwright_evaluate to extract CSRF tokens
   - Document token format and location

2. Token Validation Testing
   a. Missing Token Test:
      - Capture legitimate request
      - Remove CSRF token
      - Replay request
      - Check if action succeeds (vulnerability)

   b. Token Reuse Test:
      - Use old/expired CSRF token
      - Submit request
      - Check if action succeeds (vulnerability)

   c. Token Prediction Test:
      - Analyze token entropy
      - Test for predictable patterns

3. Same-Site Cookie Testing
   - Check for SameSite attribute on cookies
   - Test cross-origin requests
   - Verify CSRF protection mechanisms
```

**Evidence:**
```
004-MEDIUM-CSRF-password-change-20251202-150012.png
004-MEDIUM-CSRF-request-without-token-20251202-150012.txt
```

### 5. API Security Testing

**Objective:** Test RESTful and GraphQL API security

**REST API Testing:**
```
1. Endpoint Discovery
   - Monitor Playwright network traffic
   - Extract all API endpoints from requests
   - Document request/response patterns

2. Authentication Testing
   - Test API endpoints without authentication
   - Test with expired/invalid tokens
   - Test token in different positions (header, query, body)

3. Authorization Testing
   - Test IDOR on API resources
   - Test mass assignment vulnerabilities
   - Verify rate limiting

4. Input Validation
   - Test for SQL injection in API parameters
   - Test NoSQL injection
   - Test for XXE in XML endpoints
   - Test for deserialization vulnerabilities
```

**GraphQL Testing:**
```
1. Introspection
   - Enable introspection if available
   - Map out schema and queries
   - Identify sensitive fields

2. Query Complexity Testing
   - Test deeply nested queries (DoS potential)
   - Test batch query limits
   - Verify query depth restrictions

3. Authorization Testing
   - Test field-level authorization
   - Attempt to access restricted fields
   - Test for information disclosure
```

**Evidence:**
```
005-HIGH-API-AUTH-bypass-user-endpoint-20251202-151022.png
005-HIGH-API-request-response-20251202-151022.json
006-MEDIUM-GRAPHQL-introspection-20251202-152012.png
```

### 6. Client-Side Security Testing

**Objective:** Identify client-side vulnerabilities and sensitive data exposure

**Procedure:**
```
1. Client-Side Storage Inspection
   - Use playwright_evaluate to inspect:
     - localStorage
     - sessionStorage
     - IndexedDB
     - Cookies
   - Look for sensitive data (tokens, PII, credentials)
   - Document insecure storage practices

2. JavaScript Source Code Analysis
   - Extract bundled JavaScript
   - Search for:
     - Hardcoded API keys
     - Sensitive comments
     - Debug endpoints
     - Exposed credentials
     - Client-side validation logic

3. Client-Side Validation Bypass
   - Identify client-side validation rules
   - Use playwright_evaluate to bypass validation
   - Submit invalid data that passes client checks
   - Verify server-side validation exists

4. Sensitive Data Exposure
   - Monitor network traffic for:
     - Unencrypted sensitive data
     - PII in URLs or logs
     - API keys in requests
     - Debug information
```

**Evidence:**
```
007-HIGH-SENSITIVE-DATA-token-in-localstorage-20251202-153022.png
007-HIGH-SENSITIVE-DATA-storage-dump-20251202-153022.json
008-MEDIUM-CLIENT-VALIDATION-bypass-20251202-154012.png
```

---

## Practical Examples

### Example 1: Testing a React SPA Login Flow

```javascript
// 1. Navigate to login page
mcp__playwright__playwright_navigate("https://target.example.com/login")

// 2. Fill credentials
mcp__playwright__playwright_fill("input[name='username']", "testuser")
mcp__playwright__playwright_fill("input[name='password']", "TestPass123!")

// 3. Capture pre-login screenshot
mcp__playwright__playwright_screenshot("evidence/001-login-form.png")

// 4. Submit login
mcp__playwright__playwright_click("button[type='submit']")

// 5. Wait for redirect and capture authenticated state
mcp__playwright__playwright_screenshot("evidence/002-authenticated-dashboard.png")

// 6. Extract tokens from localStorage
mcp__playwright__playwright_evaluate(`
  JSON.stringify({
    localStorage: localStorage,
    sessionStorage: sessionStorage,
    cookies: document.cookie
  })
`)

// 7. Document findings in evidence/token-analysis.md
```

### Example 2: XSS Testing Automation

```javascript
// XSS Payload
const xssPayload = "<script>alert('XSS-PENTEST-2025-12-02')</script>"

// 1. Navigate to target form
mcp__playwright__playwright_navigate("https://target.example.com/contact")

// 2. Test all input fields
const inputFields = ["name", "email", "subject", "message"]

for (const field of inputFields) {
  // Fill with XSS payload
  mcp__playwright__playwright_fill(`input[name='${field}']`, xssPayload)

  // Submit form
  mcp__playwright__playwright_click("button[type='submit']")

  // Check for alert execution
  const alertDetected = await mcp__playwright__playwright_evaluate(`
    // Check if alert was called
    typeof window._alertCalled !== 'undefined'
  `)

  if (alertDetected) {
    // Capture evidence
    mcp__playwright__playwright_screenshot(`evidence/XSS-${field}-detected.png`)
    console.log(`✅ XSS vulnerability found in ${field}`)
  }
}
```

### Example 3: IDOR Testing

```javascript
// 1. Login as User 1
mcp__playwright__playwright_navigate("https://target.example.com/login")
mcp__playwright__playwright_fill("input[name='username']", "user1")
mcp__playwright__playwright_fill("input[name='password']", "pass1")
mcp__playwright__playwright_click("button[type='submit']")

// 2. Navigate to User 1's profile (capture legitimate URL)
mcp__playwright__playwright_navigate("https://target.example.com/profile/123")
// URL shows userId=123

// 3. Attempt to access User 2's profile (userId=124)
mcp__playwright__playwright_navigate("https://target.example.com/profile/124")

// 4. Check if access was granted
const content = await mcp__playwright__playwright_content()

if (content.includes("User 2") || content.includes("user2@example.com")) {
  // IDOR vulnerability confirmed!
  mcp__playwright__playwright_screenshot("evidence/IDOR-user-124-access.png")
  console.log("🚨 CRITICAL: IDOR vulnerability - User 1 can access User 2 data")
}
```

---

## Evidence Collection Standards

### Screenshot Naming Convention

```
[NUM]-[SEVERITY]-[VULN_TYPE]-[DESCRIPTION]-YYYYMMDD-HHMMSS.png

Examples:
playwright-001-CRITICAL-XSS-reflected-search-20251202-143022.png
playwright-002-HIGH-AUTH-bypass-admin-panel-20251202-144512.png
playwright-003-CRITICAL-IDOR-user-data-access-20251202-145022.png
```

### Complete Evidence Package

For each Playwright-discovered vulnerability, collect:

**1. Visual Evidence**
```
├── screenshot-vulnerability.png (showing the vulnerability)
├── screenshot-request.png (network tab showing request)
├── screenshot-console.png (browser console if relevant)
└── video-exploit-chain.mp4 (for complex vulnerabilities)
```

**2. Technical Artifacts**
```
├── network-traffic.har (HAR file with all requests)
├── request-response.json (specific vulnerable request)
├── console-errors.txt (browser console output)
└── storage-dump.json (localStorage, sessionStorage, cookies)
```

**3. Reproduction Steps**
```
reproduction-steps.md:
  1. Navigate to [URL]
  2. Execute [JavaScript code]
  3. Fill [form field] with [payload]
  4. Submit form
  5. Observe [impact]
```

### Automated Evidence Collection Script

```javascript
// Create comprehensive evidence package
async function collectEvidence(vulnId, severity, category, description) {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-')
  const prefix = `playwright-${vulnId}-${severity}-${category}-${description}`

  // Screenshot
  await mcp__playwright__playwright_screenshot(
    `evidence/screenshots/${prefix}-${timestamp}.png`
  )

  // Network logs
  const networkLogs = await mcp__playwright__playwright_evaluate(`
    JSON.stringify(window.performance.getEntries())
  `)
  // Save to evidence/logs/${prefix}-network-${timestamp}.json

  // Storage dump
  const storageDump = await mcp__playwright__playwright_evaluate(`
    JSON.stringify({
      localStorage: Object.assign({}, localStorage),
      sessionStorage: Object.assign({}, sessionStorage),
      cookies: document.cookie
    })
  `)
  // Save to evidence/artifacts/${prefix}-storage-${timestamp}.json

  // Browser console
  // Capture via browser DevTools protocol

  console.log(`✅ Evidence collected: ${prefix}`)
}
```

---

## Non-Destructive Testing Guidelines

### ✅ Approved Playwright Actions

**Safe Testing:**
- Navigate to URLs within authorized scope
- Fill forms with benign test data
- Click buttons and links
- Extract page content for analysis
- Capture screenshots and network logs
- Inspect browser storage (read-only)
- Execute safe JavaScript (no modifications)
- Test authentication with test accounts
- Simulate attack paths (without execution)

**Safe Payloads:**
- XSS: `<script>alert('PENTEST')</script>` (benign alert)
- SQLi: `' OR '1'='1` followed by read-only queries
- Command Injection: `whoami`, `id`, `hostname` (safe commands)
- File Upload: `phpinfo.php`, `test.txt` (benign files, delete after)

### ❌ Prohibited Playwright Actions

**DO NOT:**
- Exfiltrate actual client data
- Modify or delete production data
- Create persistent backdoors
- Perform privilege escalation beyond POC
- Execute destructive payloads
- Conduct denial of service attacks
- Impact production services
- Move laterally to unauthorized systems
- Install malicious software
- Maintain unauthorized access after testing

### Safety Checklist

Before executing Playwright tests:
- [ ] Verify written authorization exists
- [ ] Confirm target is in-scope
- [ ] Use test accounts (not production users)
- [ ] Test in staging/dev environment (if available)
- [ ] Have emergency client contact ready
- [ ] Monitor for service impact
- [ ] Use rate limiting for automated tests
- [ ] Document all actions for repeatability

---

## Reporting Playwright Findings

### Vulnerability Report Template

```markdown
## VULN-XXX: [Vulnerability Title]

**Severity:** Critical / High / Medium / Low
**CVSS Score:** [Score] ([Vector String])
**Category:** XSS / IDOR / CSRF / Auth Bypass / etc.
**Location:** [URL or Application Component]
**Discovery Method:** Playwright Browser Automation

### Description
[Technical description of the vulnerability]

### Impact
- **Confidentiality:** [High/Medium/Low]
- **Integrity:** [High/Medium/Low]
- **Availability:** [High/Medium/Low]

[Business impact in plain language]

### Proof of Concept

**Reproduction Steps:**
1. Navigate to [URL]
2. Using Playwright, execute: [code]
3. Fill [field] with [payload]
4. Submit form
5. Observe: [impact]

**Playwright Commands Used:**
```javascript
mcp__playwright__playwright_navigate("https://target.example.com/page")
mcp__playwright__playwright_fill("input[name='field']", "payload")
mcp__playwright__playwright_click("button[type='submit']")
```

### Evidence
- Screenshot: `evidence/playwright-XXX-screenshot.png`
- Network Log: `evidence/playwright-XXX-network.har`
- Storage Dump: `evidence/playwright-XXX-storage.json`
- Video: `evidence/playwright-XXX-exploit.mp4`

### Remediation
1. [Specific fix recommendation]
2. [Additional hardening measures]
3. [Validation criteria for retest]

### References
- OWASP: [Link to OWASP guidance]
- CWE: [CWE number and link]
- CVE: [If applicable]
```

---

## Integration with Existing Tools

### Complementary Tool Usage

**Workflow Integration:**
```
1. Nmap (Network Scan)
   └── Identifies open web ports

2. Nikto (Traditional Web Scan)
   └── Finds basic web vulnerabilities

3. Playwright MCP (Modern Web Testing) ✨
   └── Tests JavaScript-heavy applications
   └── Automated vulnerability validation
   └── Evidence collection

4. SQLmap (SQL Injection)
   └── Deep SQL injection testing

5. Burp Suite / FFUF (Fuzzing)
   └── Advanced payload testing
```

### Data Flow

```
Playwright Findings → Evidence Package → Report

Evidence Package:
├── Playwright screenshots → evidence/screenshots/
├── Network logs (HAR) → evidence/logs/
├── Storage dumps → evidence/artifacts/
├── Reproduction steps → evidence/reproduction/
└── Video recordings → evidence/videos/
```

---

## Common Testing Scenarios

### Scenario 1: E-Commerce SPA Pentest

**Target:** React-based online store

**Playwright Test Plan:**
1. **Reconnaissance**
   - Technology stack identification
   - Route mapping
   - API endpoint discovery

2. **Authentication Testing**
   - Login flow automation
   - Session token security
   - Password reset flow

3. **Shopping Cart Testing**
   - Price manipulation attempts
   - Quantity bypass testing
   - Checkout process security

4. **Payment Integration**
   - PCI DSS compliance checks
   - Payment token security
   - Client-side validation bypass

5. **Account Management**
   - IDOR testing on order history
   - Profile update authorization
   - Privilege escalation testing

### Scenario 2: SaaS Admin Portal

**Target:** Vue.js admin dashboard

**Playwright Test Plan:**
1. **RBAC Testing**
   - Create user contexts (admin, user, guest)
   - Test each role's access to admin functions
   - Document authorization flaws

2. **API Security**
   - Capture all API requests
   - Test authentication on each endpoint
   - Verify rate limiting

3. **Data Export Features**
   - Test for sensitive data exposure
   - Verify access controls on exports
   - Check for mass data exfiltration

4. **User Management**
   - Test user creation/deletion
   - Verify privilege assignment security
   - Test for privilege escalation

### Scenario 3: Cloud-Based Collaboration Tool

**Target:** Angular team collaboration platform

**Playwright Test Plan:**
1. **Real-Time Features**
   - WebSocket security testing
   - Message injection testing
   - XSS in chat/comments

2. **File Sharing**
   - File upload security
   - Malicious file handling
   - Access control on shared files

3. **Multi-Tenant Testing**
   - Tenant isolation verification
   - Cross-tenant data access attempts
   - Subdomain takeover checks

4. **OAuth Integration**
   - OAuth flow security
   - Token handling
   - Third-party integration security

---

## Troubleshooting

### Common Issues

**Issue 1: Playwright Cannot Render Page**
```
Symptoms: Blank page, timeout errors
Solutions:
- Increase page load timeout
- Check for anti-automation detection
- Use stealth mode if necessary
- Verify JavaScript is enabled
```

**Issue 2: Authentication Fails**
```
Symptoms: Login doesn't work, session not maintained
Solutions:
- Check cookie settings (httpOnly, Secure)
- Verify form field selectors are correct
- Add wait conditions after login
- Check for CAPTCHA or rate limiting
```

**Issue 3: Screenshots Not Capturing Content**
```
Symptoms: Screenshots are blank or incomplete
Solutions:
- Add wait for network idle
- Wait for specific elements to load
- Use full-page screenshot option
- Check viewport size settings
```

### Best Practices

1. **Always wait for page load:** Use wait conditions before interactions
2. **Use unique selectors:** Prefer data-testid or unique IDs over classes
3. **Handle errors gracefully:** Wrap Playwright calls in try-catch
4. **Clean up after testing:** Close browsers, clear cookies
5. **Rate limit automated tests:** Avoid triggering rate limits or WAF
6. **Document everything:** Screenshot and log every step

---

## Conclusion

Playwright MCP is a powerful addition to the VERSANT penetration testing toolkit, enabling comprehensive security assessment of modern web applications. By combining traditional tools (Nmap, Nikto, SQLmap) with Playwright's browser automation capabilities, you can achieve complete coverage across all application types.

**Key Takeaways:**
- ✅ Use Playwright for JavaScript-heavy and SPA testing
- ✅ Automate evidence collection for every finding
- ✅ Maintain non-destructive testing principles
- ✅ Integrate seamlessly with existing PTES workflow
- ✅ Generate professional reports with comprehensive evidence

**Remember:** Authorization first, non-destructive validation, comprehensive evidence, professional reporting.

---

**Playbook Version:** 1.0
**Last Updated:** 2025-12-02
**Maintained By:** VERSANT Security Team
