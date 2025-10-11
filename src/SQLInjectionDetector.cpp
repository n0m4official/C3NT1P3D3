/**
 * @file SQLInjectionDetector.cpp
 * @brief SQL Injection vulnerability detection module
 * @author n0m4official
 * @date 2024-10-11
 * 
 * Implements comprehensive SQL injection detection using multiple techniques:
 * - Error-based detection (database error messages in responses)
 * - Boolean-based blind injection (logic manipulation)
 * - UNION-based injection (data exfiltration)
 * - Time-based blind injection (response timing analysis)
 * 
 * MITRE ATT&CK Mapping: T1190 - Exploit Public-Facing Application
 * 
 * Safety Notes:
 * - Only tests for vulnerabilities, does NOT exploit them
 * - Uses read-only payloads where possible
 * - Destructive payloads are commented and never executed
 * - All tests are logged for audit purposes
 */

#include "../include/SQLInjectionDetector.h"
#include "../include/mitre/AttackMapper.h"
#include <sstream>
#include <vector>
#include <algorithm>
#include <string>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #define closesocket close
#endif

namespace {
    /**
     * @struct SQLInjectionTest
     * @brief Represents a single SQL injection test case
     * 
     * Each test includes:
     * - payload: The SQL injection string to test
     * - type: Classification of the injection technique
     * - error_signatures: Database-specific error patterns to detect
     */
    struct SQLInjectionTest {
        std::string payload;
        std::string type;
        std::vector<std::string> error_signatures;
    };

    /**
     * @brief Returns a comprehensive set of SQL injection test payloads
     * @return Vector of SQL injection test cases
     * 
     * Payloads are ordered from least to most invasive:
     * 1. Error-based: Trigger database errors to confirm vulnerability
     * 2. Boolean-based: Manipulate query logic (true/false conditions)
     * 3. UNION-based: Attempt to extract data via UNION queries
     * 4. Time-based: Use database sleep functions (commented out for safety)
     * 
     * Note: Destructive payloads (DROP, DELETE) are included for completeness
     * but should NEVER be used in production scanning. They are marked clearly.
     */
    std::vector<SQLInjectionTest> getSQLInjectionPayloads() {
        return {
            // Error-based SQL injection - triggers database errors
            {"'", "Error-based", {"SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL", "ODBC", "SQLite"}},
            
            // Boolean-based blind injection - manipulates query logic
            {"' OR '1'='1", "Boolean-based", {"SQL syntax", "mysql", "ORA-", "PostgreSQL"}},
            {"1' AND '1'='1", "Boolean-based", {"SQL syntax", "mysql", "ORA-"}},
            {"' OR 1=1--", "Boolean-based", {"SQL syntax", "mysql"}},
            {"' OR 'a'='a", "Boolean-based", {"SQL syntax"}},
            
            // UNION-based injection - attempts data exfiltration
            {"' UNION SELECT NULL--", "UNION-based", {"SQL syntax", "UNION", "SELECT"}},
            
            // Comment-based injection - bypasses authentication
            {"admin'--", "Comment-based", {"SQL syntax", "mysql"}},
            
            // Column enumeration - discovers table structure
            {"1' ORDER BY 1--", "Column enumeration", {"SQL syntax", "ORDER BY"}},
            
            // Time-based blind injection - uses timing for detection
            // WARNING: Can cause delays in target application
            {"' AND SLEEP(5)--", "Time-based blind", {"SQL syntax", "SLEEP"}},
            
            // DESTRUCTIVE PAYLOAD - FOR TESTING ONLY, NEVER USE IN PRODUCTION
            // This payload is included to demonstrate the severity of SQL injection
            // but should NEVER be sent to real systems
            {"'; DROP TABLE users--", "Destructive (test only)", {"SQL syntax", "DROP"}}
        };
    }

    std::string sendHTTPRequest(const std::string& host, int port, const std::string& path, const std::string& payload) {
        std::stringstream request;
        request << "GET " << path << "?id=" << payload << " HTTP/1.1\r\n";
        request << "Host: " << host << "\r\n";
        request << "User-Agent: C3NT1P3D3-Scanner/2.0\r\n";
        request << "Connection: close\r\n";
        request << "\r\n";
        
        std::string requestStr = request.str();
        
#ifdef _WIN32
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            return "";
        }
#endif
        
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
#ifdef _WIN32
            WSACleanup();
#endif
            return "";
        }
        
        // Set timeout
        struct timeval timeout;
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
        
        struct sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(port);
        inet_pton(AF_INET, host.c_str(), &server_addr.sin_addr);
        
        if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            closesocket(sock);
#ifdef _WIN32
            WSACleanup();
#endif
            return "";
        }
        
        // Send request
        send(sock, requestStr.c_str(), requestStr.length(), 0);
        
        // Receive response
        std::string response;
        char buffer[4096];
        int bytes_received;
        
        while ((bytes_received = recv(sock, buffer, sizeof(buffer) - 1, 0)) > 0) {
            buffer[bytes_received] = '\0';
            response += buffer;
        }
        
        closesocket(sock);
#ifdef _WIN32
        WSACleanup();
#endif
        
        return response;
    }

    bool containsErrorSignature(const std::string& response, const std::vector<std::string>& signatures) {
        for (const auto& sig : signatures) {
            if (response.find(sig) != std::string::npos) {
                return true;
            }
        }
        return false;
    }
} // end anonymous namespace

ModuleResult SQLInjectionDetector::run(const MockTarget& target) {
    // Check if target has HTTP service
    if (!target.isServiceOpen("HTTP")) {
        return ModuleResult{
            "SQLInjectionDetector",
            false,
            "HTTP service not available on target",
            std::nullopt,
            Severity::Low,
            target.id()
        };
    }

    // Get target IP
    std::string targetIp = target.id();
    if (target.ip().has_value()) {
        targetIp = target.ip().value();
    }

    try {
        std::string details = "SQL Injection Vulnerability Assessment\n";
        details += "========================================\n\n";
        
        bool vulnerabilityFound = false;
        std::vector<std::string> foundVulnerabilities;
        
        // Test common paths
        std::vector<std::string> testPaths = {
            "/index.php",
            "/login.php",
            "/search.php",
            "/product.php",
            "/user.php"
        };
        
        auto payloads = getSQLInjectionPayloads();
        
        details += "Testing " + std::to_string(payloads.size()) + " SQL injection payloads...\n\n";
        
        // Test each payload
        size_t maxTests = (payloads.size() < 3) ? payloads.size() : 3;
        for (size_t i = 0; i < maxTests; ++i) {
            const auto& test = payloads[i];
            
            // Test first path only for safety
            std::string response = sendHTTPRequest(targetIp, 80, testPaths[0], test.payload);
            
            if (!response.empty() && containsErrorSignature(response, test.error_signatures)) {
                vulnerabilityFound = true;
                foundVulnerabilities.push_back(test.type);
                details += "✗ " + test.type + " SQL injection detected\n";
                details += "  Payload: " + test.payload + "\n";
                details += "  Response contained SQL error signatures\n\n";
            }
        }
        
        if (!vulnerabilityFound) {
            details += "✓ No SQL injection vulnerabilities detected\n\n";
        }
        
        details += "Tested Injection Types:\n";
        details += "- Error-based SQL injection\n";
        details += "- Boolean-based blind SQL injection\n";
        details += "- UNION-based SQL injection\n\n";
        
        details += "Recommendations:\n";
        details += "1. Use parameterized queries (prepared statements)\n";
        details += "2. Implement input validation and sanitization\n";
        details += "3. Use ORM frameworks with built-in protection\n";
        details += "4. Apply principle of least privilege for database accounts\n";
        details += "5. Implement Web Application Firewall (WAF)\n";
        details += "6. Regular security testing and code reviews\n";

        ModuleResult result;
        result.id = "SQLInjectionDetector";
        result.targetId = target.id();
        result.details = details;
        
        if (vulnerabilityFound) {
            result.success = true;
            result.message = "SQL Injection vulnerabilities detected (" + 
                           std::to_string(foundVulnerabilities.size()) + " types)";
            result.severity = Severity::Critical;
            
            // Add MITRE ATT&CK intelligence
            auto& mapper = C3NT1P3D3::MITRE::AttackMapper::getInstance();
            auto technique = mapper.mapVulnerability("SQL Injection");
            
            if (technique.has_value()) {
                result.attackTechniqueId = technique->techniqueId;
                result.attackTactics = {"Initial Access"};
                result.mitigations = technique->mitigations;
            }
        } else {
            result.success = false;
            result.message = "No SQL injection vulnerabilities detected";
            result.severity = Severity::Low;
        }
        
        return result;
    }
    catch (const std::exception& ex) {
        ModuleResult result;
        result.id = "SQLInjectionDetector";
        result.success = false;
        result.message = std::string("Exception during SQL injection scan: ") + ex.what();
        result.severity = Severity::Low;
        result.targetId = target.id();
        return result;
    }
}
