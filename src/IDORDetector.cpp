#include "../include/IDORDetector.h"
#include <sstream>
#include <regex>
#include <vector>

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
    struct IDORTestCase {
        std::string endpoint;
        std::string description;
    };

    std::string sendHTTPRequest(const std::string& host, int port, const std::string& path) {
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

        std::stringstream request;
        request << "GET " << path << " HTTP/1.1\r\n";
        request << "Host: " << host << "\r\n";
        request << "User-Agent: C3NT1P3D3-Scanner/3.1\r\n";
        request << "Connection: close\r\n";
        request << "\r\n";

        std::string requestStr = request.str();
        send(sock, requestStr.c_str(), requestStr.length(), 0);

        std::string response;
        char buffer[4096];
        int bytesReceived;
        while ((bytesReceived = recv(sock, buffer, sizeof(buffer) - 1, 0)) > 0) {
            buffer[bytesReceived] = '\0';
            response += buffer;
        }

        closesocket(sock);
        #ifdef _WIN32
        WSACleanup();
        #endif

        return response;
    }

    bool hasSequentialIDs(const std::string& response) {
        // Look for patterns like /user/123, /api/v1/users/456, etc.
        std::regex idPattern(R"(/(?:user|profile|document|file|order|invoice|api/v\d+/\w+)/(\d+))");
        return std::regex_search(response, idPattern);
    }

    bool testIDORVulnerability(const std::string& host, int port, const std::string& basePath, int id1, int id2) {
        // Test if we can access different IDs without authorization
        std::string path1 = basePath + std::to_string(id1);
        std::string path2 = basePath + std::to_string(id2);

        std::string response1 = sendHTTPRequest(host, port, path1);
        std::string response2 = sendHTTPRequest(host, port, path2);

        if (response1.empty() || response2.empty()) {
            return false;
        }

        // Check if both requests returned 200 OK (potential IDOR)
        bool resp1_ok = response1.find("HTTP/1.1 200") != std::string::npos ||
                        response1.find("HTTP/1.0 200") != std::string::npos;
        bool resp2_ok = response2.find("HTTP/1.1 200") != std::string::npos ||
                        response2.find("HTTP/1.0 200") != std::string::npos;

        // If both succeed without authentication, potential IDOR
        return resp1_ok && resp2_ok;
    }

    std::vector<IDORTestCase> getIDORTestCases() {
        return {
            {"/api/user/", "User profile access"},
            {"/api/users/", "User listing"},
            {"/api/profile/", "Profile data"},
            {"/api/document/", "Document access"},
            {"/api/order/", "Order information"},
            {"/api/invoice/", "Invoice details"},
            {"/user/", "User page"},
            {"/profile/", "Profile page"},
            {"/account/", "Account details"}
        };
    }
}

ModuleResult IDORDetector::run(const MockTarget& target) {
    ModuleResult result;
    result.id = id();
    result.targetId = target.id();
    result.success = true;

    std::string targetIP = "127.0.0.1";
    if (target.ip().has_value()) {
        targetIP = target.ip().value();
    }

    std::vector<std::string> vulnerableEndpoints;
    auto testCases = getIDORTestCases();

    // Test for IDOR vulnerabilities
    for (const auto& testCase : testCases) {
        // Test sequential IDs (1, 2, 3, etc.)
        if (testIDORVulnerability(targetIP, 80, testCase.endpoint, 1, 2)) {
            vulnerableEndpoints.push_back(testCase.endpoint + " - " + testCase.description);
        }
    }

    // Also check homepage for sequential ID patterns
    std::string homepage = sendHTTPRequest(targetIP, 80, "/");
    bool hasSequentialIDsInResponse = hasSequentialIDs(homepage);

    if (!vulnerableEndpoints.empty() || hasSequentialIDsInResponse) {
        result.severity = Severity::High;
        result.message = "IDOR vulnerability detected: Insecure object references";
        
        std::stringstream details;
        details << "Insecure Direct Object Reference (IDOR) vulnerability detected:\n\n";
        
        if (!vulnerableEndpoints.empty()) {
            details << "Vulnerable endpoints found:\n";
            for (const auto& endpoint : vulnerableEndpoints) {
                details << "  - " << endpoint << "\n";
            }
            details << "\n";
        }

        if (hasSequentialIDsInResponse) {
            details << "Sequential IDs detected in responses:\n";
            details << "  - URLs contain predictable numeric IDs\n";
            details << "  - Pattern: /resource/[sequential_number]\n\n";
        }

        details << "Security Issues:\n";
        details << "  - Missing authorization checks on object access\n";
        details << "  - Predictable resource identifiers\n";
        details << "  - Horizontal privilege escalation possible\n\n";

        details << "Attack Scenario:\n";
        details << "  1. Attacker accesses /api/user/1 (their own profile)\n";
        details << "  2. Attacker modifies ID to /api/user/2\n";
        details << "  3. Attacker gains unauthorized access to another user's data\n\n";

        details << "Impact:\n";
        details << "  - Unauthorized data access\n";
        details << "  - Privacy violations\n";
        details << "  - Data enumeration and harvesting\n";
        details << "  - Potential account takeover\n";

        result.details = details.str();
    } else {
        result.severity = Severity::Low;
        result.message = "No obvious IDOR vulnerabilities detected";
        result.details = "Tested common endpoints for insecure direct object references.\n"
                        "No immediate vulnerabilities found, but manual testing recommended.";
    }

    // MITRE ATT&CK mapping
    result.attackTechniqueId = "T1078";
    result.attackTechniqueName = "Valid Accounts";
    result.attackTactics = {"Privilege Escalation", "Defense Evasion", "Initial Access"};
    result.mitigations = {
        "Implement proper authorization checks for every object access",
        "Use indirect object references (mapping tables) instead of direct IDs",
        "Validate user permissions at the data access layer",
        "Use UUIDs or non-sequential identifiers",
        "Implement access control lists (ACLs) for resources",
        "Log and monitor access patterns for anomalies"
    };
    result.attackUrl = "https://attack.mitre.org/techniques/T1078/";

    return result;
}
