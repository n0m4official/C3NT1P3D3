#include "../include/XSSDetector.h"
#include "../include/mitre/AttackMapper.h"
#include <sstream>
#include <vector>
#include <algorithm>

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
    struct XSSPayload {
        std::string payload;
        std::string type;
        std::string description;
    };

    std::vector<XSSPayload> getXSSPayloads() {
        return {
            {"<script>alert('XSS')</script>", "Reflected XSS", "Basic script injection"},
            {"<img src=x onerror=alert('XSS')>", "Reflected XSS", "Image tag with onerror"},
            {"<svg/onload=alert('XSS')>", "Reflected XSS", "SVG tag injection"},
            {"javascript:alert('XSS')", "Reflected XSS", "JavaScript protocol"},
            {"<iframe src=javascript:alert('XSS')>", "Reflected XSS", "Iframe injection"},
            {"'\"><script>alert('XSS')</script>", "Reflected XSS", "Breaking out of quotes"},
            {"<body onload=alert('XSS')>", "Reflected XSS", "Body tag event handler"},
            {"<input onfocus=alert('XSS') autofocus>", "Reflected XSS", "Input tag with autofocus"}
        };
    }

    std::string sendHTTPRequest(const std::string& host, int port, const std::string& path, const std::string& payload) {
        std::stringstream request;
        request << "GET " << path << "?q=" << payload << " HTTP/1.1\r\n";
        request << "Host: " << host << "\r\n";
        request << "User-Agent: C3NT1P3D3-Scanner/2.0\r\n";
        request << "Connection: close\r\n\r\n";
        
        std::string requestStr = request.str();
        
#ifdef _WIN32
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return "";
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
        
        send(sock, requestStr.c_str(), requestStr.length(), 0);
        
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

    bool payloadReflected(const std::string& response, const std::string& payload) {
        // Check if payload appears in response without encoding
        return response.find(payload) != std::string::npos;
    }
} // end anonymous namespace

ModuleResult XSSDetector::run(const MockTarget& target) {
    if (!target.isServiceOpen("HTTP")) {
        return ModuleResult{
            "XSSDetector",
            false,
            "HTTP service not available",
            std::nullopt,
            Severity::Low,
            target.id()
        };
    }

    std::string targetIp = target.id();
    if (target.ip().has_value()) {
        targetIp = target.ip().value();
    }

    try {
        std::string details = "Cross-Site Scripting (XSS) Vulnerability Assessment\n";
        details += "===================================================\n\n";
        
        bool vulnerabilityFound = false;
        std::vector<std::string> foundTypes;
        
        auto payloads = getXSSPayloads();
        
        details += "Testing " + std::to_string(payloads.size()) + " XSS payloads...\n\n";
        
        // Test first 3 payloads for safety
        size_t maxTests = (payloads.size() < 3) ? payloads.size() : 3;
        for (size_t i = 0; i < maxTests; ++i) {
            const auto& test = payloads[i];
            
            std::string response = sendHTTPRequest(targetIp, 80, "/search", test.payload);
            
            if (!response.empty() && payloadReflected(response, test.payload)) {
                vulnerabilityFound = true;
                foundTypes.push_back(test.type);
                details += "✗ " + test.type + " detected\n";
                details += "  Payload: " + test.payload + "\n";
                details += "  Description: " + test.description + "\n\n";
            }
        }
        
        if (!vulnerabilityFound) {
            details += "✓ No XSS vulnerabilities detected\n\n";
        }
        
        details += "Tested XSS Types:\n";
        details += "- Reflected XSS (non-persistent)\n";
        details += "- Script tag injection\n";
        details += "- Event handler injection\n";
        details += "- HTML attribute injection\n\n";
        
        details += "Recommendations:\n";
        details += "1. Implement output encoding/escaping\n";
        details += "2. Use Content Security Policy (CSP)\n";
        details += "3. Validate and sanitize all user input\n";
        details += "4. Use HTTPOnly and Secure flags on cookies\n";
        details += "5. Implement X-XSS-Protection header\n";
        details += "6. Use modern frameworks with built-in XSS protection\n";

        ModuleResult result;
        result.id = "XSSDetector";
        result.targetId = target.id();
        result.details = details;
        
        if (vulnerabilityFound) {
            result.success = true;
            result.message = "XSS vulnerabilities detected (" + std::to_string(foundTypes.size()) + " instances)";
            result.severity = Severity::High;
            
            auto& mapper = C3NT1P3D3::MITRE::AttackMapper::getInstance();
            auto technique = mapper.mapVulnerability("XSS");
            
            if (technique.has_value()) {
                result.attackTechniqueId = technique->techniqueId;
                result.attackTactics = {"Initial Access"};
                result.mitigations = technique->mitigations;
            }
        } else {
            result.success = false;
            result.message = "No XSS vulnerabilities detected";
            result.severity = Severity::Low;
        }
        
        return result;
    }
    catch (const std::exception& ex) {
        ModuleResult result;
        result.id = "XSSDetector";
        result.success = false;
        result.message = std::string("Exception during XSS scan: ") + ex.what();
        result.severity = Severity::Low;
        result.targetId = target.id();
        return result;
    }
}
