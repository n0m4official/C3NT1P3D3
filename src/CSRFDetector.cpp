#include "../include/CSRFDetector.h"
#include "../include/mitre/AttackMapper.h"
#include <sstream>
#include <algorithm>
#include <regex>

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
    // Common CSRF token patterns to search for
    const std::vector<std::string> CSRF_TOKEN_PATTERNS = {
        "csrf_token", "csrfToken", "_csrf", "csrf-token",
        "authenticity_token", "anti-csrf", "xsrf-token",
        "__RequestVerificationToken", "csrfmiddlewaretoken"
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

        // Build HTTP request
        std::stringstream request;
        request << "GET " << path << " HTTP/1.1\r\n";
        request << "Host: " << host << "\r\n";
        request << "User-Agent: C3NT1P3D3-Scanner/3.1\r\n";
        request << "Connection: close\r\n";
        request << "\r\n";

        std::string requestStr = request.str();
        send(sock, requestStr.c_str(), requestStr.length(), 0);

        // Receive response
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

    bool hasCSRFToken(const std::string& response) {
        std::string lowerResponse = response;
        std::transform(lowerResponse.begin(), lowerResponse.end(), lowerResponse.begin(), ::tolower);

        for (const auto& pattern : CSRF_TOKEN_PATTERNS) {
            if (lowerResponse.find(pattern) != std::string::npos) {
                return true;
            }
        }
        return false;
    }

    bool hasSameSiteCookie(const std::string& response) {
        std::string lowerResponse = response;
        std::transform(lowerResponse.begin(), lowerResponse.end(), lowerResponse.begin(), ::tolower);

        return (lowerResponse.find("samesite=strict") != std::string::npos ||
                lowerResponse.find("samesite=lax") != std::string::npos);
    }

    bool hasFormElements(const std::string& response) {
        std::string lowerResponse = response;
        std::transform(lowerResponse.begin(), lowerResponse.end(), lowerResponse.begin(), ::tolower);
        
        return (lowerResponse.find("<form") != std::string::npos &&
                (lowerResponse.find("method=\"post\"") != std::string::npos ||
                 lowerResponse.find("method='post'") != std::string::npos));
    }
}

ModuleResult CSRFDetector::run(const MockTarget& target) {
    ModuleResult result;
    result.id = id();
    result.targetId = target.id();
    result.success = true;

    // Get target IP
    std::string targetIP = "127.0.0.1"; // Default
    if (target.ip().has_value()) {
        targetIP = target.ip().value();
    }

    // Test common endpoints
    std::vector<std::string> testPaths = {"/", "/login", "/account", "/profile", "/settings"};
    
    bool foundCSRFToken = false;
    bool foundSameSite = false;
    bool foundForms = false;
    std::string vulnerableEndpoint;

    for (const auto& path : testPaths) {
        std::string response = sendHTTPRequest(targetIP, 80, path);
        
        if (response.empty()) continue;

        if (hasFormElements(response)) {
            foundForms = true;
            
            if (!hasCSRFToken(response)) {
                vulnerableEndpoint = path;
                break;
            } else {
                foundCSRFToken = true;
            }

            if (hasSameSiteCookie(response)) {
                foundSameSite = true;
            }
        }
    }

    // Determine vulnerability
    if (foundForms && !foundCSRFToken) {
        result.severity = Severity::High;
        result.message = "CSRF vulnerability detected: Missing anti-CSRF tokens";
        
        std::stringstream details;
        details << "Cross-Site Request Forgery (CSRF) vulnerability found:\n\n";
        details << "Vulnerable endpoint: " << vulnerableEndpoint << "\n";
        details << "Issues detected:\n";
        details << "  - Forms present without CSRF tokens\n";
        
        if (!foundSameSite) {
            details << "  - No SameSite cookie attribute\n";
        }
        
        details << "\nImpact:\n";
        details << "  - Attackers can forge requests on behalf of authenticated users\n";
        details << "  - Session hijacking possible\n";
        details << "  - Unauthorized state-changing operations\n";

        result.details = details.str();
    } else if (foundForms && foundCSRFToken) {
        result.severity = Severity::Low;
        result.message = "CSRF protection detected but may be incomplete";
        result.details = "CSRF tokens found, but additional validation recommended:\n"
                        "  - Verify token validation on server side\n"
                        "  - Consider adding SameSite cookie attributes\n"
                        "  - Implement Origin/Referer header validation";
    } else {
        result.severity = Severity::Low;
        result.message = "No forms detected or CSRF protection in place";
        result.details = "No state-changing forms found during scan";
    }

    // MITRE ATT&CK mapping
    result.attackTechniqueId = "T1539";
    result.attackTechniqueName = "Steal Web Session Cookie";
    result.attackTactics = {"Credential Access"};
    result.mitigations = {
        "Implement anti-CSRF tokens in all state-changing requests",
        "Set SameSite=Strict or SameSite=Lax on session cookies",
        "Validate Origin and Referer headers on server side",
        "Use double-submit cookie pattern for additional security",
        "Implement custom request headers for AJAX requests"
    };
    result.attackUrl = "https://attack.mitre.org/techniques/T1539/";

    return result;
}
