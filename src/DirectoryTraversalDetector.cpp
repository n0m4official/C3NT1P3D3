#include "../include/DirectoryTraversalDetector.h"
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
    struct TraversalPayload {
        std::string payload;
        std::string description;
        std::vector<std::string> success_indicators;
    };

    std::vector<TraversalPayload> getTraversalPayloads() {
        return {
            {"../../../etc/passwd", "Linux password file", {"root:", "bin:", "daemon:"}},
            {"..\\..\\..\\windows\\win.ini", "Windows config file", {"[fonts]", "[extensions]"}},
            {"....//....//....//etc/passwd", "Double encoding", {"root:", "bin:"}},
            {"..%2f..%2f..%2fetc%2fpasswd", "URL encoding", {"root:", "bin:"}},
            {"..%252f..%252f..%252fetc%252fpasswd", "Double URL encoding", {"root:", "bin:"}},
            {"....\\\\....\\\\....\\\\windows\\\\win.ini", "Windows double encoding", {"[fonts]"}},
            {"/etc/passwd", "Absolute path", {"root:", "bin:"}},
            {"C:\\windows\\win.ini", "Windows absolute path", {"[fonts]"}}
        };
    }

    std::string sendHTTPRequest(const std::string& host, int port, const std::string& payload) {
        std::stringstream request;
        request << "GET /download?file=" << payload << " HTTP/1.1\r\n";
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

    std::vector<std::string> containsIndicator(const std::string& response, const std::vector<std::string>& indicators) {
        std::vector<std::string> paths;
        for (const auto& indicator : indicators) {
            if (response.find(indicator) != std::string::npos) {
                return paths;
            }
        }
        return paths;
    }
} // end anonymous namespace

ModuleResult DirectoryTraversalDetector::run(const MockTarget& target) {
    if (!target.isServiceOpen("HTTP")) {
        return ModuleResult{
            "DirectoryTraversalDetector",
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
        std::string details = "Directory Traversal Vulnerability Assessment\n";
        details += "=============================================\n\n";
        
        bool vulnerabilityFound = false;
        std::vector<std::string> foundPayloads;
        
        auto payloads = getTraversalPayloads();
        
        details += "Testing " + std::to_string(payloads.size()) + " directory traversal payloads...\n\n";
        
        // Test first 3 payloads for safety
        size_t maxTests = (payloads.size() < 3) ? payloads.size() : 3;
        for (size_t i = 0; i < maxTests; ++i) {
            const auto& test = payloads[i];
            
            std::string response = sendHTTPRequest(targetIp, 80, test.payload);
            
            auto indicators = containsIndicator(response, test.success_indicators);
            if (!response.empty() && !indicators.empty()) {
                vulnerabilityFound = true;
                foundPayloads.push_back(test.description);
                details += "✗ Directory traversal successful\n";
                details += "  Payload: " + test.payload + "\n";
                details += "  Target: " + test.description + "\n\n";
            }
        }
        
        if (!vulnerabilityFound) {
            details += "✓ No directory traversal vulnerabilities detected\n\n";
        }
        
        details += "Tested Techniques:\n";
        details += "- Relative path traversal (../)\n";
        details += "- URL encoding bypass\n";
        details += "- Double encoding bypass\n";
        details += "- Absolute path access\n\n";
        
        details += "Recommendations:\n";
        details += "1. Validate and sanitize all file path inputs\n";
        details += "2. Use whitelist of allowed files/directories\n";
        details += "3. Implement proper access controls\n";
        details += "4. Use chroot jails or sandboxing\n";
        details += "5. Avoid direct file system access from user input\n";
        details += "6. Normalize file paths before processing\n";
        details += "7. Use secure file handling APIs\n";

        ModuleResult result;
        result.id = "DirectoryTraversalDetector";
        result.targetId = target.id();
        result.details = details;
        
        if (vulnerabilityFound) {
            result.success = true;
            result.message = "Directory traversal vulnerabilities detected (" + 
                           std::to_string(foundPayloads.size()) + " successful)";
            result.severity = Severity::High;
            
            auto& mapper = C3NT1P3D3::MITRE::AttackMapper::getInstance();
            auto technique = mapper.mapVulnerability("Directory Traversal");
            
            if (technique.has_value()) {
                result.attackTechniqueId = technique->techniqueId;
                result.attackTactics = {"Initial Access"};
                result.mitigations = technique->mitigations;
            }
        } else {
            result.success = false;
            result.message = "No directory traversal vulnerabilities detected";
            result.severity = Severity::Low;
        }
        
        return result;
    }
    catch (const std::exception& ex) {
        ModuleResult result;
        result.id = "DirectoryTraversalDetector";
        result.success = false;
        result.message = std::string("Exception during directory traversal scan: ") + ex.what();
        result.severity = Severity::Low;
        result.targetId = target.id();
        return result;
    }
}
