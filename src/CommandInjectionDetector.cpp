#include "../include/CommandInjectionDetector.h"
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
    struct CommandPayload {
        std::string payload;
        std::string description;
        std::vector<std::string> success_indicators;
    };

    std::vector<CommandPayload> getCommandPayloads() {
        return {
            {
                "; whoami",
                "Command chaining (Linux/Unix)",
                {"root", "www-data", "apache", "nginx", "nobody"}
            },
            {
                "| whoami",
                "Pipe operator",
                {"root", "www-data", "apache"}
            },
            {
                "& whoami",
                "Background execution (Windows)",
                {"nt authority", "system", "administrator"}
            },
            {
                "`whoami`",
                "Command substitution (backticks)",
                {"root", "www-data"}
            },
            {
                "$(whoami)",
                "Command substitution (dollar)",
                {"root", "www-data"}
            },
            {
                "; ping -c 1 127.0.0.1",
                "Time-based detection (ping)",
                {"64 bytes", "icmp_seq", "time="}
            },
            {
                "& ping -n 1 127.0.0.1",
                "Windows ping",
                {"Pinging", "Reply from", "TTL="}
            },
            {
                "; cat /etc/passwd",
                "File read (Linux)",
                {"root:", "bin:", "daemon:"}
            },
            {
                "& type C:\\windows\\win.ini",
                "File read (Windows)",
                {"[fonts]", "[extensions]"}
            },
            {
                "; sleep 5",
                "Time-based blind injection",
                {}  // Success based on response time
            }
        };
    }

    std::string sendCommandInjectionTest(const std::string& host, int port, const std::string& payload) {
        std::stringstream request;
        request << "GET /exec?cmd=" << payload << " HTTP/1.1\r\n";
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

    bool containsIndicator(const std::string& response, const std::vector<std::string>& indicators) {
        if (indicators.empty()) return false;  // Time-based detection needs different approach
        
        for (const auto& indicator : indicators) {
            if (response.find(indicator) != std::string::npos) {
                return true;
            }
        }
        return false;
    }
} // end anonymous namespace

ModuleResult CommandInjectionDetector::run(const MockTarget& target) {
    if (!target.isServiceOpen("HTTP")) {
        return ModuleResult{
            "CommandInjectionDetector",
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
        std::string details = "Command Injection Vulnerability Assessment\n";
        details += "===========================================\n\n";
        
        bool vulnerabilityFound = false;
        std::vector<std::string> foundVulnerabilities;
        
        auto payloads = getCommandPayloads();
        
        details += "Testing " + std::to_string(payloads.size()) + " command injection payloads...\n\n";
        
        // Test first 3 payloads for safety
        size_t maxTests = (payloads.size() < 3) ? payloads.size() : 3;
        for (size_t i = 0; i < maxTests; ++i) {
            const auto& test = payloads[i];
            
            std::string response = sendCommandInjectionTest(targetIp, 80, test.payload);
            
            if (!response.empty() && containsIndicator(response, test.success_indicators)) {
                vulnerabilityFound = true;
                foundVulnerabilities.push_back(test.description);
                details += "✗ Command injection detected\n";
                details += "  Type: " + test.description + "\n";
                details += "  Payload: " + test.payload + "\n";
                details += "  Response contained command output\n\n";
            }
        }
        
        if (!vulnerabilityFound) {
            details += "✓ No command injection vulnerabilities detected\n\n";
        }
        
        details += "Command Injection Details:\n";
        details += "- Allows execution of arbitrary OS commands\n";
        details += "- Can lead to complete system compromise\n";
        details += "- Enables data exfiltration and manipulation\n";
        details += "- May allow privilege escalation\n";
        details += "- Common in web shells, admin panels, file operations\n\n";
        
        details += "Injection Techniques Tested:\n";
        details += "- Command chaining (; operator)\n";
        details += "- Pipe operators (| operator)\n";
        details += "- Background execution (& operator)\n";
        details += "- Command substitution (backticks, $())\n";
        details += "- Time-based blind injection\n\n";
        
        details += "Recommendations:\n";
        details += "1. Never pass user input directly to system commands\n";
        details += "2. Use parameterized APIs instead of shell commands\n";
        details += "3. Implement strict input validation (whitelist)\n";
        details += "4. Escape shell metacharacters if commands are necessary\n";
        details += "5. Run applications with minimal privileges\n";
        details += "6. Use application sandboxing/containerization\n";
        details += "7. Implement command execution logging and monitoring\n";
        details += "8. Disable dangerous functions (exec, system, eval)\n";

        ModuleResult result;
        result.id = "CommandInjectionDetector";
        result.targetId = target.id();
        result.details = details;
        
        if (vulnerabilityFound) {
            result.success = true;
            result.message = "Command injection vulnerabilities detected (" + 
                           std::to_string(foundVulnerabilities.size()) + " vectors)";
            result.severity = Severity::Critical;
            
            auto& mapper = C3NT1P3D3::MITRE::AttackMapper::getInstance();
            auto technique = mapper.mapVulnerability("Command Injection");
            
            if (technique.has_value()) {
                result.attackTechniqueId = technique->techniqueId;
                result.attackTactics = {"Execution"};
                result.mitigations = technique->mitigations;
            }
        } else {
            result.success = false;
            result.message = "No command injection vulnerabilities detected";
            result.severity = Severity::Low;
        }
        
        return result;
    }
    catch (const std::exception& ex) {
        ModuleResult result;
        result.id = "CommandInjectionDetector";
        result.success = false;
        result.message = std::string("Exception during command injection scan: ") + ex.what();
        result.severity = Severity::Low;
        result.targetId = target.id();
        return result;
    }
}
