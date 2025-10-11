#include "../include/BlueKeepDetector.h"
#include "../include/mitre/AttackMapper.h"
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
    struct RDPInfo {
        bool accessible = false;
        std::string version;
        bool potentially_vulnerable = false;
    };

    RDPInfo testRDPConnection(const std::string& host, int port = 3389) {
        RDPInfo info;
        
#ifdef _WIN32
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return info;
#endif
        
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
#ifdef _WIN32
            WSACleanup();
#endif
            return info;
        }
        
        struct timeval timeout;
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
        
        struct sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(port);
        inet_pton(AF_INET, host.c_str(), &server_addr.sin_addr);
        
        if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == 0) {
            info.accessible = true;
            
            // Send basic RDP connection request (X.224 Connection Request)
            unsigned char rdp_request[] = {
                0x03, 0x00, 0x00, 0x13, // TPKT Header
                0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, // X.224 Connection Request
                0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00
            };
            
            send(sock, (char*)rdp_request, sizeof(rdp_request), 0);
            
            // Receive response
            char buffer[1024] = {0};
            int bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
            
            if (bytes > 0) {
                // Basic check: if we get a response, RDP is active
                // In a real implementation, we'd parse the X.224 response
                info.version = "RDP service detected";
                
                // BlueKeep affects unpatched Windows 7, Server 2008 R2, Server 2008
                // Without proper RDP protocol parsing, we mark as potentially vulnerable
                info.potentially_vulnerable = true;
            }
        }
        
        closesocket(sock);
#ifdef _WIN32
        WSACleanup();
#endif
        
        return info;
    }
} // end anonymous namespace

ModuleResult BlueKeepDetector::run(const MockTarget& target) {
    if (!target.isServiceOpen("RDP")) {
        return ModuleResult{
            "BlueKeepDetector",
            false,
            "RDP service not available",
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
        std::string details = "BlueKeep (CVE-2019-0708) Vulnerability Assessment\n";
        details += "==================================================\n\n";
        
        RDPInfo rdp_info = testRDPConnection(targetIp, 3389);
        
        if (rdp_info.accessible) {
            details += "✓ RDP service is accessible on port 3389\n";
            details += "Version: " + rdp_info.version + "\n\n";
            
            if (rdp_info.potentially_vulnerable) {
                details += "⚠️  WARNING: RDP service may be vulnerable to BlueKeep\n\n";
                details += "CVE-2019-0708 Details:\n";
                details += "- Pre-authentication remote code execution\n";
                details += "- Wormable vulnerability (can spread automatically)\n";
                details += "- Affects: Windows 7, Server 2008 R2, Server 2008, XP, Server 2003\n";
                details += "- Severity: CRITICAL (CVSS 9.8)\n\n";
                
                details += "Affected Systems:\n";
                details += "- Windows 7 (all versions)\n";
                details += "- Windows Server 2008 R2\n";
                details += "- Windows Server 2008\n";
                details += "- Windows XP\n";
                details += "- Windows Server 2003\n\n";
            }
        } else {
            details += "✗ RDP service not accessible or filtered\n\n";
        }
        
        details += "Recommendations:\n";
        details += "1. Apply Microsoft security update MS19-001 immediately\n";
        details += "2. Enable Network Level Authentication (NLA)\n";
        details += "3. Disable RDP if not required\n";
        details += "4. Use VPN for remote access\n";
        details += "5. Implement firewall rules to restrict RDP access\n";
        details += "6. Monitor for suspicious RDP connections\n";
        details += "7. Keep systems updated with latest patches\n";

        ModuleResult result;
        result.id = "BlueKeepDetector";
        result.targetId = target.id();
        result.details = details;
        
        if (rdp_info.accessible && rdp_info.potentially_vulnerable) {
            result.success = true;
            result.message = "RDP service accessible - Potentially vulnerable to BlueKeep (CVE-2019-0708)";
            result.severity = Severity::Critical;
            
            auto& mapper = C3NT1P3D3::MITRE::AttackMapper::getInstance();
            auto technique = mapper.mapVulnerability("BlueKeep");
            
            if (technique.has_value()) {
                result.attackTechniqueId = technique->techniqueId;
                result.attackTactics = {"Lateral Movement"};
                result.mitigations = technique->mitigations;
            }
        } else {
            result.success = false;
            result.message = "RDP service not accessible or not vulnerable";
            result.severity = Severity::Low;
        }
        
        return result;
    }
    catch (const std::exception& ex) {
        ModuleResult result;
        result.id = "BlueKeepDetector";
        result.success = false;
        result.message = std::string("Exception during BlueKeep scan: ") + ex.what();
        result.severity = Severity::Low;
        result.targetId = target.id();
        return result;
    }
}
