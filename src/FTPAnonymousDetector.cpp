#include "../include/FTPAnonymousDetector.h"
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
    bool testFTPAnonymous(const std::string& host, int port = 21) {
#ifdef _WIN32
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return false;
#endif
        
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
#ifdef _WIN32
            WSACleanup();
#endif
            return false;
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
            return false;
        }
        
        // Receive FTP banner
        char buffer[1024] = {0};
        recv(sock, buffer, sizeof(buffer) - 1, 0);
        
        // Try anonymous login
        std::string user_cmd = "USER anonymous\r\n";
        send(sock, user_cmd.c_str(), user_cmd.length(), 0);
        
        memset(buffer, 0, sizeof(buffer));
        int bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
        
        bool anonymous_allowed = false;
        std::string response;
        if (bytes > 0) {
            response = std::string(buffer);
            // Check for successful USER command (230 or 331)
            if (response.find("230") != std::string::npos || 
                response.find("331") != std::string::npos) {
                
                // Try PASS command
                std::string pass_cmd = "PASS anonymous@example.com\r\n";
                send(sock, pass_cmd.c_str(), pass_cmd.length(), 0);
                
                memset(buffer, 0, sizeof(buffer));
                bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
                
                if (bytes > 0) {
                    response = std::string(buffer);
                    // 230 means login successful
                    if (response.find("230") != std::string::npos) {
                        anonymous_allowed = true;
                    }
                }
            }
        }
        
        closesocket(sock);
#ifdef _WIN32
        WSACleanup();
#endif
        
        return anonymous_allowed;
    }
} // end anonymous namespace

ModuleResult FTPAnonymousDetector::run(const MockTarget& target) {
    if (!target.isServiceOpen("FTP")) {
        return ModuleResult{
            "FTPAnonymousDetector",
            false,
            "FTP service not available",
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
        std::string details = "FTP Anonymous Access Vulnerability Assessment\n";
        details += "==============================================\n\n";
        
        bool anonymousAllowed = testFTPAnonymous(targetIp, 21);
        
        if (anonymousAllowed) {
            details += "✗ CRITICAL: Anonymous FTP login is ENABLED\n\n";
            details += "Security Implications:\n";
            details += "- Unauthorized users can access FTP server\n";
            details += "- Potential data exposure\n";
            details += "- May allow file uploads (warez hosting)\n";
            details += "- Information disclosure risk\n\n";
        } else {
            details += "✓ Anonymous FTP login is disabled or not accessible\n\n";
        }
        
        details += "FTP Security Best Practices:\n";
        details += "1. Disable anonymous FTP access\n";
        details += "2. Use SFTP or FTPS instead of plain FTP\n";
        details += "3. Implement strong authentication\n";
        details += "4. Use chroot jails to restrict access\n";
        details += "5. Enable logging and monitoring\n";
        details += "6. Apply principle of least privilege\n";
        details += "7. Keep FTP server software updated\n";

        ModuleResult result;
        result.id = "FTPAnonymousDetector";
        result.targetId = target.id();
        result.details = details;
        
        if (anonymousAllowed) {
            result.success = true;
            result.message = "Anonymous FTP access is enabled - CRITICAL VULNERABILITY";
            result.severity = Severity::High;
            
            auto& mapper = C3NT1P3D3::MITRE::AttackMapper::getInstance();
            auto technique = mapper.mapVulnerability("FTP Anonymous");
            
            if (technique.has_value()) {
                result.attackTechniqueId = technique->techniqueId;
                result.attackTactics = {"Initial Access"};
                result.mitigations = technique->mitigations;
            }
        } else {
            result.success = false;
            result.message = "Anonymous FTP access is disabled";
            result.severity = Severity::Low;
        }
        
        return result;
    }
    catch (const std::exception& ex) {
        ModuleResult result;
        result.id = "FTPAnonymousDetector";
        result.success = false;
        result.message = std::string("Exception during FTP scan: ") + ex.what();
        result.severity = Severity::Low;
        result.targetId = target.id();
        return result;
    }
}
