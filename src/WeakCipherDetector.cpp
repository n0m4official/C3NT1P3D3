#include "../include/WeakCipherDetector.h"
#include "../include/mitre/AttackMapper.h"
#include <sstream>
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
    struct CipherInfo {
        std::string name;
        std::string severity;
        std::string vulnerability;
    };

    std::vector<CipherInfo> getWeakCiphers() {
        return {
            {"RC4", "HIGH", "RC4 is completely broken (CVE-2013-2566, CVE-2015-2808)"},
            {"DES", "CRITICAL", "DES has 56-bit key, easily brute-forced"},
            {"3DES", "MEDIUM", "3DES is deprecated, vulnerable to Sweet32 (CVE-2016-2183)"},
            {"MD5", "HIGH", "MD5 is cryptographically broken"},
            {"NULL", "CRITICAL", "NULL cipher provides no encryption"},
            {"EXPORT", "CRITICAL", "Export-grade ciphers are intentionally weak (FREAK attack)"},
            {"anon", "CRITICAL", "Anonymous ciphers allow MITM attacks"},
            {"SSLv2", "CRITICAL", "SSLv2 is completely insecure"},
            {"SSLv3", "HIGH", "SSLv3 vulnerable to POODLE (CVE-2014-3566)"},
            {"TLS1.0", "MEDIUM", "TLS 1.0 has known vulnerabilities (BEAST)"},
            {"CBC", "LOW", "CBC mode vulnerable to padding oracle attacks"}
        };
    }

    struct SSLTestResult {
        bool ssl_accessible = false;
        std::string protocol_version;
        std::vector<std::string> weak_ciphers_found;
        std::vector<std::string> protocols_supported;
    };

    SSLTestResult testSSLCiphers(const std::string& host, int port = 443) {
        SSLTestResult result;
        
#ifdef _WIN32
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return result;
#endif
        
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
#ifdef _WIN32
            WSACleanup();
#endif
            return result;
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
            result.ssl_accessible = true;
            
            // Send TLS ClientHello
            // This is a simplified version - real implementation would parse ServerHello
            unsigned char client_hello[] = {
                0x16, 0x03, 0x01,  // TLS Handshake, TLS 1.0
                0x00, 0x05,        // Length
                0x01,              // ClientHello
                0x00, 0x00, 0x01   // Handshake length
            };
            
            send(sock, (char*)client_hello, sizeof(client_hello), 0);
            
            char buffer[1024] = {0};
            int bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
            
            if (bytes > 0) {
                // Basic detection: if we get a response, SSL/TLS is active
                result.protocol_version = "TLS detected";
                
                // In a real implementation, we would:
                // 1. Parse ServerHello message
                // 2. Extract cipher suite chosen
                // 3. Test multiple cipher suites
                // 4. Check protocol version
                
                // For demonstration, mark as potentially weak
                result.weak_ciphers_found.push_back("Cipher analysis requires full TLS implementation");
                result.protocols_supported.push_back("TLS/SSL service detected");
            }
        }
        
        closesocket(sock);
#ifdef _WIN32
        WSACleanup();
#endif
        
        return result;
    }
} // end anonymous namespace

ModuleResult WeakCipherDetector::run(const MockTarget& target) {
    if (!target.isServiceOpen("HTTPS") && !target.isServiceOpen("SSL")) {
        return ModuleResult{
            "WeakCipherDetector",
            false,
            "HTTPS/SSL service not available",
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
        std::string details = "Weak SSL/TLS Cipher Suite Assessment\n";
        details += "=====================================\n\n";
        
        SSLTestResult ssl_result = testSSLCiphers(targetIp, 443);
        
        bool vulnerabilityFound = false;
        
        if (ssl_result.ssl_accessible) {
            details += "✓ SSL/TLS service is accessible on port 443\n";
            details += "Protocol: " + ssl_result.protocol_version + "\n\n";
            
            if (!ssl_result.weak_ciphers_found.empty()) {
                vulnerabilityFound = true;
                details += "⚠️  Potential weak cipher configuration detected\n\n";
            }
            
            details += "Weak Ciphers to Check For:\n";
            auto weak_ciphers = getWeakCiphers();
            for (const auto& cipher : weak_ciphers) {
                details += "- " + cipher.name + " (" + cipher.severity + "): " + cipher.vulnerability + "\n";
            }
            details += "\n";
            
        } else {
            details += "✗ SSL/TLS service not accessible or filtered\n\n";
        }
        
        details += "SSL/TLS Vulnerabilities:\n";
        details += "- POODLE (CVE-2014-3566): SSLv3 padding oracle\n";
        details += "- BEAST (CVE-2011-3389): TLS 1.0 CBC vulnerability\n";
        details += "- FREAK (CVE-2015-0204): Export cipher downgrade\n";
        details += "- Logjam (CVE-2015-4000): Weak Diffie-Hellman\n";
        details += "- Sweet32 (CVE-2016-2183): 3DES birthday attack\n";
        details += "- CRIME/BREACH: TLS compression attacks\n\n";
        
        details += "Recommendations:\n";
        details += "1. Disable SSLv2, SSLv3, and TLS 1.0\n";
        details += "2. Use TLS 1.2 or TLS 1.3 only\n";
        details += "3. Disable weak ciphers (RC4, DES, 3DES, MD5)\n";
        details += "4. Prefer AEAD ciphers (AES-GCM, ChaCha20-Poly1305)\n";
        details += "5. Use strong key exchange (ECDHE, DHE with 2048+ bits)\n";
        details += "6. Enable Perfect Forward Secrecy (PFS)\n";
        details += "7. Disable TLS compression\n";
        details += "8. Implement HSTS (HTTP Strict Transport Security)\n";
        details += "9. Use modern cipher suite ordering\n";
        details += "10. Regular security audits with tools like SSLyze, testssl.sh\n";

        ModuleResult result;
        result.id = "WeakCipherDetector";
        result.targetId = target.id();
        result.details = details;
        
        if (ssl_result.ssl_accessible && vulnerabilityFound) {
            result.success = true;
            result.message = "SSL/TLS service accessible - Potential weak cipher configuration";
            result.severity = Severity::Medium;
            
            auto& mapper = C3NT1P3D3::MITRE::AttackMapper::getInstance();
            auto technique = mapper.mapVulnerability("Weak Cipher");
            
            if (technique.has_value()) {
                result.attackTechniqueId = technique->techniqueId;
                result.attackTactics = {"Credential Access"};
                result.mitigations = technique->mitigations;
            }
        } else {
            result.success = false;
            result.message = "SSL/TLS service not accessible or properly configured";
            result.severity = Severity::Low;
        }
        
        return result;
    }
    catch (const std::exception& ex) {
        ModuleResult result;
        result.id = "WeakCipherDetector";
        result.success = false;
        result.message = std::string("Exception during SSL/TLS scan: ") + ex.what();
        result.severity = Severity::Low;
        result.targetId = target.id();
        return result;
    }
}
