#include "EternalBlueDetector.h"
#include "IModule.h"
#include <iostream>
#include <string>
#include <vector>
#include <array>
#include <stdexcept>
#include <cstring>
#include <memory>
#include <chrono>
#include <functional>
#include <unordered_map>
#include <sstream>
#ifdef _WIN32
// SO_CONNECT_TIME is not available in all Windows SDKs, so define it if missing
#ifndef SO_CONNECT_TIME
#define SO_CONNECT_TIME 0x700C
#endif
#endif

// Cross-platform socket support
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
typedef SOCKET socket_t;
#define INVALID_SOCKET_VALUE INVALID_SOCKET
#define SOCKET_ERROR_VALUE SOCKET_ERROR
#define CLOSE_SOCKET(s) closesocket(s)
#define LAST_ERROR WSAGetLastError()
#define WOULD_BLOCK WSAEWOULDBLOCK
#define CONN_REFUSED WSAECONNREFUSED
#define CONN_RESET WSAECONNRESET
#define TIMEOUT WSAETIMEDOUT
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
typedef int socket_t;
#define INVALID_SOCKET_VALUE -1
#define SOCKET_ERROR_VALUE -1
#define CLOSE_SOCKET(s) close(s)
#define LAST_ERROR errno
#define WOULD_BLOCK EWOULDBLOCK
#define CONN_REFUSED ECONNREFUSED
#define CONN_RESET ECONNRESET
#define TIMEOUT ETIMEDOUT
#endif

// Configuration struct for scanner settings
struct ScannerConfig {
    int connectTimeoutMs = 3000;  // Connection timeout in milliseconds
    int sendTimeoutMs = 3000;     // Send operation timeout
    int recvTimeoutMs = 3000;     // Receive operation timeout
    bool detectOSVersion = true;  // Try to detect OS version
    bool deepInspection = true;   // Perform deeper vulnerability checks

    ScannerConfig() = default;

    ScannerConfig& setConnectTimeout(int ms) {
        connectTimeoutMs = ms;
        return *this;
    }

    ScannerConfig& setSendTimeout(int ms) {
        sendTimeoutMs = ms;
        return *this;
    }

    ScannerConfig& setRecvTimeout(int ms) {
        recvTimeoutMs = ms;
        return *this;
    }

    ScannerConfig& setDetectOSVersion(bool detect) {
        detectOSVersion = detect;
        return *this;
    }

    ScannerConfig& setDeepInspection(bool deep) {
        deepInspection = deep;
        return *this;
    }
};

// Enhanced error information
struct NetworkError {
    int errorCode;
    std::string message;

    NetworkError(int code, const std::string& msg) : errorCode(code), message(msg) {}

    std::string toString() const {
        std::ostringstream oss;
        oss << "Error " << errorCode << ": " << message;
        return oss.str();
    }
};

// Detailed vulnerability information
struct VulnerabilityDetails {
    bool smb1Enabled = false;
    bool potentiallyVulnerable = false;
    std::string osVersion;
    std::string smbVersion;
    std::vector<std::string> vulnerabilities;

    void addVulnerability(const std::string& vuln) {
        vulnerabilities.push_back(vuln);
    }

    bool hasVulnerabilities() const {
        return !vulnerabilities.empty();
    }

    std::string toString() const {
        std::ostringstream oss;
        oss << "SMBv1 Enabled: " << (smb1Enabled ? "Yes" : "No") << "\
";
        oss << "Potentially Vulnerable: " << (potentiallyVulnerable ? "Yes" : "No") << "\
";

        if (!osVersion.empty()) {
            oss << "OS Version: " << osVersion << "\
";
        }

        if (!smbVersion.empty()) {
            oss << "SMB Version: " << smbVersion << "\
";
        }

        if (!vulnerabilities.empty()) {
            oss << "Detected Vulnerabilities:\
";
            for (const auto& vuln : vulnerabilities) {
                oss << "- " << vuln << "\
";
            }
        }

        return oss.str();
    }
};

enum class ExploitSeverity {
    Low,
    Medium,
    High,
    Critical
};

// Enhanced result structure
struct ExploitResult {
    bool success;
    std::string message;
    std::string targetIp;
    std::string targetHostname;
    ExploitSeverity severity;
    std::unique_ptr<NetworkError> error;
    std::unique_ptr<VulnerabilityDetails> details;

    ExploitResult(bool success, const std::string& message, const std::string& targetIp)
        : success(success), message(message), targetIp(targetIp), severity(ExploitSeverity::Critical),
        error(nullptr), details(nullptr) {
    }

    void setError(int code, const std::string& errorMsg) {
        error = std::make_unique<NetworkError>(code, errorMsg);
    }

    void setVulnerabilityDetails(std::unique_ptr<VulnerabilityDetails> vulnDetails) {
        details = std::move(vulnDetails);
    }

    std::string toString() const {
        std::ostringstream oss;
        oss << "Target: " << targetIp;
        if (!targetHostname.empty()) {
            oss << " (" << targetHostname << ")";
        }
        oss << "\
Result: " << (success ? "Vulnerable" : "Not Vulnerable") << "\
";
        oss << "Message: " << message << "\
";

        if (error) {
            oss << "Error Details: " << error->toString() << "\
";
        }

        if (details) {
            oss << "\
Vulnerability Details:\
" << details->toString();
        }

        return oss.str();
    }
};

// RAII Socket Wrapper
class Socket {
private:
    socket_t sock;
    bool initialized;

    // Private copy constructor and assignment operator to prevent copying
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;

#ifdef _WIN32
    // Windows-specific initialization
    static bool initializeWinsock() {
        static bool initialized = false;
        if (!initialized) {
            WSADATA wsaData;
            if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
                return false;
            }
            initialized = true;
        }
        return initialized;
    }
#endif

public:
    // Constructor
    Socket() : sock(INVALID_SOCKET_VALUE), initialized(false) {
#ifdef _WIN32
        initialized = initializeWinsock();
        if (!initialized) {
            throw std::runtime_error("Failed to initialize Winsock");
        }
#else
        initialized = true;
#endif
    }

    // Move constructor
    Socket(Socket&& other) noexcept : sock(other.sock), initialized(other.initialized) {
        other.sock = INVALID_SOCKET_VALUE;
    }

    // Move assignment operator
    Socket& operator=(Socket&& other) noexcept {
        if (this != &other) {
            closeSocket();
            sock = other.sock;
            initialized = other.initialized;
            other.sock = INVALID_SOCKET_VALUE;
        }
        return *this;
    }

    // Destructor - automatically closes socket
    ~Socket() {
        closeSocket();
#ifdef _WIN32
        // No need to call WSACleanup() here as it would affect all sockets
#endif
    }

    // Create socket
    bool create(int family, int type, int protocol) {
        closeSocket();
        sock = socket(family, type, protocol);
        return sock != INVALID_SOCKET_VALUE;
    }

    // Set socket option
    bool setOption(int level, int optname, const void* optval, socklen_t optlen) {
        return setsockopt(sock, level, optname, static_cast<const char*>(optval), optlen) != SOCKET_ERROR_VALUE;
    }

    // Set timeout options
    bool setTimeout(const ScannerConfig& config) {
#ifdef _WIN32
        DWORD timeout;

        // Set connect timeout
        timeout = config.connectTimeoutMs;
        if (!setOption(SOL_SOCKET, SO_CONNECT_TIME, &timeout, sizeof(timeout))) {
            return false;
        }

        // Set send timeout
        timeout = config.sendTimeoutMs;
        if (!setOption(SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout))) {
            return false;
        }

        // Set receive timeout
        timeout = config.recvTimeoutMs;
        if (!setOption(SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout))) {
            return false;
        }
#else
        struct timeval tv;

        // Set send timeout
        tv.tv_sec = config.sendTimeoutMs / 1000;
        tv.tv_usec = (config.sendTimeoutMs % 1000) * 1000;
        if (!setOption(SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv))) {
            return false;
        }

        // Set receive timeout
        tv.tv_sec = config.recvTimeoutMs / 1000;
        tv.tv_usec = (config.recvTimeoutMs % 1000) * 1000;
        if (!setOption(SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv))) {
            return false;
        }
#endif
        return true;
    }

    // Connect to address
    bool connect(const struct sockaddr* addr, socklen_t addrlen) {
        return ::connect(sock, addr, addrlen) != SOCKET_ERROR_VALUE;
    }

    // Send data
    int send(const void* buf, size_t len, int flags = 0) {
        return ::send(sock, static_cast<const char*>(buf), static_cast<int>(len), flags);
    }

    // Receive data
    int recv(void* buf, size_t len, int flags = 0) {
        return ::recv(sock, static_cast<char*>(buf), static_cast<int>(len), flags);
    }

    // Close socket
    void closeSocket() {
        if (sock != INVALID_SOCKET_VALUE) {
            CLOSE_SOCKET(sock);
            sock = INVALID_SOCKET_VALUE;
        }
    }

    // Check if socket is valid
    bool isValid() const {
        return sock != INVALID_SOCKET_VALUE;
    }

    // Get last error
    static int getLastError() {
        return LAST_ERROR;
    }

    // Get error string
    static std::string getErrorString(int errorCode) {
#ifdef _WIN32
        char* errorMsg = nullptr;
        FormatMessageA(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, errorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPSTR)&errorMsg, 0, NULL);

        std::string result = errorMsg ? errorMsg : "Unknown error";
        LocalFree(errorMsg);
        return result;
#else
        return strerror(errorCode);
#endif
    }
};

// Address resolution helper
class AddressResolver {
public:
    static std::pair<bool, std::string> resolveAddress(const std::string& host, int port, struct sockaddr_storage* addr, socklen_t* addrlen) {
        struct addrinfo hints, * result = nullptr;
        std::memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;    // Allow IPv4 or IPv6
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        // Convert port to string
        std::string portStr = std::to_string(port);

        // Resolve address
        int status = getaddrinfo(host.c_str(), portStr.c_str(), &hints, &result);
        if (status != 0) {
#ifdef _WIN32
            return { false, gai_strerrorA(status) };
#else
            return { false, gai_strerror(status) };
#endif
        }

        // Use the first result
        if (result) {
            std::memcpy(addr, result->ai_addr, result->ai_addrlen);
            *addrlen = result->ai_addrlen;

            // Get the IP address as a string
            char ipStr[INET6_ADDRSTRLEN];
            void* addrPtr;

            if (result->ai_family == AF_INET) {
                struct sockaddr_in* ipv4 = (struct sockaddr_in*)result->ai_addr;
                addrPtr = &(ipv4->sin_addr);
            }
            else {
                struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)result->ai_addr;
                addrPtr = &(ipv6->sin6_addr);
            }

            inet_ntop(result->ai_family, addrPtr, ipStr, sizeof(ipStr));
            std::string resolvedIp = ipStr;

            freeaddrinfo(result);
            return { true, resolvedIp };
        }

        freeaddrinfo(result);
        return { false, "No address found" };
    }

    static std::string getHostname(const std::string& ipAddress) {
        struct sockaddr_in sa;
        char host[NI_MAXHOST];

        std::memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        inet_pton(AF_INET, ipAddress.c_str(), &sa.sin_addr);

        if (getnameinfo((struct sockaddr*)&sa, sizeof(sa), host, sizeof(host), NULL, 0, NI_NAMEREQD) == 0) {
            return std::string(host);
        }

        return "";
    }
};

// SMB Protocol Helper
class SMBProtocol {
public:
    // SMB Negotiation packet for checking SMBv1
    static std::vector<uint8_t> createSMBv1NegotiatePacket() {
        return {
            0x00, 0x00, 0x00, 0x85, 0xff, 0x53, 0x4d, 0x42,
            0x72, 0x00, 0x00, 0x00, 0x00, 0x18, 0x53, 0xc8,
            0x00, 0x26, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x62, 0x00, 0x02,
            0x50, 0x43, 0x20, 0x4e, 0x45, 0x54, 0x57, 0x4f,
            0x52, 0x4b, 0x20, 0x50, 0x52, 0x4f, 0x47, 0x52,
            0x41, 0x4d, 0x20, 0x31, 0x2e, 0x30, 0x00, 0x02,
            0x4d, 0x49, 0x43, 0x52, 0x4f, 0x53, 0x4f, 0x46,
            0x54, 0x20, 0x4e, 0x45, 0x54, 0x57, 0x4f, 0x52,
            0x4b, 0x53, 0x20, 0x31, 0x2e, 0x30, 0x00, 0x02,
            0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x31, 0x2e,
            0x30, 0x00, 0x02, 0x57, 0x69, 0x6e, 0x64, 0x6f,
            0x77, 0x73, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x57,
            0x6f, 0x72, 0x6b, 0x67, 0x72, 0x6f, 0x75, 0x70,
            0x73, 0x20, 0x33, 0x2e, 0x31, 0x00
        };
    }

    // SMB2 Negotiation packet
    static std::vector<uint8_t> createSMB2NegotiatePacket() {
        return {
            0x00, 0x00, 0x00, 0x9E, 0xFE, 0x53, 0x4D, 0x42,
            0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x24, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x7F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x70, 0x00, 0x00, 0x00,
            0x02, 0x00, 0x00, 0x00, 0x02, 0x02, 0x10, 0x02,
            0x00, 0x03, 0x02, 0x03, 0x11, 0x03, 0x00, 0x00,
            0x01, 0x00, 0x26, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00
        };
    }

    // MS17-010 specific check packet
    static std::vector<uint8_t> createMS17010CheckPacket() {
        // This is a Trans2 request with SESSION_SETUP command
        return {
            0x00, 0x00, 0x00, 0x4F, 0xFF, 0x53, 0x4D, 0x42,
            0x32, 0x00, 0x00, 0x00, 0x00, 0x18, 0x07, 0xC0,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0xFF, 0xFE,
            0x00, 0x08, 0x41, 0x00, 0x0F, 0x0C, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00
        };
    }

    // Parse SMB response to check for SMBv1
    static bool isSMBv1Enabled(const std::vector<uint8_t>& response) {
        // Check if response has enough bytes and contains SMB signature
        if (response.size() > 5 && response[4] == 0xFF && response[5] == 0x53) {
            return true;
        }
        return false;
    }

    // Parse SMB response to check for SMB2
    static bool isSMB2Enabled(const std::vector<uint8_t>& response) {
        // Check if response has enough bytes and contains SMB2 signature
        if (response.size() > 5 && response[4] == 0xFE && response[5] == 0x53) {
            return true;
        }
        return false;
    }

    // Parse response to check for MS17-010 vulnerability
    static bool isVulnerableToMS17010(const std::vector<uint8_t>& response) {
        // Check for specific signature in response that indicates vulnerability
        // This is a simplified check - a real implementation would be more complex
        if (response.size() > 10 && response[9] == 0x05 && response[10] == 0x02 &&
            response[11] == 0x00 && response[12] == 0xC0) {
            return true;
        }
        return false;
    }

    // Try to determine Windows version from SMB response
    static std::string detectWindowsVersion(const std::vector<uint8_t>& response) {
        // This is a placeholder - real implementation would analyze specific
        // patterns in the SMB response to fingerprint the Windows version
        if (response.size() < 45) {
            return "Unknown";
        }

        // This is highly simplified - real version detection would be more complex
        uint8_t versionIndicator = response[45];
        switch (versionIndicator) {
        case 0xF1: return "Windows XP";
        case 0xF2: return "Windows Server 2003";
        case 0xF3: return "Windows Vista/Server 2008";
        case 0xF4: return "Windows 7/Server 2008 R2";
        case 0xF5: return "Windows 8/Server 2012";
        case 0xF6: return "Windows 8.1/Server 2012 R2";
        case 0xF7: return "Windows 10/Server 2016";
        default: return "Unknown Windows Version";
        }
    }

    // Determine SMB version from responses
    static std::string detectSMBVersion(bool smb1Enabled, bool smb2Enabled) {
        if (smb1Enabled && smb2Enabled) {
            return "SMBv1, SMBv2/3";
        }
        else if (smb1Enabled) {
            return "SMBv1";
        }
        else if (smb2Enabled) {
            return "SMBv2/3";
        }
        else {
            return "Unknown";
        }
    }
};

class EternalBlueExploit {
private:
    ScannerConfig config;

public:
    EternalBlueExploit() : config() {}

    // Allow configuration to be set
    void setConfig(const ScannerConfig& cfg) {
        config = cfg;
    }

    std::string Name() const {
        return "EternalBlue SMBv1 (MS17-010)";
    }

    std::string Description() const {
        return "Checks if SMBv1 is enabled and vulnerable to EternalBlue (CVE-2017-0144).";
    }

    ExploitSeverity Severity() const {
        return ExploitSeverity::Critical;
    }

    ExploitResult Run(const std::string& target) {
        // Create result object
        ExploitResult result(false, "Scan not completed", target);

        try {
            // Resolve hostname/IP
            struct sockaddr_storage addr;
            socklen_t addrlen;
            auto [resolved, resolvedIp] = AddressResolver::resolveAddress(target, 445, &addr, &addrlen);

            if (!resolved) {
                result.setError(0, "Failed to resolve address: " + resolvedIp);
                return result;
            }

            // Update target IP if it was resolved from hostname
            if (target != resolvedIp) {
                result.targetIp = resolvedIp;
                result.targetHostname = target;
            }
            else {
                // Try reverse DNS lookup
                std::string hostname = AddressResolver::getHostname(target);
                if (!hostname.empty()) {
                    result.targetHostname = hostname;
                }
            }

            // Create vulnerability details
            auto details = std::make_unique<VulnerabilityDetails>();

            // Create socket
            Socket socket;
            if (!socket.create(addr.ss_family, SOCK_STREAM, IPPROTO_TCP)) {
                int errorCode = Socket::getLastError();
                result.setError(errorCode, "Failed to create socket: " + Socket::getErrorString(errorCode));
                return result;
            }

            // Set socket options
            if (!socket.setTimeout(config)) {
                int errorCode = Socket::getLastError();
                result.setError(errorCode, "Failed to set socket options: " + Socket::getErrorString(errorCode));
                return result;
            }

            // Connect to target
            if (!socket.connect((struct sockaddr*)&addr, addrlen)) {
                int errorCode = Socket::getLastError();
                result.setError(errorCode, "Connection failed: " + Socket::getErrorString(errorCode));
                return result;
            }

            // Check for SMBv1
            auto smb1Packet = SMBProtocol::createSMBv1NegotiatePacket();
            int sent = socket.send(smb1Packet.data(), smb1Packet.size());
            if (sent != static_cast<int>(smb1Packet.size())) {
                int errorCode = Socket::getLastError();
                result.setError(errorCode, "Failed to send SMBv1 probe: " + Socket::getErrorString(errorCode));
                return result;
            }

            // Receive response
            std::vector<uint8_t> response(1024, 0);
            int bytesRead = socket.recv(response.data(), response.size());
            if (bytesRead <= 0) {
                int errorCode = Socket::getLastError();
                result.setError(errorCode, "Failed to receive response: " + Socket::getErrorString(errorCode));
                return result;
            }

            // Resize response to actual bytes received
            response.resize(bytesRead);

            // Check if SMBv1 is enabled
            bool smb1Enabled = SMBProtocol::isSMBv1Enabled(response);
            details->smb1Enabled = smb1Enabled;

            // If SMBv1 is not enabled, try SMBv2
            bool smb2Enabled = false;
            if (!smb1Enabled) {
                // Create new socket for SMB2 check
                Socket smb2Socket;
                if (smb2Socket.create(addr.ss_family, SOCK_STREAM, IPPROTO_TCP) &&
                    smb2Socket.setTimeout(config) &&
                    smb2Socket.connect((struct sockaddr*)&addr, addrlen)) {

                    auto smb2Packet = SMBProtocol::createSMB2NegotiatePacket();
                    sent = smb2Socket.send(smb2Packet.data(), smb2Packet.size());

                    if (sent == static_cast<int>(smb2Packet.size())) {
                        std::vector<uint8_t> smb2Response(1024, 0);
                        bytesRead = smb2Socket.recv(smb2Response.data(), smb2Response.size());

                        if (bytesRead > 0) {
                            smb2Response.resize(bytesRead);
                            smb2Enabled = SMBProtocol::isSMB2Enabled(smb2Response);
                        }
                    }
                }
            }

            // Set SMB version in details
            details->smbVersion = SMBProtocol::detectSMBVersion(smb1Enabled, smb2Enabled);

            // If SMBv1 is enabled and deep inspection is requested, check for MS17-010 vulnerability
            if (smb1Enabled && config.deepInspection) {
                // Create new socket for vulnerability check
                Socket vulnSocket;
                if (vulnSocket.create(addr.ss_family, SOCK_STREAM, IPPROTO_TCP) &&
                    vulnSocket.setTimeout(config) &&
                    vulnSocket.connect((struct sockaddr*)&addr, addrlen)) {

                    // First send SMBv1 negotiate
                    sent = vulnSocket.send(smb1Packet.data(), smb1Packet.size());
                    if (sent == static_cast<int>(smb1Packet.size())) {
                        // Receive and discard negotiate response
                        std::vector<uint8_t> discardResponse(1024, 0);
                        bytesRead = vulnSocket.recv(discardResponse.data(), discardResponse.size());

                        if (bytesRead > 0) {
                            // Now send MS17-010 specific check
                            auto ms17010Packet = SMBProtocol::createMS17010CheckPacket();
                            sent = vulnSocket.send(ms17010Packet.data(), ms17010Packet.size());

                            if (sent == static_cast<int>(ms17010Packet.size())) {
                                std::vector<uint8_t> vulnResponse(1024, 0);
                                bytesRead = vulnSocket.recv(vulnResponse.data(), vulnResponse.size());

                                if (bytesRead > 0) {
                                    vulnResponse.resize(bytesRead);

                                    // Check for vulnerability signature
                                    if (SMBProtocol::isVulnerableToMS17010(vulnResponse)) {
                                        details->potentiallyVulnerable = true;
                                        details->addVulnerability("MS17-010 (EternalBlue)");
                                    }

                                    // Try to detect OS version if requested
                                    if (config.detectOSVersion) {
                                        details->osVersion = SMBProtocol::detectWindowsVersion(vulnResponse);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Set result based on findings
            if (smb1Enabled) {
                if (details->potentiallyVulnerable) {
                    result.success = true;
                    result.message = "SMBv1 is enabled and the system appears to be VULNERABLE to MS17-010 (EternalBlue)";
                }
                else {
                    result.success = false;
                    result.message = "SMBv1 is enabled but the system does not appear to be vulnerable to MS17-010";
                }
            }
            else {
                result.success = false;
                result.message = "SMBv1 is not enabled - system is not vulnerable to EternalBlue";
            }

            // Set vulnerability details in result
            result.setVulnerabilityDetails(std::move(details));

            return result;
        }
        catch (const std::exception& ex) {
            result.setError(0, std::string("Exception during scan: ") + ex.what());
            return result;
        }
    }
};

// EternalBlueDetector implementation for the IModule interface
ModuleResult EternalBlueDetector::run(const MockTarget& target) {
    // Check if target has SMB service
    if (!target.isServiceOpen("SMB")) {
        return ModuleResult{
            "EternalBlueDetector",
            false,
            "SMB service not available on target",
            std::nullopt,
            Severity::Low,
            target.id()
        };
    }

    // Create EternalBlueExploit instance
    EternalBlueExploit exploit;
    ScannerConfig config;
    config.setDeepInspection(true);
    config.setDetectOSVersion(true);
    exploit.setConfig(config);

    // Get target IP (use mock IP if available, otherwise use target ID)
    std::string targetIp = target.id();
    if (target.ip().has_value()) {
        targetIp = target.ip().value();
    }

    try {
        // Run the exploit scan
        ExploitResult result = exploit.Run(targetIp);

        // Convert ExploitResult to ModuleResult
        Severity severity = Severity::Low;
        if (result.severity == ExploitSeverity::Medium) {
            severity = Severity::Medium;
        } else if (result.severity == ExploitSeverity::High) {
            severity = Severity::High;
        } else if (result.severity == ExploitSeverity::Critical) {
            severity = Severity::Critical;
        }

        std::optional<std::string> details = std::nullopt;
        if (result.details) {
            details = result.details->toString();
        }

        return ModuleResult{
            "EternalBlueDetector",
            result.success,
            result.message,
            details,
            severity,
            target.id()
        };
    }
    catch (const std::exception& ex) {
        return ModuleResult{
            "EternalBlueDetector",
            false,
            std::string("Exception during scan: ") + ex.what(),
            std::nullopt,
            Severity::Low,
            target.id()
        };
    }
}

// Example usage (commented out to avoid multiple main functions)
/*
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <target_ip_or_hostname> [connect_timeout_ms] [send_timeout_ms] [recv_timeout_ms]" << std::endl;
        return 1;
    }

    std::string target = argv[1];

    // Create scanner with custom configuration if provided
    ScannerConfig config;
    if (argc > 2) config.setConnectTimeout(std::stoi(argv[2]));
    if (argc > 3) config.setSendTimeout(std::stoi(argv[3]));
    if (argc > 4) config.setRecvTimeout(std::stoi(argv[4]));

    EternalBlueExploit exploit;
    exploit.setConfig(config);

    std::cout << "Scanning " << target << " for " << exploit.Name() << " vulnerability..." << std::endl;

    ExploitResult result = exploit.Run(target);

    std::cout << "\
Scan Results:\
" << result.toString() << std::endl;

    return 0;
}
*/
