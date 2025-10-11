#include "../include/CORSDetector.h"
#include "../include/mitre/AttackMapper.h"
#include <sstream>
#include <algorithm>
#include <chrono>

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

std::vector<CORSDetector::CORSTest> CORSDetector::getCORSTests() {
    return {
        {"Null Origin", "null", "Null origin accepted with credentials"},
        {"Arbitrary Origin", "https://evil.com", "Arbitrary origin reflected"},
        {"Subdomain Wildcard", "https://evil.target.com", "Subdomain not validated"},
        {"HTTP Downgrade", "http://target.com", "Insecure protocol allowed"},
        {"Localhost", "http://localhost", "Localhost origin accepted"},
        {"File Protocol", "file://", "File protocol allowed"},
        {"Wildcard with Credentials", "*", "Wildcard with credentials enabled"}
    };
}

std::string CORSDetector::extractHeader(const std::string& response, const std::string& headerName) {
    std::string lowerResponse = response;
    std::string lowerHeader = headerName;
    std::transform(lowerResponse.begin(), lowerResponse.end(), lowerResponse.begin(), ::tolower);
    std::transform(lowerHeader.begin(), lowerHeader.end(), lowerHeader.begin(), ::tolower);

    size_t pos = lowerResponse.find(lowerHeader + ":");
    if (pos != std::string::npos) {
        size_t start = pos + lowerHeader.length() + 1;
        size_t end = response.find("\r\n", start);
        if (end != std::string::npos) {
            std::string value = response.substr(start, end - start);
            // Trim whitespace
            value.erase(0, value.find_first_not_of(" \t"));
            value.erase(value.find_last_not_of(" \t") + 1);
            return value;
        }
    }
    return "";
}

std::map<std::string, std::string> CORSDetector::sendCORSRequest(const std::string& target, 
                                                                  const std::string& origin) {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return {};
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
        return {};
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
        return {};
    }

    // Send CORS preflight request
    std::ostringstream request;
    request << "OPTIONS /api/data HTTP/1.1\r\n"
            << "Host: " << host << "\r\n"
            << "Origin: " << origin << "\r\n"
            << "Access-Control-Request-Method: POST\r\n"
            << "Access-Control-Request-Headers: Content-Type\r\n"
            << "User-Agent: C3NT1P3D3-Scanner/2.0\r\n"
            << "Accept: */*\r\n"
            << "Connection: close\r\n\r\n";

    std::string req = request.str();
    send(sock, req.c_str(), req.length(), 0);

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

    // Parse CORS headers
    std::map<std::string, std::string> headers;
    headers["Access-Control-Allow-Origin"] = extractHeader(response, "Access-Control-Allow-Origin");
    headers["Access-Control-Allow-Credentials"] = extractHeader(response, "Access-Control-Allow-Credentials");
    headers["Access-Control-Allow-Methods"] = extractHeader(response, "Access-Control-Allow-Methods");
    headers["Access-Control-Allow-Headers"] = extractHeader(response, "Access-Control-Allow-Headers");
    headers["Access-Control-Max-Age"] = extractHeader(response, "Access-Control-Max-Age");

    return headers;
}

bool CORSDetector::isVulnerableConfiguration(const std::map<std::string, std::string>& headers, 
                                             const std::string& origin) {
    auto allowOrigin = headers.find("Access-Control-Allow-Origin");
    auto allowCredentials = headers.find("Access-Control-Allow-Credentials");

    if (allowOrigin == headers.end() || allowOrigin->second.empty()) {
        return false;
    }

    std::string allowOriginValue = allowOrigin->second;
    std::string credentialsValue = (allowCredentials != headers.end()) ? 
                                   allowCredentials->second : "";

    // Vulnerability 1: Wildcard with credentials
    if (allowOriginValue == "*" && credentialsValue == "true") {
        return true;
    }

    // Vulnerability 2: Null origin accepted
    if (origin == "null" && allowOriginValue == "null") {
        return true;
    }

    // Vulnerability 3: Arbitrary origin reflected
    if (allowOriginValue == origin && origin.find("evil") != std::string::npos) {
        return true;
    }

    // Vulnerability 4: Insecure protocol allowed
    if (origin.find("http://") == 0 && allowOriginValue == origin) {
        return true;
    }

    // Vulnerability 5: File protocol allowed
    if (origin.find("file://") == 0 && allowOriginValue == origin) {
        return true;
    }

    return false;
}

ModuleResult CORSDetector::run(const MockTarget& target) {
    ModuleResult result;
    result.id = "CORSDetector";
    result.targetId = target.id();
    result.success = false;
    result.severity = Severity::Low;

    std::vector<std::string> vulnerabilityEvidence;

    auto tests = getCORSTests();

    for (const auto& test : tests) {
        auto headers = sendCORSRequest(target.id(), test.origin);

        if (isVulnerableConfiguration(headers, test.origin)) {
            result.success = true;
            result.severity = Severity::High;

            vulnerabilityEvidence.push_back(
                "CORS Misconfiguration: " + test.name
            );
            vulnerabilityEvidence.push_back(
                "Vulnerability: " + test.expectedVulnerability
            );
            vulnerabilityEvidence.push_back(
                "Origin tested: " + test.origin
            );

            // Add header details
            for (const auto& header : headers) {
                if (!header.second.empty()) {
                    vulnerabilityEvidence.push_back(
                        header.first + ": " + header.second
                    );
                }
            }
        }
    }

    // Additional check: Overly permissive CORS
    auto defaultHeaders = sendCORSRequest(target.id(), "https://example.com");
    auto allowOrigin = defaultHeaders.find("Access-Control-Allow-Origin");
    
    if (allowOrigin != defaultHeaders.end()) {
        if (allowOrigin->second == "*") {
            result.success = true;
            if (result.severity == Severity::Low) {
                result.severity = Severity::Medium;
            }
            vulnerabilityEvidence.push_back(
                "CORS allows all origins (wildcard *)"
            );
            vulnerabilityEvidence.push_back(
                "Any website can read responses from this API"
            );
        }
    }

    if (result.success) {
        result.message = "CORS misconfiguration detected";
        result.details = "CORS misconfiguration detected. Application allows unauthorized cross-origin requests, enabling attackers to steal sensitive data from authenticated users.\n\nEvidence:\n";
        for (const auto& evidence : vulnerabilityEvidence) {
            result.details = result.details.value() + "- " + evidence + "\n";
        }
    } else {
        result.message = "No CORS misconfigurations detected";
        result.details = "No CORS misconfigurations detected. Cross-origin policy appears properly configured.";
    }

    return result;
}
