#include "../include/DeserializationDetector.h"
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

std::string DeserializationDetector::base64Encode(const std::string& input) {
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
    
    while (encoded.size() % 4) {
        encoded.push_back('=');
    }
    
    return encoded;
}

std::vector<DeserializationDetector::SerializationPayload> DeserializationDetector::getPayloads() {
    return {
        // Java - Serialized object magic bytes
        {
            "Java",
            base64Encode("\xac\xed\x00\x05"),  // Java serialization magic
            "application/x-java-serialized-object",
            "java.io.ObjectInputStream"
        },
        
        // Python pickle - Detection payload
        {
            "Python",
            base64Encode("\x80\x03c__builtin__\neval\n"),  // Pickle protocol 3
            "application/python-pickle",
            "pickle.loads"
        },
        
        // PHP - Serialized object
        {
            "PHP",
            base64Encode("O:8:\"stdClass\":0:{}"),  // PHP object serialization
            "application/vnd.php.serialized",
            "unserialize"
        },
        
        // .NET BinaryFormatter
        {
            ".NET",
            base64Encode("\x00\x01\x00\x00\x00\xff\xff\xff\xff"),  // .NET binary format
            "application/x-dotnet-serialized",
            "BinaryFormatter"
        },
        
        // YAML deserialization (Ruby/Python)
        {
            "YAML",
            "!!python/object/apply:os.system ['echo vulnerable']",
            "application/x-yaml",
            "yaml.load"
        }
    };
}

std::string DeserializationDetector::detectFramework(const std::string& target) {
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
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
        return "Unknown";
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
        return "Unknown";
    }

    std::string request = 
        "GET / HTTP/1.1\r\n"
        "Host: " + host + "\r\n"
        "User-Agent: C3NT1P3D3-Scanner/2.0\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n\r\n";

    send(sock, request.c_str(), request.length(), 0);

    char buffer[4096];
    std::string response;
    int bytesReceived = recv(sock, buffer, sizeof(buffer) - 1, 0);
    if (bytesReceived > 0) {
        buffer[bytesReceived] = '\0';
        response = buffer;
    }

    closesocket(sock);
#ifdef _WIN32
    WSACleanup();
#endif

    // Detect framework from headers
    if (response.find("X-Powered-By: PHP") != std::string::npos) {
        return "PHP";
    } else if (response.find("Server: Apache-Coyote") != std::string::npos ||
               response.find("JSESSIONID") != std::string::npos) {
        return "Java";
    } else if (response.find("X-AspNet-Version") != std::string::npos ||
               response.find("X-Powered-By: ASP.NET") != std::string::npos) {
        return ".NET";
    } else if (response.find("Server: Werkzeug") != std::string::npos ||
               response.find("Server: gunicorn") != std::string::npos) {
        return "Python";
    }

    return "Unknown";
}

std::string DeserializationDetector::sendHTTPRequest(const std::string& target, 
                                                     const std::string& payload,
                                                     const std::string& contentType) {
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

    // Test multiple endpoints
    std::vector<std::string> endpoints = {
        "/api/data",
        "/deserialize",
        "/upload",
        "/session"
    };

    std::string response;
    for (const auto& endpoint : endpoints) {
        std::ostringstream request;
        request << "POST " << endpoint << " HTTP/1.1\r\n"
                << "Host: " << host << "\r\n"
                << "Content-Type: " << contentType << "\r\n"
                << "Content-Length: " << payload.length() << "\r\n"
                << "User-Agent: C3NT1P3D3-Scanner/2.0\r\n"
                << "Accept: */*\r\n"
                << "Connection: close\r\n\r\n"
                << payload;

        std::string req = request.str();
        send(sock, req.c_str(), req.length(), 0);

        char buffer[4096];
        int bytesReceived;
        while ((bytesReceived = recv(sock, buffer, sizeof(buffer) - 1, 0)) > 0) {
            buffer[bytesReceived] = '\0';
            response += buffer;
        }

        if (!response.empty()) {
            break;
        }
    }

    closesocket(sock);
#ifdef _WIN32
    WSACleanup();
#endif

    return response;
}

bool DeserializationDetector::containsDeserializationIndicator(const std::string& response, 
                                                               const std::string& indicator) {
    std::vector<std::string> errorPatterns = {
        indicator,
        "deserialization",
        "ClassNotFoundException",
        "InvalidClassException",
        "StreamCorruptedException",
        "pickle",
        "unserialize",
        "ObjectInputStream",
        "BinaryFormatter",
        "yaml.load"
    };

    std::string lowerResponse = response;
    std::transform(lowerResponse.begin(), lowerResponse.end(), lowerResponse.begin(), ::tolower);

    for (const auto& pattern : errorPatterns) {
        std::string lowerPattern = pattern;
        std::transform(lowerPattern.begin(), lowerPattern.end(), lowerPattern.begin(), ::tolower);
        if (lowerResponse.find(lowerPattern) != std::string::npos) {
            return true;
        }
    }

    return false;
}

ModuleResult DeserializationDetector::run(const MockTarget& target) {
    ModuleResult result;
    result.id = "DeserializationDetector";
    result.targetId = target.id();
    result.success = false;
    result.severity = Severity::Low;

    std::vector<std::string> vulnerabilityEvidence;

    // Detect framework
    std::string framework = detectFramework(target.id());
    vulnerabilityEvidence.push_back("Detected framework: " + framework);

    // Test deserialization payloads
    auto payloads = getPayloads();
    
    for (const auto& payload : payloads) {
        // Focus on detected framework or test all
        if (framework != "Unknown" && payload.language != framework) {
            continue;
        }

        std::string response = sendHTTPRequest(target.id(), payload.payload, payload.contentType);
        
        if (containsDeserializationIndicator(response, payload.indicator)) {
            result.success = true;
            result.severity = Severity::Critical;
            vulnerabilityEvidence.push_back(
                "Insecure deserialization detected in " + payload.language + " application"
            );
            vulnerabilityEvidence.push_back(
                "Indicator found: " + payload.indicator
            );
            vulnerabilityEvidence.push_back(
                "Application processes untrusted serialized objects"
            );
        }

        // Check for 500 errors (may indicate deserialization attempt)
        if (response.find("500") != std::string::npos) {
            result.success = true;
            if (result.severity == Severity::Low) {
                result.severity = Severity::High;
            }
            vulnerabilityEvidence.push_back(
                "Server error when processing " + payload.language + " serialized data"
            );
        }
    }

    if (result.success) {
        result.message = "Insecure deserialization vulnerability detected";
        result.details = "Insecure deserialization vulnerability detected. Application deserializes untrusted data, allowing remote code execution through crafted serialized objects.\n\nEvidence:\n";
        for (const auto& evidence : vulnerabilityEvidence) {
            result.details = result.details.value() + "- " + evidence + "\n";
        }
    } else {
        result.message = "No insecure deserialization vulnerabilities detected";
        result.details = "No insecure deserialization vulnerabilities detected. Application appears to properly validate serialized input.";
    }

    return result;
}
