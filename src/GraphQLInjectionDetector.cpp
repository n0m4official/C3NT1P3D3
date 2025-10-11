#include "../include/GraphQLInjectionDetector.h"
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

std::vector<std::string> GraphQLInjectionDetector::getGraphQLEndpoints() {
    return {
        "/graphql",
        "/api/graphql",
        "/v1/graphql",
        "/query",
        "/api/query"
    };
}

std::string GraphQLInjectionDetector::sendGraphQLQuery(const std::string& target, const std::string& query) {
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

    // Try multiple GraphQL endpoints
    std::string response;
    for (const auto& endpoint : getGraphQLEndpoints()) {
        std::string jsonQuery = R"({"query":")" + query + R"("})";
        
        std::ostringstream request;
        request << "POST " << endpoint << " HTTP/1.1\r\n"
                << "Host: " << host << "\r\n"
                << "Content-Type: application/json\r\n"
                << "Content-Length: " << jsonQuery.length() << "\r\n"
                << "User-Agent: C3NT1P3D3-Scanner/2.0\r\n"
                << "Accept: */*\r\n"
                << "Connection: close\r\n\r\n"
                << jsonQuery;

        std::string req = request.str();
        send(sock, req.c_str(), req.length(), 0);

        char buffer[8192];
        int bytesReceived;
        while ((bytesReceived = recv(sock, buffer, sizeof(buffer) - 1, 0)) > 0) {
            buffer[bytesReceived] = '\0';
            response += buffer;
        }

        if (!response.empty() && response.find("200 OK") != std::string::npos) {
            break;
        }
    }

    closesocket(sock);
#ifdef _WIN32
    WSACleanup();
#endif

    return response;
}

bool GraphQLInjectionDetector::containsSchemaInfo(const std::string& response) {
    std::vector<std::string> schemaIndicators = {
        "__schema",
        "__type",
        "queryType",
        "mutationType",
        "subscriptionType",
        "types",
        "directives",
        "fields",
        "args",
        "kind",
        "ofType"
    };

    for (const auto& indicator : schemaIndicators) {
        if (response.find(indicator) != std::string::npos) {
            return true;
        }
    }

    return false;
}

bool GraphQLInjectionDetector::testIntrospection(const std::string& target) {
    // Standard GraphQL introspection query
    std::string introspectionQuery = R"(
        query IntrospectionQuery {
            __schema {
                queryType { name }
                mutationType { name }
                subscriptionType { name }
                types {
                    name
                    kind
                    description
                    fields {
                        name
                        description
                        args {
                            name
                            description
                            type { name kind ofType { name kind } }
                        }
                    }
                }
            }
        }
    )";

    // Remove newlines and extra spaces
    introspectionQuery.erase(std::remove(introspectionQuery.begin(), introspectionQuery.end(), '\n'), introspectionQuery.end());
    
    std::string response = sendGraphQLQuery(target, introspectionQuery);
    
    return containsSchemaInfo(response);
}

bool GraphQLInjectionDetector::testBatchQuery(const std::string& target) {
    // Batch query attack - multiple queries in one request
    std::string batchQuery = R"([
        {"query":"{ __typename }"},
        {"query":"{ __typename }"},
        {"query":"{ __typename }"},
        {"query":"{ __typename }"},
        {"query":"{ __typename }"}
    ])";

    std::string response = sendGraphQLQuery(target, batchQuery);
    
    // Check if server accepts batch queries
    return response.find("200 OK") != std::string::npos &&
           response.find("__typename") != std::string::npos;
}

bool GraphQLInjectionDetector::testDepthAttack(const std::string& target) {
    // Deep nested query (potential DoS)
    std::string deepQuery = R"(
        query {
            user {
                posts {
                    comments {
                        author {
                            posts {
                                comments {
                                    author {
                                        posts {
                                            comments {
                                                author { id }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    )";

    deepQuery.erase(std::remove(deepQuery.begin(), deepQuery.end(), '\n'), deepQuery.end());
    
    auto startTime = std::chrono::steady_clock::now();
    std::string response = sendGraphQLQuery(target, deepQuery);
    auto endTime = std::chrono::steady_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
    
    // If query takes long time or succeeds, depth limiting may be missing
    return (duration.count() > 3000) || 
           (response.find("200 OK") != std::string::npos && 
            response.find("depth") == std::string::npos);
}

ModuleResult GraphQLInjectionDetector::run(const MockTarget& target) {
    ModuleResult result;
    result.id = "GraphQLInjectionDetector";
    result.targetId = target.id();
    result.success = false;
    result.severity = Severity::Low;

    std::vector<std::string> vulnerabilityEvidence;

    // Test 1: Introspection enabled
    if (testIntrospection(target.id())) {
        result.success = true;
        result.severity = Severity::Medium;
        vulnerabilityEvidence.push_back(
            "GraphQL introspection is enabled - full schema disclosure"
        );
        vulnerabilityEvidence.push_back(
            "Attacker can enumerate all queries, mutations, and types"
        );
        vulnerabilityEvidence.push_back(
            "Recommendation: Disable introspection in production"
        );
    }

    // Test 2: Batch query attacks
    if (testBatchQuery(target.id())) {
        result.success = true;
        if (result.severity == Severity::Low) {
            result.severity = Severity::Medium;
        }
        vulnerabilityEvidence.push_back(
            "GraphQL accepts batch queries - potential for amplification attacks"
        );
        vulnerabilityEvidence.push_back(
            "Attacker can send multiple queries in single request"
        );
    }

    // Test 3: Depth-based DoS
    if (testDepthAttack(target.id())) {
        result.success = true;
        result.severity = Severity::High;
        vulnerabilityEvidence.push_back(
            "GraphQL lacks depth limiting - vulnerable to DoS attacks"
        );
        vulnerabilityEvidence.push_back(
            "Deep nested queries can exhaust server resources"
        );
        vulnerabilityEvidence.push_back(
            "Recommendation: Implement query depth and complexity limits"
        );
    }

    // Test for common GraphQL endpoints
    bool graphqlDetected = false;
    for (const auto& endpoint : getGraphQLEndpoints()) {
        std::string testQuery = "{ __typename }";
        std::string response = sendGraphQLQuery(target.id(), testQuery);
        
        if (response.find("200 OK") != std::string::npos) {
            graphqlDetected = true;
            vulnerabilityEvidence.push_back(
                "GraphQL endpoint detected: " + endpoint
            );
            break;
        }
    }

    if (result.success) {
        result.message = "GraphQL vulnerabilities detected";
        result.details = "GraphQL vulnerabilities detected. API exposes sensitive schema information and lacks proper query complexity controls, enabling reconnaissance and DoS attacks.\n\nEvidence:\n";
        for (const auto& evidence : vulnerabilityEvidence) {
            result.details = result.details.value() + "- " + evidence + "\n";
        }
    } else if (graphqlDetected) {
        result.message = "GraphQL endpoint detected";
        result.details = "GraphQL endpoint detected but appears properly secured with introspection disabled and query limits in place.";
    } else {
        result.message = "No GraphQL endpoints detected";
        result.details = "No GraphQL endpoints detected or accessible.";
    }

    return result;
}
