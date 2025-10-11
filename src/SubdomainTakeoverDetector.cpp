#include "../include/SubdomainTakeoverDetector.h"
#include "../include/mitre/AttackMapper.h"
#include <sstream>
#include <algorithm>
#include <chrono>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
    #pragma comment(lib, "dnsapi.lib")
    #include <windns.h>
#else
    #include <sys/socket.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <netdb.h>
    #include <resolv.h>
    #define SOCKET int
    #define INVALID_SOCKET -1
    #define SOCKET_ERROR -1
    #define closesocket close
#endif

std::vector<SubdomainTakeoverDetector::ServiceFingerprint> SubdomainTakeoverDetector::getServiceFingerprints() {
    return {
        // AWS S3
        {
            "AWS S3",
            {".s3.amazonaws.com", ".s3-website"},
            {"NoSuchBucket", "The specified bucket does not exist"},
            "S3 bucket does not exist - subdomain can be claimed"
        },
        
        // GitHub Pages
        {
            "GitHub Pages",
            {".github.io"},
            {"There isn't a GitHub Pages site here", "404"},
            "GitHub Pages site not found - subdomain can be claimed"
        },
        
        // Heroku
        {
            "Heroku",
            {".herokuapp.com"},
            {"No such app", "herokucdn.com/error-pages/no-such-app.html"},
            "Heroku app does not exist - subdomain can be claimed"
        },
        
        // Azure
        {
            "Azure",
            {".azurewebsites.net", ".cloudapp.azure.com"},
            {"404 Web Site not found", "Error 404"},
            "Azure resource not found - subdomain can be claimed"
        },
        
        // Shopify
        {
            "Shopify",
            {".myshopify.com"},
            {"Sorry, this shop is currently unavailable", "Only one step left!"},
            "Shopify store not configured - subdomain can be claimed"
        },
        
        // Tumblr
        {
            "Tumblr",
            {".tumblr.com"},
            {"Whatever you were looking for doesn't currently exist"},
            "Tumblr blog does not exist - subdomain can be claimed"
        },
        
        // WordPress.com
        {
            "WordPress.com",
            {".wordpress.com"},
            {"Do you want to register"},
            "WordPress site not found - subdomain can be claimed"
        },
        
        // Bitbucket
        {
            "Bitbucket",
            {".bitbucket.io"},
            {"Repository not found"},
            "Bitbucket repository not found - subdomain can be claimed"
        },
        
        // Fastly
        {
            "Fastly",
            {".fastly.net"},
            {"Fastly error: unknown domain"},
            "Fastly service not configured - subdomain can be claimed"
        },
        
        // Ghost
        {
            "Ghost",
            {".ghost.io"},
            {"The thing you were looking for is no longer here"},
            "Ghost blog not found - subdomain can be claimed"
        }
    };
}

std::vector<std::string> SubdomainTakeoverDetector::resolveCNAME(const std::string& domain) {
    std::vector<std::string> cnames;

#ifdef _WIN32
    PDNS_RECORD pDnsRecord = nullptr;
    DNS_STATUS status = DnsQuery_A(
        domain.c_str(),
        DNS_TYPE_CNAME,
        DNS_QUERY_STANDARD,
        nullptr,
        &pDnsRecord,
        nullptr
    );

    if (status == 0 && pDnsRecord) {
        PDNS_RECORD pRecord = pDnsRecord;
        while (pRecord) {
            if (pRecord->wType == DNS_TYPE_CNAME) {
                cnames.push_back(pRecord->Data.CNAME.pNameHost);
            }
            pRecord = pRecord->pNext;
        }
        DnsRecordListFree(pDnsRecord, DnsFreeRecordList);
    }
#else
    // Linux DNS resolution
    unsigned char response[4096];
    int responseLen = res_query(domain.c_str(), ns_c_in, ns_t_cname, response, sizeof(response));
    
    if (responseLen > 0) {
        ns_msg handle;
        if (ns_initparse(response, responseLen, &handle) == 0) {
            int msgCount = ns_msg_count(handle, ns_s_an);
            for (int i = 0; i < msgCount; i++) {
                ns_rr rr;
                if (ns_parserr(&handle, ns_s_an, i, &rr) == 0) {
                    if (ns_rr_type(rr) == ns_t_cname) {
                        char cname[256];
                        if (ns_name_uncompress(ns_msg_base(handle), ns_msg_end(handle),
                                              ns_rr_rdata(rr), cname, sizeof(cname)) > 0) {
                            cnames.push_back(cname);
                        }
                    }
                }
            }
        }
    }
#endif

    return cnames;
}

std::string SubdomainTakeoverDetector::sendHTTPRequest(const std::string& target) {
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
    
    // Resolve hostname to IP
    struct hostent* he = gethostbyname(host.c_str());
    if (he == nullptr) {
        closesocket(sock);
#ifdef _WIN32
        WSACleanup();
#endif
        return "";
    }
    
    memcpy(&serverAddr.sin_addr, he->h_addr_list[0], he->h_length);

    if (connect(sock, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        closesocket(sock);
#ifdef _WIN32
        WSACleanup();
#endif
        return "";
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

bool SubdomainTakeoverDetector::matchesFingerprint(const std::string& cname, 
                                                   const std::string& response,
                                                   const ServiceFingerprint& fingerprint) {
    // Check if CNAME matches service pattern
    bool cnameMatches = false;
    for (const auto& pattern : fingerprint.cnamePatterns) {
        if (cname.find(pattern) != std::string::npos) {
            cnameMatches = true;
            break;
        }
    }

    if (!cnameMatches) {
        return false;
    }

    // Check if response contains vulnerability indicators
    for (const auto& pattern : fingerprint.responsePatterns) {
        if (response.find(pattern) != std::string::npos) {
            return true;
        }
    }

    return false;
}

std::vector<std::string> SubdomainTakeoverDetector::enumerateSubdomains(const std::string& domain) {
    // Common subdomain prefixes
    std::vector<std::string> prefixes = {
        "www", "mail", "ftp", "admin", "blog", "dev", "staging", 
        "test", "api", "cdn", "static", "assets", "app", "portal"
    };

    std::vector<std::string> subdomains;
    for (const auto& prefix : prefixes) {
        subdomains.push_back(prefix + "." + domain);
    }

    return subdomains;
}

ModuleResult SubdomainTakeoverDetector::run(const MockTarget& target) {
    ModuleResult result;
    result.id = "SubdomainTakeoverDetector";
    result.targetId = target.id();
    result.success = false;
    result.severity = Severity::Low;

    std::vector<std::string> vulnerabilityEvidence;

    // Get service fingerprints
    auto fingerprints = getServiceFingerprints();

    // Test main domain and common subdomains
    std::vector<std::string> domainsToTest = {target.id()};
    auto subdomains = enumerateSubdomains(target.id());
    domainsToTest.insert(domainsToTest.end(), subdomains.begin(), subdomains.end());

    for (const auto& domain : domainsToTest) {
        // Resolve CNAME records
        auto cnames = resolveCNAME(domain);

        if (cnames.empty()) {
            continue;  // No CNAME, skip
        }

        vulnerabilityEvidence.push_back("Domain: " + domain);
        for (const auto& cname : cnames) {
            vulnerabilityEvidence.push_back("  CNAME: " + cname);

            // Get HTTP response
            std::string response = sendHTTPRequest(domain);

            // Check against fingerprints
            for (const auto& fingerprint : fingerprints) {
                if (matchesFingerprint(cname, response, fingerprint)) {
                    result.success = true;
                    result.severity = Severity::High;

                    vulnerabilityEvidence.push_back(
                        "  VULNERABLE: " + fingerprint.service
                    );
                    vulnerabilityEvidence.push_back(
                        "  " + fingerprint.vulnerability
                    );
                    vulnerabilityEvidence.push_back(
                        "  Dangling CNAME detected: " + cname
                    );
                }
            }
        }
    }

    if (result.success) {
        result.message = "Subdomain takeover vulnerability detected";
        result.details = "Subdomain takeover vulnerability detected. DNS records point to unclaimed cloud resources, allowing attackers to host malicious content on your subdomain.\n\nEvidence:\n";
        for (const auto& evidence : vulnerabilityEvidence) {
            result.details = result.details.value() + "- " + evidence + "\n";
        }
    } else {
        result.message = "No subdomain takeover vulnerabilities detected";
        result.details = "No subdomain takeover vulnerabilities detected. All DNS records point to active resources.";
    }

    return result;
}
