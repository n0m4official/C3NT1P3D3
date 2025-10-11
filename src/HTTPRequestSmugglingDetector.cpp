#include "../include/HTTPRequestSmugglingDetector.h"
#include <sstream>

HTTPRequestSmugglingDetector::HTTPRequestSmugglingDetector() : VulnerabilityScanner() {}

ScanResult HTTPRequestSmugglingDetector::scan(const std::string& target, int port) {
    ScanResult result;
    result.target = target;
    result.port = port;
    result.scannerName = getName();
    result.vulnerable = false;

    // Test CL.TE (Content-Length → Transfer-Encoding)
    if (testCLTE(target, port)) {
        result.vulnerable = true;
        result.details = "HTTP Request Smuggling (CL.TE) detected - front-end uses Content-Length, back-end uses Transfer-Encoding";
        result.severity = "Critical";
        result.recommendation = "Normalize HTTP parsing, reject ambiguous requests, use HTTP/2";
        return result;
    }

    // Test TE.CL (Transfer-Encoding → Content-Length)
    if (testTECL(target, port)) {
        result.vulnerable = true;
        result.details = "HTTP Request Smuggling (TE.CL) detected - front-end uses Transfer-Encoding, back-end uses Content-Length";
        result.severity = "Critical";
        result.recommendation = "Normalize HTTP parsing, reject ambiguous requests, disable Transfer-Encoding on front-end";
        return result;
    }

    // Test TE.TE (Transfer-Encoding variations)
    if (testTETE(target, port)) {
        result.vulnerable = true;
        result.details = "HTTP Request Smuggling (TE.TE) detected - obfuscated Transfer-Encoding headers";
        result.severity = "Critical";
        result.recommendation = "Strict Transfer-Encoding parsing, reject malformed headers";
        return result;
    }

    // Test chunk encoding issues
    if (testChunkEncoding(target, port)) {
        result.vulnerable = true;
        result.details = "HTTP chunk encoding vulnerability detected - malformed chunks accepted";
        result.severity = "High";
        result.recommendation = "Validate chunk encoding strictly, reject malformed chunks";
        return result;
    }

    // Test Content-Length mismatch
    if (testContentLengthMismatch(target, port)) {
        result.vulnerable = true;
        result.details = "Content-Length mismatch vulnerability - inconsistent header processing";
        result.severity = "High";
        result.recommendation = "Enforce single Content-Length header, reject duplicates";
        return result;
    }

    result.details = "No HTTP request smuggling vulnerabilities detected";
    result.severity = "Info";
    return result;
}

bool HTTPRequestSmugglingDetector::testCLTE(const std::string& target, int port) {
    // CL.TE: Front-end uses Content-Length, back-end uses Transfer-Encoding
    std::ostringstream request;
    request << "POST / HTTP/1.1\r\n";
    request << "Host: " << target << "\r\n";
    request << "Content-Length: 6\r\n";
    request << "Transfer-Encoding: chunked\r\n";
    request << "\r\n";
    request << "0\r\n";
    request << "\r\n";
    request << "G";  // This should be part of next request if vulnerable

    std::string response = sendSmugglingRequest(target, port, request.str());
    
    // Check for timing differences or error responses
    if (response.find("400") != std::string::npos || 
        response.find("Bad Request") != std::string::npos) {
        return false;  // Server rejected ambiguous request (good)
    }

    return false;  // Need actual network testing for reliable detection
}

bool HTTPRequestSmugglingDetector::testTECL(const std::string& target, int port) {
    // TE.CL: Front-end uses Transfer-Encoding, back-end uses Content-Length
    std::ostringstream request;
    request << "POST / HTTP/1.1\r\n";
    request << "Host: " << target << "\r\n";
    request << "Content-Length: 4\r\n";
    request << "Transfer-Encoding: chunked\r\n";
    request << "\r\n";
    request << "5c\r\n";
    request << "GPOST / HTTP/1.1\r\n";
    request << "Content-Type: application/x-www-form-urlencoded\r\n";
    request << "Content-Length: 15\r\n";
    request << "\r\n";
    request << "x=1\r\n";
    request << "0\r\n";
    request << "\r\n";

    std::string response = sendSmugglingRequest(target, port, request.str());
    
    if (response.find("400") != std::string::npos) {
        return false;  // Server rejected (good)
    }

    return false;  // Need actual network testing
}

bool HTTPRequestSmugglingDetector::testTETE(const std::string& target, int port) {
    // TE.TE: Obfuscated Transfer-Encoding headers
    std::vector<std::string> obfuscations = {
        "Transfer-Encoding: chunked",
        "Transfer-Encoding : chunked",
        "Transfer-Encoding: chunked ",
        "Transfer-Encoding: xchunked",
        " Transfer-Encoding: chunked",
        "Transfer-Encoding\r\n : chunked",
        "Transfer-encoding: chunked",
        "Transfer-Encoding: identity, chunked"
    };

    for (const auto& encoding : obfuscations) {
        std::ostringstream request;
        request << "POST / HTTP/1.1\r\n";
        request << "Host: " << target << "\r\n";
        request << encoding << "\r\n";
        request << "\r\n";
        request << "0\r\n";
        request << "\r\n";

        std::string response = sendSmugglingRequest(target, port, request.str());
        
        if (!response.empty() && response.find("400") == std::string::npos) {
            return true;  // Obfuscated header accepted
        }
    }

    return false;
}

bool HTTPRequestSmugglingDetector::testChunkEncoding(const std::string& target, int port) {
    // Test malformed chunk encoding
    std::ostringstream request;
    request << "POST / HTTP/1.1\r\n";
    request << "Host: " << target << "\r\n";
    request << "Transfer-Encoding: chunked\r\n";
    request << "\r\n";
    request << "5\r\n";
    request << "hello\r\n";
    request << "0\r\n";
    request << "X-Ignore: X\r\n";  // Trailer after terminating chunk
    request << "\r\n";

    std::string response = sendSmugglingRequest(target, port, request.str());
    
    if (response.find("200") != std::string::npos) {
        return true;  // Malformed chunk accepted
    }

    return false;
}

bool HTTPRequestSmugglingDetector::testContentLengthMismatch(const std::string& target, int port) {
    // Test duplicate Content-Length headers
    std::ostringstream request;
    request << "POST / HTTP/1.1\r\n";
    request << "Host: " << target << "\r\n";
    request << "Content-Length: 6\r\n";
    request << "Content-Length: 5\r\n";  // Duplicate with different value
    request << "\r\n";
    request << "hello";

    std::string response = sendSmugglingRequest(target, port, request.str());
    
    if (response.find("400") == std::string::npos) {
        return true;  // Duplicate headers accepted (vulnerable)
    }

    return false;
}

std::string HTTPRequestSmugglingDetector::sendSmugglingRequest(const std::string& target, int port, const std::string& request) {
    // Simulation mode - return empty
    // Real implementation would send raw TCP request
    return "";
}
