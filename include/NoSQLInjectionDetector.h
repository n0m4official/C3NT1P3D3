#pragma once
#include "VulnerabilityScanner.h"
#include <string>
#include <vector>

// NoSQL Injection Detector
// Detects injection vulnerabilities in MongoDB, CouchDB, Redis, Cassandra, etc.
// MITRE ATT&CK: T1190 - Exploit Public-Facing Application
class NoSQLInjectionDetector : public VulnerabilityScanner {
public:
    NoSQLInjectionDetector();
    ~NoSQLInjectionDetector() override = default;

    ScanResult scan(const std::string& target, int port) override;
    std::string getName() const override { return "NoSQL Injection"; }
    std::string getDescription() const override {
        return "Detects NoSQL injection vulnerabilities in MongoDB, CouchDB, Redis, and other NoSQL databases";
    }

private:
    std::vector<std::string> mongoPayloads;
    std::vector<std::string> couchdbPayloads;
    std::vector<std::string> redisPayloads;

    void initializePayloads();
    bool testMongoDBInjection(const std::string& target, int port);
    bool testCouchDBInjection(const std::string& target, int port);
    bool testRedisInjection(const std::string& target, int port);
    bool testOperatorInjection(const std::string& target, int port);
    bool testJSONInjection(const std::string& target, int port);
    
    std::string sendNoSQLPayload(const std::string& target, int port, const std::string& payload);
};
