#pragma once
#include "VulnerabilityScanner.h"
#include <string>

// API Rate Limiting Bypass Detector
// Detects missing or bypassable rate limiting on APIs
// MITRE ATT&CK: T1499 - Endpoint Denial of Service
class APIRateLimitDetector : public VulnerabilityScanner {
public:
    APIRateLimitDetector();
    ~APIRateLimitDetector() override = default;

    ScanResult scan(const std::string& target, int port) override;
    std::string getName() const override { return "API Rate Limiting Bypass"; }
    std::string getDescription() const override {
        return "Detects missing or bypassable rate limiting on APIs";
    }

private:
    bool testMissingRateLimit(const std::string& target, int port);
    bool testHeaderBypass(const std::string& target, int port);
    bool testIPSpoofing(const std::string& target, int port);
    bool testUserAgentBypass(const std::string& target, int port);
};
