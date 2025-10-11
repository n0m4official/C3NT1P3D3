#pragma once
#include "VulnerabilityScanner.h"
#include <string>
#include <vector>

// HTTP Request Smuggling Detector
// Detects CL.TE, TE.CL, and TE.TE request smuggling vulnerabilities
// MITRE ATT&CK: T1190 - Exploit Public-Facing Application
class HTTPRequestSmugglingDetector : public VulnerabilityScanner {
public:
    HTTPRequestSmugglingDetector();
    ~HTTPRequestSmugglingDetector() override = default;

    ScanResult scan(const std::string& target, int port) override;
    std::string getName() const override { return "HTTP Request Smuggling"; }
    std::string getDescription() const override {
        return "Detects HTTP request smuggling vulnerabilities (CL.TE, TE.CL, TE.TE)";
    }

private:
    bool testCLTE(const std::string& target, int port);
    bool testTECL(const std::string& target, int port);
    bool testTETE(const std::string& target, int port);
    bool testChunkEncoding(const std::string& target, int port);
    bool testContentLengthMismatch(const std::string& target, int port);
    
    std::string sendSmugglingRequest(const std::string& target, int port, const std::string& request);
};
