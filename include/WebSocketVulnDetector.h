#pragma once
#include "VulnerabilityScanner.h"
#include <string>

// WebSocket Vulnerability Detector
// Detects WebSocket security issues: CSWSH, message injection, origin bypass
// MITRE ATT&CK: T1190 - Exploit Public-Facing Application
class WebSocketVulnDetector : public VulnerabilityScanner {
public:
    WebSocketVulnDetector();
    ~WebSocketVulnDetector() override = default;

    ScanResult scan(const std::string& target, int port) override;
    std::string getName() const override { return "WebSocket Vulnerabilities"; }
    std::string getDescription() const override {
        return "Detects WebSocket security issues including CSWSH, message injection, and origin bypass";
    }

private:
    bool testCSWSH(const std::string& target, int port);
    bool testOriginBypass(const std::string& target, int port);
    bool testMessageInjection(const std::string& target, int port);
    bool testAuthBypass(const std::string& target, int port);
};
