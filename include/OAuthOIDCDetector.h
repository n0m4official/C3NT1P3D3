#pragma once
#include "VulnerabilityScanner.h"
#include <string>

// OAuth/OIDC Vulnerability Detector
// Detects OAuth 2.0 and OpenID Connect implementation flaws
// MITRE ATT&CK: T1550.001 - Use Alternate Authentication Material: Application Access Token
class OAuthOIDCDetector : public VulnerabilityScanner {
public:
    OAuthOIDCDetector();
    ~OAuthOIDCDetector() override = default;

    ScanResult scan(const std::string& target, int port) override;
    std::string getName() const override { return "OAuth/OIDC Vulnerabilities"; }
    std::string getDescription() const override {
        return "Detects OAuth 2.0 and OpenID Connect implementation flaws";
    }

private:
    bool testOpenRedirect(const std::string& target, int port);
    bool testCSRF(const std::string& target, int port);
    bool testTokenLeakage(const std::string& target, int port);
    bool testImplicitFlow(const std::string& target, int port);
    bool testScopeEscalation(const std::string& target, int port);
};
