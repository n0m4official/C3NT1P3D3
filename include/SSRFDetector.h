#pragma once
#include "IModule.h"
#include <string>

/**
 * @brief SSRF (Server-Side Request Forgery) Vulnerability Detector
 * 
 * Detects SSRF vulnerabilities that allow attackers to:
 * - Access internal network resources
 * - Read cloud metadata (AWS, Azure, GCP)
 * - Port scanning internal networks
 * - Bypass firewalls and access controls
 * 
 * MITRE ATT&CK: T1190 (Exploit Public-Facing Application)
 */
class SSRFDetector : public IModule {
public:
    std::string id() const override {
        return "SSRFDetector";
    }

    ModuleResult run(const MockTarget& target) override;
};
