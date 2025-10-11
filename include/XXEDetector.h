#pragma once
#include "IModule.h"
#include <string>

/**
 * @brief XXE (XML External Entity) Vulnerability Detector
 * 
 * Detects XML External Entity injection vulnerabilities that can lead to:
 * - Local file disclosure
 * - Server-Side Request Forgery (SSRF)
 * - Denial of Service
 * - Remote Code Execution
 * 
 * MITRE ATT&CK: T1190 (Exploit Public-Facing Application)
 */
class XXEDetector : public IModule {
public:
    std::string id() const override {
        return "XXEDetector";
    }

    ModuleResult run(const MockTarget& target) override;
};
