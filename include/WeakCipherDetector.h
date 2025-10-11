#pragma once
#include "IModule.h"
#include <string>

/**
 * @brief Weak SSL/TLS Cipher Suite Detector
 * 
 * Detects weak or deprecated cipher suites that allow:
 * - Man-in-the-middle attacks
 * - Traffic decryption
 * - Downgrade attacks
 * - Protocol vulnerabilities (POODLE, BEAST, etc.)
 * 
 * MITRE ATT&CK: T1040 (Network Sniffing), T1557 (Man-in-the-Middle)
 */
class WeakCipherDetector : public IModule {
public:
    std::string id() const override {
        return "WeakCipherDetector";
    }

    ModuleResult run(const MockTarget& target) override;
};
