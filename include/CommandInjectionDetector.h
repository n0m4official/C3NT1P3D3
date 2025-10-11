#pragma once
#include "IModule.h"
#include <string>

/**
 * @brief Command Injection Vulnerability Detector
 * 
 * Detects OS command injection vulnerabilities that allow:
 * - Remote code execution
 * - System compromise
 * - Data exfiltration
 * - Privilege escalation
 * 
 * MITRE ATT&CK: T1059 (Command and Scripting Interpreter)
 */
class CommandInjectionDetector : public IModule {
public:
    std::string id() const override {
        return "CommandInjectionDetector";
    }

    ModuleResult run(const MockTarget& target) override;
};
