#pragma once
#include "../include/IModule.h"
#include "../include/Severity.h"
#include <string>

class Spring4ShellDetector : public IModule {
public:
    std::string id() const override { return "Spring4ShellDetector"; }
    Severity severity() const override { return Severity::Critical; }
    
    bool detectVulnerability(const std::string& url);
    ModuleResult run(const MockTarget& target) override;
};
