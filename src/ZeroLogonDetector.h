#pragma once
#include "../include/IModule.h"
#include <string>
#include <memory>

class ZeroLogonDetector : public IModule {
public:
    std::string id() const override { return "ZeroLogonDetector"; }
    Severity severity() const override { return Severity::Critical; }
    
    bool detectVulnerability(const std::string& target);
    ModuleResult run(const MockTarget& target) override;
};
