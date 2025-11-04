#pragma once
#include "../include/IModule.h"
#include <string>

class DirtyPipeDetector : public IModule {
public:
    std::string id() const override { return "DirtyPipeDetector"; }
    
    bool detectVulnerability();
    ModuleResult run(const MockTarget& target) override;
};
