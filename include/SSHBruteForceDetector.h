#pragma once
#include "IModule.h"
#include <string>

class SSHBruteForceDetector : public IModule {
public:
    std::string id() const override {
        return "SSHBruteForceDetector";
    }

    ModuleResult run(const MockTarget& target) override;
};