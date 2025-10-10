#pragma once
#include "IModule.h"
#include <string>

class ShellshockDetector : public IModule {
public:
    std::string id() const override {
        return "ShellshockDetector";
    }

    ModuleResult run(const MockTarget& target) override;
};