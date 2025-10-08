#pragma once
#include "IModule.h"
#include <string>

class Log4ShellDetector : public IModule {
public:
    std::string id() const override {
        return "Log4ShellDetector";
    }

    ModuleResult run(const MockTarget& target) override;
};