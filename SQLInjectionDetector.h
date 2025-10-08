#pragma once
#include "IModule.h"
#include <string>

class SQLInjectionDetector : public IModule {
public:
    std::string id() const override {
        return "SQLInjectionDetector";
    }

    ModuleResult run(const MockTarget& target) override;
};