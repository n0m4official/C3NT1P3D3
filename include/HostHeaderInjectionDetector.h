#pragma once
#include "IModule.h"
#include <string>

class HostHeaderInjectionDetector : public IModule {
public:
    std::string id() const override {
        return "HostHeaderInjectionDetector";
    }

    ModuleResult run(const MockTarget& target) override;
};
