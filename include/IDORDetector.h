#pragma once
#include "IModule.h"
#include <string>

class IDORDetector : public IModule {
public:
    std::string id() const override {
        return "IDORDetector";
    }

    ModuleResult run(const MockTarget& target) override;
};
