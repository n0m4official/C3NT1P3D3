#pragma once
#include "IModule.h"
#include <string>

class BlueKeepDetector : public IModule {
public:
    std::string id() const override {
        return "BlueKeepDetector";
    }

    ModuleResult run(const MockTarget& target) override;
};