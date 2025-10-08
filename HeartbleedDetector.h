#pragma once
#include "IModule.h"
#include <string>

class HeartbleedDetector : public IModule {
public:
    std::string id() const override {
        return "HeartbleedDetector";
    }

    ModuleResult run(const MockTarget& target) override;
};