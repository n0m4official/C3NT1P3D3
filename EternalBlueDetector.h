#pragma once
#include "IModule.h"
#include <string>
#include <optional>

class EternalBlueDetector : public IModule {
public:
    std::string id() const override {
        return "EternalBlueDetector";
    }

    ModuleResult run(const MockTarget& target) override;
};
