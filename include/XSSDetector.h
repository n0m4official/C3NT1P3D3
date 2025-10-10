#pragma once
#include "IModule.h"
#include <string>

class XSSDetector : public IModule {
public:
    std::string id() const override {
        return "XSSDetector";
    }

    ModuleResult run(const MockTarget& target) override;
};