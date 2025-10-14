#pragma once
#include "IModule.h"
#include <string>

class CSRFDetector : public IModule {
public:
    std::string id() const override {
        return "CSRFDetector";
    }

    ModuleResult run(const MockTarget& target) override;
};
