#pragma once
#include "IModule.h"
#include <string>

class TelnetCleartextDetector : public IModule {
public:
    std::string id() const override {
        return "TelnetCleartextDetector";
    }

    ModuleResult run(const MockTarget& target) override;
};
