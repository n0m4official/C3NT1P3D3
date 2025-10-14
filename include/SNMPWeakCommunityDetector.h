#pragma once
#include "IModule.h"
#include <string>

class SNMPWeakCommunityDetector : public IModule {
public:
    std::string id() const override {
        return "SNMPWeakCommunityDetector";
    }

    ModuleResult run(const MockTarget& target) override;
};
