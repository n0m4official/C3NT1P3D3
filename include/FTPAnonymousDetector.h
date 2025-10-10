#pragma once
#include "IModule.h"
#include <string>

class FTPAnonymousDetector : public IModule {
public:
    std::string id() const override {
        return "FTPAnonymousDetector";
    }

    ModuleResult run(const MockTarget& target) override;
};