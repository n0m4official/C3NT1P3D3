#pragma once
#include "IModule.h"
#include <string>

class DirectoryTraversalDetector : public IModule {
public:
    std::string id() const override {
        return "DirectoryTraversalDetector";
    }

    ModuleResult run(const MockTarget& target) override;
};