#pragma once
#include "IModule.h"
#include <string>

class XPathInjectionDetector : public IModule {
public:
    std::string id() const override {
        return "XPathInjectionDetector";
    }

    ModuleResult run(const MockTarget& target) override;
};
