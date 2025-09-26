#pragma once
#include "IModule.h"
#include <vector>
#include <memory>

class ModuleManager {
public:
    void registerModule(std::shared_ptr<IModule> module);
    void runAll(const std::vector<MockTarget>& targets);

private:
    std::vector<std::shared_ptr<IModule>> modules;
};
