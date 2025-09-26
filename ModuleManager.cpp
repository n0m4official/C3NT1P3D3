#include "ModuleManager.h"
#include <iostream>

void ModuleManager::registerModule(std::shared_ptr<IModule> module) {
    modules.push_back(module);
}

void ModuleManager::runAll(const std::vector<MockTarget>& targets) {
    for (auto& module : modules) {
        for (const auto& target : targets) {
            ModuleResult res = module->run(target);
            res.targetId = target.id(); // store target ID in result

            // Print results
            std::cout << "Module: " << module->id() << "\n";
            std::cout << "Target: " << res.targetId << "\n";
            std::cout << "Success: " << (res.success ? "Yes" : "No") << "\n";
            std::cout << "Severity: ";
            switch (res.severity) {
            case Severity::Low: std::cout << "Low"; break;
            case Severity::Medium: std::cout << "Medium"; break;
            case Severity::High: std::cout << "High"; break;
            }
            std::cout << "\n";
            std::cout << "Message: " << res.message << "\n";
            std::cout << "Details: " << (res.details ? *res.details : "None") << "\n\n";
        }
    }
}
