#include "../include/ModuleRegistry.h"
#include <algorithm>
#include <iostream>

namespace C3NT1P3D3 {

void ModuleRegistry::registerAllModules() {
    // Clear existing modules
    modules_.clear();
    moduleMap_.clear();
    categoryMap_.clear();

    // Network vulnerabilities
    registerModule(std::make_shared<EternalBlueDetector>(), Category::NETWORK);
    registerModule(std::make_shared<BlueKeepDetector>(), Category::NETWORK);
    registerModule(std::make_shared<SSHBruteForceDetector>(), Category::NETWORK);
    registerModule(std::make_shared<FTPAnonymousDetector>(), Category::NETWORK);

    // Web vulnerabilities
    registerModule(std::make_shared<SQLInjectionDetector>(), Category::WEB);
    registerModule(std::make_shared<XSSDetector>(), Category::WEB);
    registerModule(std::make_shared<DirectoryTraversalDetector>(), Category::WEB);
    registerModule(std::make_shared<Log4ShellDetector>(), Category::WEB);
    registerModule(std::make_shared<XXEDetector>(), Category::WEB);
    registerModule(std::make_shared<SSRFDetector>(), Category::WEB);
    registerModule(std::make_shared<CommandInjectionDetector>(), Category::WEB);
    registerModule(std::make_shared<LDAPInjectionDetector>(), Category::WEB);
    registerModule(std::make_shared<JWTDetector>(), Category::WEB);
    registerModule(std::make_shared<GraphQLInjectionDetector>(), Category::WEB);
    registerModule(std::make_shared<DeserializationDetector>(), Category::WEB);
    registerModule(std::make_shared<CORSDetector>(), Category::WEB);
    registerModule(std::make_shared<SubdomainTakeoverDetector>(), Category::WEB);

    // SSL/TLS vulnerabilities
    registerModule(std::make_shared<HeartbleedDetector>(), Category::SSL_TLS);
    registerModule(std::make_shared<WeakCipherDetector>(), Category::SSL_TLS);

    // System vulnerabilities
    registerModule(std::make_shared<ShellshockDetector>(), Category::SYSTEM);

    std::cout << "✓ Registered " << modules_.size() << " vulnerability detection modules" << std::endl;
}

void ModuleRegistry::registerModule(std::shared_ptr<IModule> module, Category category) {
    if (!module) {
        return;
    }

    modules_.push_back(module);
    moduleMap_[module->id()] = module;
    categoryMap_[category].push_back(module);
}

std::vector<std::shared_ptr<IModule>> ModuleRegistry::getAllModules() const {
    return modules_;
}

std::vector<std::shared_ptr<IModule>> ModuleRegistry::getModulesByCategory(Category category) const {
    if (category == Category::ALL) {
        return getAllModules();
    }

    auto it = categoryMap_.find(category);
    if (it != categoryMap_.end()) {
        return it->second;
    }

    return {};
}

std::shared_ptr<IModule> ModuleRegistry::getModule(const std::string& moduleName) const {
    auto it = moduleMap_.find(moduleName);
    if (it != moduleMap_.end()) {
        return it->second;
    }

    return nullptr;
}

std::vector<ModuleResult> ModuleRegistry::runAllModules(const MockTarget& target) const {
    std::vector<ModuleResult> results;
    results.reserve(modules_.size());

    for (const auto& module : modules_) {
        try {
            auto result = module->run(target);
            results.push_back(result);
        } catch (const std::exception& e) {
            ModuleResult errorResult;
            errorResult.id = module->id();
            errorResult.success = false;
            errorResult.message = std::string("Module execution failed: ") + e.what();
            errorResult.severity = Severity::Low;
            errorResult.targetId = target.id();
            results.push_back(errorResult);
        }
    }

    return results;
}

std::vector<ModuleResult> ModuleRegistry::runModulesByCategory(const MockTarget& target, Category category) const {
    std::vector<ModuleResult> results;
    auto modules = getModulesByCategory(category);

    results.reserve(modules.size());

    for (const auto& module : modules) {
        try {
            auto result = module->run(target);
            results.push_back(result);
        } catch (const std::exception& e) {
            ModuleResult errorResult;
            errorResult.id = module->id();
            errorResult.success = false;
            errorResult.message = std::string("Module execution failed: ") + e.what();
            errorResult.severity = Severity::Low;
            errorResult.targetId = target.id();
            results.push_back(errorResult);
        }
    }

    return results;
}

ModuleRegistry::Statistics ModuleRegistry::getStatistics() const {
    Statistics stats{};
    stats.total_modules = modules_.size();

    auto countCategory = [this](Category cat) -> size_t {
        auto it = categoryMap_.find(cat);
        return (it != categoryMap_.end()) ? it->second.size() : 0;
    };

    stats.network_modules = countCategory(Category::NETWORK);
    stats.web_modules = countCategory(Category::WEB);
    stats.ssl_tls_modules = countCategory(Category::SSL_TLS);
    stats.system_modules = countCategory(Category::SYSTEM);
    stats.database_modules = countCategory(Category::DATABASE);

    return stats;
}

std::vector<std::string> ModuleRegistry::getModuleNames() const {
    std::vector<std::string> names;
    names.reserve(modules_.size());

    for (const auto& module : modules_) {
        names.push_back(module->id());
    }

    return names;
}

} // namespace C3NT1P3D3
