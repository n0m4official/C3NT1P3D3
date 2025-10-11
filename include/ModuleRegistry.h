#pragma once

#include "IModule.h"
#include "EternalBlueDetector.h"
#include "HeartbleedDetector.h"
#include "ShellshockDetector.h"
#include "SSHBruteForceDetector.h"
#include "SQLInjectionDetector.h"
#include "XSSDetector.h"
#include "FTPAnonymousDetector.h"
#include "DirectoryTraversalDetector.h"
#include "BlueKeepDetector.h"
#include "Log4ShellDetector.h"
#include "XXEDetector.h"
#include "SSRFDetector.h"
#include "CommandInjectionDetector.h"
#include "WeakCipherDetector.h"
#include "LDAPInjectionDetector.h"
#include "JWTDetector.h"
#include "GraphQLInjectionDetector.h"
#include "DeserializationDetector.h"
#include "CORSDetector.h"
#include "SubdomainTakeoverDetector.h"
#include <memory>
#include <vector>
#include <string>
#include <map>

namespace C3NT1P3D3 {

/**
 * @brief Central registry for all vulnerability detection modules
 * 
 * Manages the lifecycle and execution of all security scanning modules.
 * Provides categorization, filtering, and batch execution capabilities.
 */
class ModuleRegistry {
public:
    enum class Category {
        NETWORK,      // Network-level vulnerabilities (SMB, RDP, SSH)
        WEB,          // Web application vulnerabilities (XSS, SQL Injection)
        SSL_TLS,      // SSL/TLS vulnerabilities (Heartbleed, weak ciphers)
        SYSTEM,       // System-level vulnerabilities (Shellshock)
        DATABASE,     // Database vulnerabilities
        ALL           // All categories
    };

    static ModuleRegistry& getInstance() {
        static ModuleRegistry instance;
        return instance;
    }

    // Delete copy constructor and assignment operator
    ModuleRegistry(const ModuleRegistry&) = delete;
    ModuleRegistry& operator=(const ModuleRegistry&) = delete;

    /**
     * @brief Register all available modules
     */
    void registerAllModules();

    /**
     * @brief Get all registered modules
     */
    std::vector<std::shared_ptr<IModule>> getAllModules() const;

    /**
     * @brief Get modules by category
     */
    std::vector<std::shared_ptr<IModule>> getModulesByCategory(Category category) const;

    /**
     * @brief Get a specific module by name
     */
    std::shared_ptr<IModule> getModule(const std::string& moduleName) const;

    /**
     * @brief Run all modules against a target
     */
    std::vector<ModuleResult> runAllModules(const MockTarget& target) const;

    /**
     * @brief Run modules from a specific category
     */
    std::vector<ModuleResult> runModulesByCategory(const MockTarget& target, Category category) const;

    /**
     * @brief Get module statistics
     */
    struct Statistics {
        size_t total_modules;
        size_t network_modules;
        size_t web_modules;
        size_t ssl_tls_modules;
        size_t system_modules;
        size_t database_modules;
    };

    Statistics getStatistics() const;

    /**
     * @brief Get list of all module names
     */
    std::vector<std::string> getModuleNames() const;

private:
    ModuleRegistry() = default;

    void registerModule(std::shared_ptr<IModule> module, Category category);

    std::vector<std::shared_ptr<IModule>> modules_;
    std::map<std::string, std::shared_ptr<IModule>> moduleMap_;
    std::map<Category, std::vector<std::shared_ptr<IModule>>> categoryMap_;
};

} // namespace C3NT1P3D3
