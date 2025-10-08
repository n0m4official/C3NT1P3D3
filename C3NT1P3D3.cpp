#include <iostream>
#include "EternalBlueDetector.h"
#include "BlueKeepDetector.h"
#include "HeartbleedDetector.h"
#include "ShellshockDetector.h"
#include "SSHBruteForceDetector.h"
#include "SQLInjectionDetector.h"
#include "MockTarget.h"
#include "ModuleManager.h"

int main() {
    std::cout << "=== C3NT1P3D3 Advanced Vulnerability Scanner ===" << std::endl;
    std::cout << "Scanning for multiple vulnerabilities..." << std::endl << std::endl;

    // Create multiple targets with different services
    MockTarget windowsServer("windows-server", "192.168.1.100");
    windowsServer.addService("SMB", 445, true);
    windowsServer.addService("RDP", 3389, true);
    windowsServer.addService("HTTPS", 443, true);

    MockTarget linuxWebServer("linux-web-server", "192.168.1.101");
    linuxWebServer.addService("HTTP", 80, true);
    linuxWebServer.addService("HTTPS", 443, true);
    linuxWebServer.addService("SSH", 22, true);

    MockTarget databaseServer("database-server", "192.168.1.102");
    databaseServer.addService("HTTP", 80, true);
    databaseServer.addService("HTTPS", 443, true);

    MockTarget vulnerableApp("vulnerable-app", "192.168.1.103");
    vulnerableApp.addService("HTTP", 80, true);
    vulnerableApp.addService("HTTPS", 443, true);
    vulnerableApp.addService("SSH", 22, true);

    // Create module manager
    ModuleManager moduleManager;

    // Register all vulnerability detection modules
    moduleManager.registerModule(std::make_shared<EternalBlueDetector>());
    moduleManager.registerModule(std::make_shared<BlueKeepDetector>());
    moduleManager.registerModule(std::make_shared<HeartbleedDetector>());
    moduleManager.registerModule(std::make_shared<ShellshockDetector>());
    moduleManager.registerModule(std::make_shared<SSHBruteForceDetector>());
    moduleManager.registerModule(std::make_shared<SQLInjectionDetector>());

    // Create vector of targets
    std::vector<MockTarget> targets = {
        windowsServer,
        linuxWebServer,
        databaseServer,
        vulnerableApp
    };

    std::cout << "Targets to scan:" << std::endl;
    for (const auto& target : targets) {
        std::cout << "- " << target.id();
        if (target.ip().has_value()) {
            std::cout << " (" << target.ip().value() << ")";
        }
        std::cout << std::endl;
        
        std::cout << "  Open services: ";
        auto services = target.listOpenServices();
        for (size_t i = 0; i < services.size(); ++i) {
            std::cout << services[i];
            if (i < services.size() - 1) std::cout << ", ";
        }
        std::cout << std::endl << std::endl;
    }

    std::cout << "Starting vulnerability scan..." << std::endl;
    std::cout << "================================================" << std::endl << std::endl;

    // Run all modules against all targets
    moduleManager.runAll(targets);

    std::cout << "================================================" << std::endl;
    std::cout << "Scan completed!" << std::endl;
    std::cout << "C3NT1P3D3 has checked for:" << std::endl;
    std::cout << "- EternalBlue (MS17-010)" << std::endl;
    std::cout << "- BlueKeep (CVE-2019-0708)" << std::endl;
    std::cout << "- Heartbleed (CVE-2014-0160)" << std::endl;
    std::cout << "- Shellshock (CVE-2014-6271)" << std::endl;
    std::cout << "- SSH Brute Force vulnerabilities" << std::endl;
    std::cout << "- SQL Injection vulnerabilities" << std::endl;
    std::cout << std::endl;
    std::cout << "For more detailed analysis, consider running individual modules." << std::endl;

    return 0;
}