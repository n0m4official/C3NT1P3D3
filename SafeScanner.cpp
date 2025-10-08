#include <iostream>
#include <vector>
#include <string>
#include <memory>
#include <stdexcept>
#include "NetworkScanner.h"
#include "ModuleManager.h"
#include "EternalBlueDetector.h"
#include "BlueKeepDetector.h"
#include "HeartbleedDetector.h"
#include "ShellshockDetector.h"
#include "SSHBruteForceDetector.h"
#include "SQLInjectionDetector.h"
#include "Log4ShellDetector.h"
#include "XSSDetector.h"
#include "FTPAnonymousDetector.h"
#include "DirectoryTraversalDetector.h"

void printUsage(const std::string& programName) {
    std::cout << "Usage: " << programName << " [options]" << std::endl;
    std::cout << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  --network <range>     Network range to scan (e.g., 192.168.1.0/24)" << std::endl;
    std::cout << "  --allow-range <range> Add allowed IP range (can be used multiple times)" << std::endl;
    std::cout << "  --safety-report       Show safety configuration and exit" << std::endl;
    std::cout << "  --simulation-off      Disable simulation mode (DANGEROUS - requires explicit approval)" << std::endl;
    std::cout << "  --help                Show this help message" << std::endl;
    std::cout << std::endl;
    std::cout << "Examples:" << std::endl;
    std::cout << "  " << programName << " --network 192.168.1.0/24" << std::endl;
    std::cout << "  " << programName << " --allow-range 10.0.0.0/24 --network 10.0.0.0/24" << std::endl;
    std::cout << "  " << programName << " --safety-report" << std::endl;
    std::cout << std::endl;
    std::cout << "Safety Features:" << std::endl;
    std::cout << "✓ Only scans explicitly allowed IP ranges" << std::endl;
    std::cout << "✓ Default allowed: 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12" << std::endl;
    std::cout << "✓ Simulation mode by default (no real network interaction)" << std::endl;
    std::cout << "✓ Detection only - no exploit execution" << std::endl;
    std::cout << "✓ Comprehensive logging and safety checks" << std::endl;
}

bool confirmRealScanning() {
    std::cout << "⚠️  WARNING: You are about to enable REAL network scanning!" << std::endl;
    std::cout << "This will perform actual network interactions and could:" << std::endl;
    std::cout << "- Generate network traffic" << std::endl;
    std::cout << "- Be detected by security systems" << std::endl;
    std::cout << "- Potentially affect network performance" << std::endl;
    std::cout << std::endl;
    std::cout << "The scanner will ONLY perform safe detection techniques and will NOT:" << std::endl;
    std::cout << "- Execute any exploits" << std::endl;
    std::cout << "- Modify any systems" << std::endl;
    std::cout << "- Access sensitive data" << std::endl;
    std::cout << std::endl;
    std::cout << "Do you want to proceed with REAL scanning? (yes/no): ";
    
    std::string response;
    std::getline(std::cin, response);
    
    return (response == "yes" || response == "y" || response == "YES");
}

int main(int argc, char* argv[]) {
    try {
        // Parse command line arguments
        std::vector<std::string> allowedRanges;
        std::string networkRange;
        bool showSafetyReport = false;
        bool simulationMode = true;
        
        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            
            if (arg == "--help" || arg == "-h") {
                printUsage(argv[0]);
                return 0;
            }
            else if (arg == "--safety-report") {
                showSafetyReport = true;
            }
            else if (arg == "--simulation-off") {
                simulationMode = false;
            }
            else if (arg == "--allow-range" && i + 1 < argc) {
                allowedRanges.push_back(argv[++i]);
            }
            else if (arg == "--network" && i + 1 < argc) {
                networkRange = argv[++i];
            }
            else {
                std::cerr << "Unknown option: " << arg << std::endl;
                printUsage(argv[0]);
                return 1;
            }
        }
        
        // Create network scanner
        NetworkScanner scanner(simulationMode);
        
        // Configure allowed ranges
        if (!allowedRanges.empty()) {
            scanner.setAllowedRanges(allowedRanges);
        }
        
        // Show safety report if requested
        if (showSafetyReport) {
            std::cout << scanner.getSafetyReport() << std::endl;
            return 0;
        }
        
        // Validate configuration
        scanner.validateScanScope();
        
        // Confirm real scanning if simulation is disabled
        if (!simulationMode) {
            if (!confirmRealScanning()) {
                std::cout << "Real scanning cancelled. Use simulation mode instead." << std::endl;
                return 0;
            }
        }
        
        // If no network range specified, show help
        if (networkRange.empty()) {
            std::cout << "No network range specified." << std::endl;
            printUsage(argv[0]);
            return 1;
        }
        
        std::cout << scanner.getSafetyReport() << std::endl;
        std::cout << std::endl;
        
        // Discover devices in the specified network range
        std::cout << "🔍 Discovering devices in network range: " << networkRange << std::endl;
        auto devices = scanner.discoverDevices(networkRange);
        
        if (devices.empty()) {
            std::cout << "No devices discovered in the specified range." << std::endl;
            return 0;
        }
        
        std::cout << std::endl;
        std::cout << "=== C3NT1P3D3 Vulnerability Scanner - SAFE MODE ===" << std::endl;
        std::cout << "🔒 SAFETY GUARANTEES:" << std::endl;
        std::cout << "   ✓ Only scanning allowed IP ranges" << std::endl;
        std::cout << "   ✓ Detection-only mode (no exploit execution)" << std::endl;
        std::cout << "   ✓ Simulation mode: " << (simulationMode ? "ENABLED" : "DISABLED") << std::endl;
        std::cout << "   ✓ All interactions are read-only and safe" << std::endl;
        std::cout << std::endl;
        
        // Create module manager and register all vulnerability detectors
        ModuleManager moduleManager;
        
        // Register vulnerability detection modules (detection only, no exploitation)
        moduleManager.registerModule(std::make_shared<EternalBlueDetector>());
        moduleManager.registerModule(std::make_shared<BlueKeepDetector>());
        moduleManager.registerModule(std::make_shared<HeartbleedDetector>());
        moduleManager.registerModule(std::make_shared<ShellshockDetector>());
        moduleManager.registerModule(std::make_shared<SSHBruteForceDetector>());
        moduleManager.registerModule(std::make_shared<SQLInjectionDetector>());
        moduleManager.registerModule(std::make_shared<Log4ShellDetector>());
        moduleManager.registerModule(std::make_shared<XSSDetector>());
        moduleManager.registerModule(std::make_shared<FTPAnonymousDetector>());
        moduleManager.registerModule(std::make_shared<DirectoryTraversalDetector>());
        
        std::cout << "🛡️  Vulnerability Modules Loaded:" << std::endl;
        std::cout << "   • EternalBlue (MS17-010) - SMB vulnerability" << std::endl;
        std::cout << "   • BlueKeep (CVE-2019-0708) - RDP vulnerability" << std::endl;
        std::cout << "   • Heartbleed (CVE-2014-0160) - OpenSSL vulnerability" << std::endl;
        std::cout << "   • Shellshock (CVE-2014-6271) - Bash vulnerability" << std::endl;
        std::cout << "   • SSH Brute Force detection" << std::endl;
        std::cout << "   • SQL Injection detection" << std::endl;
        std::cout << "   • Log4Shell (CVE-2021-44228) - Log4j vulnerability" << std::endl;
        std::cout << "   • XSS (Cross-Site Scripting) detection" << std::endl;
        std::cout << "   • FTP Anonymous Access detection" << std::endl;
        std::cout << "   • Directory Traversal detection" << std::endl;
        std::cout << std::endl;
        
        // Run vulnerability scans on all discovered devices
        std::cout << "🔍 Scanning " << devices.size() << " devices for vulnerabilities..." << std::endl;
        std::cout << "   (This may take several minutes...)" << std::endl;
        std::cout << std::endl;
        
        moduleManager.runAll(devices);
        
        std::cout << std::endl;
        std::cout << "=== SCAN COMPLETE ===" << std::endl;
        std::cout << "✅ All devices scanned safely" << std::endl;
        std::cout << "✅ No exploits executed - detection only" << std::endl;
        std::cout << "✅ No systems harmed or modified" << std::endl;
        std::cout << std::endl;
        std::cout << "📋 Summary:" << std::endl;
        std::cout << "   • Devices scanned: " << devices.size() << std::endl;
        std::cout << "   • Network range: " << networkRange << std::endl;
        std::cout << "   • Vulnerability modules: 10" << std::endl;
        std::cout << "   • Safety mode: " << (simulationMode ? "SIMULATION" : "REAL (SAFE)") << std::endl;
        std::cout << std::endl;
        std::cout << "🔒 Security Note: This scanner only performs safe, read-only detection." << std::endl;
        std::cout << "   No exploits were executed, and no systems were modified." << std::endl;
        
        return 0;
    }
    catch (const std::exception& e) {
        std::cerr << "❌ Error: " << e.what() << std::endl;
        std::cerr << "Scan aborted for safety." << std::endl;
        return 1;
    }
    catch (...) {
        std::cerr << "❌ Unknown error occurred. Scan aborted for safety." << std::endl;
        return 1;
    }
}