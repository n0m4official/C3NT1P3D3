#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <ctime>
#include "../include/core/ProductionScanner.h"
#include "../include/core/ConfigurationManager.h"
#include "../include/core/LegalAgreementManager.h"
#include "../include/IPRangeValidator.h"

using namespace C3NT1P3D3;

// Command line options structure
struct CommandLineOptions {
    std::string target_range;
    std::string output_file;
    std::string output_format = "json";
    bool web_only = false;
    bool network_only = false;
    bool ssl_only = false;
    bool cloud_only = false;
    bool list_modules = false;
    bool show_version = false;
    int rate_limit = 100;
    int threads = 10;
    int timeout = 30;
    bool no_strict = false;
    bool verbose = false;
    bool quiet = false;
    bool help = false;
    bool enable_simulation = false;
    std::vector<std::string> exclude_modules;
    std::vector<std::string> include_modules;
};

void printBanner() {
    std::cout << R"(
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ██████╗██████╗ ███╗   ██╗████████╗ ██╗██████╗ ██████╗ ██████╗ ║
║  ██╔════╝╚════██╗████╗  ██║╚══██╔══╝███║██╔══██╗╚════██╗██╔══██╗║
║  ██║      █████╔╝██╔██╗ ██║   ██║   ╚██║██████╔╝ █████╔╝██║  ██║║
║  ██║      ╚═══██╗██║╚██╗██║   ██║    ██║██╔═══╝  ╚═══██╗██║  ██║║
║  ╚██████╗██████╔╝██║ ╚████║   ██║    ██║██║     ██████╔╝██████╔╝║
║   ╚═════╝╚═════╝ ╚═╝  ╚═══╝   ╚═╝    ╚═╝╚═╝     ╚═════╝ ╚═════╝ ║
║                                                               ║
║          Comprehensive Security Scanner v3.2.0                 ║
║          37 Modules | MITRE ATT&CK Integrated                ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
)" << std::endl;
}

void printHelp() {
    std::cout << R"(
Usage: C3NT1P3D3 <target_range> [options]

Target Range:
  192.168.1.0/24    Scan private network (Class C)
  10.0.0.0/8        Scan private network (Class A)
  172.16.0.0/12     Scan private network (Class B)
  127.0.0.1         Scan single host

Options:
  -o, --output FILE         Save results to file (auto-detects format from extension)
  -f, --format FORMAT       Output format: json, xml, txt (default: json)
  
Scanning Modes:
  --web-only                Scan only web vulnerabilities
  --network-only            Scan only network vulnerabilities
  --ssl-only                Scan only SSL/TLS vulnerabilities
  --cloud-only              Scan only cloud/container vulnerabilities
  
Module Control:
  --list-modules            List all available detection modules
  --include MODULE1,MODULE2 Only run specified modules
  --exclude MODULE1,MODULE2 Skip specified modules
  
Performance:
  --rate-limit N            Limit requests per second (default: 100)
  --threads N               Number of scanning threads (default: 10)
  --timeout N               Connection timeout in seconds (default: 30)
  
Output Control:
  -v, --verbose             Enable verbose logging
  -q, --quiet               Minimal output (errors only)
  
Safety:
  --no-strict               Disable strict mode (NOT RECOMMENDED)
  --simulation              Enable simulation mode (safe testing)
  
Information:
  --version                 Show version information
  -h, --help                Show this help message

Examples:
  # Scan local network with default settings
  C3NT1P3D3 192.168.1.0/24

  # Comprehensive scan with JSON output
  C3NT1P3D3 192.168.1.0/24 --output results.json

  # Web-only scan with rate limiting
  C3NT1P3D3 10.0.0.0/8 --web-only --rate-limit 50

  # Network scan with custom threads
  C3NT1P3D3 172.16.0.0/12 --network-only --threads 20

  # Simulation mode (no actual network traffic)
  C3NT1P3D3 192.168.1.0/24 --simulation --output test.json

Safety Features:
  ✓ Automatic IP range validation
  ✓ Private network protection (RFC 1918)
  ✓ Rate limiting to prevent network overload
  ✓ Detection-only methodology (no exploits)
  ✓ Comprehensive audit logging
  ✓ Emergency stop (Ctrl+C)

Legal Notice:
  This tool is for AUTHORIZED security testing only.
  You must have explicit permission to scan any network.
  Unauthorized scanning is illegal and may result in criminal charges.

)" << std::endl;
}

CommandLineOptions parseCommandLine(int argc, char* argv[]) {
    CommandLineOptions options;
    
    if (argc < 2) {
        options.help = true;
        return options;
    }
    
    // First argument is target range
    options.target_range = argv[1];
    
    // Parse remaining options
    for (int i = 2; i < argc; i++) {
        std::string arg = argv[i];
        
        if (arg == "--help" || arg == "-h") {
            options.help = true;
        } else if (arg == "--output" || arg == "-o") {
            if (i + 1 < argc) {
                options.output_file = argv[++i];
                // Auto-detect format from extension
                if (options.output_file.find(".xml") != std::string::npos) {
                    options.output_format = "xml";
                } else if (options.output_file.find(".txt") != std::string::npos) {
                    options.output_format = "txt";
                }
            }
        } else if (arg == "--format" || arg == "-f") {
            if (i + 1 < argc) {
                options.output_format = argv[++i];
            }
        } else if (arg == "--web-only") {
            options.web_only = true;
        } else if (arg == "--network-only") {
            options.network_only = true;
        } else if (arg == "--ssl-only") {
            options.ssl_only = true;
        } else if (arg == "--rate-limit") {
            if (i + 1 < argc) {
                options.rate_limit = std::stoi(argv[++i]);
            }
        } else if (arg == "--threads") {
            if (i + 1 < argc) {
                options.threads = std::stoi(argv[++i]);
            }
        } else if (arg == "--timeout") {
            if (i + 1 < argc) {
                options.timeout = std::stoi(argv[++i]);
            }
        } else if (arg == "--no-strict") {
            options.no_strict = true;
        } else if (arg == "--verbose" || arg == "-v") {
            options.verbose = true;
        } else if (arg == "--simulation" || arg == "--sim") {
            options.enable_simulation = true;
        }
    }
    
    return options;
}

bool validateTargetRange(const std::string& target_range, bool strict_mode) {
    auto& validator = IPRangeValidator::getInstance();
    
    std::cout << "\n🔒 Validating target range: " << target_range << std::endl;
    
    // Check if it's a valid IP or CIDR
    if (!validator.validateIP(target_range) && !validator.validateCIDR(target_range)) {
        std::cerr << "❌ ERROR: Invalid IP address or CIDR notation" << std::endl;
        return false;
    }
    
    // Check if it's a safe range (extract IP from CIDR if needed)
    std::string ip_to_check = target_range;
    size_t slash_pos = target_range.find('/');
    if (slash_pos != std::string::npos) {
        ip_to_check = target_range.substr(0, slash_pos);
    }
    
    if (!validator.isPrivateNetwork(ip_to_check)) {
        std::cout << "⚠️  WARNING: Target is a PUBLIC IP address!" << std::endl;
        
        if (strict_mode) {
            std::cerr << "❌ ERROR: Public IP scanning blocked in strict mode" << std::endl;
            std::cerr << "   Use --no-strict to override (NOT RECOMMENDED)" << std::endl;
            std::cerr << "   Ensure you have explicit authorization!" << std::endl;
            return false;
        }
        
        std::cout << "\n⚠️  LEGAL WARNING ⚠️" << std::endl;
        std::cout << "You are about to scan a PUBLIC IP address." << std::endl;
        std::cout << "Do you have EXPLICIT WRITTEN PERMISSION to scan this target? (yes/no): ";
        
        std::string response;
        std::getline(std::cin, response);
        
        if (response != "yes" && response != "YES" && response != "y") {
            std::cout << "❌ Scan cancelled. Authorization not confirmed." << std::endl;
            return false;
        }
    } else {
        std::cout << "✓ Target is in private IP range (RFC 1918)" << std::endl;
    }
    
    return true;
}

void saveResults(const ProductionScanner::ScanResult& result, const std::string& filename, const std::string& format) {
    std::ofstream outfile(filename);
    if (!outfile.is_open()) {
        std::cerr << "❌ ERROR: Could not open output file: " << filename << std::endl;
        return;
    }
    
    if (format == "json") {
        // Simple JSON output
        outfile << "{\n";
        outfile << "  \"scan_id\": \"" << result.scan_id << "\",\n";
        outfile << "  \"target_range\": \"" << result.target_range << "\",\n";
        outfile << "  \"start_time\": \"" << result.start_time << "\",\n";
        outfile << "  \"end_time\": \"" << result.end_time << "\",\n";
        outfile << "  \"status\": \"" << result.status << "\",\n";
        outfile << "  \"summary\": {\n";
        outfile << "    \"total_targets\": " << result.total_targets_scanned << ",\n";
        outfile << "    \"total_vulnerabilities\": " << result.total_vulnerabilities_found << ",\n";
        outfile << "    \"critical\": " << result.critical_vulnerabilities << ",\n";
        outfile << "    \"high\": " << result.high_vulnerabilities << ",\n";
        outfile << "    \"medium\": " << result.medium_vulnerabilities << ",\n";
        outfile << "    \"low\": " << result.low_vulnerabilities << ",\n";
        outfile << "    \"info\": " << result.info_vulnerabilities << "\n";
        outfile << "  },\n";
        
        if (!result.errors.empty()) {
            outfile << "  \"errors\": [\n";
            for (size_t i = 0; i < result.errors.size(); i++) {
                outfile << "    \"" << result.errors[i] << "\"";
                if (i < result.errors.size() - 1) outfile << ",";
                outfile << "\n";
            }
            outfile << "  ],\n";
        }
        
        if (!result.warnings.empty()) {
            outfile << "  \"warnings\": [\n";
            for (size_t i = 0; i < result.warnings.size(); i++) {
                outfile << "    \"" << result.warnings[i] << "\"";
                if (i < result.warnings.size() - 1) outfile << ",";
                outfile << "\n";
            }
            outfile << "  ],\n";
        }
        
        outfile << "  \"summary_report\": \"" << result.summary_report << "\",\n";
        outfile << "  \"detailed_report\": \"" << result.detailed_report << "\"\n";
        outfile << "}\n";
        
    } else if (format == "xml") {
        // Simple XML output
        outfile << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
        outfile << "<scan_report>\n";
        outfile << "  <scan_id>" << result.scan_id << "</scan_id>\n";
        outfile << "  <target_range>" << result.target_range << "</target_range>\n";
        outfile << "  <start_time>" << result.start_time << "</start_time>\n";
        outfile << "  <end_time>" << result.end_time << "</end_time>\n";
        outfile << "  <status>" << result.status << "</status>\n";
        outfile << "  <summary>\n";
        outfile << "    <total_targets>" << result.total_targets_scanned << "</total_targets>\n";
        outfile << "    <total_vulnerabilities>" << result.total_vulnerabilities_found << "</total_vulnerabilities>\n";
        outfile << "    <critical>" << result.critical_vulnerabilities << "</critical>\n";
        outfile << "    <high>" << result.high_vulnerabilities << "</high>\n";
        outfile << "    <medium>" << result.medium_vulnerabilities << "</medium>\n";
        outfile << "    <low>" << result.low_vulnerabilities << "</low>\n";
        outfile << "    <info>" << result.info_vulnerabilities << "</info>\n";
        outfile << "  </summary>\n";
        outfile << "</scan_report>\n";
        
    } else {
        // Plain text output
        outfile << "=== C3NT1P3D3 Scan Report ===\n\n";
        outfile << "Scan ID: " << result.scan_id << "\n";
        outfile << "Target Range: " << result.target_range << "\n";
        outfile << "Start Time: " << result.start_time << "\n";
        outfile << "End Time: " << result.end_time << "\n";
        outfile << "Status: " << result.status << "\n\n";
        outfile << "Summary:\n";
        outfile << "  Total Targets: " << result.total_targets_scanned << "\n";
        outfile << "  Total Vulnerabilities: " << result.total_vulnerabilities_found << "\n";
        outfile << "  Critical: " << result.critical_vulnerabilities << "\n";
        outfile << "  High: " << result.high_vulnerabilities << "\n";
        outfile << "  Medium: " << result.medium_vulnerabilities << "\n";
        outfile << "  Low: " << result.low_vulnerabilities << "\n";
        outfile << "  Info: " << result.info_vulnerabilities << "\n\n";
        outfile << result.summary_report << "\n\n";
        outfile << result.detailed_report << "\n";
    }
    
    outfile.close();
    std::cout << "✓ Results saved to: " << filename << std::endl;
}

void printProgress(const ProductionScanner::ScanProgress& progress) {
    int percentage = static_cast<int>(progress.progress_percentage);
    std::cout << "\r[";
    
    int bar_width = 50;
    int pos = bar_width * percentage / 100;
    
    for (int i = 0; i < bar_width; ++i) {
        if (i < pos) std::cout << "█";
        else if (i == pos) std::cout << ">";
        else std::cout << " ";
    }
    
    std::cout << "] " << percentage << "% - " 
              << progress.current_action 
              << " (" << progress.current_target << "/" << progress.total_targets << ")";
    std::cout.flush();
}

int main(int argc, char* argv[]) {
    printBanner();
    
    // Parse command line
    CommandLineOptions options = parseCommandLine(argc, argv);
    
    if (options.help || options.target_range.empty()) {
        printHelp();
        return options.target_range.empty() ? 1 : 0;
    }
    
    // ============================================================================
    // MANDATORY LEGAL AGREEMENT ACCEPTANCE
    // ============================================================================
    // Check if user has accepted legal agreements (TOS, EULA, Disclaimer)
    // This is NON-NEGOTIABLE and required under Alberta/Canadian law
    if (!LegalAgreementManager::hasAcceptedAgreements()) {
        std::cout << "\n";
        std::cout << "╔══════════════════════════════════════════════════════════════════════════════╗\n";
        std::cout << "║                    LEGAL AGREEMENTS ACCEPTANCE REQUIRED                      ║\n";
        std::cout << "╚══════════════════════════════════════════════════════════════════════════════╝\n";
        std::cout << "\n";
        std::cout << "Before using C3NT1P3D3, you MUST read and accept the legal agreements.\n";
        std::cout << "This is required under Alberta and Canadian law.\n";
        std::cout << "\n";
        
        if (!LegalAgreementManager::promptForAgreementAcceptance()) {
            std::cout << "\n⚠️  Legal agreements NOT accepted. Cannot proceed.\n";
            std::cout << "   You must accept the Terms of Service, EULA, and Disclaimer to use this software.\n";
            std::cout << "\n";
            return 1; // Exit if user declines
        }
        
        std::cout << "\n✓ Legal agreements accepted. Proceeding with scan...\n\n";
    } else {
        std::cout << "\n✓ Legal agreements previously accepted and still valid.\n";
        std::cout << "  (Acceptance recorded and governed by Alberta/Canadian law)\n\n";
    }
    // ============================================================================
    
    std::cout << "Target Range: " << options.target_range << std::endl;
    if (options.enable_simulation) {
        std::cout << "Mode: SIMULATION (No actual network traffic)" << std::endl;
    }
    std::cout << std::endl;
    
    // Validate target range
    if (!validateTargetRange(options.target_range, !options.no_strict)) {
        return 1;
    }
    
    // Initialize scanner
    ProductionScanner scanner;
    
    // Configure scanner
    scanner.setScanThreads(options.threads);
    scanner.setScanTimeout(options.timeout);
    scanner.setRateLimit(options.rate_limit);
    scanner.enableSimulationMode(options.enable_simulation);
    
    std::cout << "\n📊 Scan Configuration:" << std::endl;
    std::cout << "  Threads: " << options.threads << std::endl;
    std::cout << "  Timeout: " << options.timeout << "s" << std::endl;
    std::cout << "  Rate Limit: " << options.rate_limit << " req/s" << std::endl;
    std::cout << "  Strict Mode: " << (!options.no_strict ? "Enabled" : "Disabled") << std::endl;
    
    if (options.web_only) std::cout << "  Scan Type: Web Only" << std::endl;
    else if (options.network_only) std::cout << "  Scan Type: Network Only" << std::endl;
    else if (options.ssl_only) std::cout << "  Scan Type: SSL/TLS Only" << std::endl;
    else std::cout << "  Scan Type: Comprehensive" << std::endl;
    
    // Get safety warnings
    auto warnings = scanner.getSafetyWarnings(options.target_range);
    if (!warnings.empty()) {
        std::cout << "\n⚠️  Safety Warnings:" << std::endl;
        for (const auto& warning : warnings) {
            std::cout << "  - " << warning << std::endl;
        }
    }
    
    std::cout << "\n🚀 Starting scan..." << std::endl;
    std::cout << "Press Ctrl+C to stop the scan at any time.\n" << std::endl;
    
    // Perform scan
    auto result = scanner.performScan(options.target_range, "", options.enable_simulation);
    
    std::cout << "\n\n✓ Scan completed!" << std::endl;
    std::cout << "\n📊 Results Summary:" << std::endl;
    std::cout << "  Scan ID: " << result.scan_id << std::endl;
    std::cout << "  Status: " << result.status << std::endl;
    std::cout << "  Duration: " << result.start_time << " to " << result.end_time << std::endl;
    std::cout << "\n  Targets Scanned: " << result.total_targets_scanned << std::endl;
    std::cout << "  Vulnerabilities Found: " << result.total_vulnerabilities_found << std::endl;
    
    if (result.total_vulnerabilities_found > 0) {
        std::cout << "\n  Severity Breakdown:" << std::endl;
        if (result.critical_vulnerabilities > 0) 
            std::cout << "    🔴 Critical: " << result.critical_vulnerabilities << std::endl;
        if (result.high_vulnerabilities > 0)
            std::cout << "    🟠 High: " << result.high_vulnerabilities << std::endl;
        if (result.medium_vulnerabilities > 0)
            std::cout << "    🟡 Medium: " << result.medium_vulnerabilities << std::endl;
        if (result.low_vulnerabilities > 0)
            std::cout << "    🟢 Low: " << result.low_vulnerabilities << std::endl;
        if (result.info_vulnerabilities > 0)
            std::cout << "    ℹ️  Info: " << result.info_vulnerabilities << std::endl;
    }
    
    if (!result.errors.empty()) {
        std::cout << "\n❌ Errors:" << std::endl;
        for (const auto& error : result.errors) {
            std::cout << "  - " << error << std::endl;
        }
    }
    
    if (!result.warnings.empty()) {
        std::cout << "\n⚠️  Warnings:" << std::endl;
        for (const auto& warning : result.warnings) {
            std::cout << "  - " << warning << std::endl;
        }
    }
    
    // Save results if output file specified
    if (!options.output_file.empty()) {
        std::cout << "\n💾 Saving results..." << std::endl;
        saveResults(result, options.output_file, options.output_format);
    }
    
    std::cout << "\n" << result.summary_report << std::endl;
    
    std::cout << "\n🛡️  Scan completed safely with detection-only methodology." << std::endl;
    std::cout << "Thank you for using C3NT1P3D3 responsibly!\n" << std::endl;
    
    return 0;
}
