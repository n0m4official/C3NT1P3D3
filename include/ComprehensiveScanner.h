#pragma once

#include "ModuleRegistry.h"
#include "MockTarget.h"
#include <string>
#include <vector>
#include <memory>

namespace C3NT1P3D3 {

/**
 * @brief Comprehensive vulnerability scanner with MITRE ATT&CK integration
 * 
 * This scanner orchestrates all vulnerability detection modules and provides
 * detailed reporting with threat intelligence context.
 */
class ComprehensiveScanner {
public:
    struct ScanConfiguration {
        bool scan_network = true;
        bool scan_web = true;
        bool scan_ssl_tls = true;
        bool scan_system = true;
        bool enable_simulation = false;
        int timeout_seconds = 30;
        int max_threads = 10;
        bool verbose = false;
    };

    struct VulnerabilityReport {
        std::string target_id;
        std::string target_ip;
        int total_vulnerabilities = 0;
        int critical_count = 0;
        int high_count = 0;
        int medium_count = 0;
        int low_count = 0;
        std::vector<ModuleResult> findings;
        
        // MITRE ATT&CK summary
        std::vector<std::string> attack_techniques;
        std::vector<std::string> attack_tactics;
        std::map<std::string, std::vector<std::string>> technique_mitigations;
    };

    struct ScanSummary {
        int total_targets_scanned = 0;
        int total_vulnerabilities_found = 0;
        int critical_vulnerabilities = 0;
        int high_vulnerabilities = 0;
        int medium_vulnerabilities = 0;
        int low_vulnerabilities = 0;
        
        std::vector<VulnerabilityReport> target_reports;
        
        // MITRE ATT&CK summary
        std::map<std::string, int> techniques_found; // technique_id -> count
        std::map<std::string, int> tactics_found;    // tactic -> count
        
        std::string start_time;
        std::string end_time;
        double scan_duration_seconds = 0.0;
    };

    ComprehensiveScanner();
    ~ComprehensiveScanner();

    /**
     * @brief Configure the scanner
     */
    void configure(const ScanConfiguration& config);

    /**
     * @brief Scan a single target
     */
    VulnerabilityReport scanTarget(const std::string& target_ip);

    /**
     * @brief Scan multiple targets
     */
    ScanSummary scanTargets(const std::vector<std::string>& target_ips);

    /**
     * @brief Generate JSON report
     */
    std::string generateJSONReport(const ScanSummary& summary) const;

    /**
     * @brief Generate text report
     */
    std::string generateTextReport(const ScanSummary& summary) const;

    /**
     * @brief Generate MITRE ATT&CK Navigator JSON
     */
    std::string generateAttackNavigatorJSON(const ScanSummary& summary) const;

    /**
     * @brief Get scanner statistics
     */
    ModuleRegistry::Statistics getModuleStatistics() const;

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;

    void processModuleResults(const std::vector<ModuleResult>& results, VulnerabilityReport& report);
    std::string getCurrentTimestamp() const;
};

} // namespace C3NT1P3D3
