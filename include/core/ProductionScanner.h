#ifndef PRODUCTION_SCANNER_H
#define PRODUCTION_SCANNER_H

#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include <atomic>
#include <thread>
#include <mutex>
#include <condition_variable>

#include "ConfigurationManager.h"
#include "VulnerabilityDatabase.h"
#include "IPRangeValidator.h"

namespace C3NT1P3D3 {

class ProductionScanner {
public:
    struct ScanResult {
        std::string scan_id;
        std::string start_time;
        std::string end_time;
        std::string target_range;
        std::string status;
        std::vector<std::string> errors;
        std::vector<std::string> warnings;
        int total_targets_scanned = 0;
        int total_vulnerabilities_found = 0;
        int critical_vulnerabilities = 0;
        int high_vulnerabilities = 0;
        int medium_vulnerabilities = 0;
        int low_vulnerabilities = 0;
        int info_vulnerabilities = 0;
        std::string summary_report;
        std::string detailed_report;
    };
    
    struct ScanProgress {
        int current_target = 0;
        int total_targets = 0;
        int vulnerabilities_found = 0;
        std::string current_action;
        double progress_percentage = 0.0;
        bool is_cancelled = false;
    };
    
    ProductionScanner();
    ~ProductionScanner();
    
    // Main scanning interface
    ScanResult performScan(const std::string& target_range, 
                          const std::string& config_file = "",
                          bool enable_simulation = false);
    
    // Real-time monitoring
    ScanProgress getProgress() const;
    void cancelScan();
    
    // Configuration management
    bool loadConfiguration(const std::string& config_file);
    bool saveConfiguration(const std::string& config_file);
    
    // Safety validation
    bool validateScanRequest(const std::string& target_range) const;
    std::vector<std::string> getSafetyWarnings(const std::string& target_range) const;
    
    // Simulation mode
    void enableSimulationMode(bool enable);
    void setSimulationDataPath(const std::string& path);
    
    // Advanced scanning capabilities
    void setScanThreads(int threads);
    void setScanTimeout(int seconds);
    void setRateLimit(int requests_per_second);
    
    // Security features
    bool authenticateUser(const std::string& token);
    void setAuthenticationToken(const std::string& token);
    
private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
    
    // Core scanning methods
    std::vector<std::string> discoverTargets(const std::string& range);
    std::string scanTarget(const std::string& target);
    void processResults(const std::vector<std::string>& results, ScanResult& scan_result);
    
    // Safety methods
    bool checkSafetyConstraints(const std::string& range) const;
    void logSecurityEvent(const std::string& event, const std::string& details);
    
    // Simulation methods
    std::string simulateScan(const std::string& target);
    std::string generateMockResult(const std::string& target);
};

} // namespace C3NT1P3D3

#endif // PRODUCTION_SCANNER_H