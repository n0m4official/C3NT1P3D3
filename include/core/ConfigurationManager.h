#ifndef CONFIGURATION_MANAGER_H
#define CONFIGURATION_MANAGER_H

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <fstream>
// #include <json/json.h>  // JsonCpp not installed - comment out for now

namespace C3NT1P3D3 {

enum class Environment {
    DEVELOPMENT,
    STAGING,
    PRODUCTION
};

struct SecurityConfig {
    bool enable_encryption = true;
    std::string encryption_key_file;
    int max_concurrent_scans = 10;
    int rate_limit_per_second = 100;
    int max_scan_duration_minutes = 60;
    bool enable_audit_logging = true;
    bool require_authentication = true;
    std::string authentication_token;
};

struct NetworkConfig {
    int connection_timeout_seconds = 30;
    int read_timeout_seconds = 15;
    int retry_attempts = 3;
    int retry_delay_seconds = 1;
    bool enable_keep_alive = true;
    int max_packet_size = 65536;
};

struct LoggingConfig {
    std::string log_level = "INFO";
    std::string log_file_path = "c3nt1p3d3.log";
    int max_log_file_size_mb = 100;
    int max_log_files = 10;
    bool enable_console_logging = true;
    bool enable_file_logging = true;
    bool enable_syslog = false;
};

struct SimulationConfig {
    bool enable_simulation_mode = false;
    std::string simulation_data_path = "simulation_data/";
    bool generate_mock_results = true;
    bool enable_network_simulation = true;
    int simulation_delay_ms = 100;
};

class ConfigurationManager {
public:
    static ConfigurationManager& getInstance();
    
    bool loadConfiguration(const std::string& config_file);
    bool saveConfiguration(const std::string& config_file);
    
    // Security configuration
    const SecurityConfig& getSecurityConfig() const;
    void updateSecurityConfig(const SecurityConfig& config);
    
    // Network configuration
    const NetworkConfig& getNetworkConfig() const;
    void updateNetworkConfig(const NetworkConfig& config);
    
    // Logging configuration
    const LoggingConfig& getLoggingConfig() const;
    void updateLoggingConfig(const LoggingConfig& config);
    
    // Simulation configuration
    const SimulationConfig& getSimulationConfig() const;
    void updateSimulationConfig(const SimulationConfig& config);
    
    // Environment management
    Environment getEnvironment() const;
    void setEnvironment(Environment env);
    
    // Validation
    bool validateConfiguration() const;
    std::vector<std::string> getValidationErrors() const;
    
    // Utility methods
    void setConfigValue(const std::string& key, const std::string& value);
    std::string getConfigValue(const std::string& key) const;
    
private:
    ConfigurationManager();
    ~ConfigurationManager();
    
    bool loadFromFile(const std::string& file_path);
    bool saveToFile(const std::string& file_path) const;
    void setDefaultValues();
    
    mutable std::mutex config_mutex_;
    
    SecurityConfig security_config_;
    NetworkConfig network_config_;
    LoggingConfig logging_config_;
    SimulationConfig simulation_config_;
    Environment environment_;
    
    std::map<std::string, std::string> custom_values_;
};

} // namespace C3NT1P3D3

#endif // CONFIGURATION_MANAGER_H