#include "../../include/core/ConfigurationManager.h"
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace C3NT1P3D3 {

ConfigurationManager& ConfigurationManager::getInstance() {
    static ConfigurationManager instance;
    return instance;
}

ConfigurationManager::ConfigurationManager() {
    setDefaultValues();
}

ConfigurationManager::~ConfigurationManager() = default;

bool ConfigurationManager::loadConfiguration(const std::string& config_file) {
    std::lock_guard<std::mutex> lock(config_mutex_);
    return loadFromFile(config_file);
}

bool ConfigurationManager::saveConfiguration(const std::string& config_file) const {
    std::lock_guard<std::mutex> lock(config_mutex_);
    return saveToFile(config_file);
}

bool ConfigurationManager::loadFromFile(const std::string& file_path) {
    std::ifstream file(file_path);
    if (!file.is_open()) {
        return false;
    }
    
    try {
        Json::Value root;
        Json::CharReaderBuilder builder;
        std::string errors;
        
        if (!Json::parseFromStream(builder, file, &root, &errors)) {
            return false;
        }
        
        // Load security configuration
        if (root.isMember("security")) {
            const Json::Value& security = root["security"];
            security_config_.enable_encryption = security.get("enable_encryption", true).asBool();
            security_config_.encryption_key_file = security.get("encryption_key_file", "").asString();
            security_config_.max_concurrent_scans = security.get("max_concurrent_scans", 10).asInt();
            security_config_.rate_limit_per_second = security.get("rate_limit_per_second", 100).asInt();
            security_config_.max_scan_duration_minutes = security.get("max_scan_duration_minutes", 60).asInt();
            security_config_.enable_audit_logging = security.get("enable_audit_logging", true).asBool();
            security_config_.require_authentication = security.get("require_authentication", true).asBool();
            security_config_.authentication_token = security.get("authentication_token", "").asString();
        }
        
        // Load network configuration
        if (root.isMember("network")) {
            const Json::Value& network = root["network"];
            network_config_.connection_timeout_seconds = network.get("connection_timeout_seconds", 30).asInt();
            network_config_.read_timeout_seconds = network.get("read_timeout_seconds", 15).asInt();
            network_config_.retry_attempts = network.get("retry_attempts", 3).asInt();
            network_config_.retry_delay_seconds = network.get("retry_delay_seconds", 1).asInt();
            network_config_.enable_keep_alive = network.get("enable_keep_alive", true).asBool();
            network_config_.max_packet_size = network.get("max_packet_size", 65536).asInt();
        }
        
        // Load logging configuration
        if (root.isMember("logging")) {
            const Json::Value& logging = root["logging"];
            logging_config_.log_level = logging.get("log_level", "INFO").asString();
            logging_config_.log_file_path = logging.get("log_file_path", "c3nt1p3d3.log").asString();
            logging_config_.max_log_file_size_mb = logging.get("max_log_file_size_mb", 100).asInt();
            logging_config_.max_log_files = logging.get("max_log_files", 10).asInt();
            logging_config_.enable_console_logging = logging.get("enable_console_logging", true).asBool();
            logging_config_.enable_file_logging = logging.get("enable_file_logging", true).asBool();
            logging_config_.enable_syslog = logging.get("enable_syslog", false).asBool();
        }
        
        // Load simulation configuration
        if (root.isMember("simulation")) {
            const Json::Value& simulation = root["simulation"];
            simulation_config_.enable_simulation_mode = simulation.get("enable_simulation_mode", false).asBool();
            simulation_config_.simulation_data_path = simulation.get("simulation_data_path", "simulation_data/").asString();
            simulation_config_.generate_mock_results = simulation.get("generate_mock_results", true).asBool();
            simulation_config_.enable_network_simulation = simulation.get("enable_network_simulation", true).asBool();
            simulation_config_.simulation_delay_ms = simulation.get("simulation_delay_ms", 100).asInt();
        }
        
        return true;
    } catch (const std::exception& e) {
        return false;
    }
}

bool ConfigurationManager::saveToFile(const std::string& file_path) const {
    Json::Value root;
    
    // Security configuration
    Json::Value security;
    security["enable_encryption"] = security_config_.enable_encryption;
    security["encryption_key_file"] = security_config_.encryption_key_file;
    security["max_concurrent_scans"] = security_config_.max_concurrent_scans;
    security["rate_limit_per_second"] = security_config_.rate_limit_per_second;
    security["max_scan_duration_minutes"] = security_config_.max_scan_duration_minutes;
    security["enable_audit_logging"] = security_config_.enable_audit_logging;
    security["require_authentication"] = security_config_.require_authentication;
    security["authentication_token"] = security_config_.authentication_token;
    root["security"] = security;
    
    // Network configuration
    Json::Value network;
    network["connection_timeout_seconds"] = network_config_.connection_timeout_seconds;
    network["read_timeout_seconds"] = network_config_.read_timeout_seconds;
    network["retry_attempts"] = network_config_.retry_attempts;
    network["retry_delay_seconds"] = network_config_.retry_delay_seconds;
    network["enable_keep_alive"] = network_config_.enable_keep_alive;
    network["max_packet_size"] = network_config_.max_packet_size;
    root["network"] = network;
    
    // Logging configuration
    Json::Value logging;
    logging["log_level"] = logging_config_.log_level;
    logging["log_file_path"] = logging_config_.log_file_path;
    logging["max_log_file_size_mb"] = logging_config_.max_log_file_size_mb;
    logging["max_log_files"] = logging_config_.max_log_files;
    logging["enable_console_logging"] = logging_config_.enable_console_logging;
    logging["enable_file_logging"] = logging_config_.enable_file_logging;
    logging["enable_syslog"] = logging_config_.enable_syslog;
    root["logging"] = logging;
    
    // Simulation configuration
    Json::Value simulation;
    simulation["enable_simulation_mode"] = simulation_config_.enable_simulation_mode;
    simulation["simulation_data_path"] = simulation_config_.simulation_data_path;
    simulation["generate_mock_results"] = simulation_config_.generate_mock_results;
    simulation["enable_network_simulation"] = simulation_config_.enable_network_simulation;
    simulation["simulation_delay_ms"] = simulation_config_.simulation_delay_ms;
    root["simulation"] = simulation;
    
    std::ofstream file(file_path);
    if (!file.is_open()) {
        return false;
    }
    
    Json::StreamWriterBuilder builder;
    builder["indentation"] = "  ";
    std::unique_ptr<Json::StreamWriter> writer(builder.newStreamWriter());
    writer->write(root, &file);
    
    return true;
}

void ConfigurationManager::setDefaultValues() {
    environment_ = Environment::DEVELOPMENT;
    
    // Security defaults
    security_config_.enable_encryption = true;
    security_config_.encryption_key_file = "";
    security_config_.max_concurrent_scans = 10;
    security_config_.rate_limit_per_second = 100;
    security_config_.max_scan_duration_minutes = 60;
    security_config_.enable_audit_logging = true;
    security_config_.require_authentication = false;
    security_config_.authentication_token = "";
    
    // Network defaults
    network_config_.connection_timeout_seconds = 30;
    network_config_.read_timeout_seconds = 15;
    network_config_.retry_attempts = 3;
    network_config_.retry_delay_seconds = 1;
    network_config_.enable_keep_alive = true;
    network_config_.max_packet_size = 65536;
    
    // Logging defaults
    logging_config_.log_level = "INFO";
    logging_config_.log_file_path = "c3nt1p3d3.log";
    logging_config_.max_log_file_size_mb = 100;
    logging_config_.max_log_files = 10;
    logging_config_.enable_console_logging = true;
    logging_config_.enable_file_logging = true;
    logging_config_.enable_syslog = false;
    
    // Simulation defaults
    simulation_config_.enable_simulation_mode = false;
    simulation_config_.simulation_data_path = "simulation_data/";
    simulation_config_.generate_mock_results = true;
    simulation_config_.enable_network_simulation = true;
    simulation_config_.simulation_delay_ms = 100;
}

const SecurityConfig& ConfigurationManager::getSecurityConfig() const {
    return security_config_;
}

const NetworkConfig& ConfigurationManager::getNetworkConfig() const {
    return network_config_;
}

const LoggingConfig& ConfigurationManager::getLoggingConfig() const {
    return logging_config_;
}

const SimulationConfig& ConfigurationManager::getSimulationConfig() const {
    return simulation_config_;
}

Environment ConfigurationManager::getEnvironment() const {
    return environment_;
}

void ConfigurationManager::setEnvironment(Environment env) {
    environment_ = env;
}

bool ConfigurationManager::validateConfiguration() const {
    return getValidationErrors().empty();
}

std::vector<std::string> ConfigurationManager::getValidationErrors() const {
    std::vector<std::string> errors;
    
    if (security_config_.max_concurrent_scans <= 0) {
        errors.push_back("max_concurrent_scans must be positive");
    }
    
    if (security_config_.rate_limit_per_second <= 0) {
        errors.push_back("rate_limit_per_second must be positive");
    }
    
    if (network_config_.connection_timeout_seconds <= 0) {
        errors.push_back("connection_timeout_seconds must be positive");
    }
    
    return errors;
}

} // namespace C3NT1P3D3