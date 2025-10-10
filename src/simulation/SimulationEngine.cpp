#include "../../include/simulation/SimulationEngine.h"
#include <algorithm>
#include <random>
#include <sstream>
#include <fstream>
#include <json/json.h>

namespace C3NT1P3D3 {

class SimulationEngine::Impl {
public:
    bool simulation_enabled = false;
    int simulation_delay_ms = 100;
    double confidence_level = 0.85;
    int realism_level = 7;
    double error_rate = 0.05;
    
    std::mt19937 random_generator;
    std::uniform_real_distribution<double> probability_dist;
    std::uniform_int_distribution<int> port_dist;
    
    Impl() : random_generator(std::chrono::steady_clock::now().time_since_epoch().count()),
             probability_dist(0.0, 1.0),
             port_dist(1, 65535) {}
    
    // Service definitions
    const std::vector<std::string> common_services = {
        "http", "https", "ssh", "ftp", "smtp", "dns", "mysql", "postgresql",
        "mongodb", "redis", "telnet", "rdp", "smb", "snmp", "ldap"
    };
    
    const std::vector<std::string> service_versions = {
        "1.0.0", "1.2.3", "2.0.1", "2.1.4", "3.0.0", "3.2.1", "4.0.0"
    };
    
    const std::vector<std::string> vulnerability_templates = {
        "CVE-2023-XXXX: SQL Injection in {service} {version}",
        "CVE-2023-XXXX: Cross-Site Scripting vulnerability",
        "CVE-2023-XXXX: Buffer overflow in {service}",
        "CVE-2023-XXXX: Authentication bypass",
        "CVE-2023-XXXX: Directory traversal vulnerability",
        "CVE-2023-XXXX: Remote code execution",
        "CVE-2023-XXXX: Information disclosure"
    };
    
    const std::vector<std::string> banner_templates = {
        "{service}/{version} Server ready",
        "{service} {version} - Welcome",
        "{service} service {version} running",
        "{service} version {version} - Production",
        "{service}/{version} - Secure Server"
    };
};

SimulationEngine::SimulationEngine() : pImpl(std::make_unique<Impl>()) {}

SimulationEngine::~SimulationEngine() = default;

bool SimulationEngine::initialize(const std::string& config_path) {
    if (!config_path.empty()) {
        // Load configuration from file if provided
        std::ifstream config_file(config_path);
        if (config_file.is_open()) {
            Json::Value root;
            Json::CharReaderBuilder builder;
            std::string errors;
            
            if (Json::parseFromStream(builder, config_file, &root, &errors)) {
                if (root.isMember("simulation")) {
                    const Json::Value& sim = root["simulation"];
                    pImpl->simulation_delay_ms = sim.get("simulation_delay_ms", 100).asInt();
                    pImpl->confidence_level = sim.get("confidence_level", 0.85).asDouble();
                    pImpl->realism_level = sim.get("realism_level", 7).asInt();
                    pImpl->error_rate = sim.get("error_rate", 0.05).asDouble();
                }
            }
        }
    }
    return true;
}

void SimulationEngine::setSimulationMode(bool enabled) {
    pImpl->simulation_enabled = enabled;
}

void SimulationEngine::setDelay(int milliseconds) {
    pImpl->simulation_delay_ms = milliseconds;
}

void SimulationEngine::setConfidenceLevel(double level) {
    pImpl->confidence_level = std::max(0.0, std::min(1.0, level));
}

void SimulationEngine::setRealismLevel(int level) {
    pImpl->realism_level = std::max(1, std::min(10, level));
}

void SimulationEngine::setErrorRate(double rate) {
    pImpl->error_rate = std::max(0.0, std::min(1.0, rate));
}

std::vector<SimulationTarget> SimulationEngine::generateTargets(int count) {
    std::vector<SimulationTarget> targets;
    targets.reserve(count);
    
    for (int i = 0; i < count; ++i) {
        SimulationTarget target;
        target.ip = generateRandomIP("192.168.1.0/24");
        target.port = pImpl->port_dist(pImpl->random_generator);
        target.service = generateRandomService();
        target.version = generateRandomVersion(target.service);
        
        // Generate realistic banners
        target.banners["server"] = generateMockBanner(target.service);
        target.banners["version"] = target.version;
        
        targets.push_back(target);
    }
    
    return targets;
}

SimulationTarget SimulationEngine::generateTarget(const std::string& ip_range) {
    SimulationTarget target;
    target.ip = generateRandomIP(ip_range);
    target.port = pImpl->port_dist(pImpl->random_generator);
    target.service = generateRandomService();
    target.version = generateRandomVersion(target.service);
    
    target.banners["server"] = generateMockBanner(target.service);
    target.banners["version"] = target.version;
    
    return target;
}

SimulationResult SimulationEngine::simulateScan(const SimulationTarget& target) {
    // Simulate processing delay
    std::this_thread::sleep_for(std::chrono::milliseconds(pImpl->simulation_delay_ms));
    
    SimulationResult result;
    result.target = target.ip + ":" + std::to_string(target.port);
    result.timestamp = std::chrono::system_clock::now();
    result.confidence_score = generateConfidenceScore();
    
    // Simulate occasional errors
    if (pImpl->probability_dist(pImpl->random_generator) < pImpl->error_rate) {
        result.vulnerabilities.push_back("Scan error: Connection timeout");
        result.risk_level = "UNKNOWN";
        return result;
    }
    
    // Generate realistic vulnerabilities based on service and version
    result.vulnerabilities = generateMockVulnerabilities(target.service, target.version);
    
    // Determine risk level based on vulnerabilities found
    result.risk_level = determineRiskLevel(result.vulnerabilities);
    
    return result;
}

std::vector<SimulationResult> SimulationEngine::simulateBatch(const std::vector<SimulationTarget>& targets) {
    std::vector<SimulationResult> results;
    results.reserve(targets.size());
    
    for (const auto& target : targets) {
        results.push_back(simulateScan(target));
    }
    
    return results;
}

std::string SimulationEngine::generateMockBanner(const std::string& service) {
    if (pImpl->banner_templates.empty()) return service + "/1.0";
    
    std::uniform_int_distribution<int> template_dist(0, pImpl->banner_templates.size() - 1);
    std::string banner = pImpl->banner_templates[template_dist(pImpl->random_generator)];
    
    // Replace placeholders
    size_t pos = banner.find("{service}");
    if (pos != std::string::npos) {
        banner.replace(pos, 9, service);
    }
    
    pos = banner.find("{version}");
    if (pos != std::string::npos) {
        banner.replace(pos, 9, generateRandomVersion(service));
    }
    
    return banner;
}

std::vector<std::string> SimulationEngine::generateMockVulnerabilities(const std::string& service, const std::string& version) {
    std::vector<std::string> vulnerabilities;
    
    // Base vulnerability probability based on realism level
    double vuln_probability = pImpl->realism_level / 10.0 * pImpl->confidence_level;
    
    // Service-specific vulnerability probability
    if (service == "http" || service == "https") {
        if (pImpl->probability_dist(pImpl->random_generator) < vuln_probability * 0.7) {
            vulnerabilities.push_back("CVE-2023-XXXX: XSS vulnerability in web interface");
        }
        if (pImpl->probability_dist(pImpl->random_generator) < vuln_probability * 0.5) {
            vulnerabilities.push_back("CVE-2023-XXXX: SQL injection in login form");
        }
    }
    
    if (service == "ssh") {
        if (pImpl->probability_dist(pImpl->random_generator) < vuln_probability * 0.6) {
            vulnerabilities.push_back("CVE-2023-XXXX: Weak SSH key exchange algorithms");
        }
    }
    
    if (service == "mysql" || service == "postgresql") {
        if (pImpl->probability_dist(pImpl->random_generator) < vuln_probability * 0.8) {
            vulnerabilities.push_back("CVE-2023-XXXX: Default database credentials");
        }
    }
    
    // Version-specific vulnerabilities (older versions more vulnerable)
    int version_number = 1; // Default
    try {
        version_number = std::stoi(version.substr(0, version.find('.')));
    } catch (...) {}
    
    if (version_number < 3) {
        if (pImpl->probability_dist(pImpl->random_generator) < vuln_probability * 0.9) {
            vulnerabilities.push_back("CVE-2023-XXXX: Outdated software with known vulnerabilities");
        }
    }
    
    // Always add some informational findings
    if (vulnerabilities.empty() && pImpl->probability_dist(pImpl->random_generator) < 0.3) {
        vulnerabilities.push_back("INFO: Service banner reveals version information");
    }
    
    return vulnerabilities;
}

std::string SimulationEngine::generateRandomIP(const std::string& range) {
    // Simple IP generation for common ranges
    if (range == "192.168.1.0/24") {
        std::uniform_int_distribution<int> ip_dist(1, 254);
        return "192.168.1." + std::to_string(ip_dist(pImpl->random_generator));
    } else if (range == "10.0.0.0/8") {
        std::uniform_int_distribution<int> octet_dist(0, 255);
        return "10." + std::to_string(octet_dist(pImpl->random_generator)) + "." +
               std::to_string(octet_dist(pImpl->random_generator)) + "." +
               std::to_string(octet_dist(pImpl->random_generator));
    }
    
    // Default fallback
    return "192.168.1.100";
}

std::string SimulationEngine::generateRandomService() {
    if (pImpl->common_services.empty()) return "unknown";
    
    std::uniform_int_distribution<int> service_dist(0, pImpl->common_services.size() - 1);
    return pImpl->common_services[service_dist(pImpl->random_generator)];
}

std::string SimulationEngine::generateRandomVersion(const std::string& service) {
    if (pImpl->service_versions.empty()) return "1.0.0";
    
    std::uniform_int_distribution<int> version_dist(0, pImpl->service_versions.size() - 1);
    return pImpl->service_versions[version_dist(pImpl->random_generator)];
}

double SimulationEngine::generateConfidenceScore() {
    // Generate confidence score based on realism level
    double base_confidence = pImpl->confidence_level;
    double realism_factor = pImpl->realism_level / 10.0;
    
    std::normal_distribution<double> confidence_dist(base_confidence * realism_factor, 0.1);
    double score = confidence_dist(pImpl->random_generator);
    
    return std::max(0.0, std::min(1.0, score));
}

std::string SimulationEngine::determineRiskLevel(const std::vector<std::string>& vulnerabilities) {
    if (vulnerabilities.empty()) {
        return "LOW";
    }
    
    int critical_count = 0;
    int high_count = 0;
    int medium_count = 0;
    
    for (const auto& vuln : vulnerabilities) {
        if (vuln.find("Remote code execution") != std::string::npos ||
            vuln.find("Authentication bypass") != std::string::npos) {
            critical_count++;
        } else if (vuln.find("SQL injection") != std::string::npos ||
                  vuln.find("XSS") != std::string::npos) {
            high_count++;
        } else if (vuln.find("CVE-") != std::string::npos) {
            medium_count++;
        }
    }
    
    if (critical_count > 0) return "CRITICAL";
    if (high_count > 0) return "HIGH";
    if (medium_count > 0) return "MEDIUM";
    return "LOW";
}

bool SimulationEngine::exportSimulationData(const std::string& filename) const {
    Json::Value root;
    
    root["simulation_config"]["delay_ms"] = pImpl->simulation_delay_ms;
    root["simulation_config"]["confidence_level"] = pImpl->confidence_level;
    root["simulation_config"]["realism_level"] = pImpl->realism_level;
    root["simulation_config"]["error_rate"] = pImpl->error_rate;
    
    std::ofstream file(filename);
    if (!file.is_open()) {
        return false;
    }
    
    Json::StreamWriterBuilder builder;
    builder["indentation"] = "  ";
    std::unique_ptr<Json::StreamWriter> writer(builder.newStreamWriter());
    writer->write(root, &file);
    
    return true;
}

bool SimulationEngine::importSimulationData(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        return false;
    }
    
    Json::Value root;
    Json::CharReaderBuilder builder;
    std::string errors;
    
    if (!Json::parseFromStream(builder, file, &root, &errors)) {
        return false;
    }
    
    if (root.isMember("simulation_config")) {
        const Json::Value& config = root["simulation_config"];
        pImpl->simulation_delay_ms = config.get("delay_ms", 100).asInt();
        pImpl->confidence_level = config.get("confidence_level", 0.85).asDouble();
        pImpl->realism_level = config.get("realism_level", 7).asInt();
        pImpl->error_rate = config.get("error_rate", 0.05).asDouble();
    }
    
    return true;
}

} // namespace C3NT1P3D3