#ifndef SIMULATION_ENGINE_H
#define SIMULATION_ENGINE_H

#include <string>
#include <vector>
#include <memory>
#include <random>
#include <chrono>

namespace C3NT1P3D3 {

struct SimulationTarget {
    std::string ip;
    int port;
    std::string service;
    std::string version;
    std::map<std::string, std::string> banners;
};

struct SimulationResult {
    std::string target;
    std::vector<std::string> vulnerabilities;
    std::string risk_level;
    double confidence_score;
    std::chrono::system_clock::time_point timestamp;
};

class SimulationEngine {
public:
    SimulationEngine();
    ~SimulationEngine();
    
    // Simulation setup
    bool initialize(const std::string& config_path = "");
    void setSimulationMode(bool enabled);
    void setDelay(int milliseconds);
    void setConfidenceLevel(double level);
    
    // Target generation
    std::vector<SimulationTarget> generateTargets(int count);
    SimulationTarget generateTarget(const std::string& ip_range);
    
    // Vulnerability simulation
    SimulationResult simulateScan(const SimulationTarget& target);
    std::vector<SimulationResult> simulateBatch(const std::vector<SimulationTarget>& targets);
    
    // Mock data generation
    std::string generateMockBanner(const std::string& service);
    std::vector<std::string> generateMockVulnerabilities(const std::string& service, const std::string& version);
    
    // Realism settings
    void setRealismLevel(int level); // 1-10, higher = more realistic
    void setErrorRate(double rate); // 0.0-1.0, probability of scan errors
    
    // Data export/import
    bool exportSimulationData(const std::string& filename) const;
    bool importSimulationData(const std::string& filename);
    
private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
    
    // Internal methods
    std::string generateRandomIP(const std::string& range);
    std::string generateRandomService();
    std::string generateRandomVersion(const std::string& service);
    double generateConfidenceScore();
    std::string determineRiskLevel(const std::vector<std::string>& vulnerabilities);
    
    // Realistic data pools
    std::vector<std::string> getServices();
    std::vector<std::string> getVersions(const std::string& service);
    std::vector<std::string> getVulnerabilities(const std::string& service, const std::string& version);
    std::vector<std::string> getBanners(const std::string& service, const std::string& version);
};

} // namespace C3NT1P3D3

#endif // SIMULATION_ENGINE_H