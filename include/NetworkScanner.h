#pragma once
#include <string>
#include <vector>
#include <optional>
#include "MockTarget.h"

struct IPRange {
    std::string startIp;
    std::string endIp;
    std::string network;
    std::string subnetMask;
    
    bool contains(const std::string& ip) const;
    static std::optional<IPRange> parse(const std::string& range);
};

class NetworkScanner {
private:
    std::vector<IPRange> allowedRanges;
    bool simulationMode;
    
public:
    NetworkScanner(bool simMode = true);
    
    // Configure allowed IP ranges
    void addAllowedRange(const std::string& range);
    void setAllowedRanges(const std::vector<std::string>& ranges);
    
    // Network discovery (simulation mode)
    std::vector<MockTarget> discoverDevices(const std::string& networkRange);
    
    // Validation
    bool isIpAllowed(const std::string& ip) const;
    bool isNetworkAllowed(const std::string& network) const;
    
    // Get configured ranges
    std::vector<IPRange> getAllowedRanges() const { return allowedRanges; }
    
    // Safety checks
    void validateScanScope() const;
    std::string getSafetyReport() const;
};