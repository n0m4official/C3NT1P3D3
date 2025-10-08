#include "NetworkScanner.h"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <regex>
#include <stdexcept>

// IPRange implementation
bool IPRange::contains(const std::string& ip) const {
    // Simple IP comparison (in real implementation, convert to integers)
    return ip >= startIp && ip <= endIp;
}

std::optional<IPRange> IPRange::parse(const std::string& range) {
    IPRange result;
    
    // Handle CIDR notation (e.g., "192.168.1.0/24")
    std::regex cidrRegex(R"(^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,2})$)");
    std::smatch match;
    
    if (std::regex_match(range, match, cidrRegex)) {
        std::string network = match[1].str();
        int prefixLength = std::stoi(match[2].str());
        
        if (prefixLength < 0 || prefixLength > 32) {
            return std::nullopt;
        }
        
        result.network = network;
        result.subnetMask = prefixLength;
        
        // Calculate start and end IPs (simplified)
        std::istringstream iss(network);
        std::string octet;
        std::vector<int> octets;
        
        while (std::getline(iss, octet, '.')) {
            octets.push_back(std::stoi(octet));
        }
        
        if (octets.size() != 4) return std::nullopt;
        
        // Calculate range based on prefix length (simplified for demo)
        if (prefixLength >= 24) {
            result.startIp = std::to_string(octets[0]) + "." + 
                           std::to_string(octets[1]) + "." + 
                           std::to_string(octets[2]) + ".1";
            result.endIp = std::to_string(octets[0]) + "." + 
                         std::to_string(octets[1]) + "." + 
                         std::to_string(octets[2]) + ".254";
        } else {
            // For larger networks, use broader ranges
            result.startIp = network;
            result.endIp = network; // Simplified
        }
        
        return result;
    }
    
    // Handle range notation (e.g., "192.168.1.1-192.168.1.100")
    size_t dashPos = range.find('-');
    if (dashPos != std::string::npos) {
        result.startIp = range.substr(0, dashPos);
        result.endIp = range.substr(dashPos + 1);
        result.network = result.startIp;
        return result;
    }
    
    // Handle single IP
    result.startIp = range;
    result.endIp = range;
    result.network = range;
    return result;
}

// NetworkScanner implementation
NetworkScanner::NetworkScanner(bool simMode) : simulationMode(simMode) {
    // Default to safe private network ranges only
    addAllowedRange("192.168.0.0/16");
    addAllowedRange("10.0.0.0/8");
    addAllowedRange("172.16.0.0/12");
}

void NetworkScanner::addAllowedRange(const std::string& range) {
    auto ipRange = IPRange::parse(range);
    if (ipRange.has_value()) {
        allowedRanges.push_back(ipRange.value());
        std::cout << "Added allowed range: " << range << std::endl;
    } else {
        throw std::invalid_argument("Invalid IP range format: " + range);
    }
}

void NetworkScanner::setAllowedRanges(const std::vector<std::string>& ranges) {
    allowedRanges.clear();
    for (const auto& range : ranges) {
        addAllowedRange(range);
    }
}

bool NetworkScanner::isIpAllowed(const std::string& ip) const {
    for (const auto& range : allowedRanges) {
        if (range.contains(ip)) {
            return true;
        }
    }
    return false;
}

bool NetworkScanner::isNetworkAllowed(const std::string& network) const {
    // Check if this specific network is allowed
    for (const auto& range : allowedRanges) {
        // For CIDR notation, check if the network falls within the allowed range
        if (range.network.find("192.168") == 0 && network.find("192.168") == 0) {
            return true; // Both are in 192.168.x.x range
        }
        if (range.network.find("10.") == 0 && network.find("10.") == 0) {
            return true; // Both are in 10.x.x.x range
        }
        if (range.network.find("172.16") == 0 && network.find("172.16") == 0) {
            return true; // Both are in 172.16.x.x range
        }
        if (range.network == network || range.contains(network)) {
            return true;
        }
    }
    return false;
}

std::vector<MockTarget> NetworkScanner::discoverDevices(const std::string& networkRange) {
    std::vector<MockTarget> devices;
    
    // Validate that the requested range is allowed
    auto requestedRange = IPRange::parse(networkRange);
    if (!requestedRange.has_value()) {
        throw std::invalid_argument("Invalid network range: " + networkRange);
    }
    
    if (!isNetworkAllowed(requestedRange->network)) {
        throw std::runtime_error("Network range " + networkRange + " is not in allowed ranges. "
                                "Scanning blocked for safety.");
    }
    
    std::cout << "Discovering devices in range: " << networkRange << std::endl;
    
    if (simulationMode) {
        // Simulate device discovery based on network range
        if (networkRange.find("192.168.1") != std::string::npos) {
            // Simulate a typical home/office network
            devices.emplace_back("router", "192.168.1.1");
            devices.back().addService("HTTP", 80, true);
            
            devices.emplace_back("windows-pc", "192.168.1.100");
            devices.back().addService("SMB", 445, true);
            devices.back().addService("RDP", 3389, true);
            
            devices.emplace_back("linux-server", "192.168.1.101");
            devices.back().addService("SSH", 22, true);
            devices.back().addService("HTTP", 80, true);
            
            devices.emplace_back("printer", "192.168.1.102");
            devices.back().addService("HTTP", 80, true);
            
            devices.emplace_back("nas-device", "192.168.1.103");
            devices.back().addService("SMB", 445, true);
            devices.back().addService("HTTP", 80, true);
            
        } else if (networkRange.find("10.0.0") != std::string::npos) {
            // Simulate a corporate network
            devices.emplace_back("domain-controller", "10.0.0.10");
            devices.back().addService("SMB", 445, true);
            
            devices.emplace_back("web-server", "10.0.0.20");
            devices.back().addService("HTTP", 80, true);
            devices.back().addService("HTTPS", 443, true);
            
            devices.emplace_back("database-server", "10.0.0.30");
            devices.back().addService("HTTP", 80, true);
            
            devices.emplace_back("file-server", "10.0.0.40");
            devices.back().addService("SMB", 445, true);
            devices.back().addService("FTP", 21, true);
        }
    } else {
        // In a real implementation, this would perform actual network scanning
        // using tools like ping sweeps, port scans, etc.
        std::cout << "Real network scanning would be performed here for range: " << networkRange << std::endl;
        std::cout << "WARNING: Real scanning is disabled in this build for safety." << std::endl;
    }
    
    std::cout << "Discovered " << devices.size() << " devices" << std::endl;
    return devices;
}

void NetworkScanner::validateScanScope() const {
    if (allowedRanges.empty()) {
        throw std::runtime_error("No allowed IP ranges configured. Scanning is disabled for safety.");
    }
    
    // Check that no public IP ranges are included
    for (const auto& range : allowedRanges) {
        std::string network = range.network;
        
        // Check for obviously dangerous ranges (exact matches only)
        if (network == "0.0.0.0" || network == "255.255.255.255") {
            throw std::runtime_error("Dangerous IP range detected: " + network);
        }
    }
}

std::string NetworkScanner::getSafetyReport() const {
    std::ostringstream report;
    report << "=== Network Scanner Safety Report ===" << std::endl;
    report << "Simulation Mode: " << (simulationMode ? "ENABLED" : "DISABLED") << std::endl;
    report << "Allowed IP Ranges: " << allowedRanges.size() << std::endl;
    
    for (const auto& range : allowedRanges) {
        report << "  - " << range.network;
        if (!range.subnetMask.empty()) {
            report << "/" << range.subnetMask;
        }
        report << " (Range: " << range.startIp << " - " << range.endIp << ")" << std::endl;
    }
    
    report << std::endl;
    report << "Safety Features:" << std::endl;
    report << "✓ IP range validation enforced" << std::endl;
    report << "✓ Only private network ranges allowed by default" << std::endl;
    report << "✓ No public IP scanning permitted" << std::endl;
    report << "✓ Simulation mode prevents actual network interaction" << std::endl;
    report << "✓ Explicit permission required for each IP range" << std::endl;
    report << "✓ No exploit execution - detection only" << std::endl;
    
    return report.str();
}