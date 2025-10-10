#include "IPRangeValidator.h"
#include <algorithm>
#include <sstream>
#include <stdexcept>
#include <chrono>
#include <ctime>
#include <arpa/inet.h>

namespace C3NT1P3D3 {

// Static member definitions
std::unique_ptr<IPRangeValidator> IPRangeValidator::instance = nullptr;

const std::vector<std::string> IPRangeValidator::PRIVATE_RANGES = {
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16"
};

const std::vector<std::string> IPRangeValidator::LOOPBACK_RANGES = {
    "127.0.0.0/8",
    "::1/128"
};

const std::vector<std::string> IPRangeValidator::MULTICAST_RANGES = {
    "224.0.0.0/4",
    "239.0.0.0/8",
    "ff00::/8"
};

const std::vector<std::string> IPRangeValidator::RESERVED_RANGES = {
    "0.0.0.0/8",
    "100.64.0.0/10",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.88.99.0/24",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "240.0.0.0/4",
    "255.255.255.255/32"
};

IPRangeValidator& IPRangeValidator::getInstance() {
    if (!instance) {
        instance = std::unique_ptr<IPRangeValidator>(new IPRangeValidator());
    }
    return *instance;
}

IPRangeValidator::IPRangeValidator() : strict_mode(true), require_approval_for_public(true) {
    loadDefaultSafeRanges();
}

IPRangeValidator::~IPRangeValidator() = default;

void IPRangeValidator::loadDefaultSafeRanges() {
    // Add private network ranges as safe
    for (const auto& range : PRIVATE_RANGES) {
        addAllowedRange(range, "RFC 1918 Private Network");
    }
    
    // Add loopback as safe
    for (const auto& range : LOOPBACK_RANGES) {
        addAllowedRange(range, "Loopback Interface");
    }
    
    // Add documentation ranges as safe
    addAllowedRange("192.0.2.0/24", "RFC 5737 Documentation");
    addAllowedRange("198.51.100.0/24", "RFC 5737 Documentation");
    addAllowedRange("203.0.113.0/24", "RFC 5737 Documentation");
}

bool IPRangeValidator::addAllowedRange(const std::string& range, const std::string& description) {
    if (!validateCIDR(range) && !validateIPRange(range, range)) {
        return false;
    }
    
    IPRange ip_range;
    ip_range.cidr = range;
    ip_range.description = description;
    
    // Parse the range
    if (range.find('/') != std::string::npos) {
        // CIDR notation
        uint32_t network, mask;
        if (parseCIDR(range, network, mask)) {
            ip_range.start_ip = uintToIP(network);
            ip_range.end_ip = uintToIP(network | ~mask);
        }
    } else {
        // Single IP
        ip_range.start_ip = range;
        ip_range.end_ip = range;
    }
    
    // Check IP types
    ip_range.is_private = isPrivateNetwork(ip_range.start_ip);
    ip_range.is_loopback = isLoopback(ip_range.start_ip);
    ip_range.is_multicast = isMulticast(ip_range.start_ip);
    ip_range.requires_approval = requiresExplicitApproval(range);
    
    allowed_ranges.push_back(ip_range);
    logRangeAccess(range, "ADDED: " + description);
    
    return true;
}

bool IPRangeValidator::removeAllowedRange(const std::string& range) {
    auto it = std::remove_if(allowed_ranges.begin(), allowed_ranges.end(),
        [&range](const IPRange& r) { return r.cidr == range; });
    
    if (it != allowed_ranges.end()) {
        allowed_ranges.erase(it, allowed_ranges.end());
        logRangeAccess(range, "REMOVED");
        return true;
    }
    
    return false;
}

bool IPRangeValidator::isIPInAllowedRange(const std::string& ip) const {
    if (!validateIP(ip)) {
        return false;
    }
    
    uint32_t ip_addr = ipToUInt(ip);
    
    for (const auto& range : allowed_ranges) {
        uint32_t start = ipToUInt(range.start_ip);
        uint32_t end = ipToUInt(range.end_ip);
        
        if (ip_addr >= start && ip_addr <= end) {
            return true;
        }
    }
    
    return false;
}

bool IPRangeValidator::isRangeSafe(const std::string& range) const {
    // Check if range is explicitly blocked
    std::vector<std::string> reasons = getApprovalReasons(range);
    
    // Block if any dangerous reasons exist
    for (const auto& reason : reasons) {
        if (reason.find("PUBLIC INTERNET") != std::string::npos ||
            reason.find("GOVERNMENT") != std::string::npos ||
            reason.find("MILITARY") != std::string::npos ||
            reason.find("CRITICAL INFRASTRUCTURE") != std::string::npos) {
            return false;
        }
    }
    
    return true;
}

bool IPRangeValidator::isPrivateNetwork(const std::string& ip) const {
    uint32_t ip_addr = ipToUInt(ip);
    
    // RFC 1918 private networks
    uint32_t priv10_start = ipToUInt("10.0.0.0");
    uint32_t priv10_end = ipToUInt("10.255.255.255");
    uint32_t priv172_start = ipToUInt("172.16.0.0");
    uint32_t priv172_end = ipToUInt("172.31.255.255");
    uint32_t priv192_start = ipToUInt("192.168.0.0");
    uint32_t priv192_end = ipToUInt("192.168.255.255");
    
    return (ip_addr >= priv10_start && ip_addr <= priv10_end) ||
           (ip_addr >= priv172_start && ip_addr <= priv172_end) ||
           (ip_addr >= priv192_start && ip_addr <= priv192_end);
}

bool IPRangeValidator::isLoopback(const std::string& ip) const {
    uint32_t ip_addr = ipToUInt(ip);
    uint32_t loopback_start = ipToUInt("127.0.0.0");
    uint32_t loopback_end = ipToUInt("127.255.255.255");
    
    return ip_addr >= loopback_start && ip_addr <= loopback_end;
}

bool IPRangeValidator::isMulticast(const std::string& ip) const {
    uint32_t ip_addr = ipToUInt(ip);
    uint32_t multicast_start = ipToUInt("224.0.0.0");
    uint32_t multicast_end = ipToUInt("239.255.255.255");
    
    return ip_addr >= multicast_start && ip_addr <= multicast_end;
}

bool IPRangeValidator::isReserved(const std::string& ip) const {
    uint32_t ip_addr = ipToUInt(ip);
    
    for (const auto& range : RESERVED_RANGES) {
        uint32_t network, mask;
        if (parseCIDR(range, network, mask)) {
            if ((ip_addr & mask) == network) {
                return true;
            }
        }
    }
    
    return false;
}

bool IPRangeValidator::isPublicInternet(const std::string& ip) const {
    return !isPrivateNetwork(ip) && 
           !isLoopback(ip) && 
           !isMulticast(ip) && 
           !isReserved(ip);
}

bool IPRangeValidator::validateCIDR(const std::string& cidr) const {
    std::regex cidr_regex(R"(^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$)");
    if (!std::regex_match(cidr, cidr_regex)) {
        return false;
    }
    
    size_t slash_pos = cidr.find('/');
    std::string ip_part = cidr.substr(0, slash_pos);
    std::string mask_part = cidr.substr(slash_pos + 1);
    
    int mask = std::stoi(mask_part);
    if (mask < 0 || mask > 32) {
        return false;
    }
    
    return validateIP(ip_part);
}

bool IPRangeValidator::validateIPRange(const std::string& start_ip, const std::string& end_ip) const {
    if (!validateIP(start_ip) || !validateIP(end_ip)) {
        return false;
    }
    
    uint32_t start = ipToUInt(start_ip);
    uint32_t end = ipToUInt(end_ip);
    
    return start <= end;
}

bool IPRangeValidator::validateIP(const std::string& ip) const {
    std::regex ip_regex(R"(^(\d{1,3}\.){3}\d{1,3}$)");
    if (!std::regex_match(ip, ip_regex)) {
        return false;
    }
    
    std::stringstream ss(ip);
    std::string octet;
    while (std::getline(ss, octet, '.')) {
        int value = std::stoi(octet);
        if (value < 0 || value > 255) {
            return false;
        }
    }
    
    return true;
}

bool IPRangeValidator::requiresExplicitApproval(const std::string& range) const {
    std::vector<std::string> reasons = getApprovalReasons(range);
    return !reasons.empty();
}

std::vector<std::string> IPRangeValidator::getApprovalReasons(const std::string& range) const {
    std::vector<std::string> reasons;
    
    // Check if range contains public internet IPs
    if (range.find('/') != std::string::npos) {
        uint32_t network, mask;
        if (parseCIDR(range, network, mask)) {
            uint32_t start = network;
            uint32_t end = network | ~mask;
            
            std::string start_ip = uintToIP(start);
            std::string end_ip = uintToIP(end);
            
            if (isPublicInternet(start_ip) || isPublicInternet(end_ip)) {
                reasons.push_back("PUBLIC INTERNET RANGE DETECTED");
            }
            
            if (isMulticast(start_ip) || isMulticast(end_ip)) {
                reasons.push_back("MULTICAST RANGE DETECTED");
            }
            
            if (isReserved(start_ip) || isReserved(end_ip)) {
                reasons.push_back("RESERVED IP RANGE DETECTED");
            }
        }
    } else {
        if (isPublicInternet(range)) {
            reasons.push_back("PUBLIC INTERNET IP DETECTED");
        }
        if (isMulticast(range)) {
            reasons.push_back("MULTICAST IP DETECTED");
        }
        if (isReserved(range)) {
            reasons.push_back("RESERVED IP DETECTED");
        }
    }
    
    return reasons;
}

bool IPRangeValidator::hasScanPermission(const std::string& range) const {
    if (strict_mode && isPublicInternet(range)) {
        return false;
    }
    
    if (require_approval_for_public && isPublicInternet(range)) {
        return approved_ranges.find(range) != approved_ranges.end();
    }
    
    return isRangeSafe(range) && isIPInAllowedRange(range);
}

std::string IPRangeValidator::getRangeAuditLog() const {
    std::stringstream ss;
    for (const auto& entry : audit_log) {
        ss << entry << "\n";
    }
    return ss.str();
}

void IPRangeValidator::logRangeAccess(const std::string& range, const std::string& action) {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    
    std::stringstream ss;
    ss << std::ctime(&time_t) << " - " << action << " - " << range;
    audit_log.push_back(ss.str());
}

bool IPRangeValidator::parseCIDR(const std::string& cidr, uint32_t& network, uint32_t& mask) const {
    size_t slash_pos = cidr.find('/');
    if (slash_pos == std::string::npos) {
        return false;
    }
    
    std::string ip_part = cidr.substr(0, slash_pos);
    int prefix_len = std::stoi(cidr.substr(slash_pos + 1));
    
    if (prefix_len < 0 || prefix_len > 32) {
        return false;
    }
    
    uint32_t ip = ipToUInt(ip_part);
    mask = (prefix_len == 0) ? 0 : (0xFFFFFFFF << (32 - prefix_len));
    network = ip & mask;
    
    return true;
}

uint32_t IPRangeValidator::ipToUInt(const std::string& ip) const {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip.c_str(), &addr) != 1) {
        return 0;
    }
    return ntohl(addr.s_addr);
}

std::string IPRangeValidator::uintToIP(uint32_t addr) const {
    struct in_addr in_addr;
    in_addr.s_addr = htonl(addr);
    return std::string(inet_ntoa(in_addr));
}

void IPRangeValidator::setStrictMode(bool enabled) {
    strict_mode = enabled;
}

bool IPRangeValidator::isStrictMode() const {
    return strict_mode;
}

void IPRangeValidator::setRequireApprovalForPublicIPs(bool required) {
    require_approval_for_public = required;
}

bool IPRangeValidator::requiresApprovalForPublicIPs() const {
    return require_approval_for_public;
}

} // namespace C3NT1P3D3