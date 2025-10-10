#ifndef IP_RANGE_VALIDATOR_H
#define IP_RANGE_VALIDATOR_H

#include <string>
#include <vector>
#include <set>
#include <memory>
#include <regex>

namespace C3NT1P3D3 {

struct IPRange {
    std::string start_ip;
    std::string end_ip;
    std::string cidr;
    std::string description;
    bool is_private;
    bool is_loopback;
    bool is_multicast;
    bool requires_approval;
};

class IPRangeValidator {
public:
    static IPRangeValidator& getInstance();
    
    // IP Range Management
    bool addAllowedRange(const std::string& range, const std::string& description = "");
    bool removeAllowedRange(const std::string& range);
    bool isIPInAllowedRange(const std::string& ip) const;
    bool isRangeSafe(const std::string& range) const;
    
    // Safety Checks
    bool isPrivateNetwork(const std::string& ip) const;
    bool isLoopback(const std::string& ip) const;
    bool isMulticast(const std::string& ip) const;
    bool isReserved(const std::string& ip) const;
    bool isPublicInternet(const std::string& ip) const;
    
    // Range Validation
    bool validateCIDR(const std::string& cidr) const;
    bool validateIPRange(const std::string& start_ip, const std::string& end_ip) const;
    bool validateIP(const std::string& ip) const;
    
    // Security Enforcement
    bool requiresExplicitApproval(const std::string& range) const;
    std::vector<std::string> getApprovalReasons(const std::string& range) const;
    bool hasScanPermission(const std::string& range) const;
    
    // Default Safe Ranges
    void loadDefaultSafeRanges();
    std::vector<IPRange> getDefaultSafeRanges() const;
    
    // Audit & Logging
    std::string getRangeAuditLog() const;
    void logRangeAccess(const std::string& range, const std::string& action);
    
    // Configuration
    void setStrictMode(bool enabled);
    bool isStrictMode() const;
    void setRequireApprovalForPublicIPs(bool required);
    bool requiresApprovalForPublicIPs() const;

private:
    IPRangeValidator();
    public:
       ~IPRangeValidator();
    
    bool parseCIDR(const std::string& cidr, uint32_t& network, uint32_t& mask) const;
    bool parseIP(const std::string& ip, uint32_t& addr) const;
    uint32_t ipToUInt(const std::string& ip) const;
    std::string uintToIP(uint32_t addr) const;
    
    std::vector<IPRange> allowed_ranges;
    std::set<std::string> approved_ranges;
    std::vector<std::string> audit_log;
    
    bool strict_mode;
    bool require_approval_for_public;
    
    // Predefined safe ranges (RFC 1918, RFC 5737, etc.)
    static const std::vector<std::string> PRIVATE_RANGES;
    static const std::vector<std::string> LOOPBACK_RANGES;
    static const std::vector<std::string> MULTICAST_RANGES;
    static const std::vector<std::string> RESERVED_RANGES;
    
    static std::unique_ptr<IPRangeValidator> instance;
};

// Safety exceptions
class IPRangeSafetyException : public std::exception {
private:
    std::string message;
public:
    IPRangeSafetyException(const std::string& msg) : message(msg) {}
    const char* what() const noexcept override { return message.c_str(); }
};

class UnauthorizedIPRangeException : public IPRangeSafetyException {
public:
    UnauthorizedIPRangeException(const std::string& range) 
        : IPRangeSafetyException("IP range '" + range + "' requires explicit authorization") {}
};

class DangerousIPRangeException : public IPRangeSafetyException {
public:
    DangerousIPRangeException(const std::string& range) 
        : IPRangeSafetyException("IP range '" + range + "' is blocked for safety reasons") {}
};

} // namespace C3NT1P3D3

#endif // IP_RANGE_VALIDATOR_H