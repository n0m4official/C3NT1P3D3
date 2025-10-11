#pragma once

#include "IModule.h"
#include <string>
#include <vector>
#include <map>

/**
 * @brief Subdomain Takeover Detector
 * 
 * Detects subdomain takeover vulnerabilities by identifying:
 * - Dangling DNS records (CNAME to non-existent services)
 * - Unclaimed cloud resources (S3, Azure, GitHub Pages)
 * - Expired hosting services
 * - Vulnerable service providers
 * 
 * MITRE ATT&CK: T1584.001 - Compromise Infrastructure: Domains
 */
class SubdomainTakeoverDetector : public IModule {
public:
    std::string id() const override { return "SubdomainTakeoverDetector"; }
    ModuleResult run(const MockTarget& target) override;

private:
    struct ServiceFingerprint {
        std::string service;
        std::vector<std::string> cnamePatterns;
        std::vector<std::string> responsePatterns;
        std::string vulnerability;
    };

    std::vector<ServiceFingerprint> getServiceFingerprints();
    std::vector<std::string> resolveCNAME(const std::string& domain);
    std::string sendHTTPRequest(const std::string& target);
    bool matchesFingerprint(const std::string& cname, const std::string& response, 
                           const ServiceFingerprint& fingerprint);
    std::vector<std::string> enumerateSubdomains(const std::string& domain);
};
