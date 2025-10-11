#pragma once

#include "IModule.h"
#include <string>
#include <vector>
#include <map>

/**
 * @brief CORS Misconfiguration Detector
 * 
 * Detects Cross-Origin Resource Sharing (CORS) misconfigurations:
 * - Wildcard origin with credentials
 * - Null origin accepted
 * - Arbitrary origin reflection
 * - Insecure protocol allowed
 * 
 * MITRE ATT&CK: T1539 - Steal Web Session Cookie
 */
class CORSDetector : public IModule {
public:
    std::string id() const override { return "CORSDetector"; }
    ModuleResult run(const MockTarget& target) override;

private:
    struct CORSTest {
        std::string name;
        std::string origin;
        std::string expectedVulnerability;
    };

    std::vector<CORSTest> getCORSTests();
    std::map<std::string, std::string> sendCORSRequest(const std::string& target, 
                                                       const std::string& origin);
    bool isVulnerableConfiguration(const std::map<std::string, std::string>& headers, 
                                   const std::string& origin);
    std::string extractHeader(const std::string& response, const std::string& headerName);
};
