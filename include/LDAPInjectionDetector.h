#pragma once

#include "IModule.h"
#include <string>
#include <vector>

/**
 * @brief LDAP Injection Detector
 * 
 * Detects LDAP injection vulnerabilities in directory service queries.
 * Tests for filter injection, blind injection, and authentication bypass.
 * 
 * MITRE ATT&CK: T1078.002 - Valid Accounts: Domain Accounts
 */
class LDAPInjectionDetector : public IModule {
public:
    std::string id() const override { return "LDAPInjectionDetector"; }
    ModuleResult run(const MockTarget& target) override;

private:
    struct LDAPPayload {
        std::string payload;
        std::string type;
        std::string description;
    };

    std::vector<LDAPPayload> getLDAPPayloads();
    std::string sendHTTPRequest(const std::string& target, const std::string& payload);
    bool containsLDAPError(const std::string& response);
    bool indicatesBlindInjection(const std::string& response1, const std::string& response2);
    std::string urlEncode(const std::string& str);
};
