#pragma once

#include "IModule.h"
#include <string>
#include <vector>
#include <map>
#include <functional>

/**
 * @brief JWT Vulnerability Detector
 * 
 * Detects common JWT (JSON Web Token) vulnerabilities including:
 * - Algorithm confusion (alg: none)
 * - Weak signing secrets
 * - Key confusion attacks
 * - Missing signature verification
 * 
 * MITRE ATT&CK: T1550.001 - Use Alternate Authentication Material: Application Access Token
 */
class JWTDetector : public IModule {
public:
    std::string id() const override { return "JWTDetector"; }
    ModuleResult run(const MockTarget& target) override;

private:
    struct JWTTest {
        std::string name;
        std::string description;
        std::function<bool(const std::string&)> testFunction;
    };

    std::string extractJWT(const std::string& response);
    bool testAlgorithmNone(const std::string& target);
    bool testWeakSecret(const std::string& target);
    bool testKeyConfusion(const std::string& target);
    std::string sendHTTPRequest(const std::string& target, const std::string& jwt);
    std::string base64UrlEncode(const std::string& input);
    std::string base64UrlDecode(const std::string& input);
    std::vector<std::string> getCommonSecrets();
};
