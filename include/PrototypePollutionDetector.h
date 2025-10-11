#pragma once
#include "VulnerabilityScanner.h"
#include <string>

// Prototype Pollution Detector (JavaScript/Node.js)
// Detects prototype pollution vulnerabilities in JavaScript applications
// MITRE ATT&CK: T1059.007 - Command and Scripting Interpreter: JavaScript
class PrototypePollutionDetector : public VulnerabilityScanner {
public:
    PrototypePollutionDetector();
    ~PrototypePollutionDetector() override = default;

    ScanResult scan(const std::string& target, int port) override;
    std::string getName() const override { return "Prototype Pollution"; }
    std::string getDescription() const override {
        return "Detects prototype pollution vulnerabilities in JavaScript/Node.js applications";
    }

private:
    bool testObjectPrototype(const std::string& target, int port);
    bool testArrayPrototype(const std::string& target, int port);
    bool testConstructorPollution(const std::string& target, int port);
    bool testJSONPollution(const std::string& target, int port);
};
