#pragma once
#include "VulnerabilityScanner.h"
#include <string>
#include <vector>

// Server-Side Template Injection (SSTI) Detector
// Detects template injection vulnerabilities in Jinja2, Twig, Freemarker, Velocity, etc.
// MITRE ATT&CK: T1190 - Exploit Public-Facing Application
class SSTIDetector : public VulnerabilityScanner {
public:
    SSTIDetector();
    ~SSTIDetector() override = default;

    ScanResult scan(const std::string& target, int port) override;
    std::string getName() const override { return "Server-Side Template Injection (SSTI)"; }
    std::string getDescription() const override {
        return "Detects template injection vulnerabilities in server-side template engines";
    }

private:
    struct TemplateEngine {
        std::string name;
        std::vector<std::string> testPayloads;
        std::vector<std::string> successIndicators;
    };

    std::vector<TemplateEngine> engines;

    void initializeEngines();
    bool testJinja2(const std::string& target, int port);
    bool testTwig(const std::string& target, int port);
    bool testFreemarker(const std::string& target, int port);
    bool testVelocity(const std::string& target, int port);
    bool testThymeleaf(const std::string& target, int port);
    bool testHandlebars(const std::string& target, int port);
    bool testMustache(const std::string& target, int port);
    bool testEJS(const std::string& target, int port);
    
    std::string sendTemplatePayload(const std::string& target, int port, const std::string& payload);
    bool checkResponse(const std::string& response, const std::vector<std::string>& indicators);
};
