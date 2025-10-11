#pragma once
#include "VulnerabilityScanner.h"
#include <string>

// XML Injection Detector (XPath, XQuery, XML Bomb)
// Detects XML-based injection attacks
// MITRE ATT&CK: T1190 - Exploit Public-Facing Application
class XMLInjectionDetector : public VulnerabilityScanner {
public:
    XMLInjectionDetector();
    ~XMLInjectionDetector() override = default;

    ScanResult scan(const std::string& target, int port) override;
    std::string getName() const override { return "XML Injection"; }
    std::string getDescription() const override {
        return "Detects XPath injection, XQuery injection, and XML bomb attacks";
    }

private:
    bool testXPathInjection(const std::string& target, int port);
    bool testXQueryInjection(const std::string& target, int port);
    bool testXMLBomb(const std::string& target, int port);
    bool testBillionLaughs(const std::string& target, int port);
};
