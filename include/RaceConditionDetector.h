#pragma once
#include "VulnerabilityScanner.h"
#include <string>

// Race Condition Detector (TOCTOU, Business Logic)
// Detects Time-of-Check Time-of-Use and business logic race conditions
// MITRE ATT&CK: T1068 - Exploitation for Privilege Escalation
class RaceConditionDetector : public VulnerabilityScanner {
public:
    RaceConditionDetector();
    ~RaceConditionDetector() override = default;

    ScanResult scan(const std::string& target, int port) override;
    std::string getName() const override { return "Race Condition Vulnerabilities"; }
    std::string getDescription() const override {
        return "Detects TOCTOU and business logic race conditions";
    }

private:
    bool testTOCTOU(const std::string& target, int port);
    bool testBusinessLogicRace(const std::string& target, int port);
    bool testFileRace(const std::string& target, int port);
    bool testPaymentRace(const std::string& target, int port);
};
