#pragma once
#include "VulnerabilityScanner.h"
#include <string>

// Cloud Metadata Service Exploitation Detector
// Detects SSRF to cloud metadata services (AWS, Azure, GCP, DigitalOcean)
// MITRE ATT&CK: T1552.005 - Unsecured Credentials: Cloud Instance Metadata API
class CloudMetadataDetector : public VulnerabilityScanner {
public:
    CloudMetadataDetector();
    ~CloudMetadataDetector() override = default;

    ScanResult scan(const std::string& target, int port) override;
    std::string getName() const override { return "Cloud Metadata Exploitation"; }
    std::string getDescription() const override {
        return "Detects SSRF to cloud metadata services for credential theft";
    }

private:
    bool testAWSMetadata(const std::string& target, int port);
    bool testAzureMetadata(const std::string& target, int port);
    bool testGCPMetadata(const std::string& target, int port);
    bool testDigitalOceanMetadata(const std::string& target, int port);
    bool testIMDSv2Bypass(const std::string& target, int port);
};
