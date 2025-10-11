#pragma once
#include "VulnerabilityScanner.h"
#include <string>

// Container Escape Vulnerability Detector
// Detects Docker/Kubernetes container escape vulnerabilities
// MITRE ATT&CK: T1611 - Escape to Host
class ContainerEscapeDetector : public VulnerabilityScanner {
public:
    ContainerEscapeDetector();
    ~ContainerEscapeDetector() override = default;

    ScanResult scan(const std::string& target, int port) override;
    std::string getName() const override { return "Container Escape Vulnerabilities"; }
    std::string getDescription() const override {
        return "Detects Docker/Kubernetes container escape vulnerabilities";
    }

private:
    bool testPrivilegedContainer(const std::string& target, int port);
    bool testDockerSocketMount(const std::string& target, int port);
    bool testHostPathMount(const std::string& target, int port);
    bool testCapabilities(const std::string& target, int port);
    bool testKubernetesAPI(const std::string& target, int port);
};
