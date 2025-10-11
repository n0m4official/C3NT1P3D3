#include <iostream>
#include "include/mitre/AttackMapper.h"

using namespace C3NT1P3D3::MITRE;

int main() {
    std::cout << "=== MITRE ATT&CK Mapper Test ===" << std::endl << std::endl;
    
    auto& mapper = AttackMapper::getInstance();
    
    // Test vulnerability mappings
    std::vector<std::string> vulnerabilities = {
        "EternalBlue",
        "Heartbleed", 
        "Shellshock",
        "XSS",
        "SSHBruteForce",
        "FTPAnonymous"
    };
    
    for (const auto& vuln : vulnerabilities) {
        std::cout << "Vulnerability: " << vuln << std::endl;
        
        auto technique = mapper.mapVulnerability(vuln);
        if (technique.has_value()) {
            std::cout << "  Technique ID: " << technique->techniqueId << std::endl;
            std::cout << "  Name: " << technique->name << std::endl;
            std::cout << "  Tactics: ";
            for (size_t i = 0; i < technique->tactics.size(); i++) {
                std::cout << AttackTechnique::tacticToString(technique->tactics[i]);
                if (i < technique->tactics.size() - 1) std::cout << ", ";
            }
            std::cout << std::endl;
            std::cout << "  Description: " << technique->description << std::endl;
            std::cout << "  Mitigations:" << std::endl;
            for (const auto& mitigation : technique->mitigations) {
                std::cout << "    - " << mitigation << std::endl;
            }
            std::cout << "  URL: " << technique->url << std::endl;
        } else {
            std::cout << "  [NOT MAPPED]" << std::endl;
        }
        std::cout << std::endl;
    }
    
    // Test getting techniques by tactic
    std::cout << "=== Techniques by Tactic ===" << std::endl << std::endl;
    
    auto lateralMovement = mapper.getTechniquesByTactic(Tactic::LateralMovement);
    std::cout << "Lateral Movement techniques: " << lateralMovement.size() << std::endl;
    for (const auto& tech : lateralMovement) {
        std::cout << "  - " << tech.techniqueId << ": " << tech.name << std::endl;
    }
    std::cout << std::endl;
    
    auto initialAccess = mapper.getTechniquesByTactic(Tactic::InitialAccess);
    std::cout << "Initial Access techniques: " << initialAccess.size() << std::endl;
    for (const auto& tech : initialAccess) {
        std::cout << "  - " << tech.techniqueId << ": " << tech.name << std::endl;
    }
    std::cout << std::endl;
    
    auto credAccess = mapper.getTechniquesByTactic(Tactic::CredentialAccess);
    std::cout << "Credential Access techniques: " << credAccess.size() << std::endl;
    for (const auto& tech : credAccess) {
        std::cout << "  - " << tech.techniqueId << ": " << tech.name << std::endl;
    }
    
    return 0;
}
