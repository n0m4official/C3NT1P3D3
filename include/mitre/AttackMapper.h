#pragma once
#include "AttackTechnique.h"
#include <string>
#include <map>
#include <optional>

namespace C3NT1P3D3 {
namespace MITRE {

class AttackMapper {
public:
    // Get singleton instance
    static AttackMapper& getInstance();
    
    // Map a vulnerability to ATT&CK technique
    std::optional<AttackTechnique> mapVulnerability(const std::string& vulnerabilityName);
    
    // Get all techniques for a given tactic
    std::vector<AttackTechnique> getTechniquesByTactic(Tactic tactic);
    
    // Get technique by ID
    std::optional<AttackTechnique> getTechniqueById(const std::string& techniqueId);
    
private:
    AttackMapper();
    void initializeMappings();
    
    std::map<std::string, AttackTechnique> techniques_;
    std::map<std::string, std::string> vulnerabilityToTechnique_;
};

} // namespace MITRE
} // namespace C3NT1P3D3