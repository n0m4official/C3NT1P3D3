#pragma once
#include <string>
#include <vector>

namespace C3NT1P3D3 {
namespace MITRE {

// ATT&CK Tactics (the "why")
enum class Tactic {
    InitialAccess,
    Execution,
    Persistence,
    PrivilegeEscalation,
    DefenseEvasion,
    CredentialAccess,
    Discovery,
    LateralMovement,
    Collection,
    CommandAndControl,
    Exfiltration,
    Impact
};

// ATT&CK Technique information
struct AttackTechnique {
    std::string techniqueId;        // e.g., "T1210"
    std::string name;                // e.g., "Exploitation of Remote Services"
    std::vector<Tactic> tactics;     // Which tactics this technique belongs to
    std::string description;         // What it does
    std::vector<std::string> mitigations;  // How to defend against it
    std::string url;                 // Link to MITRE page
    
    // Helper to convert tactic to string
    static std::string tacticToString(Tactic tactic);
    
    // Helper to get tactic color for Navigator
    static std::string tacticToColor(Tactic tactic);
};

} // namespace MITRE
} // namespace C3NT1P3D3