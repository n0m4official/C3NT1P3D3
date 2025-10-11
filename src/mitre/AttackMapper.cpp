#include "../../include/mitre/AttackMapper.h"

namespace C3NT1P3D3 {
namespace MITRE {

// Tactic to string conversion
std::string AttackTechnique::tacticToString(Tactic tactic) {
    switch (tactic) {
        case Tactic::InitialAccess: return "Initial Access";
        case Tactic::Execution: return "Execution";
        case Tactic::Persistence: return "Persistence";
        case Tactic::PrivilegeEscalation: return "Privilege Escalation";
        case Tactic::DefenseEvasion: return "Defense Evasion";
        case Tactic::CredentialAccess: return "Credential Access";
        case Tactic::Discovery: return "Discovery";
        case Tactic::LateralMovement: return "Lateral Movement";
        case Tactic::Collection: return "Collection";
        case Tactic::CommandAndControl: return "Command and Control";
        case Tactic::Exfiltration: return "Exfiltration";
        case Tactic::Impact: return "Impact";
        default: return "Unknown";
    }
}

// Tactic to color (for ATT&CK Navigator)
std::string AttackTechnique::tacticToColor(Tactic tactic) {
    switch (tactic) {
        case Tactic::InitialAccess: return "#ff6666";
        case Tactic::Execution: return "#ff9966";
        case Tactic::LateralMovement: return "#ff66cc";
        case Tactic::Impact: return "#cc0000";
        default: return "#cccccc";
    }
}

AttackMapper& AttackMapper::getInstance() {
    static AttackMapper instance;
    return instance;
}

AttackMapper::AttackMapper() {
    initializeMappings();
}

void AttackMapper::initializeMappings() {
    // TODO: You'll add technique definitions here
    // Example for EternalBlue:
    
    AttackTechnique eternalBlue;
    eternalBlue.techniqueId = "T1210";
    eternalBlue.name = "Exploitation of Remote Services";
    eternalBlue.tactics = {Tactic::LateralMovement};
    eternalBlue.description = "Adversaries may exploit remote services to gain unauthorized access to internal systems.";
    eternalBlue.mitigations = {
        "Apply MS17-010 security patch",
        "Disable SMBv1 protocol",
        "Implement network segmentation",
        "Use application isolation and sandboxing",
        "Enable exploit protection features"
    };
    eternalBlue.url = "https://attack.mitre.org/techniques/T1210/";
    
    techniques_["T1210"] = eternalBlue;
    vulnerabilityToTechnique_["EternalBlue"] = "T1210";
    vulnerabilityToTechnique_["MS17-010"] = "T1210";
    vulnerabilityToTechnique_["EternalBlueDetector"] = "T1210";
    
    // Heartbleed - Network Sniffing
    AttackTechnique heartbleed;
    heartbleed.techniqueId = "T1040";
    heartbleed.name = "Network Sniffing";
    heartbleed.tactics = {Tactic::CredentialAccess, Tactic::Discovery};
    heartbleed.description = "Adversaries may sniff network traffic to capture information about an environment, including authentication material passed over the network.";
    heartbleed.mitigations = {
        "Update OpenSSL to version 1.0.1g or later",
        "Regenerate SSL certificates and private keys",
        "Reset all passwords and session tokens",
        "Implement network segmentation",
        "Use encrypted protocols (TLS 1.3+)",
        "Monitor for unusual network traffic patterns"
    };
    heartbleed.url = "https://attack.mitre.org/techniques/T1040/";
    
    techniques_["T1040"] = heartbleed;
    vulnerabilityToTechnique_["Heartbleed"] = "T1040";
    vulnerabilityToTechnique_["CVE-2014-0160"] = "T1040";
    vulnerabilityToTechnique_["HeartbleedDetector"] = "T1040";
    
    // Shellshock - Exploit Public-Facing Application
    AttackTechnique shellshock;
    shellshock.techniqueId = "T1190";
    shellshock.name = "Exploit Public-Facing Application";
    shellshock.tactics = {Tactic::InitialAccess};
    shellshock.description = "Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network.";
    shellshock.mitigations = {
        "Update Bash to version 4.3 or later",
        "Disable CGI scripts if not needed",
        "Implement web application firewall (WAF)",
        "Use application isolation and sandboxing",
        "Restrict access to web services",
        "Monitor for suspicious HTTP headers"
    };
    shellshock.url = "https://attack.mitre.org/techniques/T1190/";
    
    techniques_["T1190"] = shellshock;
    vulnerabilityToTechnique_["Shellshock"] = "T1190";
    vulnerabilityToTechnique_["CVE-2014-6271"] = "T1190";
    vulnerabilityToTechnique_["ShellshockDetector"] = "T1190";
    
    // Log4Shell - also T1190
    vulnerabilityToTechnique_["Log4Shell"] = "T1190";
    vulnerabilityToTechnique_["CVE-2021-44228"] = "T1190";
    vulnerabilityToTechnique_["Log4ShellDetector"] = "T1190";
    
    // SQL Injection - also T1190
    vulnerabilityToTechnique_["SQLInjection"] = "T1190";
    vulnerabilityToTechnique_["SQLInjectionDetector"] = "T1190";
    
    // XSS - Drive-by Compromise
    AttackTechnique xss;
    xss.techniqueId = "T1189";
    xss.name = "Drive-by Compromise";
    xss.tactics = {Tactic::InitialAccess};
    xss.description = "Adversaries may gain access to a system through a user visiting a website over the normal course of browsing.";
    xss.mitigations = {
        "Implement Content Security Policy (CSP)",
        "Sanitize all user input",
        "Use output encoding",
        "Enable XSS protection headers",
        "Regular security testing",
        "Use modern frameworks with built-in XSS protection"
    };
    xss.url = "https://attack.mitre.org/techniques/T1189/";
    
    techniques_["T1189"] = xss;
    vulnerabilityToTechnique_["XSS"] = "T1189";
    vulnerabilityToTechnique_["CrossSiteScripting"] = "T1189";
    vulnerabilityToTechnique_["XSSDetector"] = "T1189";
    
    // SSH Brute Force - Brute Force
    AttackTechnique sshBrute;
    sshBrute.techniqueId = "T1110";
    sshBrute.name = "Brute Force";
    sshBrute.tactics = {Tactic::CredentialAccess};
    sshBrute.description = "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained.";
    sshBrute.mitigations = {
        "Implement account lockout policies",
        "Use multi-factor authentication (MFA)",
        "Enforce strong password policies",
        "Use SSH key-based authentication",
        "Implement rate limiting",
        "Monitor for failed login attempts"
    };
    sshBrute.url = "https://attack.mitre.org/techniques/T1110/";
    
    techniques_["T1110"] = sshBrute;
    vulnerabilityToTechnique_["SSHBruteForce"] = "T1110";
    vulnerabilityToTechnique_["SSHBruteForceDetector"] = "T1110";
    
    // FTP Anonymous - Valid Accounts
    AttackTechnique ftpAnon;
    ftpAnon.techniqueId = "T1078";
    ftpAnon.name = "Valid Accounts";
    ftpAnon.tactics = {Tactic::InitialAccess, Tactic::Persistence, Tactic::PrivilegeEscalation, Tactic::DefenseEvasion};
    ftpAnon.description = "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.";
    ftpAnon.mitigations = {
        "Disable anonymous FTP access",
        "Implement strong authentication",
        "Use SFTP or FTPS instead of FTP",
        "Regular account audits",
        "Implement least privilege access",
        "Monitor for unauthorized access"
    };
    ftpAnon.url = "https://attack.mitre.org/techniques/T1078/";
    
    techniques_["T1078"] = ftpAnon;
    vulnerabilityToTechnique_["FTPAnonymous"] = "T1078";
    vulnerabilityToTechnique_["FTPAnonymousDetector"] = "T1078";
    
    // BlueKeep - also T1210
    vulnerabilityToTechnique_["BlueKeep"] = "T1210";
    vulnerabilityToTechnique_["CVE-2019-0708"] = "T1210";
    vulnerabilityToTechnique_["BlueKeepDetector"] = "T1210";
    
    // Directory Traversal - also T1190
    vulnerabilityToTechnique_["DirectoryTraversal"] = "T1190";
    vulnerabilityToTechnique_["PathTraversal"] = "T1190";
    vulnerabilityToTechnique_["DirectoryTraversalDetector"] = "T1190";
}

std::optional<AttackTechnique> AttackMapper::mapVulnerability(const std::string& vulnerabilityName) {
    auto it = vulnerabilityToTechnique_.find(vulnerabilityName);
    if (it != vulnerabilityToTechnique_.end()) {
        return getTechniqueById(it->second);
    }
    return std::nullopt;
}

std::optional<AttackTechnique> AttackMapper::getTechniqueById(const std::string& techniqueId) {
    auto it = techniques_.find(techniqueId);
    if (it != techniques_.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::vector<AttackTechnique> AttackMapper::getTechniquesByTactic(Tactic tactic) {
    std::vector<AttackTechnique> result;
    for (const auto& [id, technique] : techniques_) {
        for (auto t : technique.tactics) {
            if (t == tactic) {
                result.push_back(technique);
                break;
            }
        }
    }
    return result;
}

} // namespace MITRE
} // namespace C3NT1P3D3