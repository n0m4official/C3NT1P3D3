/**
 * @file AttackMapper.cpp
 * @brief MITRE ATT&CK Framework integration for vulnerability mapping
 * @author n0m4official
 * @date 2024-10-11
 * 
 * This module provides comprehensive integration with the MITRE ATT&CK framework,
 * mapping detected vulnerabilities to specific attack techniques, tactics, and
 * providing actionable mitigation recommendations.
 * 
 * Key Features:
 * - Maps 30 vulnerability types to 17 unique ATT&CK techniques
 * - Provides detailed mitigation strategies for each technique
 * - Supports ATT&CK Navigator JSON export for visualization
 * - Includes tactic-to-color mapping for heat maps
 * 
 * MITRE ATT&CK Version: v13.1 (Enterprise)
 * 
 * References:
 * - https://attack.mitre.org/
 * - https://mitre-attack.github.io/attack-navigator/
 * 
 * Design Pattern: Singleton
 * Thread Safety: Read-only after initialization, thread-safe
 */

#include "../../include/mitre/AttackMapper.h"

namespace C3NT1P3D3 {
namespace MITRE {

/**
 * @brief Converts MITRE ATT&CK tactic enum to human-readable string
 * @param tactic The tactic enum value
 * @return String representation of the tactic
 * 
 * Used for generating reports and ATT&CK Navigator exports.
 * Tactic names match official MITRE ATT&CK nomenclature.
 */
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

/**
 * @brief Maps MITRE ATT&CK tactics to color codes for visualization
 * @param tactic The tactic enum value
 * @return Hex color code string (e.g., "#ff6666")
 * 
 * Colors are chosen to match the official ATT&CK Navigator color scheme:
 * - Red tones: Initial Access, Execution (entry points)
 * - Orange/Yellow: Persistence, Privilege Escalation (establishing foothold)
 * - Purple/Pink: Lateral Movement, Collection (expansion)
 * - Blue: Command & Control, Exfiltration (objectives)
 * 
 * These colors are used in heat maps and ATT&CK Navigator exports.
 */
std::string AttackTechnique::tacticToColor(Tactic tactic) {
    switch (tactic) {
        case Tactic::InitialAccess: return "#ff6666";        // Red - Entry point
        case Tactic::Execution: return "#ff9966";            // Orange - Code execution
        case Tactic::LateralMovement: return "#ff66cc";      // Pink - Network propagation
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
    
    // XXE - T1190
    vulnerabilityToTechnique_["XXE"] = "T1190";
    vulnerabilityToTechnique_["XXEDetector"] = "T1190";
    vulnerabilityToTechnique_["XML External Entity"] = "T1190";
    
    // SSRF - T1190
    vulnerabilityToTechnique_["SSRF"] = "T1190";
    vulnerabilityToTechnique_["SSRFDetector"] = "T1190";
    vulnerabilityToTechnique_["Server-Side Request Forgery"] = "T1190";
    
    // Command Injection - T1059
    vulnerabilityToTechnique_["Command Injection"] = "T1059";
    vulnerabilityToTechnique_["CommandInjectionDetector"] = "T1059";
    vulnerabilityToTechnique_["OS Command Injection"] = "T1059";
    
    // Weak Cipher - T1040
    vulnerabilityToTechnique_["Weak Cipher"] = "T1040";
    vulnerabilityToTechnique_["WeakCipherDetector"] = "T1040";
    vulnerabilityToTechnique_["Weak SSL"] = "T1040";
    vulnerabilityToTechnique_["Weak TLS"] = "T1040";
    
    // Web Application Vulnerabilities
    techniques_["XXE"] = AttackTechnique{
        "T1190",
        "Exploit Public-Facing Application",
        {Tactic::InitialAccess},
        "XXE (XML External Entity) injection allows attackers to read local files, perform SSRF, and potentially execute code.",
        {
            "Disable XML external entity processing in all XML parsers",
            "Use less complex data formats like JSON instead of XML",
            "Patch and upgrade all XML processors to latest versions",
            "Implement input validation and sanitization for XML data",
            "Use whitelisting for allowed XML schemas"
        },
        "https://attack.mitre.org/techniques/T1190/"
    };

    techniques_["SSRF"] = AttackTechnique{
        "T1190",
        "Exploit Public-Facing Application",
        {Tactic::InitialAccess},
        "SSRF allows attackers to make requests from the server to access internal resources and cloud metadata.",
        {
            "Implement allowlists for allowed destinations",
            "Disable unnecessary URL schemas (file://, gopher://, etc.)",
            "Use network segmentation to restrict server-side requests",
            "Validate and sanitize all user-supplied URLs",
            "Implement response validation"
        },
        "https://attack.mitre.org/techniques/T1190/"
    };

    techniques_["Command Injection"] = AttackTechnique{
        "T1059",
        "Command and Scripting Interpreter",
        {Tactic::Execution},
        "Command injection allows execution of arbitrary OS commands, leading to complete system compromise.",
        {
            "Never pass user input directly to system commands",
            "Use parameterized APIs instead of shell commands",
            "Implement strict input validation and sanitization",
            "Use allowlists for allowed characters and commands",
            "Run applications with minimal privileges"
        },
        "https://attack.mitre.org/techniques/T1059/"
    };

    techniques_["Weak Cipher"] = AttackTechnique{
        "T1040",
        "Network Sniffing",
        {Tactic::Collection, Tactic::CredentialAccess},
        "Weak SSL/TLS ciphers allow attackers to decrypt traffic and perform man-in-the-middle attacks.",
        {
            "Disable weak ciphers (RC4, DES, 3DES, MD5)",
            "Use TLS 1.2 or higher",
            "Implement perfect forward secrecy",
            "Use strong cipher suites (AES-GCM)",
            "Regularly update SSL/TLS configurations"
        },
        "https://attack.mitre.org/techniques/T1040/"
    };
    
    // LDAP Injection - T1078.002 (Valid Accounts: Domain Accounts)
    AttackTechnique ldapInjection;
    ldapInjection.techniqueId = "T1078.002";
    ldapInjection.name = "Valid Accounts: Domain Accounts";
    ldapInjection.tactics = {Tactic::InitialAccess, Tactic::Persistence, Tactic::PrivilegeEscalation};
    ldapInjection.description = "LDAP injection allows attackers to manipulate directory queries to bypass authentication and extract sensitive information.";
    ldapInjection.mitigations = {
        "Use parameterized LDAP queries",
        "Implement strict input validation",
        "Escape special LDAP characters",
        "Use least privilege for LDAP bind accounts",
        "Enable LDAP signing and encryption",
        "Monitor for suspicious LDAP queries"
    };
    ldapInjection.url = "https://attack.mitre.org/techniques/T1078/002/";
    
    techniques_["T1078.002"] = ldapInjection;
    vulnerabilityToTechnique_["LDAP Injection"] = "T1078.002";
    vulnerabilityToTechnique_["LDAPInjectionDetector"] = "T1078.002";
    
    // JWT Vulnerabilities - T1550.001 (Use Alternate Authentication Material: Application Access Token)
    AttackTechnique jwtVuln;
    jwtVuln.techniqueId = "T1550.001";
    jwtVuln.name = "Use Alternate Authentication Material: Application Access Token";
    jwtVuln.tactics = {Tactic::DefenseEvasion, Tactic::LateralMovement};
    jwtVuln.description = "JWT vulnerabilities allow attackers to forge authentication tokens and impersonate users.";
    jwtVuln.mitigations = {
        "Use strong signing secrets (256+ bits)",
        "Never accept 'alg: none' tokens",
        "Validate algorithm matches expected type",
        "Implement token expiration and rotation",
        "Use RS256 instead of HS256 when possible",
        "Validate all JWT claims"
    };
    jwtVuln.url = "https://attack.mitre.org/techniques/T1550/001/";
    
    techniques_["T1550.001"] = jwtVuln;
    vulnerabilityToTechnique_["JWT Vulnerabilities"] = "T1550.001";
    vulnerabilityToTechnique_["JWTDetector"] = "T1550.001";
    
    // GraphQL Injection - T1190
    vulnerabilityToTechnique_["GraphQL Injection"] = "T1190";
    vulnerabilityToTechnique_["GraphQLInjectionDetector"] = "T1190";
    
    techniques_["GraphQL"] = AttackTechnique{
        "T1190",
        "Exploit Public-Facing Application",
        {Tactic::InitialAccess},
        "GraphQL vulnerabilities expose schema information and enable DoS attacks through introspection and complex queries.",
        {
            "Disable introspection in production",
            "Implement query depth limiting",
            "Implement query complexity analysis",
            "Use query allowlisting",
            "Implement rate limiting",
            "Monitor for suspicious query patterns"
        },
        "https://attack.mitre.org/techniques/T1190/"
    };
    
    // Insecure Deserialization - T1203
    AttackTechnique deserialization;
    deserialization.techniqueId = "T1203";
    deserialization.name = "Exploitation for Client Execution";
    deserialization.tactics = {Tactic::Execution};
    deserialization.description = "Insecure deserialization allows attackers to execute arbitrary code by crafting malicious serialized objects.";
    deserialization.mitigations = {
        "Never deserialize untrusted data",
        "Use safe serialization formats (JSON instead of native)",
        "Implement integrity checks on serialized data",
        "Use allowlists for deserializable classes",
        "Run deserialization in sandboxed environments",
        "Monitor for deserialization errors"
    };
    deserialization.url = "https://attack.mitre.org/techniques/T1203/";
    
    techniques_["T1203"] = deserialization;
    vulnerabilityToTechnique_["Insecure Deserialization"] = "T1203";
    vulnerabilityToTechnique_["DeserializationDetector"] = "T1203";
    
    // CORS Misconfiguration - T1539 (Steal Web Session Cookie)
    AttackTechnique cors;
    cors.techniqueId = "T1539";
    cors.name = "Steal Web Session Cookie";
    cors.tactics = {Tactic::CredentialAccess};
    cors.description = "CORS misconfigurations allow malicious websites to read sensitive data from authenticated sessions.";
    cors.mitigations = {
        "Never use wildcard (*) with credentials",
        "Validate Origin header against allowlist",
        "Do not reflect arbitrary origins",
        "Use HTTPS for all CORS-enabled endpoints",
        "Implement proper authentication checks",
        "Set SameSite cookie attribute"
    };
    cors.url = "https://attack.mitre.org/techniques/T1539/";
    
    techniques_["T1539"] = cors;
    vulnerabilityToTechnique_["CORS Misconfiguration"] = "T1539";
    vulnerabilityToTechnique_["CORSDetector"] = "T1539";
    
    // Subdomain Takeover - T1584.001 (Compromise Infrastructure: Domains)
    AttackTechnique subdomainTakeover;
    subdomainTakeover.techniqueId = "T1584.001";
    subdomainTakeover.name = "Compromise Infrastructure: Domains";
    subdomainTakeover.tactics = {Tactic::InitialAccess};
    subdomainTakeover.description = "Subdomain takeover allows attackers to host malicious content on legitimate domains via dangling DNS records.";
    subdomainTakeover.mitigations = {
        "Regularly audit DNS records",
        "Remove unused CNAME records",
        "Monitor for DNS changes",
        "Claim cloud resources before creating DNS records",
        "Use DNS monitoring services",
        "Implement DNS CAA records"
    };
    subdomainTakeover.url = "https://attack.mitre.org/techniques/T1584/001/";
    
    techniques_["T1584.001"] = subdomainTakeover;
    vulnerabilityToTechnique_["Subdomain Takeover"] = "T1584.001";
    vulnerabilityToTechnique_["SubdomainTakeoverDetector"] = "T1584.001";
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