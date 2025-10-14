#include "../include/TelnetCleartextDetector.h"

ModuleResult TelnetCleartextDetector::run(const MockTarget& target) {
    ModuleResult result;
    result.id = id();
    result.targetId = target.id();
    result.success = true;
    result.severity = Severity::Critical;
    result.message = "Insecure Telnet service detected";
    
    result.details = "Telnet cleartext protocol detected:\n"
                     "- Port 23 open and accepting connections\n"
                     "- All traffic transmitted in cleartext\n"
                     "- Credentials exposed to network sniffing\n\n"
                     "Impact: Credential theft, session hijacking";
    
    // MITRE ATT&CK mapping
    result.attackTechniqueId = "T1040";
    result.attackTechniqueName = "Network Sniffing";
    result.attackTactics = {"Credential Access", "Discovery"};
    result.mitigations = {
        "IMMEDIATELY disable Telnet service",
        "Use SSH (Secure Shell) instead",
        "Configure firewall to block port 23",
        "Implement SSH key-based authentication"
    };
    result.attackUrl = "https://attack.mitre.org/techniques/T1040/";
    
    return result;
}
