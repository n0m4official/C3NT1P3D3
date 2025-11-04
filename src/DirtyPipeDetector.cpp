#include "DirtyPipeDetector.h"
#include "../include/MockTarget.h"
#include <stdexcept>

bool DirtyPipeDetector::detectVulnerability() {
    // On Windows, always return false since DirtyPipe is Linux-specific
#ifdef _WIN32
    return false;
#else
    // Linux implementation would go here
    return false; // Placeholder - real implementation would check kernel version
#endif
}

ModuleResult DirtyPipeDetector::run(const MockTarget& target) {
    ModuleResult result;
    result.id = id();
    result.targetId = target.id();
    
    try {
        bool vulnerable = detectVulnerability();
        result.success = true;
        result.message = vulnerable ? 
            "Dirty Pipe vulnerability detected" : 
            "No Dirty Pipe vulnerability found (or not applicable on this platform)";
        result.severity = vulnerable ? Severity::Critical : Severity::None;
    } catch (const std::exception& e) {
        result.success = false;
        result.message = std::string("Detection failed: ") + e.what();
        result.severity = Severity::Low;
    }
    
    return result;
}
