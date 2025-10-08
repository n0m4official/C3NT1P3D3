#include "DirectoryTraversalDetector.h"
#include <iostream>
#include <optional>

// Directory Traversal Vulnerability Detector
ModuleResult DirectoryTraversalDetector::run(const MockTarget& target) {
    // Check if target has HTTP service (web applications)
    if (!target.isServiceOpen("HTTP")) {
        return ModuleResult{
            "DirectoryTraversalDetector",
            false,
            "HTTP service not available on target - directory traversal affects web applications",
            std::nullopt,
            Severity::Low,
            target.id()
        };
    }

    // Get target IP (use mock IP if available, otherwise use target ID)
    std::string targetIp = target.id();
    if (target.ip().has_value()) {
        targetIp = target.ip().value();
    }

    try {
        // Simulate directory traversal vulnerability detection
        // In a real implementation, this would involve:
        // 1. Testing file download functionality
        // 2. Attempting to access files outside web root
        // 3. Testing various path traversal payloads (../, ..\\, %2e%2e%2f, etc.)
        // 4. Checking for file inclusion vulnerabilities
        
        bool potentiallyVulnerable = false;
        std::string details = "HTTP service detected, checking for directory traversal vulnerabilities\n";
        
        // Simulate some basic checks
        if (target.id().find("file") != std::string::npos || 
            target.id().find("download") != std::string::npos ||
            target.id().find("path") != std::string::npos ||
            target.id().find("include") != std::string::npos) {
            potentiallyVulnerable = true;
            details += "Target appears to have file handling functionality\n";
            details += "Potential directory traversal vulnerabilities:\n";
            details += "- File download without path validation\n";
            details += "- File inclusion without proper sanitization\n";
            details += "- URL parameters used as file paths\n";
            details += "- Template inclusion vulnerabilities\n";
            details += "Impact: File system access, source code disclosure, configuration file access\n";
        }

        if (potentiallyVulnerable) {
            return ModuleResult{
                "DirectoryTraversalDetector",
                true,
                "Target potentially vulnerable to directory traversal attacks",
                details,
                Severity::High,
                target.id()
            };
        } else {
            return ModuleResult{
                "DirectoryTraversalDetector",
                false,
                "Target does not appear vulnerable to directory traversal",
                details,
                Severity::Low,
                target.id()
            };
        }
    }
    catch (const std::exception& ex) {
        return ModuleResult{
            "DirectoryTraversalDetector",
            false,
            std::string("Exception during directory traversal scan: ") + ex.what(),
            std::nullopt,
            Severity::Low,
            target.id()
        };
    }
}