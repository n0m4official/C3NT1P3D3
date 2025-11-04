#include "../ZeroLogonDetector.h"
#include <iostream>
#include <string>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: ZeroLogonTestHarness <target_ip>" << std::endl;
        return 1;
    }

    std::string target = argv[1];
    ZeroLogonDetector detector;
    
    std::cout << "[TEST] Scanning " << target << " for ZeroLogon vulnerability..." << std::endl;
    
    // Debug output
    std::cout << "[DEBUG] Using RPC binding for target: " << target << std::endl;
    
    try {
        bool vulnerable = detector.detectVulnerability(target);
        
        std::cout << "[STATUS] Target: " << target << std::endl;
        std::cout << "[RESULT] Vulnerable: " << (vulnerable ? "YES" : "NO") << std::endl;
        std::cout << "[SEVERITY] " << (vulnerable ? "CRITICAL" : "NONE") << std::endl;
        
        return vulnerable ? 0 : 1;
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] " << e.what() << std::endl;
        return 2;
    }
}
