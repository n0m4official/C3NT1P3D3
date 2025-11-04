#include "../../src/ZeroLogonDetector.h"
#include <iostream>

int main() {
    ZeroLogonDetector detector;
    
    // Test against known vulnerable system (replace with actual test IP)
    std::string testIP = "192.168.1.100";
    bool result = detector.detectVulnerability(testIP);
    
    std::cout << "Testing " << testIP << " - ";
    std::cout << (result ? "VULNERABLE" : "NOT VULNERABLE") << std::endl;
    
    return 0;
}
