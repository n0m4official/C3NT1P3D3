#include "ZeroLogonDetector.h"
#include "WindowsRPCUtils.h"
#include "../include/MockTarget.h"
#include <iostream>
#include <stdexcept>

using std::cout;
using std::endl;

bool ZeroLogonDetector::detectVulnerability(const std::string& target) {
    if (target.empty() || target.find('.') == std::string::npos) {
        throw std::invalid_argument("Invalid target IP");
    }
    try {
        RPCBinding binding(std::wstring(target.begin(), target.end()));
        NETLOGON_CREDENTIAL clientCred = {0};
        NETLOGON_CREDENTIAL serverCred = {0};
        
        for (int i = 0; i < 2000; i++) {
            if (NetrServerReqChallenge(binding, nullptr, nullptr, &clientCred, &serverCred) == NERR_Success) {
                return true;
            }
        }
    } catch (...) {
        return false;
    }
    return false;
}

ModuleResult ZeroLogonDetector::run(const MockTarget& target) {
    ModuleResult result;
    result.id = id();
    result.targetId = target.id();
    
    try {
        bool vulnerable = detectVulnerability(target.ip());
        result.success = true;
        result.message = vulnerable ? 
            "ZeroLogon vulnerability detected" : 
            "No ZeroLogon vulnerability found";
        result.severity = vulnerable ? Severity::Critical : Severity::None;
    } catch (const std::exception& e) {
        result.success = false;
        result.message = std::string("Detection failed: ") + e.what();
        result.severity = Severity::Low;
    }
    
    return result;
}
