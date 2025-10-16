#pragma once

#include <string>
#include <fstream>
#include <filesystem>
#include <ctime>
#include <iostream>

namespace C3NT1P3D3 {

class LegalAgreementManager {
public:
    // Check if user has accepted the legal agreements
    static bool hasAcceptedAgreements();
    
    // Display legal agreements and prompt for acceptance
    static bool promptForAgreementAcceptance();
    
    // Record user's acceptance
    static void recordAcceptance();
    
    // Get path to acceptance record file
    static std::string getAcceptanceFilePath();
    
    // Display Terms of Service
    static void displayTermsOfService();
    
    // Display EULA
    static void displayEULA();
    
    // Display legal disclaimer
    static void displayDisclaimer();
    
    // Verify acceptance is still valid (not expired)
    static bool isAcceptanceValid();
    
private:
    static constexpr int ACCEPTANCE_VALIDITY_DAYS = 365; // 1 year
    static std::string getHomeDirectory();
};

} // namespace C3NT1P3D3
