#include "../include/core/LegalAgreementManager.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <ctime>
#include <filesystem>
#include <chrono>
#include <limits>
#include <string>

#ifdef _WIN32
#define NOMINMAX  // Prevent Windows.h from defining min/max macros
#include <windows.h>
#include <shlobj.h>
#else
#include <unistd.h>
#include <pwd.h>
#endif

namespace C3NT1P3D3 {

std::string LegalAgreementManager::getHomeDirectory() {
#ifdef _WIN32
    char path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_PROFILE, NULL, 0, path))) {
        return std::string(path);
    }
    return "";
#else
    const char* home = getenv("HOME");
    if (home) return std::string(home);
    
    struct passwd* pw = getpwuid(getuid());
    if (pw) return std::string(pw->pw_dir);
    
    return "";
#endif
}

std::string LegalAgreementManager::getAcceptanceFilePath() {
    std::string home = getHomeDirectory();
    if (home.empty()) {
        return ".c3nt1p3d3_legal_acceptance";
    }
    
#ifdef _WIN32
    return home + "\\.c3nt1p3d3_legal_acceptance";
#else
    return home + "/.c3nt1p3d3_legal_acceptance";
#endif
}

bool LegalAgreementManager::hasAcceptedAgreements() {
    std::string filepath = getAcceptanceFilePath();
    return std::filesystem::exists(filepath) && isAcceptanceValid();
}

bool LegalAgreementManager::isAcceptanceValid() {
    std::string filepath = getAcceptanceFilePath();
    if (!std::filesystem::exists(filepath)) {
        return false;
    }
    
    std::ifstream file(filepath);
    if (!file.is_open()) {
        return false;
    }
    
    std::string line;
    std::getline(file, line); // Skip version line
    std::getline(file, line); // Get timestamp line
    file.close();
    
    if (line.find("ACCEPTED_TIMESTAMP=") != 0) {
        return false;
    }
    
    try {
        std::time_t acceptedTime = std::stoll(line.substr(19));
        std::time_t currentTime = std::time(nullptr);
        
        // Check if acceptance is still valid (within validity period)
        double daysDiff = std::difftime(currentTime, acceptedTime) / (60 * 60 * 24);
        return daysDiff <= ACCEPTANCE_VALIDITY_DAYS;
    } catch (...) {
        return false;
    }
}

void LegalAgreementManager::displayTermsOfService() {
    std::cout << R"(
╔══════════════════════════════════════════════════════════════════════════════╗
║                         TERMS OF SERVICE - REQUIRED READING                  ║
╚══════════════════════════════════════════════════════════════════════════════╝

C3NT1P3D3 Security Scanner - Terms of Service
Version 1.1 | Effective Date: October 11, 2025
Governing Law: Province of Alberta, Canada

IMPORTANT LEGAL NOTICE:
This software is governed by Canadian law, specifically the laws of the Province 
of Alberta and the Criminal Code of Canada. By using this software, you agree to 
be bound by these Terms of Service.

1. ACCEPTANCE OF TERMS
   By using C3NT1P3D3, you agree to these Terms of Service and acknowledge that
   you have read, understood, and agree to be legally bound by them.

2. AUTHORIZATION REQUIREMENT (MANDATORY)
   You MUST obtain explicit written authorization before scanning ANY system.
   Failure to obtain authorization is a criminal offense under:
   - Criminal Code of Canada, Section 342.1 (Unauthorized use of computer)
   - Maximum penalty: 10 years imprisonment
   
3. PROHIBITED USES
   You shall NOT:
   - Use without proper written authorization
   - Scan systems you do not own or have permission to test
   - Use for malicious, illegal, or unauthorized purposes
   - Exceed the scope of your authorization
   
4. DISCLAIMER OF WARRANTIES
   THE SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND.
   
5. LIMITATION OF LIABILITY
   The developer (n0m4official) shall NOT be liable for any damages arising
   from your use of this software. Maximum liability: CAD $50.00.
   
6. INDEMNIFICATION
   You agree to indemnify and hold harmless the developer from any claims
   arising from your use or misuse of this software.

7. GOVERNING LAW AND JURISDICTION
   These Terms are governed by the laws of Alberta, Canada. Any disputes shall
   be resolved exclusively in Alberta courts.

CRIMINAL LIABILITY WARNING:
Unauthorized use of this software may result in:
- Criminal prosecution under the Criminal Code of Canada
- Up to 10 years imprisonment
- Substantial fines and criminal record
- Civil liability and damages

For complete Terms of Service, see: docs/legal/TERMS-OF-SERVICE.md

)" << std::endl;
}

void LegalAgreementManager::displayEULA() {
    std::cout << R"(
╔══════════════════════════════════════════════════════════════════════════════╗
║                END-USER LICENSE AGREEMENT (EULA) - REQUIRED READING          ║
╚══════════════════════════════════════════════════════════════════════════════╝

C3NT1P3D3 Security Scanner - End-User License Agreement
Version 1.1 | Effective Date: October 11, 2025
Governing Law: Province of Alberta, Canada

IMPORTANT: READ CAREFULLY BEFORE USING THIS SOFTWARE

This is a legally binding agreement between you and n0m4official (sole developer).

1. LICENSE GRANT
   Subject to your compliance with this Agreement, you are granted a limited,
   non-exclusive, non-transferable, revocable license to use this software for
   AUTHORIZED security testing purposes only.

2. MANDATORY AUTHORIZATION REQUIREMENT
   You MUST obtain explicit written authorization from system owners before
   conducting ANY security testing. This is NON-NEGOTIABLE.
   
   Authorization must include:
   - Written permission from authorized personnel
   - Defined scope of testing
   - Time period for testing
   - Emergency contact information

3. PROHIBITED ACTIVITIES (CRIMINAL OFFENSES)
   You expressly agree NOT to:
   - Access systems without authorization (Criminal Code s.342.1)
   - Exceed authorized scope
   - Use for malicious purposes
   - Deploy malware or cause damage
   - Violate privacy laws (PIPEDA)

4. NO WARRANTY
   THE SOFTWARE IS PROVIDED "AS IS" WITHOUT ANY WARRANTY.
   You use this software at your own risk.

5. LIMITATION OF LIABILITY
   IN NO EVENT SHALL THE DEVELOPER BE LIABLE FOR:
   - Criminal prosecution or conviction
   - Civil liability or damages
   - Loss of data, profits, or business
   - Any direct, indirect, or consequential damages
   
   MAXIMUM LIABILITY: CAD $50.00

6. INDEMNIFICATION (MANDATORY)
   You agree to indemnify, defend, and hold harmless the developer from ALL
   claims, damages, losses, and expenses (including legal fees) arising from
   your use or misuse of this software.

7. ACKNOWLEDGMENT OF CRIMINAL LIABILITY RISK
   You explicitly acknowledge that:
   - Unauthorized use is a CRIMINAL OFFENSE in Canada
   - Penalties include up to 10 years imprisonment
   - The developer CANNOT protect you from prosecution
   - You accept COMPLETE responsibility for your actions

8. GOVERNING LAW
   This Agreement is governed by the laws of Alberta, Canada and the Criminal
   Code of Canada. Disputes shall be resolved in Alberta courts.

9. ACCEPTANCE
   BY USING THIS SOFTWARE, YOU ACCEPT ALL TERMS AND CONDITIONS.
   IF YOU DO NOT ACCEPT, DO NOT USE THIS SOFTWARE.

For complete EULA, see: docs/legal/LICENSE-AGREEMENT.md

)" << std::endl;
}

void LegalAgreementManager::displayDisclaimer() {
    std::cout << R"(
╔══════════════════════════════════════════════════════════════════════════════╗
║                      LEGAL DISCLAIMER - CRITICAL WARNING                     ║
╚══════════════════════════════════════════════════════════════════════════════╝

⚠️  UNAUTHORIZED USE OF THIS SOFTWARE IS A CRIMINAL OFFENSE ⚠️

CRIMINAL CODE OF CANADA - SECTION 342.1
"Every person who, fraudulently and without colour of right, obtains, directly
or indirectly, any computer service... is guilty of an indictable offence and
liable to imprisonment for a term of not more than 10 years."

YOU MUST HAVE "COLOUR OF RIGHT" (AUTHORIZATION) TO USE THIS SOFTWARE.

MAXIMUM LIABILITY DISCLAIMER:
The developer's total liability shall NOT exceed CAD $50.00 under any
circumstances. You accept ALL risks associated with using this software.

USER RESPONSIBILITY:
By using this software, you acknowledge and agree that:

1. ✓ You will ONLY use this software on systems you own or have explicit
     written authorization to test
     
2. ✓ You understand that unauthorized use is a CRIMINAL OFFENSE punishable
     by up to 10 years imprisonment in Canada
     
3. ✓ You accept COMPLETE responsibility for your actions and any legal
     consequences
     
4. ✓ You will indemnify and hold harmless the developer from ANY claims
     arising from your use or misuse
     
5. ✓ You understand the developer provides NO WARRANTY and NO PROTECTION
     from criminal prosecution
     
6. ✓ You have consulted with legal counsel if necessary and understand
     applicable laws in your jurisdiction

GOVERNING LAW:
This disclaimer is governed by the laws of Alberta, Canada and the Criminal
Code of Canada.

NO WARRANTY:
THE SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND.

For complete disclaimer, see: docs/legal/DISCLAIMER.md

)" << std::endl;
}

bool LegalAgreementManager::promptForAgreementAcceptance() {
    std::cout << "\n";
    std::cout << "╔══════════════════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                    LEGAL AGREEMENTS REQUIRED TO PROCEED                      ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════════════════════╝\n";
    std::cout << "\n";
    std::cout << "Before using C3NT1P3D3, you MUST read and accept the following legal documents:\n";
    std::cout << "  1. Terms of Service\n";
    std::cout << "  2. End-User License Agreement (EULA)\n";
    std::cout << "  3. Legal Disclaimer\n";
    std::cout << "\n";
    std::cout << "These agreements are legally binding under Alberta and Canadian law.\n";
    std::cout << "\n";
    std::cout << "Press ENTER to view Terms of Service..." << std::flush;
    std::cin.get();
    
    displayTermsOfService();
    
    std::cout << "\nPress ENTER to view End-User License Agreement (EULA)..." << std::flush;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::cin.get();
    
    displayEULA();
    
    std::cout << "\nPress ENTER to view Legal Disclaimer..." << std::flush;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::cin.get();
    
    displayDisclaimer();
    
    std::cout << "\n";
    std::cout << "╔══════════════════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                           ACCEPTANCE REQUIRED                                ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════════════════════╝\n";
    std::cout << "\n";
    std::cout << "By typing 'I ACCEPT' below, you acknowledge that:\n";
    std::cout << "\n";
    std::cout << "  ✓ You have read and understood all legal agreements\n";
    std::cout << "  ✓ You agree to be legally bound by these terms\n";
    std::cout << "  ✓ You will only use this software with proper authorization\n";
    std::cout << "  ✓ You understand unauthorized use is a criminal offense\n";
    std::cout << "  ✓ You accept complete responsibility for your actions\n";
    std::cout << "  ✓ You will indemnify the developer from any claims\n";
    std::cout << "  ✓ You understand this is governed by Alberta/Canadian law\n";
    std::cout << "\n";
    std::cout << "Complete legal documents are available in the docs/legal/ directory.\n";
    std::cout << "\n";
    std::cout << "Type 'I ACCEPT' to accept these terms (or 'DECLINE' to exit): ";
    
    std::string response;
    std::getline(std::cin, response);
    
    // Trim whitespace
    response.erase(0, response.find_first_not_of(" \t\n\r"));
    response.erase(response.find_last_not_of(" \t\n\r") + 1);
    
    if (response == "I ACCEPT") {
        recordAcceptance();
        std::cout << "\n✓ Legal agreements accepted and recorded.\n";
        std::cout << "  Acceptance timestamp: " << std::time(nullptr) << "\n";
        std::cout << "  Valid for: " << ACCEPTANCE_VALIDITY_DAYS << " days\n";
        std::cout << "  Governed by: Laws of Alberta, Canada\n";
        std::cout << "\n";
        return true;
    } else {
        std::cout << "\n✗ Legal agreements NOT accepted.\n";
        std::cout << "  You must accept the legal agreements to use this software.\n";
        std::cout << "  Exiting...\n\n";
        return false;
    }
}

void LegalAgreementManager::recordAcceptance() {
    std::string filepath = getAcceptanceFilePath();
    std::ofstream file(filepath);
    
    if (file.is_open()) {
        std::time_t now = std::time(nullptr);
        file << "C3NT1P3D3_LEGAL_ACCEPTANCE_VERSION=1.1\n";
        file << "ACCEPTED_TIMESTAMP=" << now << "\n";
        file << "ACCEPTED_DATE=" << std::ctime(&now);
        file << "TERMS_VERSION=1.1\n";
        file << "EULA_VERSION=1.1\n";
        file << "DISCLAIMER_VERSION=1.0\n";
        file << "GOVERNING_LAW=Alberta, Canada\n";
        file << "JURISDICTION=Alberta Courts\n";
        file << "DEVELOPER=n0m4official\n";
        file << "USER_IP="; // Could add IP logging if needed
        file << "\n";
        file << "LEGAL_NOTICE=This acceptance is recorded for compliance purposes.\n";
        file << "LEGAL_NOTICE=Unauthorized use remains a criminal offense.\n";
        file << "LEGAL_NOTICE=This acceptance does not grant authorization to scan systems.\n";
        file << "LEGAL_NOTICE=You must obtain separate written authorization from system owners.\n";
        file.close();
        
#ifndef _WIN32
        // Set file permissions to user-only on Unix-like systems
        std::filesystem::permissions(filepath, 
            std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
            std::filesystem::perm_options::replace);
#endif
    }
}

} // namespace C3NT1P3D3
