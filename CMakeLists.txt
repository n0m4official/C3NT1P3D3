################################################################################
# C3NT1P3D3 Security Scanner Framework
# CMake Build Configuration
#
# Project: Industry-Leading Vulnerability Detection Framework
# Version: 3.0.0-legendary
# Author: n0m4official
# Date: 2024-10-11
#
# Build Targets:
#   - C3NT1P3D3-Comprehensive: Production scanner with 30 modules
#   - C3NT1P3D3: Development/testing build
#   - test_ip_validator: IP range safety validator tests
#
# Supported Platforms:
#   - Windows (MSVC 2019+, Visual Studio 17 2022)
#   - Linux (GCC 9+, Clang 10+)
#   - macOS (Clang 12+)
#
# Requirements:
#   - CMake 3.20 or higher
#   - C++17 compliant compiler
#   - Threading support (pthreads on Unix, native on Windows)
#
# Build Instructions:
#   mkdir build && cd build
#   cmake .. -G "Visual Studio 17 2022" -A x64  # Windows
#   cmake .. -DCMAKE_BUILD_TYPE=Release         # Linux/macOS
#   cmake --build . --config Release
#
# Module Categories:
#   - Network Vulnerabilities: 6 modules (4 original + 2 new)
#   - Web Application: 26 modules (22 original + 4 new)
#   - Cloud & Container: 2 modules
#   - SSL/TLS: 2 modules
#   - System: 1 module
#   - Total: 37 modules
#
# MITRE ATT&CK Integration:
#   - 37 vulnerability detectors
#   - 20+ unique ATT&CK techniques mapped
#   - 12 tactics covered
#   - 180+ mitigation recommendations
################################################################################

cmake_minimum_required(VERSION 3.20)
project(C3NT1P3D3 
    VERSION 3.0.0
    DESCRIPTION "Industry-Leading Vulnerability Detection Framework"
    LANGUAGES CXX
)

# ========================================================================
# C++ Standard Configuration
# ========================================================================
# Using C++17 for:
# - std::optional (used in ModuleResult)
# - Structured bindings
# - if constexpr
# - std::filesystem (future use)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)  # Disable GNU extensions for portability


# ========================================================================
# Cross-Platform Compiler Flag Sanitization
# ========================================================================
# Remove GCC-specific flags that may have been injected by IDEs or
# environment variables. This prevents MSVC build failures.
string(REPLACE "-Wextra" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
string(REPLACE "-Wall"   "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")


# ========================================================================
# Compiler-Specific Flags
# ========================================================================
if(MSVC)
    # Microsoft Visual C++ Compiler
    # /W3: Warning level 3 (production quality)
    # /permissive-: Enforce standards compliance
    # /EHsc: Enable C++ exception handling
    # /Zc:__cplusplus: Report correct C++ standard version
    set(MSVC_COMMON_FLAGS "/W3 /permissive- /EHsc /Zc:__cplusplus")
    set(CMAKE_CXX_FLAGS_DEBUG  "${MSVC_COMMON_FLAGS} /Od /Zi")      # No optimization, debug info
    set(CMAKE_CXX_FLAGS_RELEASE "${MSVC_COMMON_FLAGS} /O2")         # Speed optimization
else()
    # GCC/Clang (Linux, macOS, MinGW)
    # -Wall -Wextra: Enable comprehensive warnings
    # -O0: No optimization (debug), -O3: Aggressive optimization (release)
    set(CMAKE_CXX_FLAGS_DEBUG  "-g -Wall -Wextra -O0")
    set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")
endif()


# ========================================================================
# Include Directories
# ========================================================================
# All project headers are in include/ subdirectory
# This allows #include "ModuleName.h" syntax throughout the codebase
include_directories(
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/core
    ${PROJECT_SOURCE_DIR}/security
    ${PROJECT_SOURCE_DIR}/simulation
)


# -----------------------------
# Gather sources from your layout
# -----------------------------
file(GLOB_RECURSE SRC_FILES
    "${PROJECT_SOURCE_DIR}/src/*.cpp"
    "${PROJECT_SOURCE_DIR}/core/*.cpp"
    "${PROJECT_SOURCE_DIR}/scanners/*.cpp"
    "${PROJECT_SOURCE_DIR}/simulation/*.cpp"
)


# debug: show what was found
message(STATUS "Found ${SRC_FILES} (count: ${SRC_FILES})")
# To print each file uncomment:
# foreach(f ${SRC_FILES})
#   message(STATUS "  SRC: ${f}")
# endforeach()


# -----------------------------
# Main executable
# -----------------------------
if(NOT SRC_FILES)
    message(FATAL_ERROR "No source files found under src/, core/, scanners/ or simulation/. Check paths.")
endif()


add_executable(C3NT1P3D3 ${SRC_FILES})


# -----------------------------
# SafeScanner static lib handling
# -----------------------------
# Prefer a MSVC .lib if present; otherwise link .a only for non-MSVC toolchains.
if(EXISTS "${PROJECT_SOURCE_DIR}/libSafeScannerLib.lib")
    message(STATUS "Linking libSafeScannerLib.lib (MSVC style) with executable.")
    target_link_libraries(C3NT1P3D3 PRIVATE "${PROJECT_SOURCE_DIR}/libSafeScannerLib.lib")
elseif(EXISTS "${PROJECT_SOURCE_DIR}/libSafeScannerLib.a")
    if(MSVC)
        message(WARNING "Found libSafeScannerLib.a but MSVC prefers .lib. Consider building SafeScanner as a .lib for MSVC.")
    else()
        message(STATUS "Linking libSafeScannerLib.a (GCC/Clang style) with executable.")
        target_link_libraries(C3NT1P3D3 PRIVATE "${PROJECT_SOURCE_DIR}/libSafeScannerLib.a")
    endif()
else()
    message(STATUS "No SafeScanner library found in project root. Skipping linking.")
endif()


# -----------------------------
# Threads (if needed)
# -----------------------------
find_package(Threads QUIET)
if(Threads_FOUND)
    target_link_libraries(C3NT1P3D3 PRIVATE Threads::Threads)
endif()


# -----------------------------
# Tests: simple CTest integration
# -----------------------------
enable_testing()
if(EXISTS "${PROJECT_SOURCE_DIR}/tests/test_ip_validator.cpp")
    add_executable(test_ip_validator "${PROJECT_SOURCE_DIR}/tests/test_ip_validator.cpp" "${PROJECT_SOURCE_DIR}/src/IPRangeValidator.cpp")
    if(Threads_FOUND)
        target_link_libraries(test_ip_validator PRIVATE Threads::Threads)
    endif()
    add_test(NAME IPRangeValidatorTest COMMAND test_ip_validator)
    message(STATUS "Added test_ip_validator target.")
else()
    message(STATUS "No tests/test_ip_validator.cpp found - test target not created.")
endif()


# -----------------------------
# Helpful final messages
# -----------------------------
message(STATUS "Project configured: ${PROJECT_NAME}")
message(STATUS "MSVC: ${MSVC}")


# ========================================================================
# Production executable (README-compliant) - 30 LEGENDARY MODULES
# ========================================================================
add_executable(C3NT1P3D3-Comprehensive 
    # Core infrastructure
    src/C3NT1P3D3-Production.cpp
    src/core/ConfigurationManager.cpp
    src/core/ProductionScanner.cpp
    src/LegalAgreementManager.cpp
    src/simulation/SimulationEngine.cpp
    src/IPRangeValidator.cpp
    src/VulnerabilityDatabase.cpp
    src/ModuleRegistry.cpp
    src/MockTarget.cpp
    src/mitre/AttackMapper.cpp
    
    # ===== NETWORK VULNERABILITY MODULES (6) =====
    src/EternalBlueDetector.cpp
    src/BlueKeepDetector.cpp
    src/SSHBruteForceDetector.cpp
    src/FTPAnonymousDetector.cpp
    src/SNMPWeakCommunityDetector.cpp
    src/TelnetCleartextDetector.cpp
    
    # ===== WEB APPLICATION MODULES (26) =====
    # Original web modules (13)
    src/SQLInjectionDetector.cpp
    src/XSSDetector.cpp
    src/XXEDetector.cpp
    src/SSRFDetector.cpp
    src/CommandInjectionDetector.cpp
    src/LDAPInjectionDetector.cpp
    src/JWTDetector.cpp
    src/GraphQLInjectionDetector.cpp
    src/DeserializationDetector.cpp
    src/CORSDetector.cpp
    src/SubdomainTakeoverDetector.cpp
    src/DirectoryTraversalDetector.cpp
    src/Log4ShellDetector.cpp
    
    # Advanced web modules (9)
    src/SSTIDetector.cpp
    src/NoSQLInjectionDetector.cpp
    src/HTTPRequestSmugglingDetector.cpp
    src/WebSocketVulnDetector.cpp
    src/OAuthOIDCDetector.cpp
    src/APIRateLimitDetector.cpp
    src/XMLInjectionDetector.cpp
    src/RaceConditionDetector.cpp
    src/PrototypePollutionDetector.cpp
    
    # New web modules (4) - LATEST!
    src/CSRFDetector.cpp
    src/IDORDetector.cpp
    src/XPathInjectionDetector.cpp
    src/HostHeaderInjectionDetector.cpp
    
    # ===== CLOUD & CONTAINER MODULES (2) - NEW! =====
    src/CloudMetadataDetector.cpp
    src/ContainerEscapeDetector.cpp
    
    # ===== SSL/TLS MODULES (2) =====
    src/HeartbleedDetector.cpp
    src/WeakCipherDetector.cpp
    
    # ===== SYSTEM MODULES (1) =====
    src/ShellshockDetector.cpp
)

# Link threading library
if(Threads_FOUND)
    target_link_libraries(C3NT1P3D3-Comprehensive PRIVATE Threads::Threads)
endif()

# Windows-specific libraries for network operations
if(WIN32)
    target_link_libraries(C3NT1P3D3-Comprehensive PRIVATE ws2_32 dnsapi)
endif()

# Linux-specific libraries
if(UNIX AND NOT APPLE)
    target_link_libraries(C3NT1P3D3-Comprehensive PRIVATE resolv)
endif()

message(STATUS "========================================================================")
message(STATUS "C3NT1P3D3-Comprehensive - 37 LEGENDARY MODULES")
message(STATUS "========================================================================")
message(STATUS "  Network modules:           6  (4 original + 2 new)")
message(STATUS "  Web Application modules:  26  (13 original + 9 advanced + 4 new)")
message(STATUS "  Cloud & Container modules: 2")
message(STATUS "  SSL/TLS modules:           2")
message(STATUS "  System modules:            1")
message(STATUS "========================================================================")
message(STATUS "Total: 37 vulnerability detectors")
message(STATUS "MITRE ATT&CK: 20+ techniques mapped")
message(STATUS "========================================================================")
message(STATUS "")
message(STATUS "LATEST ADDITIONS (v3.1):")
message(STATUS "  Web: CSRF, IDOR, XPath Injection, Host Header Injection")
message(STATUS "  Network: SNMP Weak Community, Telnet Cleartext")
message(STATUS "========================================================================")
message(STATUS "STATUS: INDUSTRY-LEADING SECURITY SCANNER (v3.1.0-legendary)")
message(STATUS "========================================================================")
