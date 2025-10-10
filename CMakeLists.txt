cmake_minimum_required(VERSION 3.16)
project(C3NT1P3D3 VERSION 2.0.0)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Compiler flags
set(CMAKE_CXX_FLAGS_DEBUG "-g -Wall -Wextra -O0")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")

# Find required packages
find_package(Threads REQUIRED)

# Include directories
include_directories(include)

# Source files
set(CORE_SOURCES
    src/VulnerabilityDatabase.cpp
    src/IPRangeValidator.cpp
    src/VulnerabilityDatabaseExtended.cpp
    src/EnterpriseScanner.cpp
)

set(DETECTOR_SOURCES
    src/BlueKeepDetector.cpp
    src/CoreEngine.cpp
    src/DirectoryTraversalDetector.cpp
    src/EternalBlueDetector.cpp
    src/FTPAnonymousDetector.cpp
    src/HeartbleedDetector.cpp
    src/Log4ShellDetector.cpp
    src/MockTarget.cpp
    src/ModuleManager.cpp
    src/NetworkScanner.cpp
    src/SQLInjectionDetector.cpp
    src/SSHBruteForceDetector.cpp
    src/ShellshockDetector.cpp
    src/XSSDetector.cpp
)

# Original scanner (legacy)
add_executable(C3NT1P3D3
    src/C3NT1P3D3.cpp
    ${DETECTOR_SOURCES}
)

# Enterprise scanner (legitimate)
add_executable(C3NT1P3D3-Enterprise
    src/C3NT1P3D3-Comprehensive.cpp
    ${DETECTOR_SOURCES}
    ${CORE_SOURCES}
)

# Enterprise demo
add_executable(demo_enterprise_scanner demo_enterprise_scanner.cpp)
target_link_libraries(demo_enterprise_scanner ${CMAKE_THREAD_LIBS_INIT})

# Link libraries
target_link_libraries(C3NT1P3D3 Threads::Threads)
target_link_libraries(C3NT1P3D3-Enterprise Threads::Threads)

# Compiler-specific options
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(C3NT1P3D3 PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(C3NT1P3D3-Enterprise PRIVATE -Wall -Wextra -Wpedantic)
endif()

# Testing
enable_testing()
add_executable(test_ip_validator tests/test_ip_validator.cpp src/IPRangeValidator.cpp)
target_link_libraries(test_ip_validator Threads::Threads)
add_test(NAME IPRangeValidatorTest COMMAND test_ip_validator)
