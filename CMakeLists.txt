cmake_minimum_required(VERSION 3.10)
project(C3NT1P3D3 VERSION 1.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Add compiler warnings
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wpedantic -Werror)
elseif(MSVC)
    add_compile_options(/W4 /WX)
endif()

# Platform-specific settings
if(WIN32)
    add_definitions(-D_WIN32_WINNT=0x0601) # Windows 7 and later
    set(PLATFORM_LIBS ws2_32)
else()
    set(PLATFORM_LIBS pthread)
endif()

# Source files
set(SOURCES
    C3NT1P3D3.cpp
    EternalBlueDetector.cpp
    BlueKeepDetector.cpp
    HeartbleedDetector.cpp
    ShellshockDetector.cpp
    SSHBruteForceDetector.cpp
    SQLInjectionDetector.cpp
    Log4ShellDetector.cpp
    XSSDetector.cpp
    FTPAnonymousDetector.cpp
    DirectoryTraversalDetector.cpp
    NetworkScanner.cpp
    MockTarget.cpp
    CoreEngine.cpp
    ModuleManager.cpp
)

# Header files
set(HEADERS
    IModule.h
    EternalBlueDetector.h
    BlueKeepDetector.h
    HeartbleedDetector.h
    ShellshockDetector.h
    SSHBruteForceDetector.h
    SQLInjectionDetector.h
    Log4ShellDetector.h
    XSSDetector.h
    FTPAnonymousDetector.h
    DirectoryTraversalDetector.h
    NetworkScanner.h
    MockTarget.h
    CoreEngine.h
    ModuleManager.h
    IExploit.h
)

# Create executables
add_executable(C3NT1P3D3 ${SOURCES})
add_executable(SafeScanner 
    SafeScanner.cpp
    NetworkScanner.cpp
    ModuleManager.cpp
    MockTarget.cpp
    CoreEngine.cpp
    EternalBlueDetector.cpp
    BlueKeepDetector.cpp
    HeartbleedDetector.cpp
    ShellshockDetector.cpp
    SSHBruteForceDetector.cpp
    SQLInjectionDetector.cpp
    Log4ShellDetector.cpp
    XSSDetector.cpp
    FTPAnonymousDetector.cpp
    DirectoryTraversalDetector.cpp
)

# Link platform-specific libraries
target_link_libraries(C3NT1P3D3 ${PLATFORM_LIBS})
target_link_libraries(SafeScanner ${PLATFORM_LIBS})

# Include directories
target_include_directories(C3NT1P3D3 PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(SafeScanner PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# Install target
install(TARGETS C3NT1P3D3 DESTINATION bin)

# Install headers
install(FILES ${HEADERS} DESTINATION include/C3NT1P3D3)

# Create a simple test target
enable_testing()
add_test(NAME BasicTest COMMAND C3NT1P3D3)

# Package configuration
set(CPACK_PACKAGE_NAME "C3NT1P3D3")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Advanced Vulnerability Scanner")
set(CPACK_PACKAGE_VENDOR "C3NT1P3D3 Team")
include(CPack)