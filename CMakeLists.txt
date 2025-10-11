cmake_minimum_required(VERSION 3.20)
project(C3NT1P3D3 LANGUAGES CXX)

# -----------------------------
# C++ standard
# -----------------------------
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# -----------------------------
# Ensure stray GCC flags don't break MSVC builds
# -----------------------------
# Remove common GCC flags if they were injected into cache/environment
string(REPLACE "-Wextra" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
string(REPLACE "-Wall"   "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")

# -----------------------------
# Compiler flags: MSVC vs others
# -----------------------------
if(MSVC)
    # MSVC: use /W3 (or /W4 if you want more verbosity), no -Wall/-Wextra
    set(MSVC_COMMON_FLAGS "/W3 /permissive- /EHsc /Zc:__cplusplus")
    set(CMAKE_CXX_FLAGS_DEBUG  "${MSVC_COMMON_FLAGS} /Od /Zi")
    set(CMAKE_CXX_FLAGS_RELEASE "${MSVC_COMMON_FLAGS} /O2")
else()
    # GCC/Clang
    set(CMAKE_CXX_FLAGS_DEBUG  "-g -Wall -Wextra -O0")
    set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")
endif()

# -----------------------------
# Include directories (project-specific)
# -----------------------------
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
    message(STATUS "No tests/test_ip_validator.cpp found — test target not created.")
endif()

# -----------------------------
# Helpful final messages
# -----------------------------
message(STATUS "Project configured: ${PROJECT_NAME}")
message(STATUS "MSVC: ${MSVC}")
