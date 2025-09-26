#pragma once
#include <string>
#include <optional>
#include "MockTarget.h"

// Severity levels for results
enum class Severity {
    Low,
    Medium,
    High,
	Critical
};

// Structure for module result
struct ModuleResult {
    std::string id;                   // Module ID
    bool success;
    std::string message;
    std::optional<std::string> details;
    Severity severity = Severity::Low;
    std::string targetId;             // The ID of the target scanned
};

// Forward declaration
class MockTarget;

// Module interface
class IModule {
public:
    virtual ~IModule() = default;

    virtual std::string id() const = 0;                       // Module ID
    virtual ModuleResult run(const MockTarget& target) = 0;   // Run module against target
};
