#pragma once
#include <string>

// Minimal engine; can be expanded for run-id, logging, scheduling, etc.
class CoreEngine {
public:
    CoreEngine(bool simulationOnly = true);
    ~CoreEngine();

    bool simulationMode() const;
    std::string runId() const;

private:
    struct Impl;
    Impl* pImpl;
};
