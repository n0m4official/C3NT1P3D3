#include <iostream>
#include "EternalBlueDetector.h"
#include "MockTarget.h"

int main() {
    MockTarget host1("host1");
    host1.addService("SMB", 445, true);

    EternalBlueDetector detector;
    ModuleResult res = detector.run(host1);

    std::cout << "Module: " << res.id << "\n";
    std::cout << "Target: " << res.targetId << "\n";
    std::cout << "Success: " << (res.success ? "Yes" : "No") << "\n";
    std::cout << "Severity: " << static_cast<int>(res.severity) << "\n";
    std::cout << "Message: " << res.message << "\n";
    std::cout << "Details: " << (res.details.has_value() ? res.details.value() : "") << "\n";

    return 0;
}
