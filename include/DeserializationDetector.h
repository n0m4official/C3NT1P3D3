#pragma once

#include "IModule.h"
#include <string>
#include <vector>
#include <map>

/**
 * @brief Insecure Deserialization Detector
 * 
 * Detects insecure deserialization vulnerabilities in:
 * - Java (ObjectInputStream)
 * - Python (pickle)
 * - PHP (unserialize)
 * - .NET (BinaryFormatter)
 * 
 * MITRE ATT&CK: T1203 - Exploitation for Client Execution
 */
class DeserializationDetector : public IModule {
public:
    std::string id() const override { return "DeserializationDetector"; }
    ModuleResult run(const MockTarget& target) override;

private:
    struct SerializationPayload {
        std::string language;
        std::string payload;
        std::string contentType;
        std::string indicator;
    };

    std::vector<SerializationPayload> getPayloads();
    std::string sendHTTPRequest(const std::string& target, const std::string& payload, 
                                const std::string& contentType);
    bool containsDeserializationIndicator(const std::string& response, const std::string& indicator);
    std::string detectFramework(const std::string& target);
    std::string base64Encode(const std::string& input);
};
