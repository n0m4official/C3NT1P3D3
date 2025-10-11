#pragma once

#include "IModule.h"
#include <string>
#include <vector>

/**
 * @brief GraphQL Injection Detector
 * 
 * Detects GraphQL-specific vulnerabilities including:
 * - Introspection enabled (information disclosure)
 * - Batch query attacks
 * - Depth-based DoS
 * - Field duplication attacks
 * 
 * MITRE ATT&CK: T1190 - Exploit Public-Facing Application
 */
class GraphQLInjectionDetector : public IModule {
public:
    std::string id() const override { return "GraphQLInjectionDetector"; }
    ModuleResult run(const MockTarget& target) override;

private:
    struct GraphQLTest {
        std::string name;
        std::string query;
        std::string expectedPattern;
    };

    bool testIntrospection(const std::string& target);
    bool testBatchQuery(const std::string& target);
    bool testDepthAttack(const std::string& target);
    std::string sendGraphQLQuery(const std::string& target, const std::string& query);
    std::vector<std::string> getGraphQLEndpoints();
    bool containsSchemaInfo(const std::string& response);
};
