#pragma once
#include <string>
#include <unordered_map>
#include <optional>
#include <vector>

class MockTarget {
public:
    MockTarget(std::string id, std::optional<std::string> ip = std::nullopt)
        : id_(std::move(id)), ipAddress_(std::move(ip)) {
    }

    const std::string& id() const { return id_; }
    const std::optional<std::string>& ip() const { return ipAddress_; }

    // Services simulation
    void addService(const std::string& service, int port, bool open = true);
    bool isServiceOpen(const std::string& service) const;
    std::vector<std::string> listOpenServices() const;

    // Display info
    void printInfo() const;

private:
    std::string id_;
    std::optional<std::string> ipAddress_;

    struct ServiceInfo {
        int port;
        bool open;
    };

    std::unordered_map<std::string, ServiceInfo> services_;
};
