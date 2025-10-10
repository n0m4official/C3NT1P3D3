#include "MockTarget.h"
#include <iostream>

void MockTarget::addService(const std::string& service, int port, bool open) {
    services_[service] = { port, open };
}

bool MockTarget::isServiceOpen(const std::string& service) const {
    auto it = services_.find(service);
    if (it == services_.end()) return false;
    return it->second.open;
}

std::vector<std::string> MockTarget::listOpenServices() const {
    std::vector<std::string> openServices;
    for (const auto& [name, info] : services_) {
        if (info.open) openServices.push_back(name);
    }
    return openServices;
}

void MockTarget::printInfo() const {
    std::cout << "Target ID: " << id_;
    if (ipAddress_) {
        std::cout << " (" << *ipAddress_ << ")";
    }
    std::cout << "\nOpen services:\n";

    for (const auto& service : listOpenServices()) {
        std::cout << "  - " << service << " (port " << services_.at(service).port << ")\n";
    }
}
