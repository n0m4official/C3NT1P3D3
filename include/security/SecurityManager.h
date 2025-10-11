#ifndef SECURITY_MANAGER_H
#define SECURITY_MANAGER_H

#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include <mutex>
#include <map>

namespace C3NT1P3D3 {

enum class UserRole {
    GUEST,
    USER,
    ADMINISTRATOR,
    SECURITY_ADMIN
};

struct User {
    std::string username;
    std::string email;
    UserRole role;
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point last_login;
    bool is_active;
    std::vector<std::string> permissions;
};

struct SecurityEvent {
    std::string event_type;
    std::string username;
    std::string ip_address;
    std::string details;
    std::chrono::system_clock::time_point timestamp;
    std::string severity;
};

class SecurityManager {
public:
    static SecurityManager& getInstance();
    
    // Authentication
    bool authenticateUser(const std::string& username, const std::string& password);
    bool authenticateToken(const std::string& token);
    std::string generateToken(const std::string& username);
    void invalidateToken(const std::string& token);
    
    // Authorization
    bool hasPermission(const std::string& username, const std::string& permission);
    bool hasRole(const std::string& username, UserRole role);
    std::vector<std::string> getUserPermissions(const std::string& username);
    
    // User management
    bool createUser(const std::string& username, const std::string& password, 
                   const std::string& email, UserRole role);
    bool updateUser(const std::string& username, const std::string& email, UserRole role);
    bool deactivateUser(const std::string& username);
    User getUser(const std::string& username);
    
    // Audit logging
    void logSecurityEvent(const std::string& event_type, const std::string& username,
                         const std::string& ip_address, const std::string& details,
                         const std::string& severity = "INFO");
    std::vector<SecurityEvent> getSecurityEvents(const std::string& username = "",
                                                const std::string& event_type = "",
                                                int limit = 100);
    
    // Encryption
    std::string encryptData(const std::string& data);
    std::string decryptData(const std::string& encrypted_data);
    
    // Rate limiting
    bool checkRateLimit(const std::string& identifier, const std::string& action, 
                       int max_attempts, std::chrono::seconds time_window);
    void resetRateLimit(const std::string& identifier, const std::string& action);
    
    // Security validation
    bool validatePassword(const std::string& password);
    bool validateUsername(const std::string& username);
    std::string hashPassword(const std::string& password);
    
    // Session management
    std::string createSession(const std::string& username, const std::string& ip_address);
    bool validateSession(const std::string& session_id);
    void terminateSession(const std::string& session_id);
    
private:
    SecurityManager();
    ~SecurityManager();
    
    std::string generateSalt();
    bool verifyPassword(const std::string& password, const std::string& hash);
    void cleanupExpiredSessions();
    
    mutable std::mutex security_mutex_;
    std::map<std::string, User> users_;
    std::map<std::string, std::string> tokens_;
    std::map<std::string, std::pair<std::chrono::system_clock::time_point, std::string>> sessions_;
    std::vector<SecurityEvent> security_events_;
    
    static std::unique_ptr<SecurityManager> instance_;
};

} // namespace C3NT1P3D3

#endif // SECURITY_MANAGER_H