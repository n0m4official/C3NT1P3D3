# 🏗️ C3NT1P3D3 Architecture Overview

## System Architecture

C3NT1P3D3 is built on a modular, extensible architecture designed for professional security scanning with enterprise-grade safety controls and threat intelligence integration.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     C3NT1P3D3 Scanner Core                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    │
│  │   CLI Layer  │───▶│ Core Engine  │───▶│   Reporting  │    │
│  └──────────────┘    └──────────────┘    └──────────────┘    │
│                             │                                  │
│                             ▼                                  │
│                    ┌─────────────────┐                        │
│                    │ Module Registry │                        │
│                    └─────────────────┘                        │
│                             │                                  │
│          ┌──────────────────┼──────────────────┐             │
│          ▼                  ▼                  ▼             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   Network    │  │     Web      │  │    System    │      │
│  │   Modules    │  │   Modules    │  │   Modules    │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│          │                  │                  │             │
│          └──────────────────┼──────────────────┘             │
│                             ▼                                  │
│                    ┌─────────────────┐                        │
│                    │ MITRE ATT&CK    │                        │
│                    │    Mapper       │                        │
│                    └─────────────────┘                        │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                     Safety & Security Layer                     │
├─────────────────────────────────────────────────────────────────┤
│  • IP Range Validator  • Rate Limiting  • Audit Logging       │
│  • Timeout Controls    • Simulation Mode • Emergency Stop      │
└─────────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. Module Registry (`ModuleRegistry`)

**Purpose:** Central management system for all vulnerability detection modules

**Responsibilities:**
- Module registration and lifecycle management
- Category-based organization (Network, Web, System)
- Module discovery and enumeration
- Execution orchestration

**Key Features:**
```cpp
class ModuleRegistry {
public:
    void registerModule(std::unique_ptr<IModule> module, Category category);
    std::vector<IModule*> getModulesByCategory(Category category);
    std::vector<IModule*> getAllModules();
    void runAllModules(const std::string& target);
    
private:
    std::map<Category, std::vector<std::unique_ptr<IModule>>> modules_;
};
```

**Categories:**
- `NETWORK` - Network protocol vulnerabilities (SMB, SSH, FTP, RDP, TLS)
- `WEB` - Web application vulnerabilities (SQLi, XSS, XXE, SSRF)
- `SYSTEM` - System-level vulnerabilities (Shellshock, Command Injection)

### 2. Module Interface (`IModule`)

**Purpose:** Abstract interface for all vulnerability detection modules

**Contract:**
```cpp
class IModule {
public:
    virtual ~IModule() = default;
    virtual std::string getName() const = 0;
    virtual std::string getDescription() const = 0;
    virtual ModuleResult run(const std::string& target) = 0;
};
```

**Result Structure:**
```cpp
struct ModuleResult {
    std::string moduleName;
    bool vulnerable;
    std::string severity;           // Critical, High, Medium, Low
    std::string details;
    std::vector<std::string> evidence;
    AttackTechnique attackInfo;     // MITRE ATT&CK data
    std::chrono::system_clock::time_point timestamp;
};
```

### 3. MITRE ATT&CK Integration (`AttackMapper`)

**Purpose:** Map vulnerabilities to MITRE ATT&CK framework

**Data Structure:**
```cpp
struct AttackTechnique {
    std::string techniqueId;        // e.g., "T1210"
    std::string techniqueName;      // e.g., "Exploitation of Remote Services"
    std::vector<std::string> tactics; // e.g., ["Lateral Movement"]
    std::string description;
    std::vector<std::string> mitigations;
    std::string url;                // MITRE ATT&CK reference
};
```

**Mapping System:**
```cpp
class AttackMapper {
public:
    AttackTechnique getTechniqueForVulnerability(const std::string& vulnName);
    std::vector<AttackTechnique> getAllTechniques();
    
private:
    std::map<std::string, AttackTechnique> vulnerabilityToTechnique_;
    void initializeMappings();
};
```

**Current Mappings:**
- EternalBlue → T1210 (Exploitation of Remote Services)
- Heartbleed → T1040 (Network Sniffing)
- SQL Injection → T1190 (Exploit Public-Facing Application)
- XSS → T1189 (Drive-by Compromise)
- Shellshock → T1068 (Exploitation for Privilege Escalation)
- BlueKeep → T1210 (Exploitation of Remote Services)
- XXE → T1190 (Exploit Public-Facing Application)
- SSRF → T1090 (Proxy)
- Command Injection → T1059 (Command and Scripting Interpreter)
- Weak Ciphers → T1040 (Network Sniffing)

### 4. Safety Layer (`IPRangeValidator`)

**Purpose:** Prevent unauthorized scanning and ensure ethical usage

**Features:**
```cpp
class IPRangeValidator {
public:
    bool isIPAllowed(const std::string& ip);
    bool requiresUserApproval(const std::string& ip);
    void addToAllowlist(const std::string& ipRange);
    void addToBlocklist(const std::string& ipRange);
    
private:
    std::vector<IPRange> privateRanges_;    // RFC 1918
    std::vector<IPRange> allowlist_;
    std::vector<IPRange> blocklist_;
};
```

**Protected Ranges:**
- `10.0.0.0/8` - Private network (auto-allowed)
- `172.16.0.0/12` - Private network (auto-allowed)
- `192.168.0.0/16` - Private network (auto-allowed)
- `127.0.0.0/8` - Loopback (auto-allowed)
- Public IPs - Require explicit approval

### 5. Network Communication Layer

**Purpose:** Handle all network protocols safely and efficiently

**Socket Management:**
```cpp
class NetworkSocket {
public:
    bool connect(const std::string& host, int port, int timeout_ms);
    ssize_t send(const void* data, size_t length);
    ssize_t receive(void* buffer, size_t length);
    void close();
    
private:
    SOCKET socket_;
    bool connected_;
    std::chrono::steady_clock::time_point connectTime_;
};
```

**Protocol Implementations:**
- **HTTP/HTTPS** - Custom implementation with TLS support
- **SMB** - Direct SMB protocol for EternalBlue detection
- **SSH** - Banner grabbing and version detection
- **FTP** - Anonymous login testing
- **RDP** - X.224 connection testing
- **TLS/SSL** - Heartbeat extension testing, cipher analysis

## Module Architecture

### Module Lifecycle

```
┌──────────────┐
│ Registration │ ─── Module added to registry with category
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Discovery    │ ─── CLI or scanner queries available modules
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Execution    │ ─── Module.run(target) called
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Detection    │ ─── Network testing, payload injection
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Analysis     │ ─── Response parsing, vulnerability confirmation
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Mapping      │ ─── MITRE ATT&CK technique assignment
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Reporting    │ ─── ModuleResult with full context
└──────────────┘
```

### Example Module Implementation

```cpp
class ExampleDetector : public IModule {
public:
    std::string getName() const override {
        return "Example Vulnerability";
    }
    
    std::string getDescription() const override {
        return "Detects example vulnerability in target systems";
    }
    
    ModuleResult run(const std::string& target) override {
        ModuleResult result;
        result.moduleName = getName();
        result.timestamp = std::chrono::system_clock::now();
        
        // 1. Network connection
        if (!connectToTarget(target)) {
            result.vulnerable = false;
            result.details = "Target unreachable";
            return result;
        }
        
        // 2. Vulnerability testing
        bool isVulnerable = testVulnerability(target);
        
        // 3. Result population
        result.vulnerable = isVulnerable;
        result.severity = isVulnerable ? "High" : "Info";
        result.details = isVulnerable ? 
            "Vulnerability confirmed" : "Target is patched";
        
        // 4. MITRE ATT&CK mapping
        if (isVulnerable) {
            result.attackInfo = AttackMapper::getTechniqueForVulnerability(getName());
        }
        
        return result;
    }
    
private:
    bool connectToTarget(const std::string& target);
    bool testVulnerability(const std::string& target);
};
```

## Data Flow

### Scan Execution Flow

```
User Input (CLI)
    │
    ▼
IP Validation ──────┐
    │               │ (Blocked)
    │ (Allowed)     ▼
    │           Error + Exit
    ▼
Module Selection
    │
    ▼
For Each Module:
    │
    ├─▶ Safety Checks (timeout, rate limit)
    │
    ├─▶ Network Connection
    │
    ├─▶ Vulnerability Testing
    │
    ├─▶ Response Analysis
    │
    ├─▶ MITRE ATT&CK Mapping
    │
    └─▶ Result Collection
    │
    ▼
Report Generation
    │
    ├─▶ JSON Output
    ├─▶ Console Output
    └─▶ Audit Log
```

### Module Result Aggregation

```cpp
struct ScanReport {
    std::string targetIP;
    std::chrono::system_clock::time_point scanTime;
    std::vector<ModuleResult> results;
    
    // Statistics
    int totalModules;
    int vulnerabilitiesFound;
    int criticalFindings;
    int highFindings;
    
    // MITRE ATT&CK summary
    std::set<std::string> techniques;
    std::set<std::string> tactics;
    
    // Compliance
    std::string scannerVersion;
    std::string operatorId;
    bool userApprovalReceived;
};
```

## Security Design Principles

### 1. Defense in Depth

- **Input Validation:** All user inputs validated
- **IP Filtering:** Multi-layer IP range validation
- **Timeout Controls:** Every network operation has timeout
- **Rate Limiting:** Prevents aggressive scanning
- **Audit Logging:** Complete activity trail

### 2. Fail-Safe Defaults

- **Default Deny:** Public IPs require approval
- **Simulation Mode:** Safe testing without network traffic
- **Limited Payloads:** Detection-only, no exploitation
- **Graceful Degradation:** Failures don't crash scanner

### 3. Least Privilege

- **Read-Only Operations:** Never writes to targets
- **Minimal Permissions:** No admin rights required
- **Isolated Modules:** Module failures don't affect others
- **Resource Limits:** Memory and CPU constraints

### 4. Complete Mediation

- **Every Request Validated:** No bypass mechanisms
- **Continuous Monitoring:** Real-time safety checks
- **Audit Trail:** All actions logged
- **User Approval:** Required for sensitive operations

## Performance Considerations

### Optimization Strategies

1. **Parallel Scanning:**
   ```cpp
   std::vector<std::future<ModuleResult>> futures;
   for (auto& module : modules) {
       futures.push_back(std::async(std::launch::async, 
           [&]() { return module->run(target); }));
   }
   ```

2. **Connection Pooling:**
   - Reuse TCP connections where possible
   - Maintain connection cache
   - Implement connection timeout

3. **Smart Timeouts:**
   - Fast-fail for unreachable hosts
   - Progressive timeout increase
   - Adaptive based on network conditions

4. **Memory Management:**
   - RAII for all resources
   - Smart pointers for module management
   - Limited buffer sizes

### Performance Metrics

- **Scan Speed:** ~20 modules in 30-60 seconds
- **Memory Usage:** <100MB for full scan
- **Network Efficiency:** Minimal packets per test
- **CPU Usage:** <50% single core

## Extensibility

### Adding New Modules

1. **Create Header:**
   ```cpp
   // include/NewDetector.h
   class NewDetector : public IModule {
   public:
       std::string getName() const override;
       std::string getDescription() const override;
       ModuleResult run(const std::string& target) override;
   };
   ```

2. **Implement Detection:**
   ```cpp
   // src/NewDetector.cpp
   ModuleResult NewDetector::run(const std::string& target) {
       // Implementation
   }
   ```

3. **Register Module:**
   ```cpp
   // src/ModuleRegistry.cpp
   void ModuleRegistry::registerAllModules() {
       registerModule(std::make_unique<NewDetector>(), Category::NETWORK);
   }
   ```

4. **Add MITRE Mapping:**
   ```cpp
   // src/mitre/AttackMapper.cpp
   vulnerabilityToTechnique_["New Vulnerability"] = {
       "T1234", "Technique Name", {"Tactic"}, ...
   };
   ```

### Plugin Architecture (Future)

```cpp
// Future: Dynamic module loading
class PluginLoader {
public:
    void loadPlugin(const std::string& path);
    void unloadPlugin(const std::string& name);
    std::vector<std::string> listPlugins();
};
```

## Testing Architecture

### Unit Testing

```cpp
TEST(EternalBlueDetector, DetectsVulnerableSystem) {
    EternalBlueDetector detector;
    MockTarget target("192.168.1.100", true);  // Vulnerable
    
    ModuleResult result = detector.run(target.getIP());
    
    EXPECT_TRUE(result.vulnerable);
    EXPECT_EQ(result.severity, "Critical");
    EXPECT_EQ(result.attackInfo.techniqueId, "T1210");
}
```

### Integration Testing

```cpp
TEST(ModuleRegistry, ExecutesAllModules) {
    ModuleRegistry registry;
    registry.registerAllModules();
    
    auto results = registry.runAllModules("192.168.1.100");
    
    EXPECT_EQ(results.size(), 20);  // All modules executed
    EXPECT_TRUE(std::all_of(results.begin(), results.end(),
        [](const auto& r) { return !r.moduleName.empty(); }));
}
```

### Safety Testing

```cpp
TEST(IPRangeValidator, BlocksPublicIPs) {
    IPRangeValidator validator;
    
    EXPECT_FALSE(validator.isIPAllowed("8.8.8.8"));  // Google DNS
    EXPECT_TRUE(validator.requiresUserApproval("8.8.8.8"));
}
```

## Deployment Architecture

### Standalone Executable

```
C3NT1P3D3-Comprehensive.exe
├── Embedded modules (20+)
├── MITRE ATT&CK data
├── Configuration defaults
└── Safety controls
```

### Docker Container (Future)

```dockerfile
FROM alpine:latest
RUN apk add --no-cache libstdc++ openssl
COPY C3NT1P3D3-Comprehensive /usr/local/bin/
ENTRYPOINT ["C3NT1P3D3-Comprehensive"]
```

### Cloud Deployment (Future)

- AWS Lambda for serverless scanning
- Azure Functions for enterprise integration
- GCP Cloud Run for scalable deployment

## Future Enhancements

### Planned Features

1. **Distributed Scanning:**
   - Master/worker architecture
   - Load balancing across nodes
   - Centralized result aggregation

2. **Real-Time Dashboard:**
   - Web UI for scan management
   - Live vulnerability feed
   - Historical trend analysis

3. **Advanced Reporting:**
   - PDF/HTML report generation
   - Executive summaries
   - Compliance mapping (PCI-DSS, HIPAA, SOC 2)

4. **Machine Learning:**
   - Anomaly detection
   - False positive reduction
   - Predictive vulnerability analysis

5. **API Integration:**
   - RESTful API for automation
   - Webhook notifications
   - SIEM integration (Splunk, ELK)

---

**Document Version:** 1.0  
**Last Updated:** October 2025  
**Author:** n0m4official - C3NT1P3D3 Developer
