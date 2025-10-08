# C3NT1P3D3 - Advanced Vulnerability Scanner

## 🛡️ SAFETY-FIRST SECURITY SCANNER

**C3NT1P3D3** is a comprehensive vulnerability scanner designed with safety as the primary concern. It performs **detection-only** scanning with **no exploit execution**, ensuring your network remains safe while identifying potential security issues.

## 🔒 SAFETY GUARANTEES

### Core Safety Principles
- **Detection Only**: Never executes exploits or harmful actions
- **Read-Only Operations**: All interactions are safe and non-invasive
- **IP Range Restrictions**: Only scans explicitly allowed network ranges
- **Private Networks Only**: Default configuration blocks public IP scanning
- **Simulation Mode**: Operates in safe simulation mode by default
- **User Confirmation**: Requires explicit approval for real network interaction

### Safety Features
✅ **No Exploit Execution** - Purely detects vulnerabilities without exploiting them  
✅ **Network Range Validation** - Prevents scanning outside authorized ranges  
✅ **Private Network Protection** - Default allowlist: 192.168.x.x, 10.x.x.x, 172.16-31.x.x  
✅ **Simulation Mode** - Safe, non-invasive scanning by default  
✅ **Audit Trail** - Comprehensive logging of all scan activities  
✅ **Emergency Stop** - Immediate scan termination capabilities  

## 🚀 QUICK START

### Safe Network Scanning
```bash
# Show safety configuration
./SafeScanner --safety-report

# Scan a specific network range (safe simulation mode)
./SafeScanner --network 192.168.1.0/24

# Add custom allowed range and scan
./SafeScanner --allow-range 10.0.0.0/24 --network 10.0.0.0/24

# Enable real scanning (requires confirmation)
echo "yes" | ./SafeScanner --network 192.168.1.0/24 --simulation-off
```

## 📋 VULNERABILITY DETECTION MODULES

### Critical Vulnerabilities
- **EternalBlue (MS17-010)** - SMB vulnerability that enabled WannaCry
- **BlueKeep (CVE-2019-0708)** - RDP vulnerability affecting Windows systems
- **Heartbleed (CVE-2014-0160)** - OpenSSL memory disclosure vulnerability
- **Shellshock (CVE-2014-6271)** - Bash command injection vulnerability
- **Log4Shell (CVE-2021-44228)** - Log4j JNDI injection vulnerability

### Network Security
- **SSH Brute Force Detection** - Weak SSH configurations
- **FTP Anonymous Access** - Unsecured FTP services

### Web Application Security
- **SQL Injection Detection** - Database vulnerability identification
- **XSS (Cross-Site Scripting)** - Client-side script injection
- **Directory Traversal** - File system access vulnerabilities

## 🏗️ BUILD INSTRUCTIONS

### Requirements
- C++17 compatible compiler
- CMake 3.10+
- Linux/Unix environment (Windows support available)

### Build Process
```bash
# Clone the repository
git clone https://github.com/n0m4official/C3NT1P3D3.git
cd C3NT1P3D3

# Create build directory
mkdir build && cd build

# Configure with CMake
cmake ..

# Build the project
make

# Run tests
make test
```

### Build Outputs
- `C3NT1P3D3` - Original vulnerability scanner
- `SafeScanner` - Safety-enhanced network scanner

## 🎯 USAGE EXAMPLES

### Basic Network Discovery
```bash
# Discover devices in your home network
./SafeScanner --network 192.168.1.0/24

# Scan corporate network segment
./SafeScanner --network 10.0.0.0/24

# Add specific office network
./SafeScanner --allow-range 172.16.10.0/24 --network 172.16.10.0/24
```

### Advanced Configuration
```bash
# Multiple network ranges
./SafeScanner \
  --allow-range 192.168.1.0/24 \
  --allow-range 10.0.0.0/24 \
  --network 192.168.1.0/24

# Custom IP range (192.168.1.100-192.168.1.200)
./SafeScanner --network 192.168.1.100-192.168.1.200
```

### Safety Verification
```bash
# Always check safety configuration first
./SafeScanner --safety-report

# Verify allowed ranges before scanning
./SafeScanner --allow-range 192.168.1.0/24 --safety-report
```

## 🔧 CONFIGURATION

### Network Ranges
The scanner supports multiple IP range formats:
- **CIDR Notation**: `192.168.1.0/24`
- **IP Range**: `192.168.1.1-192.168.1.254`
- **Single IP**: `192.168.1.100`

### Default Allowed Ranges
- `192.168.0.0/16` - Private Class C networks
- `10.0.0.0/8` - Private Class A networks  
- `172.16.0.0/12` - Private Class B networks

### Custom Configuration
```bash
# Override default ranges
./SafeScanner \
  --allow-range 192.168.1.0/24 \
  --allow-range 10.0.0.0/16 \
  --network 192.168.1.0/24
```

## 🚨 SAFETY PROTOCOLS

### Pre-Scan Safety Checklist
1. ✅ **Verify Network Range** - Ensure you're scanning authorized networks only
2. ✅ **Check Permissions** - Confirm you have permission to scan the target network
3. ✅ **Review Safety Report** - Run `./SafeScanner --safety-report`
4. ✅ **Test Simulation Mode** - Default behavior is safe simulation
5. ✅ **Confirm Real Scanning** - Explicit "yes" required for real network interaction

### During Scan Safety
- **Real-time Monitoring** - All activities are logged and monitored
- **Safe Payloads Only** - No dangerous or invasive techniques used
- **Immediate Termination** - Scan can be stopped at any time
- **No System Modification** - Read-only operations guarantee

### Post-Scan Safety
- **Comprehensive Reporting** - Detailed results with safety confirmations
- **No Persistent Changes** - No modifications to scanned systems
- **Audit Trail** - Complete log of all scan activities

## 📊 SCAN RESULTS

### Result Format
```
Module: BlueKeepDetector
Target: windows-server (192.168.1.100)
Success: Yes
Severity: Critical
Message: Target potentially vulnerable to BlueKeep (CVE-2019-0708)
Details: RDP service detected on port 3389
Target appears to be Windows-based, potentially vulnerable to BlueKeep
Affected versions: Windows 7, Windows Server 2008 R2, Windows Server 2008
CVE-2019-0708 allows remote code execution without authentication
```

### Severity Levels
- **Critical** - Immediate attention required
- **High** - Significant security risk
- **Medium** - Moderate security concern
- **Low** - Minor issue or informational

## 🛠️ DEVELOPMENT

### Adding New Modules
1. Create header file inheriting from `IModule`
2. Implement detection logic (detection only, no exploitation)
3. Register module in `SafeScanner.cpp`
4. Update CMakeLists.txt
5. Test thoroughly in simulation mode

### Safety Guidelines for Developers
- **Never Execute Exploits** - Detection only, always
- **Validate All Inputs** - Strict input validation for IP ranges
- **Safe Defaults** - Conservative, safe default settings
- **Comprehensive Logging** - Log all activities for audit
- **Fail-Safe Design** - Fail securely, never dangerously

## 🔍 TROUBLESHOOTING

### Common Issues
```bash
# Range not allowed error
./SafeScanner --network 192.168.1.0/24
# Error: Network range not in allowed ranges
# Solution: Add the range first
./SafeScanner --allow-range 192.168.1.0/24 --network 192.168.1.0/24

# Permission denied for real scanning
# Solution: Confirm with "yes" when prompted
echo "yes" | ./SafeScanner --network 192.168.1.0/24 --simulation-off
```

### Safety Errors
- **"Dangerous IP range detected"** - You're trying to scan public/reserved IPs
- **"Network range not allowed"** - Add the range to allowed list first
- **"No allowed IP ranges configured"** - Configure at least one allowed range

## 📚 SECURITY CONSIDERATIONS

### Legal Compliance
- **Authorization Required** - Only scan networks you own or have permission to scan
- **Privacy Protection** - Respect privacy and data protection regulations
- **Responsible Disclosure** - Report findings through appropriate channels

### Ethical Usage
- **Permission First** - Always obtain proper authorization before scanning
- **Minimal Impact** - Use least invasive methods possible
- **Responsible Reporting** - Share findings responsibly and constructively

## 🤝 CONTRIBUTING

### Safety-First Development
1. **Safety Review** - All contributions must pass safety review
2. **Detection Only** - No exploit code will be accepted
3. **Comprehensive Testing** - Thorough testing in simulation mode required
4. **Documentation** - Update safety documentation for all changes

### Code Standards
- Follow safety-first principles
- Maintain comprehensive error handling
- Include detailed safety comments
- Test extensively before submission

## 📄 LICENSE

This project is designed for legitimate security testing and research purposes only. Users are responsible for ensuring compliance with all applicable laws and regulations.

## ⚠️ DISCLAIMER

**C3NT1P3D3 is designed for authorized security testing only.**  
**Misuse of this tool may violate applicable laws.**  
**Always obtain proper authorization before scanning any network.**

---

**🔒 Remember: Safety First, Security Always**