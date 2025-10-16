# C3NT1P3D3 Security Scanner Framework

**A comprehensive vulnerability detection framework with MITRE ATT&CK integration**  
**Developed entirely by a single person as a solo project**

[![Release](https://img.shields.io/badge/release-v3.2.0--legendary-blue.svg)](https://github.com/n0m4official/C3NT1P3D3/releases)
[![Build](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com/n0m4official/C3NT1P3D3)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![C++](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://isocpp.org/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey.svg)](https://github.com/n0m4official/C3NT1P3D3)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/n0m4official/C3NT1P3D3)

---

<img width="474" height="447" alt="centipede" src="https://github.com/user-attachments/assets/0338f914-4239-452f-95d0-e3fcf60e076b"/>

---

## Overview

C3NT1P3D3 is an open-source security scanning framework designed for authorized penetration testing and security research. Built with modern C++17 by a single developer, it provides 37 vulnerability detection modules that integrate with the MITRE ATT&CK framework for threat intelligence reporting.

**This is a solo development project** - all code, documentation, and features have been created and maintained by one person (n0m4official).

This project serves the cybersecurity community by offering:
- **Educational resources** for security students and researchers
- **Professional tools** for authorized penetration testing
- **Research capabilities** for vulnerability analysis
- **Framework foundation** for custom security tool development

Note: C3NT1P3D3 is maintained by a single developer.

### Key Capabilities

- **37 Vulnerability Detection Modules** covering network, web, cloud, and system security
- **MITRE ATT&CK Integration** with automatic mapping to 20+ attack techniques
- **Real Protocol Implementations** including SMB, TLS/SSL, HTTP, SSH, FTP, and RDP
- **Production-Ready Code** with comprehensive safety controls and legal compliance
- **Cross-Platform Support** for Windows and Linux environments

---

## Important Legal Notice

**This software is intended exclusively for authorized security testing and research.**

### Before You Begin

You must have explicit written permission to scan any network or system. Unauthorized use of security scanning tools is illegal in most jurisdictions and may result in:

- Criminal prosecution under laws such as the Computer Fraud and Abuse Act (CFAA)
- Civil liability and substantial financial penalties
- Professional sanctions and reputational damage

### Your Responsibilities

By using this software, you agree to:

1. Obtain proper authorization before conducting any security scans
2. Comply with all applicable local, state, and federal laws
3. Use the tool only within the scope of your authorization
4. Accept full responsibility for your actions

**This framework contains detection logic only—no exploit code or attack payloads.** It is designed as a defensive security tool for authorized analysis.

For complete legal terms, please review:
- [Usage Guidelines](docs/legal/Usage-Guidelines.md)
- [End-User License Agreement](docs/legal/LICENSE-AGREEMENT.md)
- [Terms of Service](docs/legal/TERMS-OF-SERVICE.md)

---

## What's Included

### Network Security Modules (4)

- **EternalBlue (MS17-010)** - Detects SMB vulnerabilities with OS fingerprinting
- **BlueKeep (CVE-2019-0708)** - Identifies RDP remote code execution risks
- **SSH Brute Force** - Analyzes SSH configurations for weak authentication
- **FTP Anonymous Access** - Tests for unauthorized FTP access

### Web Application Security Modules (22)

**Core Web Vulnerabilities:**
- SQL Injection (error-based, boolean, UNION, time-based)
- Cross-Site Scripting (XSS)
- XML External Entity (XXE) Injection
- Server-Side Request Forgery (SSRF)
- Command Injection
- LDAP Injection
- Directory Traversal
- CORS Misconfiguration
- Insecure Deserialization
- Subdomain Takeover
- Log4Shell (CVE-2021-44228)

**Advanced Web Vulnerabilities:**
- Server-Side Template Injection (8 template engines)
- NoSQL Injection (MongoDB, CouchDB, Redis)
- HTTP Request Smuggling (CL.TE, TE.CL, TE.TE)
- WebSocket Security Issues
- OAuth/OIDC Vulnerabilities
- JWT Token Weaknesses
- GraphQL Injection
- API Rate Limiting Bypass
- XML Injection
- Race Conditions
- Prototype Pollution
- CSRF (Cross-Site Request Forgery)
- IDOR (Insecure Direct Object Reference)

### Cloud & Container Security (2)

- **Cloud Metadata Exploitation** - Tests AWS, Azure, GCP, and DigitalOcean metadata services
- **Container Escape Detection** - Identifies Docker and Kubernetes security misconfigurations

### SSL/TLS Security (2)

- **Heartbleed (CVE-2014-0160)** - Detects OpenSSL memory disclosure vulnerability
- **Weak Cipher Detection** - Analyzes SSL/TLS configuration weaknesses

### System Security (1)

- **Shellshock (CVE-2014-6271)** - Tests for Bash environment variable exploitation

---

## MITRE ATT&CK Integration

C3NT1P3D3 automatically maps detected vulnerabilities to the MITRE ATT&CK framework, providing:

- **17 Unique Attack Techniques** across 11 tactical categories
- **Detailed Mitigation Recommendations** for each vulnerability
- **SOC-Ready Reporting** compatible with security operations workflows
- **Threat Intelligence Context** for better risk assessment

Example output includes technique IDs (e.g., T1210), tactic classifications, and specific remediation steps—making it easy to integrate findings into your existing security processes.

---

## Getting Started

### System Requirements

- **Operating System:** Windows 10/11 (x64) or Linux (x64)
- **Memory:** 2 GB minimum, 4 GB recommended
- **Disk Space:** 100 MB
- **Compiler:** Visual Studio 2022 (Windows) or GCC 7+ (Linux)
- **Permissions:** Administrator/root access for certain network operations

### Installation

#### Option 1: Download Pre-Built Release

```bash
# Download from GitHub Releases
https://github.com/n0m4official/C3NT1P3D3/releases/tag/v3.0.0-legendary

# Extract the archive
unzip C3NT1P3D3-v3.0.0-legendary-windows-x64.zip
cd C3NT1P3D3-v3.0.0-legendary/bin

# Run the scanner
./C3NT1P3D3-Comprehensive.exe --help
```

#### Option 2: Build from Source (Windows)

```powershell
# Clone the repository
git clone https://github.com/n0m4official/C3NT1P3D3.git
cd C3NT1P3D3

# Build with CMake
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release --target C3NT1P3D3-Comprehensive

# Run the scanner
.\build\Release\C3NT1P3D3-Comprehensive.exe --help
```

#### Option 3: Build from Source (Linux)

```bash
# Clone the repository
git clone https://github.com/n0m4official/C3NT1P3D3.git
cd C3NT1P3D3

# Build with CMake
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

# Run the scanner
./C3NT1P3D3-Comprehensive --help
```

### Basic Usage

```bash
# Test in simulation mode (safe, no actual network traffic)
C3NT1P3D3-Comprehensive 192.168.1.0/24 --simulation --output test.json

# Scan your authorized network
C3NT1P3D3-Comprehensive 192.168.1.0/24 --output results.json

# Scan with custom settings
C3NT1P3D3-Comprehensive 192.168.1.0/24 --threads 5 --rate-limit 50 --output scan.json
```

---

## Safety Features

C3NT1P3D3 is designed with safety as a top priority:

### IP Range Protection

- **Automatic Validation** - All IP ranges are validated before scanning begins
- **Private Network Detection** - Automatically identifies RFC 1918 private networks
- **Public IP Warnings** - Requires explicit confirmation for public internet scanning
- **Blocked Ranges** - Prevents scanning of reserved, multicast, and special-use addresses

### Operational Safety

- **Read-Only Operations** - Never modifies systems or executes exploits
- **Rate Limiting** - Prevents network overload and detection
- **Timeout Controls** - Prevents hanging connections
- **Simulation Mode** - Test functionality without actual network traffic
- **Emergency Stop** - Immediate termination with Ctrl+C

### Audit & Compliance

- **Comprehensive Logging** - All scan activities are recorded
- **Authorization Tracking** - Maintains records of user confirmations
- **Compliance Reporting** - Generates reports suitable for security assessments

---

## Configuration

### Command-Line Options

```
Usage: C3NT1P3D3-Comprehensive <target_range> [options]

Target Range:
  192.168.1.0/24    Private network (Class C)
  10.0.0.0/8        Private network (Class A)
  172.16.0.0/12     Private network (Class B)
  127.0.0.1         Single host

Options:
  --output FILE     Save results to file
  --format FORMAT   Output format: json, xml, txt (default: json)
  --simulation      Enable simulation mode (no network traffic)
  --threads N       Number of scanning threads (default: 10)
  --rate-limit N    Requests per second (default: 100)
  --timeout N       Connection timeout in seconds (default: 30)
  --verbose         Enable detailed logging
  --help            Show this help message

Examples:
  # Safe testing with simulation mode
  C3NT1P3D3-Comprehensive 192.168.1.0/24 --simulation --output test.json

  # Authorized network scan
  C3NT1P3D3-Comprehensive 192.168.1.0/24 --output results.json --threads 5

  # Generate XML report
  C3NT1P3D3-Comprehensive 10.0.0.0/8 --output scan.xml --format xml
```

### Configuration File

Advanced users can create a configuration file for persistent settings:

```json
{
  "scanning": {
    "thread_count": 10,
    "timeout_seconds": 30,
    "rate_limit": 100
  },
  "safety": {
    "strict_mode": true,
    "allowed_ranges": [
      "192.168.0.0/16",
      "10.0.0.0/8",
      "172.16.0.0/12"
    ]
  },
  "output": {
    "format": "json",
    "include_mitre_attack": true
  }
}
```

---

## Output & Reporting

### JSON Output Example

```json
{
  "scan_id": "C3NT1P3D3-20251014-132200",
  "target_range": "192.168.1.0/24",
  "start_time": "2025-10-14 13:22:00 UTC",
  "end_time": "2025-10-14 13:25:45 UTC",
  "status": "COMPLETED",
  "vulnerabilities": [
    {
      "target": "192.168.1.50",
      "vulnerability": "EternalBlue",
      "severity": "Critical",
      "mitre_attack": {
        "technique_id": "T1210",
        "technique_name": "Exploitation of Remote Services",
        "tactics": ["Lateral Movement"],
        "mitigations": [
          "Apply MS17-010 security patch immediately",
          "Disable SMBv1 protocol on all systems",
          "Implement network segmentation",
          "Enable Windows Firewall with strict rules",
          "Monitor for suspicious SMB traffic"
        ],
        "references": "https://attack.mitre.org/techniques/T1210/"
      }
    }
  ],
  "summary": {
    "total_targets": 254,
    "vulnerabilities_found": 12,
    "critical": 2,
    "high": 4,
    "medium": 5,
    "low": 1
  }
}
```

---

## Project Architecture

### Core Components

```
C3NT1P3D3/
├── src/
│   ├── core/                    # Core scanning engine
│   ├── mitre/                   # MITRE ATT&CK integration
│   ├── simulation/              # Simulation mode
│   └── [30 detector modules]    # Individual vulnerability detectors
├── include/                     # Header files
├── docs/                        # Documentation
│   ├── legal/                   # Legal documentation
│   ├── technical/               # Technical guides
│   └── features/                # Feature documentation
└── config/                      # Configuration templates
```

### Technology Stack

- **Language:** C++17 with modern features (RAII, smart pointers, move semantics)
- **Build System:** CMake 3.15+
- **Protocols:** Native implementations of SMB, TLS/SSL, HTTP, SSH, FTP, RDP
- **Standards:** MITRE ATT&CK Framework, RFC compliance
- **Platform:** Cross-platform (Windows, Linux)

---

## Development Status

### Current Release (v3.1.0-legendary)

✅ **Completed:**
- 37 vulnerability detection modules with real protocol implementations
- MITRE ATT&CK framework integration
- Core scanning infrastructure
- Safety controls and IP validation
- Comprehensive documentation
- Legal compliance framework

🚧 **In Progress:**
- Enhanced command-line interface (v3.1.0)
- Advanced reporting capabilities
- ATT&CK Navigator export

📋 **Planned:**
- Web-based dashboard
- REST API interface
- Plugin architecture for custom modules
- Additional vulnerability modules
- Distributed scanning capabilities

---

## Contributing

As a solo development project, I welcome contributions from the security community! Here's how you can help:

### Areas for Contribution

1. **New Vulnerability Modules** - Implement detection for additional vulnerabilities
2. **Protocol Implementations** - Enhance existing protocol handlers
3. **Documentation** - Improve guides, tutorials, and examples
4. **Testing** - Add unit tests and integration tests
5. **Bug Fixes** - Report and fix issues

### Contribution Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/YourFeature`)
3. Implement your changes with appropriate tests
4. Follow the existing code style and safety principles
5. Submit a pull request with a clear description

**Note:** As the sole maintainer, I review all contributions personally. Please be patient with response times.

### Code of Conduct

- Write clean, well-documented code
- Include safety checks in all network operations
- Add appropriate legal warnings for sensitive functionality
- Test thoroughly before submitting
- Be respectful and professional in all interactions

---

## Support & Community

### Getting Help

- **GitHub Issues:** Report bugs and request features at [Issues](https://github.com/n0m4official/C3NT1P3D3/issues)
- **GitHub Discussions:** Ask questions and share ideas at [Discussions](https://github.com/n0m4official/C3NT1P3D3/discussions)
- **Documentation:** Comprehensive guides available in the `docs/` directory

### Response Times

**This is a solo development project maintained by one person.** Response times vary based on my availability:

- **Security Issues:** Prioritized and addressed as quickly as possible
- **Bug Reports:** Typically reviewed within one week
- **Feature Requests:** Evaluated based on feasibility and project roadmap

Please be patient - I maintain this project in my personal time while balancing other commitments.

---

## Comparison with Commercial Tools

C3NT1P3D3 offers capabilities comparable to commercial security scanners:

| Feature | C3NT1P3D3 | Commercial Tools |
|---------|-----------|------------------|
| Vulnerability Modules | 30 | 40-100 |
| MITRE ATT&CK Integration | Native | Limited/None |
| Source Code Access | Full | None |
| Customization | Complete | Limited |
| Cost | Free (Open Source) | $500-$5,000/year |
| Community Support | Active | Vendor-only |
| Learning Resource | Excellent | Limited |

---

## Frequently Asked Questions

### Is this tool legal to use?

Yes, when used with proper authorization. You must have explicit written permission to scan any network or system you don't own.

### Does it contain exploit code?

No. C3NT1P3D3 contains detection logic only. It identifies vulnerabilities but does not exploit them.

### Can I use this for my job?

Yes, if you're authorized to perform security testing as part of your professional duties. Always follow your organization's policies.

### How is this different from Metasploit or Nmap?

C3NT1P3D3 focuses on vulnerability detection with MITRE ATT&CK integration. It's designed for assessment and reporting, not exploitation.

### Can I contribute new modules?

Absolutely! We welcome contributions. Please review our contribution guidelines and submit a pull request.

### Is commercial use allowed?

Yes, under the MIT License terms. However, you must still obtain proper authorization for any scanning activities.

---

## Acknowledgments

### Technology & Standards

- **MITRE ATT&CK Framework** - For providing the industry-standard threat intelligence taxonomy
- **C++ Community** - For excellent tools, libraries, and best practices
- **Security Research Community** - For vulnerability disclosure and research

### About This Project

This project was created and is maintained entirely by one person (n0m4official) as a solo development effort. It was inspired by the need for transparent, educational security tools that help practitioners understand vulnerability detection techniques while maintaining the highest ethical and legal standards.

Every line of code, every module, and every piece of documentation has been written by a single developer dedicated to advancing cybersecurity education and defensive security research.

---

## License

C3NT1P3D3 is released under the MIT License with additional safety requirements.

### Key Terms

- ✅ Free to use for authorized security testing
- ✅ Open source with full access to code
- ✅ Commercial use permitted (with proper authorization)
- ✅ Modification and distribution allowed
- ❌ No warranty for unauthorized or illegal use
- ❌ Authors not liable for misuse

See the [LICENSE](LICENSE) file for complete terms.

---

## Project Information

**Version:** 3.2.0-legendary  
**Release Date:** October 16, 2025  
**Author:** n0m4official  
**Repository:** https://github.com/n0m4official/C3NT1P3D3  
**License:** MIT with Safety Requirements

---

## Final Notes

C3NT1P3D3 represents my personal commitment to transparent, ethical security research and education. By making professional-grade vulnerability detection tools available to the community, I hope to:

- **Educate** the next generation of security professionals
- **Improve** overall security through better understanding of vulnerabilities
- **Democratize** access to security testing tools
- **Promote** responsible disclosure and ethical hacking practices

Thank you for using C3NT1P3D3 responsibly and contributing to a more secure digital world.

**Remember: With great power comes great responsibility. Always scan ethically and legally.**

---

*Developed entirely by n0m4official - A solo project made with dedication to cybersecurity education and responsible disclosure.*
