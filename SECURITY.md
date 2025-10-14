# Security Policy

## Supported Versions

We release patches for security vulnerabilities in the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 3.1.x   | :white_check_mark: |
| 3.0.x   | :x:                |
| < 3.0   | :x:                |

## Reporting a Vulnerability

We take the security of C3NT1P3D3 seriously. If you discover a security vulnerability, please follow responsible disclosure practices.

### What to Report

Please report any vulnerabilities that could:

- Allow unauthorized access to systems
- Bypass safety controls or rate limiting
- Cause denial of service
- Expose sensitive information
- Enable malicious use of the tool
- Circumvent authorization checks

### How to Report

**DO NOT** report security vulnerabilities through public GitHub issues.

Instead, please report them privately:

1. **Email:** Create a security advisory on GitHub (preferred)
   - Go to the Security tab
   - Click "Report a vulnerability"
   - Fill out the form with details

2. **Alternative:** Open a private issue
   - Contact maintainers directly
   - Use encrypted communication if possible

### What to Include

When reporting a vulnerability, please include:

- **Type of vulnerability** (e.g., buffer overflow, injection, etc.)
- **Full paths** of source file(s) related to the vulnerability
- **Location** of the affected source code (tag/branch/commit)
- **Step-by-step instructions** to reproduce the issue
- **Proof-of-concept or exploit code** (if possible)
- **Impact** of the vulnerability
- **Suggested fix** (if you have one)

### Response Timeline

- **Initial Response:** Within 48 hours
- **Status Update:** Within 7 days
- **Fix Timeline:** Depends on severity
  - Critical: 1-7 days
  - High: 7-30 days
  - Medium: 30-90 days
  - Low: Best effort

### Disclosure Policy

- We follow coordinated disclosure
- We'll work with you to understand and validate the issue
- We'll develop a fix and test it thoroughly
- We'll credit you in the security advisory (if desired)
- We'll publish the advisory after the fix is released

### Security Best Practices for Users

When using C3NT1P3D3:

#### Legal Compliance

- ✅ **Always obtain written authorization** before scanning
- ✅ **Respect scope limitations** in your authorization
- ✅ **Follow local laws** and regulations
- ✅ **Document your authorization** and keep records

#### Safe Usage

- ✅ **Use in isolated environments** for testing
- ✅ **Implement rate limiting** to avoid DoS
- ✅ **Monitor your scans** for unexpected behavior
- ✅ **Keep the tool updated** to latest version
- ✅ **Review results carefully** before acting on them

#### What NOT to Do

- ❌ **Never scan without authorization**
- ❌ **Don't target critical infrastructure** without explicit permission
- ❌ **Don't use for malicious purposes**
- ❌ **Don't bypass safety controls**
- ❌ **Don't share exploits publicly** without responsible disclosure

### Known Security Considerations

#### By Design

This tool is designed for security testing and includes:

- Network scanning capabilities
- Vulnerability detection methods
- Protocol implementations
- Payload generation

These features are **intentional** and required for the tool's purpose. They are not vulnerabilities but must be used responsibly.

#### Safety Controls

Built-in safety features include:

- Rate limiting on network requests
- Timeout controls
- Private IP range validation (RFC 1918)
- Detection-only methodology (no exploitation)
- Comprehensive logging

### Security Updates

Security updates will be:

- Released as soon as possible after validation
- Announced in release notes
- Tagged with security advisory
- Documented in CHANGELOG.md

### Scope

This security policy applies to:

- The C3NT1P3D3 codebase
- Official releases and distributions
- Documentation and examples

It does NOT apply to:

- Third-party forks or modifications
- Vulnerabilities in target systems (report to system owners)
- Misuse of the tool (user responsibility)

### Legal Notice

**Important:** This tool is for authorized security testing only.

- Users are responsible for legal compliance
- Authors are not liable for misuse
- Unauthorized use may violate laws including:
  - Computer Fraud and Abuse Act (CFAA)
  - Computer Misuse Act
  - Local cybercrime legislation

### Questions?

If you have questions about this security policy:

- Open a GitHub issue (for non-sensitive questions)
- Contact maintainers privately (for sensitive matters)
- Review our [Code of Conduct](CODE_OF_CONDUCT.md)

---

**Thank you for helping keep C3NT1P3D3 and its users safe!**
