# Contributing to C3NT1P3D3

Thank you for your interest in contributing to C3NT1P3D3! As a solo development project, I welcome contributions from the security community to help improve this educational security framework.

**Important:** This project is developed and maintained entirely by one person (n0m4official). All contributions are reviewed personally by me, so please be patient with response times.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How to Contribute](#how-to-contribute)
- [Development Guidelines](#development-guidelines)
- [Pull Request Process](#pull-request-process)
- [Adding New Modules](#adding-new-modules)

## Code of Conduct

This project adheres to a [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to me (the project maintainer) via GitHub issues.

## Getting Started

### Prerequisites

- Visual Studio 2022 (Windows) or GCC 7+ (Linux)
- CMake 3.15 or higher
- Git for version control
- Basic understanding of C++17
- Knowledge of network security concepts

### Setting Up Development Environment

```bash
# Clone the repository
git clone https://github.com/n0m4official/C3NT1P3D3.git
cd C3NT1P3D3

# Create build directory
mkdir build
cd build

# Configure with CMake
cmake .. -G "Visual Studio 17 2022" -A x64

# Build
cmake --build . --config Release
```

## How to Contribute

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates. When creating a bug report, include:

- **Clear title** describing the issue
- **Detailed description** of the problem
- **Steps to reproduce** the behavior
- **Expected vs actual behavior**
- **Environment details** (OS, compiler version, etc.)
- **Relevant logs or error messages**

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion:

- **Use a clear title** describing the enhancement
- **Provide detailed description** of the proposed functionality
- **Explain why** this enhancement would be useful
- **List any alternatives** you've considered

### Security Vulnerabilities

**Do not** report security vulnerabilities through public GitHub issues. Instead:

1. Review our [Security Policy](SECURITY.md)
2. Report privately to me (the sole maintainer) via GitHub Security Advisories
3. Allow time for responsible disclosure

## Development Guidelines

### Code Style

- Follow existing code formatting and style
- Use meaningful variable and function names
- Add comments for complex logic
- Keep functions focused and modular
- Use C++17 standard features appropriately

### Module Structure

All detection modules must:

- Inherit from `IModule` interface
- Implement `run(const MockTarget& target)` method
- Return `ModuleResult` with proper fields populated
- Include MITRE ATT&CK mapping
- Implement proper error handling
- Use timeouts for network operations
- Be detection-only (no exploitation)

### Testing

- Test your changes on multiple platforms when possible
- Verify compilation with no errors
- Test against safe, authorized targets only
- Document any new dependencies

### Documentation

- Update README.md if adding new features
- Add entries to CHANGELOG.md
- Include inline code comments
- Update module count if applicable

## Pull Request Process

### Before Submitting

1. **Fork** the repository
2. **Create a branch** from `master` for your changes
3. **Make your changes** following the guidelines above
4. **Test thoroughly** on authorized systems only
5. **Update documentation** as needed
6. **Commit with clear messages** describing your changes

### Submitting

1. **Push** your branch to your fork
2. **Open a Pull Request** against the `master` branch
3. **Fill out the PR template** completely
4. **Link any related issues**
5. **Wait for review** from maintainers

### PR Requirements

- ✅ Code compiles without errors
- ✅ Follows existing code style
- ✅ Includes appropriate documentation
- ✅ No security vulnerabilities introduced
- ✅ Passes all existing tests
- ✅ Commits are clear and descriptive

### Review Process

1. I will review your PR personally (as the sole maintainer)
2. Feedback may be provided for improvements
3. Make requested changes if needed
4. Once approved, PR will be merged
5. You'll be credited in release notes

**Note:** As a solo developer, I review PRs in my personal time. Please be patient - response times may vary from a few days to a couple of weeks depending on my availability.

## Adding New Modules

### Module Checklist

When adding a new vulnerability detection module:

- [ ] Create header file in `include/` directory
- [ ] Create implementation in `src/` directory
- [ ] Inherit from `IModule` interface
- [ ] Implement `id()` and `run()` methods
- [ ] Add MITRE ATT&CK mapping
- [ ] Include proper error handling
- [ ] Add to `CMakeLists.txt`
- [ ] Update module count in README
- [ ] Add entry to CHANGELOG
- [ ] Test compilation and basic functionality

### Module Template

```cpp
// include/MyDetector.h
#pragma once
#include "IModule.h"

class MyDetector : public IModule {
public:
    std::string id() const override { return "MyDetector"; }
    ModuleResult run(const MockTarget& target) override;
};

// src/MyDetector.cpp
#include "../include/MyDetector.h"

ModuleResult MyDetector::run(const MockTarget& target) {
    ModuleResult result;
    result.id = id();
    result.targetId = target.id();
    result.success = true;
    
    // Your detection logic here
    
    // MITRE ATT&CK mapping
    result.attackTechniqueId = "TXXXX";
    result.attackTechniqueName = "Technique Name";
    result.attackTactics = {"Tactic"};
    result.mitigations = {"Mitigation 1", "Mitigation 2"};
    result.attackUrl = "https://attack.mitre.org/techniques/TXXXX/";
    
    return result;
}
```

## Questions?

If you have questions about contributing:

- Open a GitHub issue with the `question` label
- Check existing documentation
- Review closed issues for similar questions

**Note:** I respond to questions personally, so please allow time for a response.

## Recognition

Contributors will be recognized in:

- Release notes
- Project documentation
- GitHub contributors page

Thank you for helping make C3NT1P3D3 better! Your contributions help this solo project grow and serve the security community.

#### C3NT1P3D3 is maintained by a single developer. While all requests will be handled responsibly, response times may vary depending on the maintainer’s availability.

---

**Remember:** All contributions must comply with legal and ethical standards for security research.

**About the Maintainer:** This project is developed and maintained entirely by n0m4official as a solo effort. Every contribution is personally reviewed and appreciated.
