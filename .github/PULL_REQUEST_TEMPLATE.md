# Pull Request

## Description

Please provide a clear and concise description of your changes.

## Type of Change

- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update
- [ ] Code refactoring
- [ ] Performance improvement
- [ ] Other (please describe):

## Related Issues

Fixes #(issue number)
Related to #(issue number)

## Changes Made

Please list the main changes:

- 
- 
- 

## New Module Checklist (if applicable)

If this PR adds a new detection module:

- [ ] Header file created in `include/`
- [ ] Implementation created in `src/`
- [ ] Inherits from `IModule` interface
- [ ] Implements `id()` and `run()` methods
- [ ] Includes MITRE ATT&CK mapping
- [ ] Added to `CMakeLists.txt`
- [ ] Module count updated in README.md
- [ ] Entry added to CHANGELOG.md
- [ ] Includes proper error handling
- [ ] Uses timeouts for network operations
- [ ] Detection-only (no exploitation code)

## Testing

### Test Environment

- **OS:** [e.g., Windows 11, Ubuntu 22.04]
- **Architecture:** [e.g., x64, ARM64]
- **Compiler:** [e.g., Visual Studio 2022, GCC 11]

### Testing Performed

- [ ] Code compiles without errors
- [ ] Code compiles without warnings (or warnings documented)
- [ ] Tested on authorized target systems
- [ ] Verified existing functionality not broken
- [ ] Tested edge cases

### Test Results

Describe your test results:

```
Paste relevant test output here
```

## Code Quality

- [ ] My code follows the project's style guidelines
- [ ] I have performed a self-review of my code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] My changes generate no new warnings
- [ ] I have updated the documentation accordingly

## Documentation

- [ ] README.md updated (if needed)
- [ ] CHANGELOG.md updated
- [ ] Code comments added where necessary
- [ ] No sensitive information included

## Security & Ethics

- [ ] This code is for detection only (no exploitation)
- [ ] No hardcoded credentials or sensitive data
- [ ] Follows responsible disclosure practices
- [ ] Tested only on authorized systems
- [ ] Complies with legal requirements

## Breaking Changes

Does this PR introduce breaking changes?

- [ ] No
- [ ] Yes (please describe below)

**Description of breaking changes:**



## Additional Notes

Any additional information reviewers should know:



## Screenshots (if applicable)

Add screenshots to help explain your changes.

## Checklist

- [ ] I have read the [CONTRIBUTING.md](../CONTRIBUTING.md) guidelines
- [ ] I have read and agree to the [Code of Conduct](../CODE_OF_CONDUCT.md)
- [ ] My commits have descriptive messages
- [ ] I have tested my changes thoroughly
- [ ] I am authorized to submit this contribution
- [ ] This PR is ready for review

---

**By submitting this pull request, I confirm that my contribution is made under the terms of the project's MIT license and that I have the right to submit this work.**
