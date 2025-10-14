# Changelog

All notable changes to C3NT1P3D3 will be documented in this file.

## [3.1.0] - 2025-01-14

### Added
- CSRF detection module with form analysis
- IDOR detection module with sequential ID testing
- Enhanced CLI with `--include` and `--exclude` module filtering
- `--list-modules` option to view all available detectors
- `--cloud-only` scanning mode

### Changed
- Updated module count from 30 to 37
- Improved CLI help documentation
- Enhanced MITRE ATT&CK coverage (20+ techniques)

### Technical Notes
- 2 new modules fully implemented (CSRF, IDOR)
- 4 additional module stubs added for future development
- All modules compile successfully on Windows ARM64

## [3.0.0] - 2024-10-11

### Added
- 30 vulnerability detection modules
- MITRE ATT&CK framework integration
- Production scanner with safety controls
- Comprehensive documentation

### Security
- IP range validation
- Private network protection (RFC 1918)
- Rate limiting and timeout controls

## [2.0.0] - 2024-09-15

### Added
- Initial release with core scanning capabilities
- Network and web vulnerability detection
- Basic reporting functionality
