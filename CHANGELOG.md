# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Automatic SHA256 hash verification using asset digest from GitHub API

### Improved
- Enhanced installer selection logic with better fallback mechanisms
- Comprehensive error handling with retry logic, timeout handling, and validation
- Windows platform testing completed

## [1.0.0] - 2024-12-19

### Added

- Cross-platform Python script to download latest stable Brave Browser from GitHub Releases
- Automatic OS detection (macOS, Windows, Linux)
- Automatic CPU architecture detection (x64, ARM64, x86)
- Linux distribution family detection (Debian-based, RHEL-based, Arch-based)
- Intelligent installer selection:
  - `.dmg` / `.pkg` for macOS (prefers universal DMG, falls back to arch-specific)
  - `.exe` for Windows (prefers StandaloneSetup offline installer)
  - `.deb` for Debian-based Linux distributions
  - `.rpm` for RHEL-based Linux distributions
- Download functionality with progress indication
- Optional installation step via `--install` flag
- `--print-only` flag to output download URL for automation
- `--dir` flag to specify custom download directory
- GitHub API token support via `GITHUB_TOKEN` environment variable
- macOS installation support (DMG mounting and app copying to /Applications)
- Windows installation support (launches installer)
- Linux installation support (dpkg for .deb, dnf/yum/rpm for .rpm)
- Interactive prompts before destructive operations
- Error handling for missing assets and unsupported systems
- Uses only Python standard library (no external dependencies)
- Python 3.8+ compatibility

