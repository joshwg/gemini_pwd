# Build Scripts

This directory contains build scripts for Gemini PWD that support multiple platforms and build configurations.

## Quick Start

### Unix/Linux/macOS (build.sh)
```bash
# Make executable (first time only)
chmod +x build.sh

# Local development build
./build.sh local dev

# Local optimized build
./build.sh local release

# Cross-platform builds
./build.sh windows release
./build.sh linux release
./build.sh darwin release

# Build for all platforms
./build.sh all release

# Clean build artifacts
./build.sh clean
```

### Windows (build.bat)
```cmd
# Local development build
.\build.bat local dev

# Local optimized build
.\build.bat local release

# Cross-platform builds
.\build.bat windows release
.\build.bat linux release
.\build.bat darwin release

# Build for all platforms
.\build.bat all release

# Clean build artifacts
.\build.bat clean
```

## Build Targets

- **local**: Build for the current platform
- **linux**: Build for Linux (amd64 and arm64)
- **windows**: Build for Windows (amd64 and arm64)
- **darwin**: Build for macOS (amd64 and arm64)
- **all**: Build for all supported platforms
- **clean**: Remove all build artifacts

## Build Types

- **dev**: Development build with debug information
- **release**: Optimized build with stripped debug info (smaller size)

## Output

All build artifacts are placed in the `./bin/` directory:

- `gemini-pwd` - Local platform build
- `gemini-pwd-linux-amd64` - Linux x64
- `gemini-pwd-linux-arm64` - Linux ARM64
- `gemini-pwd-windows-amd64.exe` - Windows x64
- `gemini-pwd-windows-arm64.exe` - Windows ARM64
- `gemini-pwd-darwin-amd64` - macOS Intel
- `gemini-pwd-darwin-arm64` - macOS Apple Silicon

## Features

- **Automatic testing**: Runs core functionality tests before building
- **Version information**: Embeds build version, timestamp, and git commit
- **Cross-compilation**: Supports building for different platforms from any host
- **Size optimization**: Release builds are significantly smaller
- **Clean builds**: Easy cleanup of artifacts
- **Colored output**: Clear visual feedback during build process

## Build Information

The builds include embedded version information:
- Version: Based on current date (YYYY.MM.DD)
- Build time: UTC timestamp
- Git commit: Short commit hash (if available)

This information can be displayed in the application for debugging and support purposes.

## Requirements

- Go 1.21 or later
- Git (for commit hash embedding)
- Cross-compilation support (automatically available with Go)

## Examples

```bash
# Quick development build and test
./build.sh local dev

# Production release for current platform
./build.sh local release

# Build Windows executables for distribution
./build.sh windows release

# Build everything for release
./build.sh all release
```

The build scripts automatically handle:
- Creating output directories
- Running tests
- Cross-compilation setup
- Build optimization
- Error handling
- Progress reporting
