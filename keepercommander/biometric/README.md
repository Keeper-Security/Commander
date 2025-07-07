# Biometric Authentication Module

This module provides biometric authentication support for Keeper Commander across multiple platforms.

## Overview

The biometric module enables users to authenticate with Keeper using platform-specific biometric methods such as:
- Windows Hello (Windows)
- Touch ID (macOS)

## Architecture

The module is structured as follows:

- `biometric.py` - Core biometric functionality and command implementations
- `biometric_win.py` - Windows-specific biometric implementations
- `biometric_mac.py` - macOS-specific biometric implementations

## Dependencies

- `fido2` - FIDO2/WebAuthn support for biometric authentication
- Platform-specific libraries are imported conditionally

## Usage

### Adding a biometric method
```bash
biometric register
```

### Listing biometric methods
```bash
biometric list
```

### Testing biometric authentication
```bash
biometric test
```

### Verifying biometric authentication
```bash
biometric verify
```

### Disabling biometric authentication
```bash
biometric unregister
```

## Platform Support

### Windows
- Windows Hello Face recognition
- Windows Hello Fingerprint
- WebAuthn support via Windows Hello

### macOS
- Touch ID
- FIDO2 device support


## Implementation Details

The module uses FIDO2/WebAuthn standards for biometric authentication, ensuring compatibility with Keeper's backend systems. Platform-specific implementations handle the nuances of each operating system's biometric APIs.

## Registry/Configuration Storage

- **Windows**: Uses Windows Registry to store biometric authentication flags

## Error Handling

The module provides comprehensive error handling for various biometric authentication scenarios:
- Hardware not available
- User cancellation
- Timeout conditions
- Authentication failures
- Platform-specific errors 