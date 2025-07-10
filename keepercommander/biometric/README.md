# Biometric Authentication Module

This module provides biometric authentication support for Keeper Commander across multiple platforms.

## Overview

The biometric module enables users to authenticate with Keeper using platform-specific biometric methods such as:
- Windows Hello (Windows)
- Touch ID (macOS)


## Prerequisites

### OS-Level Biometric Setup

**Before using biometric authentication with Keeper Commander, you must have biometric credentials already configured in your operating system:**

#### Windows Requirements:
- **Windows Hello must be set up** in Windows Settings
- Navigate to: `Settings > Accounts > Sign-in options > Windows Hello`
- Configure at least one of:
  - **Face recognition**: Set up Windows Hello Face
  - **Fingerprint**: Set up Windows Hello Fingerprint
  - **PIN**: Required as a backup authentication method
- Hardware requirements:
  - Compatible biometric hardware (fingerprint reader, IR camera, etc.)
  - TPM (Trusted Platform Module) chip

#### macOS Requirements:
- **Touch ID must be enabled** in System Preferences
- Navigate to: `System Preferences > Touch ID & Password`
- Add your fingerprint(s) to the system
- Hardware requirements:
  - Mac with Touch ID sensor (MacBook Pro 2016+, MacBook Air 2018+, iMac with Touch ID, etc.)

## Usage

### Setup Process

1. **Install required dependencies**:
   ```bash
   pip install cbor2 pyobjc-framework-LocalAuthentication
   ```
2. **Device registration is mandatory before biometric authentication can be used:**
    After login with keeper shell:
    ```bash
    # First, register your device with Keeper
    this-device register
    ```

    This step is required because:
    - Biometric authentication requires a trusted device relationship
    - The device must be approved by Keeper's security system
    - Without device registration, biometric login will still require default authentication.

**Note**: For macOS, Touch ID for sudo is automatically configured when you use biometric authentication for the first time.

### Available Commands

#### Adding a biometric method
```bash
biometric register
```
- Registers your OS-configured biometric credentials with Keeper
- Requires prior device registration via `this-device register`

#### Listing biometric methods
```bash
biometric list
```
- Shows all registered biometric credentials for your account

#### Testing biometric authentication
```bash
biometric verify
```
- Tests biometric authentication without logging in
- Useful for troubleshooting setup issues

#### Disabling biometric authentication
```bash
biometric unregister
```
- Removes biometric authentication from your account
- You'll need to use password authentication after this

## Platform Support

### Windows
- **Windows Hello Face recognition**
- **Windows Hello Fingerprint**
- **WebAuthn support via Windows Hello**
- **Storage**: Windows Registry (`HKEY_CURRENT_USER\Software\KeeperSecurity\Commander`)

### macOS
- **Touch ID**
- **FIDO2 device support**
- **Storage**: Property list files (`~/Library/Application Support/Keeper/biometric_flags.plist`)

## Troubleshooting

### Common Issues

#### Password prompt after Biometric
```bash
# Solution: Register your device first
this-device register

# Then try biometric registration again
biometric register
```

#### "Authentication failed"
- Verify your biometric credentials work for OS login
- Try re-registering: `biometric unregister` then `biometric register`
- Ensure your biometric sensor is clean and unobstructed

#### "No biometric hardware detected"
- **Windows**: Ensure Windows Hello is properly configured in Settings
  - Also check if FIDO libraries are installed: `pip install fido2`
- **macOS**: Verify Touch ID is enabled in System Preferences
  - Also check if local authentication CBOR libraries are installed: `pip install cbor2 pyobjc-framework-LocalAuthentication`
- Check that your hardware supports biometric authentication

## Implementation Details

The module uses FIDO2/WebAuthn standards for biometric authentication, ensuring compatibility with Keeper's backend systems. Platform-specific implementations handle the nuances of each operating system's biometric APIs.

### Storage Locations

- **Windows**: `HKEY_CURRENT_USER\Software\KeeperSecurity\Commander`
- **macOS**: `~/Library/Application Support/Keeper/biometric_flags.plist`

### Security Features

- Uses platform-specific secure storage
- Implements proper FIDO2/WebAuthn protocols
- Supports user presence verification
- Handles timeout and cancellation scenarios

## Dependencies

- `fido2` - FIDO2/WebAuthn support for biometric authentication
- `cbor2` - CBOR encoding/decoding for biometric data
- `pyobjc-framework-LocalAuthentication` - macOS local authentication framework
- Platform-specific libraries are imported conditionally
- No additional dependencies required beyond base Keeper Commander

## Error Handling

The module provides comprehensive error handling for various biometric authentication scenarios:
- Hardware not available
- User cancellation
- Timeout conditions
- Authentication failures
- Platform-specific errors
- Device approval requirements 