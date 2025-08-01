# Biometric Authentication

## Secure Authentication with Platform Biometrics for Keeper Commander

The Biometric Authentication module for Keeper Commander enables users to authenticate using platform-specific biometric methods such as Windows Hello and Touch ID. This module provides a secure, convenient alternative to password-based authentication while maintaining the highest security standards through FIDO2/WebAuthn protocols.

### Core Functionality

- **Cross-Platform Support**: Windows Hello and Touch ID integration 
- **WebAuthn Protocol**: FIDO2-compliant authentication implementation  
- **Secure Credential Storage**: Platform-native secure storage (Windows Hello, macOS Keychain) 
- **Device Trust Management**: Required device registration for security   
- **Credential Lifecycle**: Complete registration, verification, and removal workflows 
- **Error Handling**: Comprehensive error handling with user-friendly messages   

---

## Prerequisites

### OS-Level Biometric Setup

**Before using biometric authentication with Keeper Commander, you must have biometric credentials already configured in your operating system:**

#### Windows Requirements:
- **Windows 11** (required for biometric authentication support)
- **Windows Hello must be set up** in Windows Settings
- Navigate to: `Settings > Accounts > Sign-in options > Windows Hello`
- Configure at least one of:
  - **Face recognition**: Set up Windows Hello Face
  - **Fingerprint**: Set up Windows Hello Fingerprint
  - **PIN**: Required as a backup authentication method
- Hardware requirements:
  - Compatible biometric hardware (fingerprint reader, IR camera, etc.)

#### macOS Requirements:
- **Touch ID must be enabled** in System Preferences
- Navigate to: `System Preferences > Touch ID & Password`
- Add your fingerprint(s) to the system
- Hardware requirements:
  - Mac with Touch ID sensor (MacBook Pro 2016+, MacBook Air 2018+, iMac with Touch ID, etc.)

### Software Dependencies

Install the required Python packages:

```bash
pip install cbor2 pyobjc-framework-LocalAuthentication fido2
```

---

## Usage

### Initial Setup Process

#### 1. Biometric Registration

Register your biometric credentials with Keeper (requires initial login with your Master password):

```bash
# First, log in to Keeper Commander
keeper shell

# Register biometric authentication
biometric register
```

You'll be prompted to:
- Complete biometric authentication (Touch ID/Windows Hello)
- Provide a friendly name for the credential (optional)

Example with custom settings:

```bash
biometric register --name "My MacBook"
```

#### 2. Device Registration (Mandatory)

**Device registration is required before biometric authentication can be used:**

```bash
# Register your device with Keeper (mandatory step)
this-device register
```

**Why Device Registration is Required:**
- Biometric authentication requires a trusted device relationship
- The device must be approved by Keeper's security system
- Without device registration, biometric login will fall back to default authentication

---

## Commands

### Available Commands

| Command | Description |
|---------|-------------|
| `biometric register` | Add biometric authentication method |
| `biometric list` | List registered biometric authentication methods |
| `biometric verify` | Test biometric authentication without logging in |
| `biometric unregister` | Remove biometric authentication from account |
| `biometric update-name` | Update friendly name of a biometric passkey |

### Register Command

Add a new biometric authentication method:

```bash
biometric register [options]
```

**Parameters:**
- `--name`: Friendly name for the biometric method

**Examples:**

```bash
# Basic registration with default settings
biometric register

# Registration with custom name
biometric register --name "Work Laptop"
```

**Sample Output:**

```
Adding biometric authentication method: My MacBook
Please complete biometric authentication...
Biometric authentication completed successfully!

Success! Biometric authentication "Commander CLI (MacBook)" has been registered.

Please register your device using the "this-device register" command to set biometric authentication as your default login method.
```

### List Command

Display all registered biometric authentication methods:

```bash
biometric list
```

**Sample Output:**

```
Registered Biometric Authentication Methods:
----------------------------------------------------------------------
Name: Commander CLI (MacBook)
Created: December 20, 2023
Last Used: Today
----------------------------------------------------------------------
Name: iCloud Keychain
Created: December 18, 2023
Last Used: July 10, 2025
----------------------------------------------------------------------
Name: Chrome on Mac
Created: November 15, 2023
Last Used: Never
----------------------------------------------------------------------
```

### Verify Command

Test biometric authentication without performing a login:

```bash
biometric verify
```

**Sample Output:**

```
Please complete biometric authentication...

Biometric Authentication Verification Results:
==================================================
Status: SUCCESSFUL
Purpose: LOGIN
Login Token: Received

Your biometric authentication is working correctly!
==================================================
```

### Unregister Command

Remove biometric authentication from your account:

```bash
biometric unregister [options]
```

**Parameters:**
- `--confirm`: Skip confirmation prompt

**Examples:**

```bash
# Interactive unregistration (with confirmation)
biometric unregister

# Silent unregistration (no confirmation)
biometric unregister --confirm
```

**Sample Output:**

```
Are you sure you want to disable biometric authentication for user 'user@example.com'? (y/n): y

Biometric authentication has been completely removed for user 'user@example.com'.
Default authentication will be used for future logins.
```

### Update Name Command

Update the friendly name of an existing biometric credential:

```bash
biometric update-name
```

This command provides an interactive interface to:
1. Select from available credentials
2. Enter a new friendly name (max 32 characters)
3. Confirm the update

**Sample Interaction:**

```
Found 2 biometric credential(s) with friendly names

Available Biometric Credentials:
--------------------------------------------------
 1. Commander CLI (MacBook)
    Created: January 15, 2024
    Last Used: Today

 2. Commander CLI (Desktop)  
    Created: January 10, 2024
    Last Used: January 18, 2024

Select credential number (1-2): 1
Selected: Commander CLI (MacBook)

Current Name: Commander CLI (MacBook)
Enter a new friendly name (max 32 characters):
New name: Personal MacBook

Update Summary:
--------------------
Current Name:  Commander CLI (MacBook)
New Name:      Personal MacBook

Proceed with update? (y/n): y

Passkey Update Results:
==============================
Status: Success
Old Name: Commander CLI (MacBook)
New Name: Personal MacBook
Message: Passkey friendly name was successfully updated
==============================
```

---

## Platform Support

### Windows

**Supported Methods:**
- Windows Hello Face recognition
- Windows Hello Fingerprint  
- Windows Hello PIN (as backup)
- WebAuthn support via Windows Hello

**Setup Requirements:**
- Windows 11 (required for biometric authentication support)
- Windows Hello configured in Settings > Accounts > Sign-in options
- At least one enrolled biometric factor (Face/Fingerprint) OR PIN
- Compatible biometric hardware (for Face/Fingerprint)
- Administrative privileges for initial Windows Hello setup

### macOS

**Supported Methods:**
- Touch ID
- Custom macOS WebAuthn client integration
- Keychain-based credential management

**Setup Requirements:**
- Touch ID enabled in System Preferences > Touch ID & Password
- At least one enrolled fingerprint in system settings
- Compatible Mac with Touch ID sensor (MacBook Pro 2016+, MacBook Air 2018+, iMac with Touch ID, etc.)
- LocalAuthentication framework dependencies

---

## Troubleshooting

### Common Issues

#### "Authentication failed" Error

**Possible Causes:**
- Biometric sensors are dirty or obstructed
- OS-level biometric credentials need re-enrollment
- Hardware compatibility issues

**Solutions:**
```bash
# Re-register biometric authentication
biometric unregister --confirm
biometric register

# Verify OS biometric setup is working
# Windows: Test Windows Hello in Settings
# macOS: Test Touch ID in System Preferences
```

#### "No biometric hardware detected" Error

**Windows Solutions:**
```bash
# Check Windows Hello setup status
# Navigate to Settings > Accounts > Sign-in options > Windows Hello

# Verify biometric enrollment
# Check if Face recognition or Fingerprint is set up
# Ensure at least PIN is configured as backup

# Install FIDO2 libraries if missing
pip install fido2
```

**macOS Solutions:**
```bash
# Check Touch ID setup comprehensively
# Navigate to System Preferences > Touch ID & Password

# Install required dependencies
pip install cbor2 pyobjc-framework-LocalAuthentication

# Test Touch ID detection manually
bioutil -r -s
```

#### "Password prompt after biometric" Issue

**Cause:** Device not registered with Keeper

**Solution:**
```bash
# Register device first (mandatory step)
this-device register

# Then try biometric authentication
biometric verify
```

#### "Credential already exists" Error

**Solution:**
```bash
# Remove existing credential first
biometric unregister --confirm

# Register new credential
biometric register
```

---


## Support

For support or feature requests regarding biometric authentication, please contact:

• **Email**: commander@keepersecurity.com

If you encounter issues with biometric authentication or would like to request additional platform support, please reach out with:
- Operating system and version
- Hardware specifications
- Error messages or logs
- Steps to reproduce the issue
