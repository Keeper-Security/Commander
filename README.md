![](https://raw.githubusercontent.com/Keeper-Security/Commander/master/keepercommander/images/commander_logo_512x205.png)

----
#### The Password Management SDK for IT Admins & Developers

Keeper Commander is a command-line and SDK interface to [Keeper&reg; Password Manager](https://keepersecurity.com).  Keeper Commander can be used to interactively access your Keeper Vault via a standard terminal or SSH console, or it can be used as an SDK for integrating your back-end into Keeper's zero-knowledge Cloud Security Vault&trade;.

Commander can securely rotate passwords in your Keeper vault and then automatically synchronize the change to all users with privileged access to the record.  Using our connector [plugins](https://github.com/Keeper-Security/commander/tree/master/keeper/plugins), you can then perform the password reset directly on the source (e.g. database, active directory, unix/pc login, etc...).  Using Commander to rotate passwords, combined with the flexibility of Keeper's secure record sharing features provides you with the most secure and flexible way to grant and revoke access to extremely confidential data.

[Here's a Video](https://youtu.be/p50OKRiaxl8) demonstrating Commander.

### Features

* Console access to your Keeper vault
* Login, download and decrypt your vault records
* Search for content with regular expressions
* Display vault record details
* Change logins, passwords and other record data
* Rotate passwords and push changes to connected platforms
* Control record and user permissions
* Automate everything

![](https://raw.githubusercontent.com/Keeper-Security/Commander/serge-docfix/keepercommander/images/keeper_intro.gif)

Keeper Commander provides deep integration of privileged password management into back-end systems to securely access credentials, elevate permissions and rotate passwords. With Keeper Commander you can automate key security features on any platform.

Changes made through Keeper Commander instantly propagate to the users who have access to that specific record.

When you grant and revoke access or rotate a password, it instantly updates to users on their mobile and desktop devices. Control access to highly secure systems by rotating passwords and pushing those credentials to users - all within the Keeper ecosystem.

### Installation

You can install Keeper Commander with pip (the only requirement for this type of install is python 3.
You can install python3 by going to [python.org](https://www.python.org) and following the instructions):

```bash
pip3 install keepercommander
```

### Three ways to use Keeper Commander

1. From the command line or script
2. As an interactive shell (keeper shell command)
3. In your own python program by importing keepercommander package

### Command line usage
```
Usage: keeper [OPTIONS] COMMAND [ARGS]...

Options:
  -u, --user TEXT      Email address for the account
  -p, --password TEXT  Master password for the account
  --config TEXT        Config file to use
  --debug BOOLEAN      Turn on debug mode
  --version            Show the version and exit.
  --help               Show this message and exit.

Commands:
  list   List Keeper records
  shell  Use Keeper interactive shell
  ...
```  
**Environment variables**

for --user and --password options, you can set environment variables KEEPER_USER and KEEPER_PASWORD. User and password specified as options have priority over user and password settings specified in the configuration file.  

### Interactive shell
If you would like to use keeper interactively within a shell session, invoke shell by typing

```bash
keeper shell
```

To see a list of supported commands, simply type '?':

```
Keeper > ?

Commands:

  d         ... download & decrypt data
  l         ... list folders and titles
  s <regex> ... search with regular expression
  g <uid>   ... get record details for uid
  r <uid>   ... rotate password for uid
  b <regex> ... rotate password for matches of regular expression
  a         ... add a new record interactively
  c         ... clear the screen
  h         ... show command history
  q         ... quit

```

* d (download): Downloads all records from the account, decrypts the data key, private key, decrypts records and shared folders.

* l (list): Displays the Record UID, Folder and Title for all records.

* s (search): search across all record data and display the Record UID, Folder and Title for matching records.

* g (get): displays the full record details for a specified Record UID.  The Record UID can be determined by looking at the response from the "l" or "s" commands.

* r (rotate): rotates the password field of a specified Keeper record.  The new password generated is by default set to a very strong 64-byte ASCII-based string.  The previous password is also backed up and stored as a custom field in the record, saved with the timestamp of the change.

* b (batch rotate): search across all record data and rotate the password for matching records.


### Auto-configuration file

To automate the use of Commander, create a file called config.json and place the file in your install folder.  If you don't provide a config file, Commander will just prompt you for the information.

Here's an example config.json file:

```
{
    "server":"https://keeperapp.com/v2/",
    "user":"your_email_here",
    "password":"your_password_here",
    "debug":false,
    "commands":[]
}
```

You can also tell Commander which config file to use.  By default, we look at the config.json file.  Example:

```bash
keeper --config=foo.json shell
```

In this case, Commander will start up using foo.json as the configuration.

### Auto-command execution

You can provide Commander a set of commands to run without having to type them manually.  This is the easiest way to automate password resets.

Example:

```
{
    "debug":false,
    "server":"https://keeperapp.com/v2/",
    "user":"admin@company.com",
    "password":"somereallystrongpassword",
    "commands":["d", "r 3PMqasi9hohmyLWJkgxCWg", "r tlCK0x1chKH8keW8-NOraA"]
}
```

In this example, we are telling Commander to first download and decrypt records, then reset 2 passwords.  As you can see, each unique password record in the Keeper system is represented by a unique record UID.  Use the "l" or "s" command in Commander's interactive mode to display the record UIDs in your account.

### Two-Factor Authentication and Device Token

If you have Two-Factor Authentication enabled on your Keeper account (highly recommended), Keeper Commander will prompt you for the one-time passcode the first time you login.  After successfully logging in, you will be provided a device token. This device token needs to be saved for subsequent calls. Copy-paste this device token into your config.json file.  For example:

```
{
    "debug":false,
    "server":"https://keeperapp.com/v2/",
    "user":"email@company.com",
    "password":"123456",
    "mfa_token":"vFcl44TdjQcgTVfCMlUw0O9DIw8mOg8fJypGOlS_Rw0WfXbCD9iw",
    "mfa_type":"device_token",
    "commands":["d", "r 3PMqasi9hohmyLWJkgxCWg", "r tlCK0x1chKH8keW8-NOraA"]
}
```

### Plugins

Keeper Commander can talk to external systems for the purpose of resetting a password and synchronizing the change inside the Keeper Vault.  For example, you might want to rotate your MySQL password and Active Directory password automatically.  To support a plugin, simply add a custom field to the record to specify which plugin Keeper Commander should use when changing passwords.  Example:

```
Name: cmdr:plugin
Value: mysql
```
```
Name: cmdr:plugin
Value: adpasswd
```

When a plugin is specified in a record, Commander will search in the plugins/ folder to load the module based on the name provided (e.g. mysql.py and active_directory.py).

Keeper's team is expanding the number of plugins on an ongoing basis. If you need a particular plugin created, just let us know.

### Support 
We're here to help.  If you need help integrating Keeper into your environment, contact us at ops@keepersecurity.com.

### About Our Security

Keeper is a zero-knowledge platform.  This means that the server does not have access to your Keeper Master Password or the crypto keys used to encrypt and decrypt your data.  The cryptography is performed on the *client device* (e.g. iPhone, Android, Desktop, Commander).

When you create a Keeper account from our [web app](https://keepersecurity.com/vault) or [mobile/desktop app](https://keepersecurity.com/download), you are asked to create a Master Password and a security question.  The Keeper app creates your crypto keys, RSA keys and encryption parameters (iv, salt, iterations).  Your RSA private key is encrypted with your data key, and your data key is encrypted with your Master Password.  The encrypted version of your data key is stored in Keeper's Cloud Security Vault and provided to you after successful device authentication.

When you login to Keeper on any device (or on Commander), your Master Password is used to derive a 256-bit PBKDF2 key.  This key is used to decrypt your data key.  The data key is used to decrypt individual record keys.  Finally, your record keys are then used to decrypt your stored vault information (e.g. your MySQL password).

When storing information to your vault, Keeper stores and synchronizes the encrypted data.

For added security, you can enable Two-Factor Authentication on your Keeper account via the [web app](https://keepersecurity.com/vault) settings screen.  When logging into Commander with Two-Factor Authentication turned on, you will be asked for a one time passcode.  After successful authentication, you will be provided with a device token that can be used for subsequent requests without having to re-authenticate.

All of this cryptography is packaged and wrapped into a simple and easy-to-use interface.  Commander gives you the power to access, store and synchronize encrypted vault records with ease.

To learn about Keeper's security, certifications and implementation details, visit the [Security Disclosure](https://keepersecurity.com/security.html) page on our website.

### About Keeper

Keeper is the world's most downloaded password keeper and secure digital vault for protecting and managing your passwords and other secret information.  Millions of people and companies use Keeper to protect their most sensitive and private information.

Keeper's Features &amp; Benefits

* Manages all your passwords and secret info
* Protects you against hackers
* Encrypts everything in your vault 
* High-strength password generator
* Login to websites with one click
* Store private files, photos and videos
* Take private photos inside vault 
* Share records with other Keeper users
* Access on all your devices and computers
* Keeper DNA&trade; multi-factor authentication
* Login with Fingerprint or Touch ID
* Auto logout timer for theft prevention
* Unlimited backups
* Self-destruct protection
* Customizable fields
* Background themes
* Integrated Apple Watch App
* Instant syncing between devices
* AES-256 encryption
* Zero-Knowledge security architecture
* TRUSTe and SOC-2 Certified

### Keeper Website
[https://keepersecurity.com](https://keepersecurity.com)

### Pricing
Keeper is free for local password management on your device.  Premium subscription provides cloud-based features and premium device-specific features including Sync, Backup & Restore, Secure Sharing, File Storage and multi-device usage.  More info about our consumer and enterprise pricing plans can be found [here](https://keepersecurity.com/pricing.html). 

### Mobile Apps

[iPhone, iPad, iPod] (https://itunes.apple.com/us/app/keeper-password-manager-digital/id287170072?mt=8)

[Android (Google Play)](https://play.google.com/store/apps/details?id=com.callpod.android_apps.keeper&hl=en)

[Kindle (Amazon App Store)](http://amzn.com/B00NUK3F6S)

[BlackBerry (OS10+)](http://appworld.blackberry.com/webstore/content/33358889/?countrycode=US&lang=en)

[Windows Phone (8+)](http://www.windowsphone.com/en-us/store/app/keeper/8d9e0020-9785-e011-986b-78e7d1fa76f8)

[Surface](http://apps.microsoft.com/windows/en-us/app/keeper/07fe8361-f512-4873-91a1-acd0cb4c851d)

### Desktop Apps (Mac, PC, Linux)

[Windows PC](https://s3.amazonaws.com/keepersecurity/en_US/static/apps/Keeper.exe)

[Mac](https://s3.amazonaws.com/keepersecurity/en_US/static/apps/KeeperDesktop.dmg)

[Linux](https://s3.amazonaws.com/keepersecurity/en_US/static/apps/KeeperDesktopLinux.zip)

[Mac App Store](https://keepersecurity.com/macreview)

[Windows Store](http://apps.microsoft.com/windows/en-us/app/keeper/07fe8361-f512-4873-91a1-acd0cb4c851d)

### Web-Based Apps and Browser Extensions

[Online Vault](https://keepersecurity.com/vault)

[FastFill for Chrome](https://chrome.google.com/webstore/detail/keeper-browser-extension/bfogiafebfohielmmehodmfbbebbbpei)

[FastFill for Firefox](https://addons.mozilla.org/en-us/firefox/addon/keeper-password-manager-digita/)

[FastFill for Safari](https://s3.amazonaws.com/keepersecurity/ext/update/safari/keeper.safariextz)

[FastFill for Internet Explorer](https://s3.amazonaws.com/keepersecurity/en_US/static/apps/SetupKeeperIE.exe)

[Enterprise Admin Console](https://keepersecurity.com/console)

