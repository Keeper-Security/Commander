![](https://raw.githubusercontent.com/Keeper-Security/Commander/master/keepercommander/images/commander_logo_512x205.png)

[![Build Status](https://travis-ci.org/Keeper-Security/Commander.svg)](https://travis-ci.org/Keeper-Security/Commander)

----
#### The Password Management SDK for IT Admins & Developers

Keeper Commander is a command-line and SDK interface to [Keeper&reg; Password Manager](https://keepersecurity.com).  Keeper Commander is designed to perform targeted password rotations and eliminate the use of hardcoded passwords in your systems and software.  Commander will securely rotate passwords in your Keeper vault and then instantly push the changes to all users with privileged access to the password.  Using our connector [plugins](https://github.com/Keeper-Security/Commander/tree/master/keepercommander/plugins), Commander executes a strong password rotation directly to the target system (Unix Logins, Databases, Active Directory, network devices, etc...).

Commander also has a command-line shell interface which provides instant terminal access to your vault on any Unix, Mac or Windows system.  Since Keeper Commander is an open source SDK and written in Python, it can be customized to meet your needs and integrated into your back-end systems.

[Here's a Video](https://youtu.be/p50OKRiaxl8) demonstrating Commander.

### Use Cases

* Eliminate hard-coded or plaintext passwords in back-end systems
* Rotate passwords on shared accounts 
* Perform password rotations on target systems
* Access passwords through a terminal or SSH session
* Authenticate with Yubikey and other 2FA methods
* Schedule and automate rotations 

![](https://raw.githubusercontent.com/Keeper-Security/Commander/master/keepercommander/images/keeper_intro.gif)

Keeper Commander provides deep integration of privileged password management into back-end systems to securely access credentials, elevate permissions and rotate passwords. With Keeper Commander you can automate key security features on any platform.

Changes made through Keeper Commander instantly propagate to the users who have access to that specific record.

When you grant and revoke access or rotate a password, it instantly updates to users on their mobile and desktop devices. Control access to highly secure systems by rotating passwords and pushing those credentials to users - all within the Keeper ecosystem.

### Installation

If you do not have Python 3 installed already (check by trying to run `pip3` in the Terminal), you can install it by going to [python.org](https://www.python.org) and following the instructions).

Note: Restart your terminal session after installation

Install Keeper Commander with pip3:

```bash
pip3 install keepercommander
```

Note: Restart your terminal session after installation

### Upgrade

To upgrade Keeper Commander to the newest version, call pip3 install with --upgrade parameter:

```bash
pip3 install --upgrade keepercommander
```

### Three ways to use Keeper Commander

1. From the command line or script
2. As an interactive shell
3. In your own Python program by importing the keepercommander package

### Command line usage
```
Usage: keeper [OPTIONS] COMMAND [ARGS]...

Options:
  -s, --server TEXT    Host address
  -u, --user TEXT      Email address for the account
  -p, --password TEXT  Master password for the account
  --config TEXT        Config file to use
  --debug              Turn on debug mode
  --version            Show the version and exit.
  --help               Show this message and exit.

Commands:
  list        List Keeper records
  shell       Use Keeper interactive shell
  ...
```  
**Environment variables**

for `--user` and `--password` options, you can set environment variables `KEEPER_SERVER`, `KEEPER_USER` and `KEEPER_PASSWORD`. Server, user and password specified as options have priority over server, user and password settings specified in the configuration file.  

### Interactive shell
If you would like to use Keeper interactively within a shell session, invoke shell by typing

```bash
keeper shell
```

To see a list of supported commands, simply type '?':

```
Keeper > ?

Commands:

  d         ... download & decrypt data
  l         ... list folders and titles
  lsf       ... list shared folders 
  s <regex> ... search with regular expression
  g <uid>   ... get record or shared folder details
  r <uid>   ... rotate password for uid
  b <regex> ... rotate password for matches of regular expression
  a         ... add a new record interactively
  c         ... clear the screen
  h         ... show command history
  q         ... quit

```

* d (download): Downloads all records from the account, decrypts the data key, private key, decrypts records and shared folders.

* l (list): Displays the Record UID, Folder and Title for all records.

* s (search): Searches across all record data and display the Record UID, Folder and Title for matching records.

* g (get): Displays the full record details for a specified Record UID.  The Record UID can be determined by looking at the response from the "l" or "s" commands.

* r (rotate): Rotates the password field of a specified Keeper record.  The new password generated is by default set to a very strong 64-byte ASCII-based string.  The previous password is also backed up and stored as a custom field in the record, saved with the timestamp of the change.

* b (batch rotate): Searches across all record data and rotate the password for matching records.

The Record UID is a unique identifier for every record in your Keeper vault.  This is used for deep linking and also for password rotation as described below. The search/list/get commands can be used to look up the Record UID when setting up a password rotation scheduler.

### Deep linking to records

The Record UID that is displayed on password record output can be used for deep linking directly into the Web Vault and mobile platforms. The link format is like this: https://keepersecurity.com/vault#detail/XXXXXX where you simply replace XXXXXX with the Record UID.

### Automating Commander 

To automate the use of Commander, create a JSON file (let's call it config.json) and place the file in the working directory where you are invoking the shell commands.  If you don't provide a config file, Commander will just prompt you for the information interactively.

Here's an example config.json file:

```
{
    "server":"https://keepersecurity.com/api/v2/",
    "user":"your_email_here",
    "password":"your_password_here",
    "debug":false,
    "commands":[]
}
```

All fields are optional.  You can also tell Commander which config file to use.  By default, we look at the config.json file.  

Example 1: Simply access your vault interactively (if config.json is in the current folder, it will take precedence)

```bash
keeper shell
```

Example 2: Load up parameters from the specified JSON file

```bash
keeper --config=foo.json shell
```

In this case, Commander will start up using foo.json as the configuration.

### JSON file parameters

```
server: do not change.  Default is https://keepersecurity.com/api/v2/.
user: the Keeper email address
password: the Keeper master password
debug: turn on verbose debugging output
commands: comma-separated list of commands to run
timedelay: number of seconds to wait before running all commands again
mfa_type: if multi-factor auth is used, this will be set to "device_token"
mfa_token: two-factor token used to authenticate this Commander instance
challenge: challenge phrase if you are using a Yubikey device 
```

If you have turned on two-factor authentication on your Keeper account, you will be prompted the first time you run Commander to enter the two-factor code.  Once authenticated, Commander will update the mfa_type and mfa_token parameters in the config file.  This way, subsequent calls are authenticated without needing additional two-factor tokens.

You may ask, why is the master password stored in the JSON configuration file?  It doesn't need to be. You can omit the password field from the JSON file, and you'll be prompted with the password interactively.  It is our recommendation to set up a Keeper account that is solely used for Commander interaction. Using Keeper's sharing features, share the records with the Commander account that will be rotated.  Set a strong master password (such as a long hash key) and turn on Two-Factor authentication on this Commander account.  Then store the account master password in the JSON file and do not use this account for any other operations. 

### Scheduling & Automation

If you want to fully automate Commander operations, such as rotating a password on a regular schedule, there are a few different ways to accomplish this.

Using config.json file and **timedelay** setting, you tell Commander the time delay in seconds to wait and then reissue all commands.  This is the easiest way to schedule automated password resets.

Below is an example:

config.json:

```
{
    "debug":false,
    "server":"https://keepersecurity.com/api/v2/",
    "user":"admin@company.com",
    "password":"somereallystrongpassword",
    "timedelay":600,
    "commands":["d", "r 3PMqasi9hohmyLWJkgxCWg", "r tlCK0x1chKH8keW8-NOraA"]
}
```

Terminal command:

```
keeper --config config.json shell
```

In this example, Commander would download and decrypt records, rotate 2 passwords (with Record UIDs specified), and then wait for 600 seconds (10 minutes) before issuing the commands again.  Also in this example, the master password is stored in the JSON file.  If you don't want to store a credential or Yubikey challenge phrase in the JSON config file, you can leave that out and you'll be prompted for the password on the interactive shell.  But in this scenario, you'll need to leave Commander running in a persistent terminal session.

If you prefer not to keep a persistent terminal session active, you can also add Commander to a cron script (for Unix/Linux systems) or the launchctl daemon on Mac systems.  Below is an example of executing Commander from a Mac launchctl scheduler:

### Setting up Keeper Commander to run via scheduler on a Mac

1. Create LaunchAgents folder if not there already:
```
mkdir -p ~/Library/LaunchAgents
```

2. Create a new file representing this process

```
vi ~/Library/LaunchAgents/com.keeper.commander.plist
```

In the file, add something like this:
```
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.keeper.commander.rotation_test</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Path/to/folder/my_script.sh</string>
    </array>
    <key>StartInterval</key>
    <integer>600</integer>
    <key>WorkingDirectory</key>
    <string>/Path/to/folder</string>
    <key>StandardOutPath</key>
    <string>/Path/to/folder/output.log</string>
    <key>StandardErrorPath</key>
    <string>/Path/to/folder/output.err</string>
</dict>
</plist>
```

Note: replace /Path/to/folder with the path to your working directory
and replace 600 with the number of seconds between runs.
 
3.  In /Path/to/folder/ create a script my_script.sh like this:

```
vi my_script.sh
```

Add the following lines to the file:

```
export LANG=en_US.UTF-8
say starting Keeper
MYLOGLINE="`date +"%b %d %Y %H:%M"` $0:"
echo "$MYLOGLINE Executing Keeper"
/Library/Frameworks/Python.framework/Versions/3.5/bin/keeper --config config.json shell
say rotation complete
```

Change the permissions to executable
```
chmod +x my_script.sh
```

4. Activate the process 

```
launchctl unload ~/Library/LaunchAgents/com.keeper.commander.plist
launchctl load -w ~/Library/LaunchAgents/com.keeper.commander.plist
```
 
Based on this example, Keeper Commander will execute the commands specified in config.json every 600 seconds.

### Two-Factor Authentication and Device Token

If you have Two-Factor Authentication enabled on your Keeper account (highly recommended), Keeper Commander will prompt 
you for the one-time passcode the first time you login.  After successfully logging in, you will be provided a device token. 
This device token is automatically saved to the config file when you login interactively. 
If you have multiple config files, you can just copy-paste this device token into your config.json file.  For example:

```
{
    "debug":false,
    "server":"https://keepersecurity.com/api/v2/",
    "user":"email@company.com",
    "password":"123456",
    "mfa_token":"vFcl44TdjQcgTVfCMlUw0O9DIw8mOg8fJypGOlS_Rw0WfXbCD9iw",
    "mfa_type":"device_token",
    "device_token_expiration":true,
    "commands":["d", "r 3PMqasi9hohmyLWJkgxCWg", "r tlCK0x1chKH8keW8-NOraA"]
}
```
Note: If you want your device tokens to expire, set "device_token_expiration" to "true". If set, your device token will expire in 30 days.

To activate Two-Factor Authentication on your Keeper account, login to the [Web App](https://keepersecurity.com/vault) 
and visit the Settings screen.  Keeper supports Text Message, Google Authenticator, RSA SecurID and Duo Security methods.


### Yubikey Support 

Commander supports the ability to authenticate a session with a connected Yubikey device instead of using a Master Password.  To configure Yubikey authentication, follow the [setup instructions](https://github.com/Keeper-Security/Commander/tree/master/keepercommander/yubikey).  You will end up using a challenge phrase to authenticate instead of the master password.

### Targeted Password Rotations & Plugins 

Keeper Commander can communicate to internal and external systems for the purpose of rotating a password and synchronizing the change to your Keeper Vault.  For example, you might want to rotate your MySQL password and Active Directory password automatically.  To support a plugin, simply add a set of **custom field** values to the Keeper record that you will be rotating.  To do this, simply login to Keeper on the [Web Vault](https://keepersecurity.com/vault) and edit the record you will be rotating.  Add custom fields to the record and save it. The custom field value tells Commander which plugin to use when rotating the password.

For example:

```
Name: cmdr:plugin
Value: mysql
```
```
Name: cmdr:plugin
Value: adpasswd
```

When a plugin is specified in a record, Commander will search in the plugins/ folder to load the module based on the name provided (e.g. mysql.py and active_directory.py).

Check out the [plugins folder](https://github.com/Keeper-Security/Commander/tree/master/keepercommander/plugins) for all of the available plugins.  Keeper's team is expanding the number of plugins on an ongoing basis. If you need a particular plugin created, just let us know.

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

[iOS - iPhone, iPad, iPod](https://itunes.apple.com/us/app/keeper-password-manager-digital/id287170072?mt=8)

[Android - Google Play](https://play.google.com/store/apps/details?id=com.callpod.android_apps.keeper&hl=en)

[Kindle and Amazon App Store](http://amzn.com/B00NUK3F6S)

[Windows Phone](http://www.windowsphone.com/en-us/store/app/keeper/8d9e0020-9785-e011-986b-78e7d1fa76f8)


### Cross-Platform Desktop App (Mac, PC, Linux)

[Windows PC](https://s3.amazonaws.com/keepersecurity/en_US/static/apps/KeeperDesktop.exe)

[Mac](https://s3.amazonaws.com/keepersecurity/en_US/static/apps/KeeperDesktop.dmg)

[Linux](https://s3.amazonaws.com/keepersecurity/en_US/static/apps/KeeperDesktopLinux.zip)

### Mac App Store (Thin Client)

[Mac App Store](https://itunes.apple.com/us/app/keeper-password-manager-digital/id414781829?mt=12)

### Microsoft Store Platform

[Microsoft Store Version - Windows 10](https://www.microsoft.com/store/apps/9wzdncrdmpt6)

[Microsoft Store Version - Windows 8.1 and earlier](http://apps.microsoft.com/windows/app/07fe8361-f512-4873-91a1-acd0cb4c851d)

[Microsoft Store Version - Windows Phone 8.1 and earlier](http://windowsphone.com/s?appid=8d9e0020-9785-e011-986b-78e7d1fa76f8)

[Surface](http://apps.microsoft.com/windows/en-us/app/keeper/07fe8361-f512-4873-91a1-acd0cb4c851d)

### Web-Based Apps and Browser Extensions

[Web App - Online Vault](https://keepersecurity.com/vault)

[KeeperFill for Chrome](https://chrome.google.com/webstore/detail/keeper-browser-extension/bfogiafebfohielmmehodmfbbebbbpei)

[KeeperFill for Firefox](https://addons.mozilla.org/en-US/firefox/addon/keeper-password-manager-digita/)

[KeeperFill for Safari](https://safari-extensions.apple.com/details/?id=com.keepersecurity.safari.KeeperExtension-234QNB7GCA)

[KeeperFill for Internet Explorer](https://s3.amazonaws.com/keepersecurity/en_US/static/apps/SetupKeeperIE.exe)

[Enterprise Admin Console](https://keepersecurity.com/console)

