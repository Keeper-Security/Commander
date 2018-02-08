![](https://raw.githubusercontent.com/Keeper-Security/Commander/master/keepercommander/images/commander_logo_512x205.png)

[![Build Status](https://travis-ci.org/Keeper-Security/Commander.svg)](https://travis-ci.org/Keeper-Security/Commander)

----
#### The Password Management SDK for IT Admins & Developers

Keeper Commander is a command-line and SDK interface to [Keeper&reg; Password Manager](https://keepersecurity.com).  Keeper Commander is designed to perform targeted password rotations and eliminate the use of hardcoded passwords in your systems and software.  Commander will securely rotate passwords in your Keeper vault and then instantly push the changes to all users with privileged access to the password.  Using our connector [plugins](https://github.com/Keeper-Security/Commander/tree/master/keepercommander/plugins), Commander executes a strong password rotation directly to the target system (Unix Logins, Databases, Active Directory, network devices, etc...).

Commander also has a command-line shell interface for accessing your Keeper vault, importing data and performing other actions from any Unix, Mac or Windows system.  Since Keeper Commander is an open source SDK and written in Python, it can be customized to meet your needs and integrated into your back-end systems.

[Here's a Video](https://youtu.be/p50OKRiaxl8) demonstrating Commander.

### Use Cases

* Access passwords through a terminal or SSH session
* Import or export vault records   
* Add password records programatically to your Keeper vault
* Eliminate hard-coded or plaintext passwords in back-end systems
* Rotate passwords on shared accounts 
* Perform password rotations on target systems
* Authenticate with Yubikey and other 2FA methods
* Schedule and automate rotations 

![](https://raw.githubusercontent.com/Keeper-Security/Commander/master/keepercommander/images/keeper_intro.gif)

Keeper Commander provides deep integration of privileged password management into back-end systems to securely access credentials, elevate permissions and rotate passwords. With Keeper Commander you can automate key security features on any platform.

Changes made through Keeper Commander instantly propagate to the users who have access to that specific record.

When you grant and revoke access or rotate a password, it instantly updates to users on their mobile and desktop devices. Control access to highly secure systems by rotating passwords and pushing those credentials to users - all within the Keeper ecosystem.

### Installation - Windows 

Unless you're planning to modify code or build Python scripts, the quick and easy way to install Commander on Windows is using the [WinPython](https://winpython.github.io/) package.

Instructions:

1. Download and install [WinPython](https://winpython.github.io/)

2. From the install folder of WinPython, run the "WinPython Command Prompt" 

3. Install Commander from the command prompt:

```bash
pip3 install keepercommander
```

To start using Commander just type:

```bash
keeper shell
```

### Installation - Mac and Linux OS

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

The quickest way to look up records or get a password is through the Keeper command line interface.  The interactive shell mode is discussed in the next section. To see all available commands, just type:
```
$ keeper
```

The help screen displays as seen below.

```
Usage: keeper [OPTIONS] COMMAND [ARGS]...

  Some commands have their own options. To see the help message for a specific command, type
  keeper COMMAND --help
  for example: keeper import --help

Options:
  -s, --server TEXT    Host address. You can set KEEPER_SERVER environment
                       variable instead.
  -u, --user TEXT      Email address for the account. You can set KEEPER_USER
                       environment variable instead.
  -p, --password TEXT  Master password for the account. You can set
                       KEEPER_PASSWORD environment variable instead.
  --config TEXT        Config file to use
  --debug              Turn on debug mode
  --version            Show the version and exit.
  --help               Show this message and exit.

Commands:
  delete-all  Delete all Keeper records on server
  export      Export data from Keeper to local file
  get         Display specified Keeper record/folder/team
  import      Import data from local file to Keeper
  list        Display all record UID/titles
  rotate      Rotate Keeper record
  search      Search vault with a regular expression
  shell       Use Keeper interactive shell
```  

Running most commands will require you to authenticate to Keeper and decrypt your vault.  Authentication requires your email address ("user"), master password ("password") and optionally your 2FA code.  You can type these parameters interactively in the terminal or you can store these parameters into a file called config.json.  You can also store the parameters in environmental variables.

Here's a basic "config.json" file which will prompt you for your Keeper master password upon every usage:

```
{
    "server":"https://keepersecurity.com/api/v2/",
    "user":"youremail@company.com",
    "password":"",
    "mfa_token":"",
    "mfa_type":"",
    "debug":false,
    "plugins":[],
    "commands":[]
}
```

Any parameter that is not filled in will be prompted on the command line interactively. 

Instead of using a config.json file for "server", "user" and "password" options, you can also set environment variables `KEEPER_SERVER`, `KEEPER_USER` and `KEEPER_PASSWORD`. Server, user and password specified as options have priority over server, user and password settings specified in the configuration file.  

More advanced usage of configuration files for automated commands is in the <a href="#scheduling--automation">Scheduling & Automation</a> section below.  Yubikey security key devices can also be used to authenticate as described <a href="#yubikey-support">here</a>.

### Example commands 

Here's an example on searching your vault with a regular expression.  Commander will display search results in a list with just record UID and title, and if there are less than 5 records it will display all of the record details.

```
clurey@home:~/test/ $ keeper search "Capital.*One"
Password: <typed in>
Syncing...
Decrypted [63] Records
Searching for Capital.*One
  #  Record UID              Folder    Title
---  ----------------------  --------  -------------------
  1  LYwEGKAvkRbCRfaH2wQgnA  TESTING   Capital One Example


                 UID: LYwEGKAvkRbCRfaH2wQgnA
            Revision: 162196517
              Folder: TESTING             
               Title: Capital One Example 
               Login: craiglurey          
            Password: xKLKd2hLc8vS1195RJaR
                 URL: https://www.capitalone.com
                Link: https://keepersecurity.com/vault#detail/LYwEGKAvkRbCRfaH2wQgnA
```

As seen here, the matching vault record is displayed on the screen.  Since the master password is not stored in any environmental variable or config file, you will be prompted to type in your master password. 

As another example, to list all of the record UIDs and record titles in your vault:

```
clurey@home:~/test/ $ keeper list 

1  7T13cQ6NQACZaT-7FXQsfg  Secure Documents       Case File #25
2  2uSii52DF5ny1K8CEZoj8g  Secure Documents       Confidential Files
3  6Z0uci6wesloF4YxtRUxzQ  Secure Documents       Medical Recs

```

To view a specific record, just use the record UID like this:
 
```
clurey@home:~/test/ $ keeper get LYwEGKAvkRbCRfaH2wQgnA
Password: <typed in>
Syncing...
Decrypted [63] Records

                 UID: LYwEGKAvkRbCRfaH2wQgnA
            Revision: 162196517
              Folder: TESTING             
               Title: Capital One Example 
               Login: craiglurey          
            Password: xKLKd2hLc8vS1195RJaR
                 URL: https://www.capitalone.com
                Link: https://keepersecurity.com/vault#detail/LYwEGKAvkRbCRfaH2wQgnA
```

### Interactive shell
To just authenticate a single time and run a series of commands, you can use Commander's interactive shell.  Invoke shell by typing

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
  lt        ... list teams 
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

* l (list): Displays the Record UID, Folder and Title for all stored records.

* lsf (list shared folders): Displays a list of all Shared Folder UID and names 

* lt (list teams): Displays a list of all Team UID and names 

* s (search): Searches across all record data and display the Record UID, Folder and Title for matching records.

* g (get): Displays the full details for a specified Record UID, Shared Folder UID or Team UID.  For records, this will show the login, password, custom fields and other record-related information that you would normally see in your Keeper Vault.  For Shared Folders, this will display the records stored in the shared folder, user permissions and team permissions associated with the shared folder.  For Teams, this will display the team name and team permissions as specified in the Keeper Admin Console.

* r (rotate): Rotates the password field of a specified Keeper record.  The new password generated is by default set to a very strong 64-byte ASCII-based string.  The previous password is also backed up and stored as a custom field in the record, saved with the timestamp of the change.

* b (batch rotate): Searches across all record data and rotate the password for matching records.

The Record UID is a unique identifier for every record in your Keeper vault.  This is used for deep linking and also for password rotation as described below. The search/list/get commands can be used to look up the Record UID when setting up a password rotation scheduler.

### Deep linking to records (Web Vault Hyperlink)

The Record UID that is displayed on password record output can be used for deep linking directly into the Keeper Web Vault only for privileged users. This Vault link can be stored and sent over unsecure channels because it only provides a reference to the record within your vault -- it does not provide access to the actual record content.  To access the content, you must still authenticate into the vault and decrypt the data.  The link is in the format `https://keepersecurity.com/vault#detail/XXXXXX` and you simply replace XXXXXX with the Record UID. Providing this link to another user does NOT initiate sharing.  To share a vault record, you must authenticate to your vault, open the record and click the "Share" feature.

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

### JSON Config file format

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


### Importing Password Records into Keeper

To import records into your vault, you can provide either JSON or tab-delimited file.
If using a JSON file, make sure it's an a valid JSON array.  For example, here's a JSON array file with 2 records:

```
[{
    "title":"Dev Server",
    "folder": "Servers",
    "login": "root",
    "password": "lk4j139sk4j",
    "login_url": "https://myserver.com",
    "notes": "These are some notes.",
    "custom_fields": [{"Security Group":"Private"}]
},
{
    "title":"Prod Server",
    "folder": "Servers",
    "login": "root",
    "password": "kj424094fsdjhfs4jf7h",
    "login_url": "https://myprodserver.com",
    "notes": "These are some notes.",
    "custom_fields": [{"Security Group":"Public","IP Address":"12.45.67.8"}]
}]
```

The format must be perfect JSON or it will fail.  The keys in each JSON hash must be present.  Use a JSON validator if you get errors running this.
Here's the command to run:

```
keeper import --format=json import.json
```

### Importing Shared Folders into Keeper

To automatically create Shared Folders into your vault, you need to provide a JSON file in the format defined below..

A shared folder is an object which contains Keeper records, default permissions, users and teams.  You must specify the name of the folder, the default permissions, which specific records to add, which users to add and which teams (if any) to add.  Records are defined by the Record UID.  Users are defined by their email address (note: the user must exist).  Teams are defined by the Team UID.  Records, teams and users must exist prior to creating the shared folder, or the command will fail.  Record UID and Team UID can be found using Commander ("list" command). Use a JSON validator if you get errors running this command.  Make sure it's an a valid JSON array.  For example, here's a JSON array file with one shared folder defined: 

```
    [{
      "name":"My Shared Folder",
      "default_can_edit": false,
      "default_can_share": false,
      "default_manage_records": false,
      "default_manage_users": false,
      "records":[
        {
          "record_uid":"YWRkcmVjb3JkICAgICAgIA",
          "can_share":true,
          "can_edit":true
        }
      ],
      "users":[
        {
          "username":"somebody@company.com",
          "manage_users":false,
          "manage_records":false
        },
        {
          "username":"me@company.com",
          "manage_users":true,
          "manage_records":true
        }
      ],
      "teams":[
        {
          "team_uid":"yKz9nxpJS1yzDxBl-Akdog",
          "manage_users":true,
          "manage_records":true
        }
      ]
    }]
```

Note that all users with access to the shared folder must be specified, even the user who is executing the API call.

Here's the example command to run:

```
keeper create_sf my_shared_folder.json
```

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

[Windows Phone](https://www.microsoft.com/en-us/store/p/keeper-password-manager/9wzdncrdmpt6)


### Cross-Platform Desktop App (Mac, PC, Linux)

[Windows PC, 32-bit](https://keepersecurity.com/desktop_electron/Win32/KeeperSetup32.zip)

[Windows PC, 64-bit](https://keepersecurity.com/desktop_electron/Win64/KeeperSetup64.zip)

[Windows PC, 32-bit MSI Installer](https://keepersecurity.com/desktop_electron/Win32/KeeperSetup32.msi)

[Mac](https://keepersecurity.com/desktop_electron/Darwin/KeeperSetup.dmg)

[Linux](https://s3.amazonaws.com/keepersecurity/en_US/static/apps/KeeperDesktopLinux.zip)

### Mac App Store (Thin Client)

[Mac App Store](https://itunes.apple.com/us/app/keeper-password-manager-digital/id414781829?mt=12)

### Microsoft Store (Windows 10, Surface) Platform

[Microsoft Store Version - Windows 10](https://www.microsoft.com/en-us/store/p/keeper-password-manager/9wzdncrdmpt6)

### Web-Based Apps and Browser Extensions

[Web App - Online Vault](https://keepersecurity.com/vault)

[KeeperFill for Chrome](https://chrome.google.com/webstore/detail/keeper-browser-extension/bfogiafebfohielmmehodmfbbebbbpei)

[KeeperFill for Firefox](https://addons.mozilla.org/en-US/firefox/addon/keeper-password-manager-digita/)

[KeeperFill for Safari](https://safari-extensions.apple.com/details/?id=com.keepersecurity.safari.KeeperExtension-234QNB7GCA)

[KeeperFill for Edge](https://www.microsoft.com/en-us/store/p/keeper-password-manager-digital-vault/9n0mnnslfz1t)

[KeeperFill for Internet Explorer](https://s3.amazonaws.com/keepersecurity/en_US/static/apps/SetupKeeperIE.exe)

[Enterprise Admin Console](https://keepersecurity.com/console)

