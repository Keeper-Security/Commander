## Keeper Commander 
----
Commander is a command-line and SDK interface to *Keeper&reg; Password Manager 
&amp; Digital Vault*.  Keeper Commander can be used to interactively access 
your Keeper Vault via a standard terminal or SSH console, or it can be used as
an SDK for integrating your back-end into Keeper's encrypted cloud storage.

### Commander Features

* Terminal-based access to your Keeper vault 
* Login, download and decrypt your vault records  
* Search for content with regular expressions
* Display vault record details
* Change or rotate a password
* Push password resets to external systems (Active Directory, MySQL, etc...) 

### Security

Keeper is a zero-knowledge platform.  This means that the server does not 
have access to your Keeper Master Password or the crypto keys used to 
encrypt and decrypt your data.  The cryptography is performed on the 
*client device* (e.g. mobile app, desktop app, Commander).

When you create a Keeper account from our 
[web app](https://keepersecurity.com/vault) or 
[mobile/desktop app](https://keepersecurity.com/download), you are asked
to create a master password and a security question &amp; answer.  Keeper
then creates your crypto keys, RSA keys and encryption parameters 
(iv, salt, iterations).  Your RSA private key is encrypted with your data
key, and your data key is encrypted with your master password.  The
encrypted version of your data key is stored in Keeper's Cloud Security
Vault and provided to you after successful authentication.

When you login to Keeper on any device (or on Commander), your master password 
is used to derive a 256-bit PBKDF2 key.  This key is used to decrypt 
your data key.  The data key is used to decrypt individual record keys.  
Finally, your record keys are then used to decrypt your stored vault 
information (e.g. your Facebook password).

When saving information to your vault, Keeper stores only the encrypted
data, which can only be decrypted on your client device.  

All of this cryptography is packaged and wrapped into a simple and 
easy-to-use interface.  Commander gives you the power to access, store
and syncronize encrypted vault records with ease.

To learn about Keeper's security, certifications and implementation details, 
visit the [Security Disclosure](https://keepersecurity.com/security.html) page
on our website.

### About Keeper

<img src="hand.jpg" style="max-width:400px;">

Keeper is the world's most downloaded password keeper and secure digital 
vault for protecting and managing your passwords and other secret information. 
Millions of people and companies use Keeper to protect their most 
sensitive and private information.

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
* Login with Touch ID
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

----
### Supported Platforms
Mac, Unix, Linux and Windows

### Requirements
To use Commander, you currently need to set up a Python 3 environment.
Installation instructions can be found in the 
[python](https://github.com/Keeper-Security/commander/python) folder.

### Use Cases

* Terminal/Console Vault Access

Commander can be launched directly from any Unix/Linux/Mac/PC terminal 
on a local session or via SSH. Quick access to frequently used data 
or updates can be performed without a user interface.  Any information 
that the named user has access to will be available for access via the 
Commander interface.  This includes shared records and shared folders.

* Password Reset

Commander can be configured to modify a particular password record 
(such as generating a new randomized password) and synchronize those changes 
to all users with access.  For example, your Active Directory or MySQL database 
password can be rotated daily and shared to privileged users.

### Additional Connectors
We're here to help.  If you help adding connections, contact us and we'll
assist.  Keeper's Commander support team can be 
reached at ops@keepersecurity.com.


