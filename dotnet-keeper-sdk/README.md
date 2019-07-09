### .Net SDK for Keeper Password Manager 

The Keeper .Net SDK is under active development and will be enhanced to include all of the capabilities of Keeper's [Python Commander SDK platform](https://github.com/Keeper-Security/Commander).  The current features of the .Net SDK include the following:

* Access your Keeper vault (records, folders, shared folders)
* Manage records, folders and shared folders
* Customize integration into your backend systems
* Update/Rotate passwords in the vault

For integration into your .Net systems, please utilize the [KeeperSDK library](https://github.com/Keeper-Security/Commander/tree/master/dotnet-keeper-sdk/KeeperSdk).

For help with implementation of SDK features, please see the [Commander](https://github.com/Keeper-Security/Commander/tree/master/dotnet-keeper-sdk/Commander) sample application.  This application contains several basic operations such as logging in, authentication with two-factor, loading and decrypting the vault and updating passwords.

### Developer Requirements for KeeperSDK Library

* .Net Framework 4.5
* .Net Core 2.1
* .Net Standard 2.0

### Sample Commander application reference 

* ```login``` Login to Keeper

* ```logout``` Logout from Keeper

* ```sync-down``` or ```d``` Download, sync and decrypt vault

* ```list``` or ```ls``` List all records (try ```ls -l``` as well)

* ```tree``` Display entire folder structure as a tree

* ```cd``` Change current folder

* ```get``` Retrieve and display specified Keeper Record/Folder/Team in printable or JSON format.

* ```list-sf``` Display all shared folders

**Record Management Commands**

* ```add-record``` Add a record to the vault

* ```update-record``` Update a record contents such as the password

If you need any assistance or require specific functionality not supported in Commander yet, please contact us at commander@keepersecurity.com.
