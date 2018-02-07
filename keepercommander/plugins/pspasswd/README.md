Commander Plugin for Windows net Command
----

This plugin allows rotating any user account password on a remote computer using the pspasswd.exe tool. 

### Dependencies

1) Install PSTools

- Download the [PSTools Package](https://docs.microsoft.com/en-us/sysinternals/downloads/pspasswd) from Microsoft

- Extract the PSTools.zip folder to a location on your computer

- Add this PSTools folder to your user or system environmental variable "PATH"
  
  (System Properties -> Advanced -> Environmental Variables)

  Select PATH and then "Edit"

  On some systems, you have to append the location where you installed PSTools, e.g.:

  ;C:\Users\craig\PSTools

  On newer systems, just click "New" then type in the full path to the install, e.g.:
  C:\Users\craig\PSTools

2) Add the following Custom Fields to the record that you want to rotate within Keeper

```
Name: cmdr:plugin
Value: pspasswd

Name: cmdr:host
Value: <computer or computers where the local account exists>
```

3) Commander will use the "Login" field, "cmdr:host" and "cmdr:rules" fields of your Keeper record to execute the password rotation.

### Optional custom fields

To specify the rules for password complexity to use when generating a new password, add a custom field:

```
Name: cmdr:rules
Value: 4,6,3,8
```

This would generate a new password with :
```
  4 uppercase characters
  6 lowercase characters
  3 numerical characters
  8 punctuation characters
```

### Manually executing this command

To run the command manually, just login to Keeper interactive shell, locate the record and use the "rotate" command:

```
$ keeper shell

  _  __
 | |/ /___ ___ _ __  ___ _ _
 | ' </ -_) -_) '_ \/ -_) '_|
 |_|\_\___\___| .__/\___|_|
              |_|

 password manager & digital vault


User(Email):
Password:
Syncing...
Decrypted [1] Record
Keeper > l
  #  Record UID              Folder    Title
---  ----------------------  --------  -------------
  1  HKj0T-NmBndy8SJ6ttbt1A            Test


                 UID: HKj0T-NmBndy8SJ6ttbt1A
            Revision: 194201556
               Title: Rotation Test
               Login: Administrator
         cmdr:plugin: pspasswd
           cmdr:host: mycomputer
          cmdr:rules: 4,6,3,8

Keeper > r HKj0T-NmBndy8SJ6ttbt1A
```

### Auto-command execution

You can automate password resets using this plugin

Example config.json file:

```
{                                                                               
    "debug":false,
    "user":"yourkeeperaccount@company.com",
    "password":"yourkeepermasterpassword",
    "commands":["d", "r HKj0T-NmBndy8SJ6ttbt1A"]
}
```

In this example, we are telling Commander to first download and decrypt records, then rotate this password using the plugin programmed into the record. Use the "l" or "s" command in Commander's interactive mode to display the record UIDs in your account.  The Record UID is also viewable on the Keeper Web Vault and Desktop App.
