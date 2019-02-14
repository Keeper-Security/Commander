Commander Plugin for Windows PSPasswd.exe Command
----

This plugin provides IT Admins with the ability to rotate the password of a remote system's administrative local password. The password is rotated using the widely used "pspasswd" utility and the change is syncronized to a specific Keeper record in your vault.  

The way this plugin is implemented requires that Commander and pspasswd is installed on the Domain Controller.  The instructions in this README assume that you are executing Commander scripts from the Domain Controller.

### Setup and Dependencies

1. Enabled Remote Service Management on each target computer

- Assuming all computers are domain-attached and reachable from the Domain Controller, ensure that "Remote Service Management" is allowed for inbound in Domain by enabling the relevant Firewall rule on all computers.  On each of the target computers, go to Windows Firewall rules -> Inbound Rules -> and enabled the "Remote Service Management" rule.

2. Install Commander

- Python and Commander only need to be installed on the domain controller.  Follow the [instructions](https://github.com/Keeper-Security/Commander#installation) provided on the Commander github page.

3. Install pspasswd 

- Download the [PSTools Package](https://docs.microsoft.com/en-us/sysinternals/downloads/pspasswd) from Microsoft

- Extract the PSTools.zip folder to a location on your computer

- Add this PSTools folder to your user or system environmental variable "PATH"
  
  (System Properties -> Advanced -> Environmental Variables)

  Select PATH and then "Edit"

  On some systems, you have to append the location where you installed PSTools, e.g.:

  ;C:\Users\craig\PSTools

  On newer systems, just click "New" then type in the full path to the install, e.g.:
  C:\Users\craig\PSTools

4. Add the following Custom Fields to the record that you want to rotate within Keeper

```
Name: cmdr:plugin
Value: pspasswd

Name: cmdr:host
Value: <computer or computers where the local account exists>
```
5. Store Windows account name into Login field of the record

6. Commander will use the "Login" field, "cmdr:host" and "cmdr:rules" fields of your Keeper record to execute the password rotation.

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

To run the command manually, just login to Keeper interactive shell, locate the record and use the "rotate" command.  Here's an example:

```
$ keeper shell

  _  __
 | |/ /___ ___ _ __  ___ _ _
 | ' </ -_) -_) '_ \/ -_) '_|
 |_|\_\___\___| .__/\___|_|
              |_|

 password manager & digital vault


User(Email): *******
Password: *******
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
Rotating with plugin pspasswd

PsPasswd v1.24 - Local and remote password changer
Copyright (C) 2003-2016 Mark Russinovich
Sysinternals - www.sysinternals.com

Password successfully changed.

Password changed successfully
Pushing update...
New record successful for record_uid=HKj0T-NmBndy8SJ6ttbt1A, revision=194238452 , new_revision=194243895
Syncing...
Decrypted [1] Record
Rotation successful for record_uid=HKj0T-NmBndy8SJ6ttbt1A, revision=194243895
Keeper >
```

### Auto-command execution

You can automate password resets using this plugin

Example config.json file:

```
{                                                                               
    "user":"yourkeeperaccount@company.com",
    "password":"yourkeepermasterpassword",
    "commands":["d", "r HKj0T-NmBndy8SJ6ttbt1A"]
}
```

In this example, we are telling Commander to first download and decrypt records, then rotate the password (record UID HKj0T-NmBndy8SJ6ttbt1A) using the plugin programmed into the record. To locate the Record UID, simply view it on the commander interactive shell or view it on the Keeper Web Vault and Desktop App (small 'key' icon to the right of the record title).

![](https://raw.githubusercontent.com/Keeper-Security/Commander/master/keepercommander/images/record_uid.png)

If you have any feature requests for this plugin, please contact us at commander@keepersecurity.com.

