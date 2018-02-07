Commander Plugin for Windows net Command
----

This plugin allows rotating a remote computer password using the pspasswd.exe application, which is part of the Microsoft / PSTools package. 

### Dependencies

1) Install the PSTools package from Microsoft Sysinternals:

https://docs.microsoft.com/en-us/sysinternals/downloads/pspasswd

- Extract the PSTools.zip folder to a location on your computer

- Make sure that the PSTools folder you extracted is in your environmental variable "PATH"
  
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

3) The plugin will use the Login field as the username of the pspasswd command when rotating a password.

For example, the below command is similar to what will be executed:
pspasswd.exe \\myhostname Administrator somegeneratedpassword

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

### Auto-command execution

You can now automate password resets using this plugin

Example:

```
{                                                                               
    "debug":false,
    "user":"yourkeeperaccount@company.com",
    "password":"yourkeepermasterpassword",
    "commands":["d", "r 3PMqasi9hohmyLWJkgxCWg"]
}
```

In this example, we are telling Commander to first download and decrypt records, then rotate a password on the provided host and user account. The custom fields in the record give the plugin the information it needs to rotate the password appropriately. As you can see, each unique password record in the Keeper system is represented by a unique record UID.  Use the "l" or "s" command in Commander's interactive mode to display the record UIDs in your account.

