Commander Plugin for Windows net Command
----

This plugin allows rotating a windows user's password using the net user command.

### Dependencies 

1) Add the following Custom Fields to the record that you want to rotate within Keeper

```
Name: cmdr:plugin
Value: windows
```

2) The plugin will use the Login field as the username of the passwd command when rotating a password.

### Optional custom fields

To specify the rules for password complexity to use add a custom field

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
    "user":"admin@company.com",
    "password":"somereallystrongpassword",
    "commands":["d", "r 3PMqasi9hohmyLWJkgxCWg"]
}
```

In this example, we are telling Commander to first download and decrypt records, then rotate the password (record UID HKj0T-NmBndy8SJ6ttbt1A) using the plugin programmed into the record. To locate the Record UID, simply view it on the commander interactive shell or view it on the Keeper Web Vault and Desktop App (small 'key' icon to the right of the record title).

![](https://raw.githubusercontent.com/Keeper-Security/Commander/master/keepercommander/images/record_uid.png)

If you have any feature requests for this plugin, please contact us at commander@keepersecurity.com.
