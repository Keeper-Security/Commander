Commander Plugin for SSH Command
----

The SSH plugin for Keeper Commander gives you the ability to rotate any local or remote user's Unix/Linux password.  The 'username' and 'password' in the Keeper record must be set one time based on the current password.  The 'cmdr:host' field controls the server that you are connectig to.  Note: For rotating the password on the local machine, make sure to set the 'cmdr:host' field to 'localhost'.

### Dependencies 

1) Install the below modules

```
pip3 install pexpect
```

2) Add the following Custom Fields to the record that you want to rotate within Keeper

```
Name: cmdr:plugin
Value: ssh

Name: cmdr:host
Value: <hostname of the server to ssh into, or "localhost">
```

3) The plugin will use the Login field as the username of the passwd command when rotating a password.

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

You can now automate password rotations using this plugin.

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

