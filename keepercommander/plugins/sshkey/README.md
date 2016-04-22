Commander Plugin for Generating SSH keys
----

This plugin rotates and distributes SSH keys for the provided user on the local system.  The 'Login' field of the Keeper record defines the user account which is being rotated. The 'password' field is used as the optional passphrase to encrypt the private key.  The resulting SSH key information is stored in custom fields and sync'd to your Keeper vault.  Any user or shared folder associated with the record is then accessible to any user with permission.

### Dependencies 

1) Add the following Custom Fields to the Keeper record

```
Name: cmdr:plugin
Value: sshkey
```

2) The plugin will use the 'Login' field as the username of the 'passwd' command

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

You can automate SSH key rotations using this plugin

Example:

```
{                                                                               
    "debug":false,
    "server":"https://keeperapp.com/v2/",
    "user":"admin@company.com",
    "password":"somereallystrongpassword",
    "commands":["d", "r 3PMqasi9hohmyLWJkgxCWg"]
}
```

In this example, we are telling Commander to first download and decrypt records, then generate SSH keys. The custom fields in the record give the plugin the information it needs to rotate the SSH key appropriately. Each unique record in the Keeper system is represented by a unique record UID.  Use the "l" or "s" command in Commander's interactive mode ('keeper shell') to display the record UIDs in your account.

