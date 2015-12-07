Commander Plugin for Active Directory
----

This plugin allows rotating an Active Directory user's password.

### Dependencies 

1) Install the below modules

```
pip3 install ldap3
```

2) Add the following Custom Fields to the record that you want to rotate within Keeper

```
Name: cmdr:plugin
Value: adpasswd

Name: cmdr:host
Value: <hostname of your active directory server>

Name: cmdr:searchdn
Value: <search base for your active directory>
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

You can now automate password resets using this plugin

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

In this example, we are telling Commander to first download and decrypt records, then reset a password. The custom fields in the record give the plugin the information it needs to rotate the password appropriately. As you can see, each unique password record in the Keeper system is represented by a unique record UID.  Use the "l" or "s" command in Commander's interactive mode to display the record UIDs in your account.

