Commander Plugin for Oracle Database Server
----

This plugin allows rotating a user's password in Oracle Database Server

### Dependencies 

NOTE: Oracle requires Instant Client setup to enable client applications. Consult the following page:
[http://www.oracle.com/technetwork/database/features/instant-client/index-097480.html]

1) Install the below modules

```
pip3 install cx_Oracle
```

2) Add the following Custom Fields to the record that you want to rotate within Keeper

```
Name: cmdr:plugin
Value: oracle

Name: cmdr:host
Value: <hostname of your Oracle server>

Name: cmdr:db
Value: <database service to connect to on Oracle server>
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
    "email":"admin@company.com",
    "password":"somereallystrongpassword",
    "commands":["d", "r 3PMqasi9hohmyLWJkgxCWg"]
}
```

In this example, we are telling Commander to first download and decrypt records, then reset a password. The custom fields in the record give the plugin the information it needs to rotate the password appropriately. As you can see, each unique password record in the Keeper system is represented by a unique record UID.  Use the "l" or "s" command in Commander's interactive mode to display the record UIDs in your account.

