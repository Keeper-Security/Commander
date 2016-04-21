Commander Plugin for Generating AWS Access keys
----

This plugin allows rotating a AWS Access key used to access to Amazon Web Services.
The password is ignored by this plugin

### Dependencies 

1) Install and configure AWS CLI package with the AWS account that has administrative privileges

```
pip3 install awscli

aws configure
```

2) Add the following Custom Fields to the record that you want to rotate within Keeper

```
Name: cmdr:plugin
Value: awskey
```

3) The plugin will use the Login field as the ASW account username. Password field is ignored

### Optional custom fields

Optional setting to prevent password rotation. AWS plugin does not use passwords

```
Name: cmdr:rules
Value: 0,0,0,0
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

In this example, we are telling Commander to first download and decrypt records, then rotate AWS access key keys. The custom fields in the record give the plugin the information it needs to rotate the access key appropriately. As you can see, each unique record in the Keeper system is represented by a unique record UID.  Use the "l" or "s" command in Commander's interactive mode to display the record UIDs in your account.

