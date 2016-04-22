Commander Plugin for Generating/Rotating AWS Access Keys
----

This plugin generates/rotates AWS Access Keys for any user within your Amazon Web Services account.

### Dependencies

1) Install and configure AWS CLI package with an AWS account that has administrative privileges

```
pip3 install awscli

aws configure
```

Note: You must configure your AWS environment on the environment with an account that has administrative privileges in order to modify the Access Keys for the specified user.

2) Add the following Custom Fields to the Keeper record that you want to update

```
Name: cmdr:plugin
Value: awskey
```

3) Add a custom rule to tell the plugin NOT to rotate a password. This plugin does not use the password field.

```
Name: cmdr:rules
Value: 0,0,0,0
```

4) The plugin will use the 'Login' field as the AWS account username that will be updated. The 'Password' field is ignored.

After rotation is completed, the Access Key ID and Secret Key are stored in Keeper custom fields 'cmdr:aws_key_id'  and 'cmdr:aws_key_secret'.  Any Keeper user or Keeper Shared Folder associated with the record is updated instantly.

### Auto-command execution

You can also automate password resets using this plugin

Example:

```
{                                                                               
    "debug":false,
    "server":"https://keeperapp.com/v2/",
    "user":"admin@company.com",
    "password":"somereallystrongpassword",
    "mfa_token":"vFcl44TdjQcgTVfCMlUw0O9DIw8mOg8fJypGOlS_Rw0WfXbCD9iw",
    "mfa_type":"device_token",
    "commands":["d", "r 3PMqasi9hohmyLWJkgxCWg"]
}
```

In this example, we are telling Commander to first download and decrypt records, then rotate AWS access key keys for record ID 3PMqasi9hohmyLWJkgxCWg. The custom fields in the record give the plugin the information it needs to rotate the access key appropriately. Each unique record in the Keeper system is represented by a unique record UID.  Use the "l" or "s" command in Commander's interactive mode to display the record UIDs in your account.

