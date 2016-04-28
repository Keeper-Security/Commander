Commander Plugin for Generating/Rotating AWS Passwords
----

This plugin generates/rotates AWS passwords for any user within your Amazon Web Services account.
Note: To rotate AWS Access Keys, use the 'awskey' AWS Access Key rotation plugin.  Both 'awskey' and 'awspswd' plugins can be used together on the same Keeper record.

### Dependencies

1) Install and configure AWS CLI package with an AWS account that has administrative privileges

```
pip3 install awscli

aws configure
```

Note: You must configure your AWS environment on the environment with an account that has administrative privileges in order to modify the Password for the specified user.

2) Add the following Custom Fields to the Keeper record that you want to update

```
Name: cmdr:plugin
Value: awspswd
```

3) The plugin will use the Login field as the username of the passwd command when rotating a password.

### Optional custom fields
To specify the rules for password complexity to use add a custom field

```
Name: cmdr:rules
Value: 4,6,3,0
```

This would generate a new password with :
```
  4 uppercase characters
  6 lowercase characters
  3 numerical characters
  0 punctuation characters
```

4) The plugin will use the 'Login' field as the AWS account username and 'Password' field as AWS account password.

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

In this example, we are telling Commander to first download and decrypt records, then rotate the AWS password for record ID 3PMqasi9hohmyLWJkgxCWg. The custom fields in the record give the plugin the information it needs to rotate the password appropriately. Each unique record in the Keeper system is represented by a unique record UID.  Use the "l" or "s" command in Commander's interactive mode to display the record UIDs in your account.

