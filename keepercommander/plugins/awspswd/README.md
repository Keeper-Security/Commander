Commander Plugin for Generating/Rotating AWS Passwords
----

This plugin generates/rotates AWS passwords for any user within your Amazon Web Services account.
Note: To rotate AWS Access Keys, use the 'awskey' AWS Access Key rotation plugin.

### Dependencies

1. Install AWS CLI package
```
pip3 install awscli
```

2. Configure AWS CLI package
```
aws configure
```

<sub>**Note:** You need to configure your AWS environment on the environment with an account that has administrative privileges in order to modify the Password for the specified user.</sub>

3. Populate the **'Login'** field of the Keeper record with the AWS login name

4. Add the following Custom Fields to the record that you want to rotate within Keeper

Name          | Value     | Comment
---------     | -------   | ------------
cmdr:plugin   | awspswd   |
cmdr:rules    |           | Optional [password complexity rules](https://github.com/Keeper-Security/Commander/tree/master/keepercommander/plugins/password_rules.md)

![](https://raw.githubusercontent.com/Keeper-Security/Commander/master/keepercommander/images/plugin_awspswd.png)

### Output

1. The **'Password'** field of the Keeper record contains a new password to AWS account.