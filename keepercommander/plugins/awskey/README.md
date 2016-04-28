Commander Plugin for Generating/Rotating AWS API Access Keys
----

This plugin generates/rotates AWS API Access Key for any user within your Amazon Web Services account.

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
cmdr:plugin   | awskey    |
cmdr:rules    |           | (Optional) [password complexity rules](https://github.com/Keeper-Security/Commander/tree/master/keepercommander/plugins/password_rules.md)

![](https://raw.githubusercontent.com/Keeper-Security/Commander/master/keepercommander/images/plugin_awskey.png)


### Output

1. After rotation is completed, the Access Key ID and Secret Key are stored in Keeper custom fields 'cmdr:aws_key_id'  and 'cmdr:aws_key_secret'.  Any Keeper user or Keeper Shared Folder associated with the record is updated instantly.

Name                | Value     | Comment
---------           | -------   | ------------
cmdr:aws_key_id     |           | generated AWS Access Key ID
cmdr:aws_key_secret |           | generated AWS Secret Access Key

2. The **'Password'** field is ignored by this plugin


