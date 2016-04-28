Commander Plugin for Generating/Rotating attribute/field value in AWS DynamoDB
----

This plugin generates/rotates password/random text and stores it into DynamoDB field/attribute.

### Dependencies

1. Install AWS CLI package
```
pip3 install awscli
```

2. Configure AWS CLI package
```
aws configure
```

<sub>**Note:** You need to configure your AWS environment on the environment with an account that has full access to DynamoDB service.</sub>

3) Populate the **'Login'** field of the Keeper record with DynamoDB ItemID that holds the password

4) Add the following Custom Fields to the Keeper record that you want to update

Name               | Value        | Comment
---------          | -------      | ------------
cmdr:plugin        | dynamodb     |
cmdr:dyn_tbl_name  |              | (Mandatory) DynamoDB table name
cmdr:dyn_attr_name |              | (Mandatory) Attribute/field name in the DynamoDB table name that holds password
cmdr:dyn_key_name  |              | (Optional) Key attribute/field name. If ommited this field will be resolded on first run.
cmdr:rules         |              | (Optional) [password complexity rules](https://github.com/Keeper-Security/Commander/tree/master/keepercommander/plugins/password_rules.md)


![](https://raw.githubusercontent.com/Keeper-Security/Commander/master/keepercommander/images/plugin_dynamodb.png)

### Output

1. The **'Password'** field of the Keeper record contains a new password to AWS account.
2. Attribute in the DynamoDB is updated.