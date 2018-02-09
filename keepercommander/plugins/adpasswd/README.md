Commander Plugin for Active Directory User Password Rotation
----

This plugin provides IT Admins with the ability to rotate the password of an Active Directory user account. This plugin can be run on any system that has network access to the AD server.

### Setup and Dependencies 

1) Install the ldap3 module

```
pip3 install ldap3
```

2) In the Keeper record, put the user's current password in the "Password" field

3) Add the following Custom Fields to the record 

Name         | Value         | Comment
---------    | -------       | ------------
cmdr:plugin  | adpasswd      | 
cmdr:host    |               | Host name or IP address of your AD Server 
cmdr:use_ssl | True or False | Whether or not to use SSL connection to AD Server 
cmdr:userdn  |               | [Distinguished name](https://msdn.microsoft.com/en-us/library/windows/desktop/aa366101.aspx) of the AD user you want to rotate the password on.
cmdr:rules   |                | Optional [password complexity rules](https://github.com/Keeper-Security/Commander/tree/master/keepercommander/plugins/password_rules.md)   

![](https://raw.githubusercontent.com/Keeper-Security/Commander/master/keepercommander/images/plugin_adpasswd.png)

Note: Login field is not used.  The user is identified with the cmdr:userdn custom field.

