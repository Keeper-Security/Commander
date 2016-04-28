Commander Plugin for Active Directory
----

This plugin allows rotating an Active Directory user's password.

### Dependencies 

1) Install the below modules

```
pip3 install ldap3
```

2) Add the following Custom Fields to the record that you want to rotate within Keeper

Name          | Value     | Comment
---------     | -------   | ------------
cmdr:plugin   | adpasswd  | 
cmdr:host     |           | Host name or IP address of your active directory server
cmdr:userdn   |           | [Distinguished name](https://msdn.microsoft.com/en-us/library/windows/desktop/aa366101.aspx) of the AD user you want to rotate the password on.    
cmdr:rules   |           | Optional [password complexity rules](https://github.com/Keeper-Security/Commander/tree/master/keepercommander/plugins/password_rules)   

![](https://raw.githubusercontent.com/Keeper-Security/Commander/master/keepercommander/images/plugin_adpasswd.png)

Note: Login field is not used in the process of the AD user password rotation.
