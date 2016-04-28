Commander Plugin for Unix Passwd Command
----

This plugin allows rotating a local user's password using the Unix Passwd command.

### Dependencies 

1) Install the below modules

```
pip3 install pexpect
```

2) Add the following Custom Fields to the record that you want to rotate within Keeper

Name         | Value      | Comment
---------    | -------    | ------------
cmdr:plugin  | unixpasswd | 
cmdr:rules   |            | Optional [password complexity rules](https://github.com/Keeper-Security/Commander/tree/master/keepercommander/plugins/password_rules.md)   

![](https://raw.githubusercontent.com/Keeper-Security/Commander/master/keepercommander/images/plugin_unixpasswd.png)
