Commander Plugin for MySQL Database Server
----

This plugin allows rotating a user's password in MySQL.

### Dependencies 

1) Install the below modules

```
pip3 install PyMySQL
```

2) Add the following Custom Fields to the record that you want to rotate within Keeper

```
Name: cmdr:plugin
Value: mysql

Name: cmdr:host
Value: <hostname of your MySQL server>
```

3) The plugin will use the Login field as the username of the passwd command when rotating a password.

### Optional custom fields

```
Name: cmdr:port
Value: <MySQL port. 3306 assumed if omitted>
```
```
Name: cmdr:user_host
Value: <user host. If omitted '%' assumed>
```


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
    "user":"admin@company.com",
    "password":"somereallystrongpassword",
    "commands":["d", "r 3PMqasi9hohmyLWJkgxCWg"]
}
```

### Intergation with the Keeper Commander's `connect` command

Custom Field Name         | Custom Field Value             
------------------------- | ------------------------------
connect:xxx:env:MYSQL_PWD | ${password} 
connect:xxx               | mysql -u${login} -h${cmdr:host}
```xxx``` refers to the 'friendly name' which can be referenced when connecting on the command line.

Here's a screenshot of the Keeper Vault record for this use case:

![](https://raw.githubusercontent.com/Keeper-Security/Commander/master/keepercommander/images/connect_mysql_screenshot.png)


In this example, we are telling Commander to first download and decrypt records, then rotate the password (record UID HKj0T-NmBndy8SJ6ttbt1A) using the plugin programmed into the record. To locate the Record UID, simply view it on the commander interactive shell or view it on the Keeper Web Vault and Desktop App (small 'key' icon to the right of the record title).

![](https://raw.githubusercontent.com/Keeper-Security/Commander/master/keepercommander/images/record_uid.png)

If you have any feature requests for this plugin, please contact us at commander@keepersecurity.com.

