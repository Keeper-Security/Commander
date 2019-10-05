Commander Plugin for PostgreSQL Database Server
----

This plugin allows rotating a user's password in PostgreSQL Server

### Dependencies 

1) Install the below modules

```
pip3 install psycopg2-binary
```

2) Add the following Custom Fields to the record that you want to rotate within Keeper

```
Name: cmdr:plugin
Value: postgresql

Name: cmdr:host
Value: <hostname of your PostgreSQL server>

Name: cmdr:db
Value: <database to connect to on PostgreSQL server>
```

3) The plugin will use the Login field as the username of the passwd command when rotating a password.

### Optional custom fields

```
Name: cmdr:port
Value: <Postgres port. 5432 assumed if omitted>
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

In this example, we are telling Commander to first download and decrypt records, then rotate the password (record UID HKj0T-NmBndy8SJ6ttbt1A) using the plugin programmed into the record. To locate the Record UID, simply view it on the commander interactive shell or view it on the Keeper Web Vault and Desktop App (small 'key' icon to the right of the record title).

![](https://raw.githubusercontent.com/Keeper-Security/Commander/master/keepercommander/images/record_uid.png)

If you have any feature requests for this plugin, please contact us at commander@keepersecurity.com.

### Intergation with the Keeper Commander's `connect` command

Custom Field Name          | Custom Field Value             
-------------------------- | ------------------------------
connect:xxx:env:PGPASSWORD | ${password}
connect:xxx                | psql --host=${cmdr:host} --port=${cmdr:port} --username=${login} --dbname=${cmdr:db} --no-password
```xxx``` refers to the 'friendly name' which can be referenced when connecting on the command line.

Here's a screenshot of the Keeper Vault record for this use case:

![](https://raw.githubusercontent.com/Keeper-Security/Commander/master/keepercommander/images/connect_postgres_screenshot.png)
