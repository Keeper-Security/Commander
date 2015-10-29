Keeper Commander Plugins
----

Keeper Commander can talk to external systems for the purpose of resetting a password and synchronizing the change inside the Keeper Vault.  For example, you might want to rotate your MySQL password and Active Directory password automatically.  To support a plugin, simply add a custom field to the record to specify which plugin Keeper Commander should use when changing passwords.  Example:

```
Name: cmdr:plugin
Value: mysql
```

When a plugin is specified in a record, Commander will search in the plugins/ folder to load the module based on the name provided (e.g. mysql.py and active_directory.py).

Keeper's team is expanding the number of plugins on an ongoing basis. If you need a particular plugin created, just let us know.