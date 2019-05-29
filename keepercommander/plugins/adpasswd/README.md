Commander Plugin for Active Directory User Password Rotation
----

This plugin provides IT Admins with the ability to rotate the password of an Active Directory user account. This plugin can be run on any system that has network access to the AD server.

### Setup and Dependencies 

1. Install the ldap3 module

```
pip3 install ldap3
```

2. In the Keeper record, put the user's current password in the "Password" field

3. Add the following Custom Fields to the record 

Name         | Value         | Comment
---------    | -------       | ------------
cmdr:plugin  | adpasswd      | 
cmdr:host    |               | Host name or IP address of your AD Server 
cmdr:use_ssl | True or False | Whether or not to use SSL connection to AD Server 
cmdr:userdn  |               | [Distinguished name](https://msdn.microsoft.com/en-us/library/windows/desktop/aa366101.aspx) of the AD user you want to rotate the password on.
cmdr:rules   |                | Optional [password complexity rules](https://github.com/Keeper-Security/Commander/tree/master/keepercommander/plugins/password_rules.md)   

![](https://raw.githubusercontent.com/Keeper-Security/Commander/master/keepercommander/images/plugin_adpasswd.png)

### Notes and Troubleshooting: 
1. The Keeper "Login" field is not used for this plugin.  The user is identified with the <strong>cmdr:userdn</strong> custom field.

2. If you get the error "Error during connection to AD server":

- Verified connectivity to the host server, make sure it is accessible.  Download a tool such as the [Softerra LDAP Browser](http://www.ldapadministrator.com/download.htm) to test if you're able to connect to Active Directory. 

- Check that your Distinguished Name <strong>cmdr:userdn</strong> is set correctly.  It needs to be exactly right or else the connection will fail.  You can check the value of this from within the Softerra LDAP browser software or you can run the below command prompt utility on the AD Server:

```
C:\Users\craig>dsquery user -name Craig*
"CN=Craig Lurey,CN=Users,DC=keeper,DC=test,DC=keepersecurity,DC=com"
```
For connecting as Craig in this scenario, make sure the <strong>cmdr:userdn</strong> custom field contains this exact string (without the quotes).

###Note
Microsoft Active Directory requires SSL connection in order to change the password.
The following link explains how how secure connection to Active Directory

https://blogs.msdn.microsoft.com/microsoftrservertigerteam/2017/04/10/step-by-step-guide-to-setup-ldaps-on-windows-server/