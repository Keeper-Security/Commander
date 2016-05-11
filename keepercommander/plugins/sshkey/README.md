Commander Plugin for Rotating SSH keys
----

This plugin generates and rotates SSH keys then pushes the keys to one or more target systems.  The 'Login' field of the Keeper record defines the user account which is being rotated. The 'password' field is used as the optional passphrase to encrypt the private key (the passphrase is then also rotated).  The resulting SSH key information is stored in custom fields and sync'd to your Keeper vault.  Any Keeper user or Keeper Shared Folder associated with the record is updated instantly.

If one or more `cmdr:host` custom fields are provided, Commander will connect to the target hosts and upload the newly generated SSH public key.

### Dependencies

1. This plugin requires **OpenSSL** and **OpenSSH** packages to be installed on the computer running Keeper Commander.

To verify this, open the Terminal application and make sure `'openssl'` and `'ssh'` commands are installed and accessible with the system **PATH** environment variable.

2. Specify the login name to the target system(s) in the **'Login'** field of the Keeper record

3. The plugin will use **'Password'** field to store the passkey used to encrypt the private key.

4. Add the following 'Custom Fields' to the Keeper record

Name          | Value     | Comment
---------     | -------   | ------------
cmdr:plugin   | sshkey    |
cmdr:host     |           | (Optional, Multiple) Host name or IP address of target server
cmdr:rules    |           | (Optional) [password complexity rules](https://github.com/Keeper-Security/Commander/tree/master/keepercommander/plugins/password_rules.md)

![](https://raw.githubusercontent.com/Keeper-Security/Commander/master/keepercommander/images/plugin_sshkey1.png)

  NOTE: In order to automate the rotation of the public key on the target server, the public key must be manually updated one time in .ssh/authorized_keys on the target server.  After it has been set this first time, subsequent rotations can be automated by Commander.
  
  When setting up this plugin for the first time please use the following steps:
  
   1. Do **not** add `cmdr:host` to the record.
   2. Generate SSH key and passphrase by telling Commander to rotate the password ('r' command')
   3. Use `ssh-copy-id` or any other method to copy the generated public key to the target system manually.
   4. Add `cmdr:host` to the record. `.ssh/authorized_keys` in the target system will then be automatically updated the next time the key is rotated by Commander.

<sub>**Note:** This plugin makes an assumption that the target system uses the default settings for SSH service, i.e. `authorized_keys` file is located in the `.ssh` directory of the user **HOME** directory.</sub>

### Output

When successful, this plugin adds/modifies the following record fields:

1. **'Password'** field contains the passkey used to encrypt the private key.  It is also rotated every time.

2. **'Custom Fields'**

Name                | Value   | Comment
-----------------   | ------- | --------
cmdr:ssh_public_key |         | Public key in SSH format. This key is uploaded to the target system.
cmdr:rsa_public_key |         | Public key in RSA format.
cmdr:private_key    |         | Private key encrypted with the passkey stored in the **'Password'** field

![](https://raw.githubusercontent.com/Keeper-Security/Commander/master/keepercommander/images/plugin_sshkey2.png)
