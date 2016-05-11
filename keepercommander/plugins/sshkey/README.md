Commander Plugin for Generating/Rotating SSH keys
----

This plugin generates/rotates SSH keys for the provided user on the local system.  The 'Login' field of the Keeper record defines the user account which is being rotated. The 'password' field is used as the optional passphrase to encrypt the private key.  The resulting SSH key information is stored in custom fields and sync'd to your Keeper vault.  Any Keeper user or Keeper Shared Folder associated with the record is updated instantly.

### Dependencies

1. This plugin requires **OpenSSL** and **OpenSSH** packages to be installed on the computer running Keeper Commander.

Open Terminal application and make sure `'openssl'` and `'ssh'` commands are installed and accessible with the system **PATH** environment variable.

2. Specify the login name to the target system(s) in the **'Login'** field of the Keeper record

3. The plugin will use **'Password'** field to store the passkey used to encrypt private key.

4. Add the following 'Custom Fields' to the Keeper record

Name          | Value     | Comment
---------     | -------   | ------------
cmdr:plugin   | sshkey    |
cmdr:host     |           | (Optional, Multiple) Host name or IP address of target server
cmdr:rules    |           | (Optional) [password complexity rules](https://github.com/Keeper-Security/Commander/tree/master/keepercommander/plugins/password_rules.md)


![](https://raw.githubusercontent.com/Keeper-Security/Commander/master/keepercommander/images/plugin_sshkey1.png)

  Automatic public key update on the target server expects that .ssh/authorized_keys already contains the valid public key.
  When setting up this pluging for the first time please use the following steps:
   1. Do **not** add `cmdr:host` to the record.
   2. Generate SSH key
   3. Use `ssh-copy-id` or any other method to copy public key to the target system.
   4. Add `cmdr:host` to the record. `.ssh/authorized_keys` file will be automatically updated the next time the key rotated.

<sub>**Note:** This plugin makes an assumption that the target system uses the default settings for SSH service , i.e. `authorized_keys` file is located
 in the `.ssh` directory of the user **HOME** directory.</sub>

### Output

When succeeded, plugin add/modifies the following record fields

1. **'Password'** field contains the passkey used to encrypt private key.

2. **'Custom Fields'**

Name                | Value   | Comment
-----------------   | ------- | --------
cmdr:ssh_public_key |         | Public key in SSH format. This key is uploaded to the target system(s)
cmdr:rsa_public_key |         | Public key in RSA format.
cmdr:private_key    |         | Private key encrypted with the passkey stored in **'Password'** field

![](https://raw.githubusercontent.com/Keeper-Security/Commander/master/keepercommander/images/plugin_sshkey2.png)
