Commander Plugin for Generating/Rotating Azure AD User Password
----

This plugin generates/rotates Azure AD password for any user.

### Dependencies

1. Install [Microsoft Authentication Library (MSAL) for Python](https://github.com/AzureAD/microsoft-authentication-library-for-python) 
```
pip install msal
```


<sub>**Note:** You need to configure your Azure application that will have User Administrative privileges in order to modify the Password for the specified user. See "Configure Azure Application" section below</sub>

2. Populate the **'Login'** field of the Keeper record with the AWS login name

3. Add the following Custom Fields to the record that you want to rotate in Azure and within Keeper

Name                 | Value      | Comment
---------            | -------    | ------------
cmdr:plugin          | azureadpwd | 
cmdr:azure_secret    |            | Displayed upon Registration of a new application (under Azure portal -> `Azure Active Directory` -> `App Registrations` -> `New Registration`. <br/><br/>See "Create App Secret" section below
cmdr:azure_client_id |            | Azure portal -> `Azure Active Directory` -> `App Registrations` -> [App name] -> `Application (client) ID`
cmdr:azure_tenant_id |            | Azure portal -> `Azure Active Directory` -> `App Registrations` -> [App name] -> `Directory (tenant) ID`
cmdr:rules           |            | (Optional) [password complexity rules](https://github.com/Keeper-Security/Commander/tree/master/keepercommander/plugins/password_rules.md)

![](https://raw.githubusercontent.com/Keeper-Security/Commander/master/keepercommander/images/plugin_azure_ad_pwd1.jpg)


### Output

After rotation is completed, the new password will be stored in the **`Password`** field of the record


# Configure Azure Application

### Steps to register new application
1. Navigate to new app registration page: Azure portal -> `Azure Active Directory` -> `App Registrations` -> `New Registration`
2. Give a name to the application and leave Supported account type as "Accounts in this organizational directory only (Default Directory only - Single tenant)"
3. Click "Register"

### Steps to add `User Administrator` role to the 
1. Azure portal -> `Azure Active Directory` -> `Roles and administrators`
2. Search for `User administrator` role and click on it
3. Click on `+ Add assignments`
4. Search for the application that was created above, select it, and click on "Add"

### Create App Secret
1. Navigate to Azure portal -> `Azure Active Directory` -> `App Registrations` -> Select app that was created above -> `Certificates & secrets`
2. Under "Client secrets" click on `+ New client secret`
3. Give description to a secret and click "Add"
4. Make sure to copy "Value" of the secret