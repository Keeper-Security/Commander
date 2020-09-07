![](https://raw.githubusercontent.com/Keeper-Security/Commander/master/keepercommander/images/commander_logo_250x100.png)

----

Jump to:
* [Overview](#password-management-sdk-for-it-admins--developers)
* [Use Cases](#use-cases)
* [Installation](#python-installation---linux-and-mac)
* [Developer Setup](#developer-mode)
* [Command-line Usage](#command-line-usage)
* [Interactive Shell](#interactive-shell)
* [Keeper Command Reference](#keeper-command-reference)
* [Importing Data](#importing-records-into-keeper)
* [Exporting Data](#exporting-records-from-keeper)
* [Event Reporting](#ad-hoc-event-reporting)
* [SIEM integration](#event-logging-to-siem)
* [Advanced Configuration](#advanced-configuration-file)
* [Batch Mode](#batch-mode)
* [Enterprise SSO Login](#enterprise-sso-login)
* [Pushing Records to Users and Teams](#pushing-records-to-users-and-teams)
* [Creating and Pre-Populating Vaults](#creating-and-pre-populating-vaults)
* [Password Retrieval API](#password-retrieval-api)
* [Jenkins CI Integration](#jenkins-ci-integration)
* [Launching and Connecting to Remote Servers](#launching-and-connecting-to-remote-servers)
* [Environmental Variables](#environmental-variables)
* [Password Rotation](#targeted-password-rotations--plugins)
* [Troubleshooting](#troubleshooting)
* [About Keeper](#about-our-security)
* [Enterprise Resources](#enterprise-resources)
* [Binary Package](#build-binary-package)

### Password Management SDK for IT Admins & Developers

Keeper Security develops the world's most downloaded password manager and encrypted digital vault with millions of individual customers and thousands of enterprise customers worldwide.  Keeper is a zero-knowledge, native and cloud-based solution available on every mobile and desktop device platform. <a href="#about-keeper">Read more</a> about Keeper or visit the [Keeper Security](https://keepersecurity.com) website.

Keeper Commander is a command-line and SDK interface to [Keeper&reg; Password Manager](https://keepersecurity.com). Commander can be used to access and control your Keeper vault, perform administrative functions (such as end-user onboarding and data import/export), launch remote sessions, rotate passwords, eliminate hardcoded passwords and more. Keeper Commander is an open source project with contributions from Keeper's engineering team and partners. 

If you need any assistance or require specific functionality not supported in Commander yet, please contact us at commander@keepersecurity.com.

### Use Cases

* Access your Keeper vault through a command-line interface
* Perform bulk import and export of vault records 
* Manage records, folders and shared folders
* Customize integration into your backend systems
* Provision new Enterprise user accounts and shared folders
* Manage nodes, roles, teams and users
* Rotate passwords on service accounts or other targets
* Integrate Keeper into your existing backend systems
* Schedule and automate commands
* Initiate remote connections (such as SSH and RDP) 

### Python Installation - Linux and Mac

1. Get Python 3 from [python.org](https://www.python.org).
2. Install Keeper Commander with pip3:

```bash
$ pip3 install keepercommander
```

Important: Restart your terminal session after installation

### Python Installation - Windows 

1. Download and install [WinPython](https://winpython.github.io/)
2. From the install folder of WinPython, run the "WinPython Command Prompt" 
2. Install Keeper Commander with pip3:

```bash
$ pip3 install keepercommander
```

### Upgrading to Latest Python Code

```bash
$ pip3 install --upgrade keepercommander
```

Please do not upgrade a production system without validation in your test environment as commands and functionality is under rapid development.

### .Net SDK and PowerShell Module

We are in active development of a .Net SDK and PowerShell that covers the core use cases of accessing and updating vault records.  See the [.Net SDK](https://github.com/Keeper-Security/keeper-sdk-dotnet) for sample code and PowerShell modules.

### Developer Mode

If you are a developer and you want to modify the Python source code then follow these steps:

1. Clone/Download the Commander repository 
2. Install Python3 from python.org
3. Install virtualenv:
```bash
$ sudo pip3 install virtualenv
```
4. Create and activate the virtual environment for your keeper project:

```bash
$ cd /path/to/Commander
$ virtualenv -p python3 venv
$ source venv/bin/activate
$ pip install -r requirements.txt
$ pip install -e .
```

Keeper supports plugins for various 3rd party systems for password reset integration. Depending on the plugin, you will need to also install the modules required by that plugin. For example, our MySQL plugin requires the PyMySQL module.

See the [custom](https://github.com/Keeper-Security/Commander/tree/master/keepercommander/custom) folder for examples on creating your own custom scripts.

### Command-line Usage

Commander's command-line interface and interactive shell is a powerful and convenient way to access and control your Keeper vault and perform many administrative operations. To see all available commands, just type:

```
$ keeper

usage: keeper [--server SERVER] [--user USER] [--password PASSWORD]
              [--version] [--config CONFIG] [--debug]
              [command] [options [options ...]]

positional arguments:
  command               Command
  options               Options

optional arguments:
  --server SERVER, -ks SERVER
                        Keeper Host address.
  --user USER, -ku USER
                        Email address for the account.
  --password PASSWORD, -kp PASSWORD
                        Master password for the account.
  --version             Display version
  --config CONFIG       Config file to use
  --debug               Turn on debug mode
```

### Interactive Shell
To run a series of commands and stay logged in, you will enjoy using Commander's interactive shell.

```
$ keeper shell

  _  __
 | |/ /___ ___ _ __  ___ _ _
 | ' </ -_) -_) '_ \/ -_) '_|
 |_|\_\___\___| .__/\___|_|
              |_|

 password manager & digital vault

Logging in...
Syncing...
Decrypted [400] Records

My Vault> search amazon                                                                                                                 

  #  Record UID              Title                        Login              URL
---  ----------------------  ---------------------------  -----------------  ----------------------
  1  8Q_NiK10JWKppngL5R4IvQ  Amazon AWS Demo              admin@company.com  https://aws.amazon.com
  2  Pe8N7Ii0rDd64XVDOnlS4g  Business Account             me@company.com     https://aws.amazon.com

My Vault> get Pe8N7Ii0rDd64XVDOnlS4g                                                                                                    

                 UID: Pe8N7Ii0rDd64XVDOnlS4g
              Folder: Amazon AWS          
               Title: Business Account    
               Login: me@company.com      
            Password: BmW2NKqfaV@2O%DT!Qg0emOJQf
                 URL: https://aws.amazon.com
 Account ID or alias: mycompanyname
       Access Key ID: BLklAomJ9NvGWtupv3QZmc0#m@
          Secret Key: 0MZenvr0x4rzK$8qLHwzS42i8r7fsdjh4DKJASHd34
               Notes: These are some notes 
        Shared Users: craig@acme-demo.com (Owner) self
      Shared Folders: Amazon AWS          

My Vault>                                                                                                                               

```

Type ```h``` to display all commands and help information.

### Keeper Command Reference

Whether using the interactive shell, CLI or JSON config file, Keeper supports the following features specified by ```command```.  Each command supports additional parameters and options.  

To get help on a particular command, run:

 ```help <command>```

**Basic Vault Commands**

_Note:_ Some commands accept record or shared folder UID parameter. UID values may start with dash character (**-**) that is interpreted by command parser as an option. To pass a parameter starting with dash separate this parameter with two dashes (**--**). For example: `rmdir -- -Gd9l4daPw-fMd`

* ```login``` Login to Keeper

* ```whoami``` Information about logged in user

* ```logout``` Logout from Keeper

* ```help``` Display help docs on a particular command

* ```shell``` Use Keeper interactive shell

* ```sync-down``` or ```d``` Download, sync and decrypt vault

* ```list``` or ```l``` List all records or search with a regular expression.

* ```search``` or ```s``` Search all records with a regular expression.

* ```ls``` List folder contents (try ```ls -l``` as well)

* ```tree``` Display entire folder structure as a tree

* ```cd``` Change current folder

* ```get``` Retrieve and display specified Keeper Record/Folder/Team in printable or JSON format.

* ```find-password``` or ```clipboard-copy``` Copy the specified Keeper Record password field to the system output or clipboard 
  accordingly. Command accepts record UID or record path. If record is not found then command matches records by title.
  
    Parameters:   
    - ```--username``` Matches records by login/username field in addition to matching by title. Can be used if matching by record title returns more than one record.
    
* ```record-history``` Display the record version history or a specific version of a record.

    Parameters:
    - ```--action=list``` Display the revision number, modified by user, time of modification.
    - ```--action=diff``` Display revision, field changed and old/new values. 
    - ```--action=show``` Provided the revision number, display the record for that specific revision and record. 
    - ```--action=restore``` Restore the current version to the specified record UID and version.
    - ```--revision``` Get a specific revision 

* ```totp``` Display the Two-Factor Code (TOTP) attached to a vault record. If no record UID is provided, a list of available records that contain Two-Factor Codes will be displayed. If a record UID is provided, the code is displayed with a countdown timer.

* ```download-attachment``` Download all file attachments in specified record

* ```upload-attachment``` Upload file attachments to the specified record

* ```delete-attachment``` Delete a file attachment from the specified record.  Specify Record UID and Filename (or Attachment ID)

* ```file-report``` File attachment report

* ```list-sf``` or ```lsf``` Display all shared folders

* ```create-user``` Create Keeper vault account.
Note: If executed by an admin, the user will be provisioned to the Enterprise license. - [See Details](#creating-and-pre-populating-vaults)

* ```list-team``` or ```lt``` Display all teams

**Record Management Commands**

* ```add``` Add a record to the vault

* ```edit``` Edit a record in the vault

* ```rm``` Remove record

* ```append-notes``` or ```an``` Append notes to existing record

**Folder Management Commands**

* ```mkdir``` Create folder

* ```rmdir``` Remove folder and its content

* ```mv``` Move record or folder

* ```ln``` Create a link between record or folder

* ```set``` Set environmental variables that can be used for substitution within other commands/arguments. 

* ```echo``` Display environmental variables

**Remote Connection Commands**

* ```connect``` Connect to external server using SSH, RDP or any other protocol.

**Password Rotation Commands**

* ```rotate``` or ```r``` Rotate password in record

**Import and Export Commands**

* ```import``` Import data from local file to Keeper. JSON, CSV, Keepass, LastPass formats accepted. Keepass import includes all file attachments.

* ```export``` Export data from Keeper to local file or stdout. JSON, CSV, Keepass file formats supported.  Keepass exports include all file attachments.

**Folder and Record Sharing Commands**

* ```share-record``` or ```sr``` Grant or revoke record's user access

* ```share-folder``` or ```sf``` Grant or revoke shared folder's user access or record permission

* ```record-permission``` Changes record permissions inside the folder or folder tree. 

    Parameters:
    - ```--action``` Grant or revoke requested permissions
    - ```--share-record``` Modify direct record share permissions only
    - ```--share-folder``` Modify record permissions on shared folders
    - ```--recursive``` Apply permissions to all records in folder tree
    - ```--can-share``` Permission to share the record
    - ```--can-edit``` Permission to edit the record
    - ```--dry-run``` Do not modify but display permissions that are about to be changed by this command 

**Enterprise Console Management Commands**

* ```enterprise-info``` or ```ei```   Display enterprise information

    Parameters:
    - ```--nodes``` Show node structure in a tree form
    - ```--users``` Show users in a list view
    - ```--roles``` Show all roles in a list view
    - ```--teams``` Show all teams in a list view
    - ```--node``` Specify a single node to limit view
    - ```--v``` Verbose mode 

* ```enterprise-user <email(s)>``` or ```eu <email(s)>```   Enterprise user management

    Parameters:
    - ```--expire``` Expire the Master Password for the user
    - ```--extend``` Extend vault transfer consent by 7 days 
    - ```--lock``` Unlock the user account
    - ```--unlock``` Lock the user account 
    - ```--disable-2fa``` Disable 2FA for a user
    - ```--add``` Invite a new user to join the enterprise
    - ```--delete``` Delete the user and all stored vault records (use with caution)
    - ```--name``` Rename a user's display name
    - ```--node``` Move user into a node 
    - ```--add-role``` Add a user to a role
    - ```--remove-role``` Remove a user from a role
    - ```--add-team``` Add a user to a team
    - ```--remove-team``` Remove a user from a team
    - If no parameters are provided, displays information about specified email

    Multiple emails can be provided, for example: 
    - ```enterprise-user --lock user1@company.com user2@company.com user3@company.com```

* ```enterprise-role <Role ID>``` or ```er <Role ID>```   Enterprise role management

    Parameters:
    - ```--add-user``` Add a user to a specified role
    - ```--remove-user``` Remove a user from a specified role
    - If no parameters are provided, displays information about specified role

* ```enterprise-team <Team ID>``` or ```et <Team ID>```   Enterprise team management

    Parameters:
    - ```--add``` Create a new team in the root node
    - ```--node``` Move a team into the specified node
    - ```--add-user``` Add a user to a team
    - ```--remove-user``` Remove a user from a team
    - ```--name``` Change the Team name
    - ```--delete``` Delete a team
    - ```--restrict-edit``` Restrict record edit on the team
    - ```--restrict-share``` Restrict record re-sharing on the team
    - ```--restrict-view``` Restrict record viewing on the team 
    - If no parameters are provided, displays information about specified team

* ```team-approve``` Approve queued teams and users that have been provisioned by SCIM or Active Directory Bridge 

    Parameters:
    - ```--team``` Approve teams only
    - ```--user``` Approve team users only
    - ```--restrict-edit {on,off}``` disable record edits
    - ```--restrict-share {on,off}``` disable record re-shares
    - ```--restrict-view {on,off}``` disable view/copy passwords

* ```enterprise-push <Record Template File Name>```   Populate user and team vaults with default records - [See Details](#pushing-records-to-users-and-teams)

    Parameters:
    - ```--syntax-help``` Displays information of record template file format
    - ```--team TEAM_NAME or TEAM UID``` Populate all team users' vaults
    - ```--email USER_EMAIL``` Populate user's vault
    - ```file``` JSON file name containing template records

* ```audit-log``` Export audit and event logs to SIEM - [See Details](#event-logging-to-siem)
    - ```--target=splunk``` Export events to Splunk HTTP Event Collector 
    - ```--target=sumo``` Export events to Sumo Logic HTTP Event Collector
    - ```--target=syslog``` Export events to a local file in syslog format
    - ```--target=syslog-port``` Export events in syslog format to TCP port. Both plain and SSL connections are supported
    - ```--target=azure-la``` Export events to Azure Log Analytics to custom log named Keeper_CL
    - ```--target=json``` Export events to a local file in JSON format

* ```audit-report``` Generate ad-hoc customized audit event reports in raw and summarized formats - [See Details](#ad-hoc-event-reporting)

    Parameters:
    - ```--report-type``` {raw,dim,hour,day,week,month,span}
    - ```--report-format``` {message,fields} output format (raw reports only)
    - ```--columns COLUMNS```     Can be repeated. (ignored for raw reports)
    - ```--aggregate``` {occurrences,first_created,last_created} aggregated value. Can be repeated. (ignored for raw reports)
    - ```--timezone TIMEZONE```   return results for specific timezone
    - ```--limit LIMIT```         maximum number of returned rows
    - ```--order``` {desc,asc}    sort order
    - ```--created CREATED```  Filter: Created date. Predefined filters: today, yesterday, last_7_days, last_30_days, month_to_date, last_month, year_to_date, last_year
    - ```--event-type EVENT_TYPE``` Filter: Audit Event Type
    - ```--username USERNAME``` Filter: Username of event originator
    - ```--to-username TO_USERNAME``` Filter: Username of event target
    - ```--record-uid RECORD_UID``` Filter: Record UID
    - ```--shared-folder-uid SHARED_FOLDER_UID``` Filter: Shared Folder UID

* ```user-report``` Generate ad-hoc user status report

    Parameters:
    - ```--format``` {table,json,csv}
    - ```--output``` output to the given filename
    - ```--days``` {number of days} number of days to look back for last login date

* ```share-report``` Generate ad-hoc sharing permission report that displays users and team permissions for all records in the vault

    Parameters:
    - ```--record``` View share permissions on specific record 
    - ```--email``` View share permissions with specific account. User email or team name
    - ```--owner``` Include the owner information for each record 
    - ```--verbose``` Include the record title and permission settings for each record 

**MSP Console Management Commands**

* ```msp-info``` or ```mi``` Display MSP details, such as licenses and managed companies

    Sample Output:
    
    ```
      MSP Plans and Licenses
    -----------------------
      #  Plan Id           Available Licenses    Total Licenses    Stash
    ---  --------------  --------------------  ----------------  -------
      1  business                           6                10       10
      2  businessPlus                       8                10       10
      3  enterprise                         2                10       10
      4  enterprisePlus                     6                10       10
  
      #    ID  Name         Plan              Allocated    Active
    ---  ----  -----------  --------------  -----------  --------
      1  3861  Company 1     businessPlus              2         2
      2  3862  Company 2     enterprise                0         0
      3  3900  Company 3     business                  2         0
      4  3877  Company 4     enterprisePlus            4         0
      5  3863  Company 5     enterprise                8         0
      6  3875  Company 6     business                  2         0

  ```
  
* ```msp-down``` or ```md``` Refresh local MSP data from the server. Useful in case when there was an update made on 
the font end and user wants to retrieve current configurations without re-login to the commander  

* ```msp-license``` or ```ml``` View and Manage MSP licenses

    Usage example:
    ```
  msp-license --add --seats=4 --mc 3984
  ```
    Parameters:
    
    - ```-h```, ```--help``` Show help message
    - ```-a {add,reduce,usage}```, ```--action {add,reduce,usage}``` Action to perform on the licenses. Default: `usage`
        
        Options:
        - `usage` - View current usage of licenses given to the MSP. Will print the table listing License Plan ID, available license, total allocated licenses, and Stash
        - `add` - Add licenses to the managed company
        - `reduce` - Reduce licenses from the managed company
    - ```--mc MC```  Managed Company identifier (managed company name or ID). Example: `3862` OR `"Keeper Security, Inc."`. ID of the company can be located by running `msp-info` command
    - ```-s SEATS```, ```--seats SEATS``` - Number of seats to add or reduce.


* ```msp-license-report``` or ```mlr``` MSP License Reports

    Usage example:
    ```
    msp-license-report [-h] [--type {allocation,audit}]
                      [--format {table,csv,json}]
                      [--range {today,yesterday,last_7_days,last_30_days,month_to_date,last_month,year_to_date,last_year}]
                      [--from FROM_DATE] [--to TO_DATE] [--output OUTPUT]

     ```
    Parameters:
    - ```-h``` or ```--help``` Show help message
    - ```--type {allocation,audit}``` Type of the report. Default `allocation`
    - ```--format {table,csv,json}``` Format of the report output. 
    - ```--range {today,yesterday,last_7_days,last_30_days,month_to_date,last_month,year_to_date,last_year}``` Pre-defined data ranges to run the report.
     Only application to the `audit` report. Default `last_30_days`
    - ```--from FROM_DATE``` Run report from this date.  Value in ISO 8601 format (YYYY-mm-dd) or Unix timestamp format. Only application to the `audit` report AND when there is no `range` specified. Example: `2020-08-18` or `1596265200`
    - ```--to TO_DATE```     Run report until this date. Value in ISO 8601 format (YYYY-mm-dd) or Unix timestamp format. Only application to the `audit` report AND when there is no `range` specified. Example: `2020-08-18` or `1596265200`
    - ```--output OUTPUT``` Output file name. (ignored for table format)

#### Running commands as Managed Company (MC) administrator

In the Web Console interface MSP users have ability to login to the managed company and perform actions as an admin of the Managed Company.

In Commander's command line interface the same can be achieved by running one command as MC or switching the context to MC and running all following commands 
under that particular company.

##### One-off Command as MC Administrator

To run one-off command w/o switching context from MSP can be achieved by adding MS ID as one of the arguments to the command (ex. `--mc 12345`). The ID of the MC can
be found by running `msp-info` command.

Example to add user as an admin of MC with id 3900:

```
$ enterprise-user --add user@example.com --mc 3900
```

##### Switching to MC

To switch the context to run all commands as MC administrator, use the `switch-to-mc [MC ID]` command. The ID of the MC can be found by running `msp-info` command.

Example:

```
$ switch-to-mc 3900
```

To switch the context back to MSP, use the `switch-to-msp` command.

Example: 

```
switch-to-msp
```

### Importing Records into Keeper

To import records into your vault, use the ```import``` command.  Supported import formats:

* JSON
* CSV 
* Keepass (see additional [install instructions](keepercommander/importer/keepass/README.md))
* LastPass (see additional [install instructions](keepercommander/importer/lastpass/README.md))

JSON import files can contain records, folders, subfolders, shared folders, default folder permissions  and user/team permissions.
CSV import files contain records, folders, subfolders, shared folders and default shared folder permissions.
Keepass files will transfer records, file attachments, folders and subfolders. Option exists to make all folders as shared folders. File attachments are supported in both import and export with Keepass however they are limited to 1MB for each file based on keepass' structure.
LastPass import will transfer the vault passwords directly to Keeper retaining the folder structure.

**JSON Record Import**

Below is a JSON import file with 2 records. The first record is added to a folder called "My Servers". The second record is added to "My Servers" and also added to a shared folder called "Shared Servers". 

The import file example below is an array of record objects which can import into private folders and shared folders:

```bash
[{
    "title":"Dev Server",
    "folders": [
      {
        "folder": "My Servers"
      }
    ],
    "login": "root",
    "password": "lk4j139sk4j",
    "login_url": "https://myserver.com",
    "notes": "These are some notes.",
    "custom_fields": {"Security Group":"Private"}
},
{
    "title":"Prod Server",
    "folders": [
      {
        "folder": "My Servers"
      },
      {
       "shared_folder": "Shared Servers",
       "can_edit": true,
       "can_share": true
      }
    ],
    "login": "root",
    "password": "kj424094fsdjhfs4jf7h",
    "login_url": "https://myprodserver.com",
    "notes": "These are some notes.",
    "custom_fields": {"Security Group":"Public","IP Address":"12.45.67.8"}
}]
```

Another example below first creates shared folders that are shared to users and teams, then imports records into the shared folders.  The format of the file is slightly different and allows you to separate the creation of shared folder objects and records:


```
{
  "shared_folders": [
    {
      "path": "My Customer 1",
      "manage_users": true,
      "manage_records": true,
      "can_edit": true,
      "can_share": true,
      "permissions": [
        {
          "uid": "kVM96KGEoGxhskZoSTd_jw",
          "manage_users": true,
          "manage_records": true
        },
        {
          "name": "user@mycompany.com",
          "manage_users": true,
          "manage_records": true
        }
      ]
    },
    {
      "path": "Testing\\My Customer 2",
      "manage_users": true,
      "manage_records": true,
      "can_edit": true,
      "can_share": true,
      "permissions": [
        {
          "uid": "ih1CggiQ-3ENXcn4G0sl-g",
          "manage_users": true,
          "manage_records": true
        },
        {
          "name": "user@mycompany.com",
          "manage_users": true,
          "manage_records": true
        }
      ]
    }
  ],
  "records": [
    {
      "title": "Bank Account 1",
      "login": "customer1234",
      "password": "4813fJDHF4239fdk",
      "login_url": "https://chase.com",
      "notes": "These are some notes.",
      "custom_fields": {
        "Account Number": "123-456-789"
      },
      "folders": [
        {
          "folder": "Optional Private Folder 1"
        }
      ]
    },
    {
      "title": "Bank Account 2",
      "login": "mybankusername",
      "password": "w4k4k193f$^&@#*%2",
      "login_url": "https://amex.com",
      "notes": "Some great information here.",
      "custom_fields": {
        "Security Group": "Public",
        "IP Address": "12.45.67.8"
      },
      "folders": [
        {
          "folder": "Optional Private Folder 1"
        },
        {
          "shared_folder": "My Customer 1",
          "can_edit": true,
          "can_share": true
        }
      ]
    }
  ]
}
```

The format must be strict JSON or it will fail parsing. To import this file:

```bash
$ keeper import --format=json import.json
```

There are more complex import file examples that supports shared folders, folder permissions, user permissions and team permissions located in the sample_data/ folder. To import the sample JSON file into your vault, type this command:

* Example 1: [import.json.txt](sample_data/import.json.txt)
* Example 2: [import_records_existing_folders.json.txt](sample_data/import_records_existing_folders.json.txt)
* Example 3: [import_records_into_folders.json.txt](sample_data/import_records_into_folders.json.txt)
* Example 4: [import_shared_folders.json.txt](sample_data/import_shared_folders.json.txt)
* Example 5: [import_shared_folders_and_records.json.txt](sample_data/import_shared_folders_and_records.json.txt)

```bash
$ keeper import --format=json sample_data/import.json.txt
```

The sample file contains "permissions" objects that contain email address or team names.  If the email or team name exists in your Keeper enterprise account, they will be added to the shared folder, otherwise the information is ignored. 


**CSV Record Import**

Keeper supports .csv text file import using comma delimited fields.

File Format:
Folder,Title,Login,Password,Website Address,Notes,Shared Folder,Custom Fields

* To specify subfolders, use backslash "\\" between folder names
* To set shared folder permission on the record, use the #edit or #reshare tags as seen below 
* Enclose fields in quotes for multi-line or special characters
* Ensure files are UTF-8 encoded for support of international or double-byte characters 

Below is an example csv file that showcases several import features including personal folders, shared folders, subfolders, special characters and multi-line fields.

```
Business,Twitter,marketing@company.com,"a bad password",https://twitter.com,Some interesting notes!,,API Key,"131939-AAAEKJLE-491231$##%!",Date Created,2018-04-02
Subfolder1,Twitter,craig@gmail.com,xwVnk0hfJmd2M$2l4shGF#p,https://twitter.com,,Social Media\Customer1#edit#reshare
Subfolder2,Facebook,craig@gmail.com,TycWyxodkQw4IrX9VFxj8F8,https://facebook.com,,Social Media\Customer2#edit#reshare
,Google Dev Account,mydevaccount@gmail.com,"8123,9fKJRefa$!@#4912fkk!--3",https://accounts.google.com,"Google Cloud ID 448812771239122
Account Number 449128
This is multi-line",Shared Accounts#edit#reshare,2FA Phone Number,+19165551212
```

To import this file:
```bash
$ keeper import --format=csv test.csv
4 records imported successfully
```

The resulting vault will look like [this image](https://raw.githubusercontent.com/Keeper-Security/Commander/master/keepercommander/images/csv_import.png)

**Keepass Import**

Keeper supports importing the record and folder structure directly from an encrypted Keepass file. File attachments are also supported.  Make sure to first follow [these instructions](keepercommander/importer/keepass/README.md) to install the necessary keepass modules.

```bash
$ keeper import --format=keepass test.kdbx
```

You can optionally make all top level folders as shared folder object with default permissions.

```bash
$ keeper import --format=keepass --shared --permissions=URES test.kdbx
```

For more options, see the help screen:
```bash
$ keeper help import
```

**LastPass Import**

Keeper supports automatic import of your LastPass vault by providing your LastPass email, Master Password and 2FA code. Make sure to first follow [these instructions](keepercommander/importer/lastpass/README.md) to install the necessary LastPass modules.

```bash
$ keeper import --format=lastpass craig@acme-demo.com 
Processing... please wait.
...             LastPass Password: *******
Press <Enter> if account is not protected with Multifactor Authentication
...          Multifactor Password: ******
13 records imported successfully
My Vault>
```

You can optionally make all top level folders as shared folder object with default permissions.

```bash
$ keeper import --format=lastpass --shared --permissions=URES craig@acme-demo.com 
```

For more options, see the help screen:
```bash
$ keeper help import
```

### Exporting Records from Keeper

To export records from your vault, use the ```export``` command.  Supported export formats:

* JSON
* CSV
* Keepass (see additional [install instructions](keepercommander/importer/keepass/README.md))

JSON export files contain records, folders, subfolders, shared folders, default folder permissions and user/team permissions.
CSV import files contain records, folders, subfolders, shared folders and default shared folder permissions.
Keepass files contain records, file attachments, folders and subfolders.

### Ad-Hoc Event Reporting 

Business customers can now generate advanced ad-hoc event reports with over 100 different event types and custom filters. For help with the syntax of the report, use the below command:

```
My Vault> audit-report --syntax-help                                                                                                                                                                        
``` 

The list of over 100 event types is documented in our Enterprise Guide:

[https://docs.keeper.io/enterprise-guide/event-reporting](https://docs.keeper.io/enterprise-guide/event-reporting)

```
Audit Report Command Syntax Description:

Event properties
  id                event ID
  created           event time
  username          user that created audit event
  to_username       user that is audit event target
  from_username     user that is audit event source
  ip_address        IP address
  geo_location      location
  audit_event_type  audit event type
  keeper_version    Keeper application
  channel           2FA channel
  status            Keeper API result_code
  record_uid        Record UID
  shared_folder_uid Shared Folder UID
  node_id           Node ID (enterprise events only)
  team_uid          Team UID (enterprise events only)

--report-type:
            raw     Returns individual events. All event properties are returned.
                    Valid parameters: filters. Ignored parameters: columns, aggregates

  span hour day	    Aggregates audit event by created date. Span drops date aggregation
     week month     Valid parameters: filters, columns, aggregates

            dim     Returns event property description (audit_event_type, keeper_version) or distinct values.
                    Valid parameters: columns. Ignored parameters: filters, aggregates

--columns:          Defines break down report properties.
                    can be any event property except: id, created

--aggregates:       Defines the aggregate value:
     occurrences    number of events. COUNT(*)
   first_created    starting date. MIN(created)
    last_created    ending date. MAX(created)

--limit:            Limits the number of returned records

--order:            "desc" or "asc"
                    raw report type: created
                    aggregate reports: first aggregate

Filters             Supported: '=', '>', '<', '>=', '<=', 'IN(<>,<>,<>)'. Default '='
--created           Predefined ranges: today, yesterday, last_7_days, last_30_days, month_to_date, last_month, year_to_date, last_year
                    Range 'BETWEEN <> AND <>'
                    where value is UTC date or epoch time in seconds
--event-type        Audit Event Type.  Value is event id or event name
--username          Email
--to-username
--record-uid	    Record UID
--shared-folder-uid Shared Folder UID
```

For example, to see all record deletions that occurred in the last 7 days:
```
My Vault> audit-report --report-type=raw --event-type record_delete --created last_7_days
```

Another example, to see all event history for a particular record UID:
```
My Vault> audit-report --report-type=raw --record-uid cQxq0MZ1ZmB-s9JE8CZpdA
```

To see certain events (in this case, login_failure) today:
```
My Vault> audit-report --report-type=raw --event-type=login_failure --created=today
```

To list all possible event types:
```
My Vault> audit-report --report-type=dim --column=audit_event_type 
```

There are hundreds of possible report variations possible. If you have any questions, please contact us at commander@keepersecurity.com and we'll help you construct the perfect report syntax.

### Event Logging to SIEM

Commander supports integration with popular SIEM solutions such as Splunk, Sumo and general Syslog format.  For more general reporting of events, we recommend using the ```audit-report``` command.  For pushes of event data into on-prem SIEM, the ```audit-log``` command is a good choice because it automatically tracks the last event exported and only sends incremental updates.  The list of over 100 event types is documented in our Enterprise Guide:

[https://docs.keeper.io/enterprise-guide/event-reporting](https://docs.keeper.io/enterprise-guide/event-reporting)

Using Commander for SIEM integration works well in an on-prem environment where the HTTP event collector is only available within your network.  The Keeper Admin Console versino 13.3+ is capable of integrating our backend event data into your SIEM solution but it requires that you are utilizing a cloud-based SIEM solution. If you need assistance in integrating Keeper into your SIEM solution without Commander, please contact our business support team at business.support@keepersecurity.com. 

**Export of Event Logs in Syslog Format**

Commander can export all event logs to a local file in syslog format, or export data in incremental files.  A Keeper record in your vault
is used to store a reference to the last event  

```bash
$ keeper shell
```

To export all events and start tracking the last event time exported:

```
My Vault> audit-log --target=syslog
Do you want to create a Keeper record to store audit log settings? [y/n]: y
Choose the title for audit log record [Default: Audit Log: Syslog]: 
Enter filename for syslog messages.
...              Syslog file name: all_events.log
...          Gzip messages? (y/N): n
Exported 3952 audit events
My Vault>
```

This creates a record in your vault (titled "Audit Log: Syslog" in this example) which tracks the timestamp of the last exported event and the output filename.
Then the event data is exported to the file in either text or gzip format.

Each subsequent audit log export can be performed with this command:

```bash
$ keeper audit-log --format=syslog --record=<your record UID>
```
or from the shell:

```
My Vault> audit-log --target=syslog --record=<your record UID>
```

To automate the syslog event export every 5 minutes, create a JSON configuration file such as this:

```bash
{
    "server":"https://keepersecurity.com/api/v2/",
    "user":"craig@company.com",
    "password":"your_password_here",
    "mfa_token":"filled_in_by_commander",
    "mfa_type":"device_token",
    "debug":false,
    "plugins":[],
    "commands":["sync-down","audit-log --target=syslog"],
    "timedelay":600,
}
```

Then run Commander using the config parameter. For example:

```bash
$ keeper --config=my_config_file.json
```


**Splunk HTTP Event Collector Push**

Keeper can post event logs directly to your on-prem or cloud Splunk instance. Please follow the below steps:

* Login to Splunk enterprise 
* Go to Settings -> Data Inputs -> HTTP Event Collector
* Click on "New Token" then type in a name, select an index and finish.
* At the last step, copy the "Token Value" and save it for the next step.
* Login to Keeper Commander shell

```bash
$ keeper shell
```

Next set up the Splunk integration with Commander. Commander will create a record in your vault that stores the provided token and Splunk HTTP Event Collector. This will be used to also track the last event captured so that subsequent execution will pick up where it left off.  Note that the default port for HEC is 8088.

```
$ keeper audit-log --format=splunk

Do you want to create a Keeper record to store audit log settings? [y/n]: y
Choose the title for audit log record [Default: Audit Log: Splunk]: <enter> 

Enter HTTP Event Collector (HEC) endpoint in format [host:port].
Example: splunk.company.com:8088
...           Splunk HEC endpoint: 192.168.51.41:8088
Testing 'https://192.168.51.41:8088/services/collector' ...Found.
...                  Splunk Token: e2449233-4hfe-4449-912c-4923kjf599de
```
You can find the record UID of the Splunk record for subsequent audit log exports:

```
My Vault> search splunk

  #  Record UID              Title              Login    URL
---  ----------------------  -----------------  -------  -----
  1  schQd2fOWwNchuSsDEXfEg  Audit Log: Splunk
```

Each subsequent audit log export can be performed with this command:

```bash
$ keeper audit-log --format=splunk --record=<your record UID>
```
or from the shell:

```
My Vault> audit-log --target=splunk --record=<your record UID>
```

To automate the push of Splunk events every 5 minutes, create a JSON configuration file such as this:

```bash
{
    "server":"https://keepersecurity.com/api/v2/",
    "user":"craig@company.com",
    "password":"your_password_here",
    "mfa_token":"filled_in_by_commander",
    "mfa_type":"device_token",
    "debug":false,
    "plugins":[],
    "commands":["sync-down","audit-log --target=splunk"],
    "timedelay":600,
}
```

Then run Commander using the config parameter. For example:

```bash
$ keeper --config=my_config_file.json
```


**Sumo Logic HTTP Event Collector Push**

Keeper can post event logs directly to your Sumo Logic account. Please follow the below steps:

* Login to Sumo Logic
* Go to Manage Data -> Collection 
* Click on Add Collector -> Hosted Collector then Add Source -> HTTP Logs & Metrics 
* Name the collector and Save. Any other fields are default.
* Note the HTTP Source Address which is the collector URL  
* Login to Keeper Commander shell

```bash
$ keeper shell
```

Next set up the Sumo Logic integration with Commander. Commander will create a record in your vault that stores the HTTP Collector information. This will be used to also track the last event captured so that subsequent execution will pick up where it left off.

```
$ keeper audit-log --format=sumo
```

When asked for “HTTP Collector URL:” paste the URL captured from the Sumo interface above.

After this step, there will be a record in your vault used for tracking the event data integration.
You can find the record UID of the Sumo record for subsequent audit log exports:

```
My Vault> search sumo

  #  Record UID              Title              Login    URL
---  ----------------------  -----------------  -------  -----
  1  schQd2fOWwNchuSsDEXfEg  Audit Log: Sumo
```

Each subsequent audit log export can be performed with this command:

```bash
$ keeper audit-log --format=sumo --record=<your record UID>
```
or from the shell:

```
My Vault> audit-log --target=sumo --record=<your record UID>
```

To automate the push of Sumo Logic events every 5 minutes, create a JSON configuration file such as this:

```bash
{
    "server":"https://keepersecurity.com/api/v2/",
    "user":"craig@company.com",
    "password":"your_password_here",
    "mfa_token":"filled_in_by_commander",
    "mfa_type":"device_token",
    "debug":false,
    "plugins":[],
    "commands":["sync-down","audit-log --target=sumo"],
    "timedelay":600,
}
```

Then run Commander using the config parameter. For example:

```bash
$ keeper --config=my_config_file.json
```


**Export of Event Logs in JSON Format**

Commander can export all event logs to a local file in JSON format. The local file is overwritten with every run of Commander. 
This kind of export can be used with conjunction with other application that process the file. 
A Keeper record in your vault is used to store a reference to the last event.

```bash
$ keeper shell
```

To export all events and start tracking the last event time exported:

```
My Vault> audit-log --target=json
Do you want to create a Keeper record to store audit log settings? [y/n]: y
Choose the title for audit log record [Default: Audit Log: JSON]:
JSON file name: all_events.json
Exported 3952 audit events
My Vault>
```

This creates a record in your vault (titled "Audit Log: JSON" in this example) which tracks the timestamp of the last exported event and the output filename.
Then the event data is exported to the file.

Each subsequent audit log export can be performed with this command:

```bash
$ keeper audit-log --format=json --record=<your record UID>
```
or from the shell:

```
My Vault> audit-log --target=json --record=<your record UID>
```

To automate the JSON event export every 5 minutes, create a JSON configuration file such as this:

```bash
{
    "server":"https://keepersecurity.com/api/v2/",
    "user":"craig@company.com",
    "password":"your_password_here",
    "mfa_token":"filled_in_by_commander",
    "mfa_type":"device_token",
    "debug":false,
    "plugins":[],
    "commands":["sync-down","audit-log --target=json"],
    "timedelay":600,
}
```

Then run Commander using the config parameter. For example:

```bash
$ keeper --config=my_config_file.json
```

**Azure Log Analytics**

Keeper can post event logs directly to your Azure Log Analytics workspace. Please follow the below steps:

* Login to Azure Portal and open Log Analytics workspace
* Go to Settings -> Advanced settings
* Note the Workspace ID and Primary or Secondary key
* Login to Keeper Commander shell

```bash
$ keeper shell
```

Next set up the Log Analytics integration with Commander. Commander will create a record in your vault that stores the Log Analytics access information. This will be used to also track the last event captured so that subsequent execution will pick up where it left off.

```
$ keeper audit-log --format=azure-la
```

When asked for “Workspace ID:” paste Workspace ID captured from the Advanced settings interface above.
When asked for “Key:” paste Primary or Secondary key captured from the Advanced settings interface above.

After this step, there will be a record in your vault used for tracking the event data integration.
You can find the record UID of the Log Analytics record for subsequent audit log exports:

```
My Vault> search analytics

  #  Record UID              Title                           Login                                 URL
---  ----------------------  ------------------------------  ------------------------------------  -----
  1  schQd2fOWwNchuSsDEXfEg  Audit Log: Azure Log Analytics  <WORKSPACE GUID>
```

Each subsequent audit log export can be performed with this command:

```bash
$ keeper audit-log --format=azure-la --record=<your record UID>
```
or from the shell:

```
My Vault> audit-log --target=azure-la --record=<your record UID>
```

To automate the push of events to Azure Log Analytics every 5 minutes, create a JSON configuration file such as this:

```bash
{
    "server":"https://keepersecurity.com/api/v2/",
    "user":"craig@company.com",
    "password":"your_password_here",
    "mfa_token":"filled_in_by_commander",
    "mfa_type":"device_token",
    "debug":false,
    "plugins":[],
    "commands":["sync-down","audit-log --target=azure-la"],
    "timedelay":600,
}
```

Then run Commander using the config parameter. For example:

```bash
$ keeper --config=my_config_file.json
```


### Advanced Configuration File

By default, Keeper will look for a file called ```config.json``` in the current working directory and it will use this file for reading and writing session parameters. For example, if you login with two factor authentication, the device token is written to this file. The configuration file loaded can also be customized through the ```config``` parameter. The config file can also be used to automate and schedule commands.

Below is a fully loaded config file. 

```bash
{
    "server":"https://keepersecurity.com/api/v2/",
    "user":"craig@company.com",
    "password":"your_password_here",
    "mfa_token":"filled_in_by_commander",
    "mfa_type":"device_token",
    "debug":false,
    "plugins":[],
    "commands":[],
    "timedelay":0,
}
```

Notes:

* ```server``` can be left blank and defaults to the United States data center. If your account is in the European data center then change the server domain from ```.com``` to ```.eu```.

* ```mfa_token``` will be set by Commander automatically after successful two-factor authentication.

* ```debug``` parameter can be set to ```true``` or ```false``` to enable detailed crypto and network logging.

* ```plugins``` parameter determines which password rotation plugin will be loaded. [Learn more](https://github.com/Keeper-Security/Commander/tree/master/keepercommander/plugins) about password rotation plugins for Commander.

* ```commands``` parameter is a comma-separated list of Keeper commands to run.  For example:
```"commands":["sync-down", "upload-attachment --file=\"/Users/craig/something.zip\" \"3PMqasi9hohmyLWJkgxCWg\"","share-record --email=\"somebody@gmail.com\" --write \"3PMqasi9hohmyLWJkgxCWg\""]``` will sync your vault, upload a file and then share the record with another user.

* ```timedelay``` parameter can be used to automatically run the specified commands every X seconds. For example:
```"timedelay":600``` will run the commands every 10 minutes.

* ```logout_timer``` parameter can be used to logout automatically in shell mode after inactivity period. Time period in minutes

To configure Yubikey device authentication, follow the [setup instructions](https://github.com/Keeper-Security/Commander/tree/master/keepercommander/yubikey).  In this mode, you will use a challenge phrase to authenticate instead of a Master Password.

* ```device_token_expiration``` can be set to ```true``` to require 2FA every login.  Otherwise, the 2FA token will not expire. To manually force a 2FA token to expire, login to your Keeper vault (on desktop app, Web Vault or mobile app) and disable then re-enable your Two-Factor Authentication settings. This will invalidate all previously saved tokens across all devices.

### Batch Mode 

You can batch execute a series of commands and pipe the file to STDIN of Commander.  For example, create a text file called ```test.cmd``` with the following lines:

```
add --login=blah@gmail.com --pass=somemasterpass --url=https://google.com --force "Some Record Title"
upload-attachment --file="/path/to/some/file.txt" "Some Record Title"
share-record --email="user@company.com" --write "Some Record Title"
```

To run this file in a batch mode:
```bash
cat test.cmd | keeper --batch-mode shell
```
or 
```bash
cat test.cmd | keeper -
```

The batch execution is aborted if some command returns failure. 
Use `@` in front of the command to suppress the possible command error. 
```
add --login=blah@gmail.com --pass=somemasterpass --url=https://google.com --force "Some Record Title"
@upload-attachment --file="/path/to/some/file.txt" "Some Record Title"
share-record --email="user@company.com" --write "Some Record Title"
```

### Enterprise SSO Login

Customers who normally login to their Keeper Vault using Enterprise SSO Login (SAML 2.0) can also login to Keeper Commander using a Master Password.  To make use of this capability, it must be enabled by the Keeper Administrator and then configured by the user.  The steps are below:

1. Login to the Admin Console
[https://keepersecurity.com/console](https://keepersecurity.com/console)

2. For the User/Role who will be accessing Keeper Commander, open the Role Enforcement Policy setting screen.

3. Enable the option "Allow users who login with SSO to create a Master Password"

4. Login to the End-User Vault using SSO at [https://keepersecurity.com/vault](https://keepersecurity.com/vault) 

5. Visit the Settings > General screen and setup a Master Password

After the Master Password is created, you are now able to login to Keeper Commander.

### Pushing Records to Users and Teams

The Keeper Admin can push vault records automatically to any user or team vault in their organization using the "enterprise-push" command.

Examples:

```
enterprise-push --team "Engineering Admins" push.json
```

```
enterprise-push --email user@company.com push.json
```

The "push.json" file is structured an an array of password objects.  For example:

```json
[
    {
        "title": "Google",
        "login": "${user_email}",
        "password": "${generate_password}",
        "login_url": "https://google.com",
        "notes": "",
        "custom_fields": {
            "Name 1": "Value 1",
            "Name 2": "Value 2"
        }
    },
    {
        "title": "Admin Tool",
        "login": "${user_email}",
        "password": "",
        "login_url": "https://192.168.1.1",
        "notes": "",
        "custom_fields": {
        }
    }
]
```

Supported template parameters:

```
${user_email}          User email address
${generate_password}   Generate random password
${user_name}           User full name
```

### Creating and Pre-Populating Vaults

A Keeper Admin can create a user vault and pre-populate it with records. This can all be accomplished with a single command.

For example:

```
create-user --generate --name="Test User" --expire --records="push.json" user@company.com

Created account: user@company.com
Generated password: <displayed on the screen>
```

This command performs the following streamlined operations:
1. Creates a new user account for "Test User" with the email address user@company.com
2. The account is automatically provisioned to the Enterprise license and receives the default role policy
3. The records stored in push.json are pushed to the user's vault

After command completion, the "Generated Password" displayed to the admin is the temporary Master Password set for the user account. You can provide this Master Password to the user via a separate channel. 

Upon first logging in, the user will be prompted to set a new Master Password according to the password complexity requirements set by the role enforcement policy in the Keeper Admin Console.  If Two-Factor Authentication is required, the user will also be prompted to activate 2FA prior to accessing vault data.

The "push.json" file is structured an an array of password objects.  For example:

```
[
    {
        "title": "Google For ${user_name}",
        "login": "${user_email}",
        "password": "${generate_password}",
        "login_url": "https://google.com",
        "notes": "",
        "custom_fields": {
            "2FA Phone": "916-555-1212"
        }
    },
    {
        "title": "Development Server",
        "login": "${user_email}",
        "password": "${generate_password}",
        "login_url": "",
        "notes": "Here are some\nMulti-line\nNotes",
        "custom_fields": {
        }
    }
]
```

Supported template parameters:

```
${user_email}          User email address
${generate_password}   Generate random password
${user_name}           User full name
```

### Password Retrieval API

A common use case for Commander is pulling credentials from the vault to replace hard-coded passwords, and to automate processes within CI/CD pipelines.  The recommended architecture is to isolate vault access to specific "service account" vaults in order to limit access.  Follow the process below:

1. Create a separate "service account" vault for each set of records that the service needs access to.

2. Set a strong Master Password, 2FA and role enforcement policy on each vault.

3. Share records (either direct share or shared folder) from the source vault to the service account vault.

Once configured, you can simply authenticate to Commander using the service accounts. By isolating the vaults to only contain a set of shared records, you will be limiting the exposure if the process or server becomes compromised.  Note that a unique and valid email address must be used for each service account.

#### Command-line Password Retrieval

The `get` command allows you to query a stored Keeper password by record UID.  For example:

```bash
$ keeper --user=<Keeper Email> get --format=password <Record UID>
```
The password retrieved is written to standard output. 

In this case, you will be asked for the Keeper Master Password. There are a few ways to provide Commander with the Master Password. All of these methods make the Keeper Master Password accessible on the filesystem and should be used with caution:

1. `--password` parameter. i.e. `keeper --user=<Keeper Email> --password=<Keeper Password>`. 

2. `KEEPER_PASSWORD` environment variable. i.e. `KEEPER_PASSWORD=<Keeper Password> keeper --user<Keeper Email>`. This method is demonstrated in the Jenkins script explained below.

3. Stored to `config.json` file. Commander searches for file named `config.json` in the current working directory and uses the ```password``` parameter.

```json
{
  "user": "<Keeper Email>",
  "password": "<Keeper Master Password>"
}
``` 

### Jenkins CI Integration

This example demonstrates retrieving a password in Keeper for use in the Jenkins CI environment.

1. Create a Python virtual environment in the jenkins user home directory and install keepercommander package with pip:
 
```sh
jenkins@jenkins:~$ python3 -m venv keeper
jenkins@jenkins:~/$ cd keeper
jenkins@jenkins:~/$ . bin/activate
(keeper)jenkins@jenkins:~/keeper$ pip install keepercommander
```

2. Login to Commander with the account you are planning to use with Jenkins. Authenticate with Keeper Commander on the command-line in order to provide a two-factor code if the account has 2FA protection enabled.

```sh
(keeper)jenkins@jenkins:~/keeper$ keeper --user=jenkins@mycompany.com -- shell
My Vault> q
```

3. Add the Keeper user account to Jenkins Credentials configuration:

- Credential Kind: Username with password
- Username: `jenkins@mycompany.com`
- Password: [Password]
- ID: `Keeper`

```groovy
node {
    environment {
        PASSWORD=''     // define environment variable
    }
   stage('Load') {
       // change working directory to keeper venv
       dir("/var/jenkins_home/keeper") {      
           // load Keeper credentials into environmenmt variables. Commander uses KEEPER_PASSWORD variable if set 
           withCredentials([usernamePassword(credentialsId: 'Keeper', usernameVariable: 'KEEPER_USERNAME', passwordVariable: 'KEEPER_PASSWORD')]) {
                    // retrieve the password 
                   env.PASSWORD = sh(script: ". bin/activate; keeper --user=${KEEPER_USERNAME} get --format=password <Record UID>", returnStdout: true).trim()
            }
       }
   }
   stage('Run') {
       echo "${env.PASSWORD}"
   }
}
```

In this example, replace the Record UID with the actual UID from the Keeper vault. To locate the Record UID see [this section](#locating-the-record-uid-and-other-identifiers).


### Launching and Connecting to Remote Servers 

Using the ```connect``` command, Keeper Commander can launch SSH, RDP or other external connections utilizing content and metadata stored in the Keeper vault record.  Command-line parameters are supplied through custom fields and file attachments. This command is very flexible and can be totally customized to use any 3rd party application or utility for performing the remote connections.

The ```connect``` command reads the record's custom fields with names starting with "connect:".

Below is a simple example of SSH to a remote server via SSH tunnel gateway.

#### SSH Launcher Example: SSH to a server via Gateway

In this example, we are showing how to connect to a server through a SSH gateway. The following fields are set:

Custom Field Name       | Custom Field Value             
----------------------- | ------------------------------
connect:xxx:description | Production Server via Gateway 
connect:xxx             | ssh -o "ProxyCommand ssh -i ${file:gateway.pem} ec2-user@gateway -W %h:%p" -i ${file:server.pem} ec2-user@server 
File Attachment         | gateway.pem
File Attachment         | server.pem

```xxx``` refers to the friendly name which can be referenced when connecting on the command line. In this example we have "my_server".

Here's a screenshot of the Keeper Vault record for this example:
![](https://raw.githubusercontent.com/Keeper-Security/Commander/master/keepercommander/images/connect_ssh_screenshot.png)

To connect to this server, simply run the below command:

```
My Vault> connect my_server
Connecting to my_server...

Last login: Sat Sep 28 00:25:34 2019 from 12.23.34.5
ec2-user@my_server:~$ 
ec2-user@my_server:~$ logout
Connection to my_server closed.
My Vault>                                                                                           
```

If the SSH private key is encrypted with a passphrase, you will be prompted every time to type in the passphrase.  To avoid this, we recommend using the SSH Agent variation described in the next section.

#### SSH connection using SSH Agent capabilities

Commander can integrate with the local SSH agent to register RSA private keys. This eliminates the need for you to type in the SSH passphrase every time you connect to the remote system. Commander uses the `SSH_AUTH_SOCK` environment variable on Mac OS / Linux systems. The PowerShell OpenSSH implementation is supported on Windows systems.

To enable integration with ssh-agent ensure that `SSH_AUTH_SOCK` environment variable is set on Posix compatible systems. For Microsoft Windows, ensure the `SSH Agent` system service is running. Keeper's ```connect``` command uses SSH Agent to temporarily store the private key used in the connection session.  After the session disconnects, the private key is removed.

To utilize SSH Agent for connecting to a remote system, simply add one additional custom field to the Vault record:

Custom Field Name       | Custom Field Value             
----------------------- | ------------------------------
connect:xxx:ssh-key:yyy | ${<custom field name with private key>} ${password}

or

Custom Field Name       | Custom Field Value             
----------------------- | ------------------------------
connect:xxx:ssh-key:yyy | {<custom field with private key>} ${password}

Here, ```xxx``` is the friendly name of the connection.  ```yyy``` is an optional key name used with the SSH agent.

In this example, the first parameter references the private key, the second parameter references the passphase used to encrypt the private key.

```${password}``` references the value stored in the record's Password field 

Here's a screenshot of a Keeper Vault record where the private key is stored in a custom field:

![](https://raw.githubusercontent.com/Keeper-Security/Commander/master/keepercommander/images/connect_ssh_screenshot2.png)

Here's a screenshot of a Keeper Vault record where the private key is stored in a file attachment:

![](https://raw.githubusercontent.com/Keeper-Security/Commander/master/keepercommander/images/connect_ssh_screenshot3.png)

Connecting to the remote system using an encrypted passphrase is easy. In our example, to connect to the server called "example2":

```
My Vault> connect example2
Connecting to example2...

Last login: Sat Sep 28 00:25:34 2019 from 12.23.34.5
craig@example2:~$ 
craig@example2:~$ logout
Connection to example2 closed.
My Vault>                                                                                           
```

#### Postgres connection using environment variables capabilities

Commander can set environment variables for the `connect` application.

Custom Field Name          | Custom Field Value             
-------------------------- | ------------------------------
connect:xxx:env:PGPASSWORD | ${password}

Here, ```xxx``` is the friendly name of the connection.  

```${password}``` references the value stored in the record's Password field 

Here's a screenshot of a Keeper Vault record:

![](https://raw.githubusercontent.com/Keeper-Security/Commander/master/keepercommander/images/connect_postgres_screenshot.png)


#### Combining SSH Key Rotation with Connection

Utilizing the sshkey rotation plugin, Commander can also rotate the SSH private/public key pair.

The same vault record can be created that provides connection capability as well as SSH key rotation.  Here's a screenshot of a vault record that is configured for both connection and key rotation:

![](https://raw.githubusercontent.com/Keeper-Security/Commander/master/keepercommander/images/connect_ssh_screenshot5.png)

To rotate the password from the Commander interface, simply use the 'rotate' command:

```
My Vault> rotate example2                                                                  
Rotating with plugin sshkey
Update record successful for record_uid=2TlvQqNe7YSF9idGQ
Rotation successful for record_uid=2TlvQqNe7YSF9idGQ

My Vault>                                                                                           
```

Note: The 'rotate' command accepts either Record UID or friendly name (specified with the ```cmdr:plugin:xxx``` custom field where xxx is the friendly name)

Below is a summary of the fields required to perform connection and rotation:

Name                  | Field         | Comments
--------------------- | ------------- | ------------
Login                 | Login         | Set to the username, e.g. **'ec2-user'** in the **'Login'** field. 
Password              | Password      | Set to the passphrase to encrypt the SSH key in the **'Password'** field
cmdr:plugin:xxx       | Custom        | ```sshkey``` "xxx" is the friendly name which can be referenced in command line 'rotate' and 'connect' calls.
cmdr:host             | Custom        | (Optional, Multiple) Set to hostname or IP address of target server
cmdr:rules            | Custom        | (Optional) [passphrase complexity rules](https://github.com/Keeper-Security/Commander/tree/master/keepercommander/plugins/password_rules.md)
connect:xxx:ssh-key   | Custom        | ```${cmdr:private_key} ${password}``` where "xxx" is the friendly name
connect:xxx           | Custom        | ```ssh ${login}@${cmdr:host}``` for a basic SSH connection but can be customized
cmdr:ssh_public_key   | Custom        | Public key in SSH format. This key is uploaded to the target system.
cmdr:rsa_public_key   | Custom        | Public key in RSA format.
cmdr:private_key      | Custom        | Private key encrypted with the passkey stored in the **'Password'** field.

Important: Please read the [SSH Key Rotation Doc](https://github.com/Keeper-Security/Commander/tree/master/keepercommander/plugins/sshkey) on how to perform the initial setup of SSH keys in the vault record. Once set up the first time, all connection and rotations will be seamless.

#### Remote Desktop (RDP) Launcher Example

To connect seamlessly to a remote windows server using the standard Microsoft Remote Desktop application, Keeper executes a command pre-login, login, and post-login via system calls.  In this example, the "pre-login" command stores the password temporarily in the Windows credential manager for the current user.  The "login" command initiates the connection using an RDP template file and the stored credentials (the RDP template file is optional).  Upon session termination, the "post login" command is executed that deletes the password from the credential manager.

Vault Record Fields:

Custom Field Name                  | Custom Field Value
---------------------------------- | ----------------------------------
connect:rdp_demo:description       | Remote connection to Demo Server 
connect:rdp_demo:pre               | cmdkey /generic:12.34.56.78 /user:${login} /pass:${password} > NUL 
connect:rdp_demo                   | mstsc ${file:Default.rdp} 
connect:rdp_demo:post              | cmdkey /delete:12.34.56.78 > NUL
File Attachment                    | Default.rdp

Screenshot of Keeper Vault record:
![](https://raw.githubusercontent.com/Keeper-Security/Commander/master/keepercommander/images/connect_rdp_screenshot.png)

Note: The Default.rdp file is saved from Remote Desktop Connection with your desired configuration.

#### Supported parameter substitutions

You can customize the commands with parameter substitutions described below:

```
${user_email}: Email address of Keeper user 
${login}: Record login field
${password}: Record password field
${text:<name>}: Custom per-user variable, prompted for value, not shared 
${mask:<name>}: Custom per-user variable, prompted for value, not shared 
${file:<attachment_name>}: Stored in temp file during use and deleted after connection close,
${body:<attachment_name>}: Raw content of the attachment file.
```

#### Listing all available connections

To get a list of available connections, type:

```
My Vault> connect
```
 
#### Initiating connections

To initiate a connection (using the SSH/RDP examples) from Commander simply type:

```
My Vault> connect my_server
```

or

```
My Vault> connect rdp_demo
```

Alternatively, you can execute the connection from the terminal without the interactive shell:

```
$ keeper connect my_server
```

Notes:

- A single vault record can contain any number of connection references, or the connections can be separated one per record.
- If a system command requires user interaction (e.g. if a passphrase is included on an SSH key file), Commander will prompt for input.
- Just like any other Keeper vault record, a connection record can be shared among a team, shared to another Keeper user or remain private.


### Environmental Variables 

Custom environmental variables can be created on the command line and through batch script files in order to perform data substitutions.

A few default variables can be used:

```
${last_folder_uid} - This contains the last added Folder UID
${last_record_uid} - This contains the last added Record UID
${last_shared_folder_uid} - This contains the last added Shared Folder UID
```

To add a new environmental variable, use the "set" command:

```
My Vault> set my_test foo
```

To use this variable, use ${my_test} 

The below example will add a record and then share the record with a user:

```
My Vault> add --login "testing123" --pass "12345" --url "https://google.com" "Test from Commander" -f
My Vault> share-record -e another_user@company.com -a grant -w ${last_record_uid}
```

### Targeted Password Rotations & Plugins 

Keeper Commander can communicate to internal and external systems for the purpose of rotating a password and synchronizing the change to your Keeper Vault.  We accomplish this by associating a Keeper record with a physical system through the use of custom fields.  For example, you might want to rotate your MySQL password, Active Directory password and local Administrator password automatically.  To support a plugin, simply add a set of **custom field** values to the Keeper record. The custom field values tell Commander which plugin to use, and what system to communicate with when rotating the password.  To modify your Keeper record to include custom fields, login to Keeper on the [Web Vault](https://keepersecurity.com/vault) or [Keeper Desktop](https://keepersecurity.com/download.html) app.  

Example custom fields for MySQL password rotation:

Custom Field Name     | Custom Field Value
----------------------| ----------------------------------
cmdr:plugin           | mysql
cmdr:host             | 192.168.1.55
cmdr:db               | testing

When a plugin is specified in a record, Commander will search in the plugins/ folder to load the module based on the name provided (e.g. mysql.py) then it will use the values of the Keeper record to connect, rotate the password and save the resulting data.

Check out the [plugins folder](https://github.com/Keeper-Security/Commander/tree/master/keepercommander/plugins) for all of the available plugins.  Keeper's team adds new plugins on an ongoing basis. If you need a particular plugin created, send us an email to commander@keepersecurity.com.

### Locating the Record UID and other Identifiers 

The Record UID and Shared Folder UID can be found either through the "get", "list", "ls -l" or "search" commands, or through the Web Vault user interface.

![](https://raw.githubusercontent.com/Keeper-Security/Commander/master/keepercommander/images/record_uid.png)

![](https://raw.githubusercontent.com/Keeper-Security/Commander/master/keepercommander/images/shared_folder_uid.png)

### Deep linking to records (Web Vault Hyperlink)

The Record UID that is displayed on password record output can be used for deep linking directly into the Keeper Web Vault only for privileged users. This Vault link can be stored and sent over unsecure channels because it only provides a reference to the record within your vault -- it does not provide access to the actual record content.  To access the content, you must still authenticate into the vault and decrypt the data.  The link is in the format `https://keepersecurity.com/vault#detail/XXXXXX` and you simply replace XXXXXX with the Record UID. Providing this link to another user does NOT initiate sharing.  To share a vault record, you must authenticate to your vault, open the record and click the "Share" feature.

### About Our Security

Keeper is a zero-knowledge platform.  This means that the server does not have access to your Keeper Master Password or the crypto keys used to encrypt and decrypt your data.  The cryptography is performed on the *client device* (e.g. iPhone, Android, Desktop, Commander).

When you create a Keeper account from our [web app](https://keepersecurity.com/vault) or [mobile/desktop app](https://keepersecurity.com/download), you are asked to create a Master Password and a security question.  The Keeper app creates your crypto keys, RSA keys and encryption parameters (iv, salt, iterations).  Your RSA private key is encrypted with your data key, and your data key is encrypted with your Master Password.  The encrypted version of your data key is stored in Keeper's Cloud Security Vault and provided to you after successful device authentication.

When you login to Keeper on any device (or on Commander), your Master Password is used to derive a 256-bit PBKDF2 key.  This key is used to decrypt your data key.  The data key is used to decrypt individual record keys, shared folder keys and team keys.  Record keys, shared folder keys and team keys are then used to decrypt each individual record in the vault.

When storing information to your vault, Keeper stores and synchronizes the encrypted data.

We strongly recommend that you enable Two-Factor Authentication on your Keeper account via the [web app](https://keepersecurity.com/vault) settings screen.  This can also be enforced at the Keeper Enterprise level. When logging into Commander with Two-Factor Authentication turned on, you will be asked for a one-time passcode.  After successful authentication, Commander receives a device token that can be used for subsequent requests without another two-factor auth request.

For more details on Keeper's security architecture, certifications and implementation details, visit the [Security Disclosure](https://keepersecurity.com/security.html) page of our website. If you have any specific questions related to security, email security@keepersecurity.com.

### Vulnerability Disclosure Program

Keeper has partnered with Bugcrowd to manage our vulnerability disclosure program. Please submit reports through https://bugcrowd.com/keepersecurity or send an email to security@keepersecurity.com.

### Troubleshooting 

**SSL Certificate Errors**

When running Commander or related Keeper SDK code, if you receive SSL certificate errors such as:

```bash
requests.exceptions.SSLError: HTTPSConnectionPool(host='keepersecurity.com', port=443): Max retries exceeded with url: /api/rest/authentication/get_device_token (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1108)')))
```

If you receive this message, please make sure that your network is not attempting to do packet inspection with a proxy.  Due to our advanced encryption, Keeper traffic cannot be intercepted by a network proxy device.  Consult with your IT team to allow traffic to keepersecurity.com on the firewall outbound.

### About Keeper

Keeper is the world's most downloaded password keeper and secure digital vault for protecting and managing your passwords and other secret information.  Millions of people and companies use Keeper to protect their most sensitive and private information.

Keeper's Features &amp; Benefits

* Manages all your passwords and secret info
* Protects you against hackers
* Encrypts everything in your vault 
* High-strength password generator
* Login to websites with one click
* Store private files, photos and videos
* Take private photos inside vault 
* Share records with other Keeper users
* Access on all your devices and computers
* Keeper DNA&trade; multi-factor authentication
* Login with Fingerprint or Touch ID
* Auto logout timer for theft prevention
* Unlimited backups
* Self-destruct protection
* Customizable fields
* Background themes
* Integrated Apple Watch App
* Instant syncing between devices
* AES-256 encryption
* Zero-Knowledge security architecture
* SOC-2 and ISO 27001 Certified
* GDPR Compliant 

### Keeper Website
[https://keepersecurity.com](https://keepersecurity.com)

### Pricing
Keeper is free for local password management on your device.  Premium subscriptions provides cloud-based capabilites including multi-device sync, shared folders, teams, SSO integration and encrypted file storage. More info about our enterprise pricing plans can be found [here](https://keepersecurity.com/pricing.html?tab=business).

### Mobile Apps

[iOS - iPhone, iPad, iPod](https://itunes.apple.com/us/app/keeper-password-manager-digital/id287170072?mt=8)

[Android - Google Play](https://play.google.com/store/apps/details?id=com.callpod.android_apps.keeper&hl=en)

[Kindle and Amazon App Store](http://amzn.com/B00NUK3F6S)

### Cross-Platform Desktop App

[Windows PC, 64-bit and 32-bit Recommended Installer](https://www.keepersecurity.com/desktop_electron/packages/KeeperPasswordManager.appinstaller)

[Windows PC, 32-bit](https://keepersecurity.com/desktop_electron/Win32/KeeperSetup32.zip)

[Windows PC, 64-bit](https://keepersecurity.com/desktop_electron/Win64/KeeperSetup64.zip)

[Windows PC, 32-bit MSI Installer](https://keepersecurity.com/desktop_electron/Win32/KeeperSetup32.msi)

[Mac](https://keepersecurity.com/desktop_electron/Darwin/KeeperSetup.dmg)

[Linux](https://keepersecurity.com/download.html)

### Web Vault and Browser Extensions

[Web App - Online Vault](https://keepersecurity.com/vault)

[KeeperFill for Chrome](https://chrome.google.com/webstore/detail/keeper-browser-extension/bfogiafebfohielmmehodmfbbebbbpei)

[KeeperFill for Firefox](https://addons.mozilla.org/en-US/firefox/addon/keeper-password-manager-digita/)

[KeeperFill for Safari](https://keepersecurity.com/download.html)

[KeeperFill for Edge](https://www.microsoft.com/en-us/store/p/keeper-password-manager-digital-vault/9n0mnnslfz1t)

### Enterprise Resources

[Enterprise Admin Console](https://keepersecurity.com/console)

[Enterprise Guide](https://docs.keeper.io/enterprise-guide/)

### Sales & Support 

[White Papers & Data Sheets](https://keepersecurity.com/enterprise-resources.html)

[Contact Sales or Support](https://keepersecurity.com/contact.html)

We're here to help.  If you need help integrating Keeper into your environment, contact us at commander@keepersecurity.com.

### Build Binary Package

Commander can be bundled with [PyInstaller](https://pyinstaller.readthedocs.io/en/stable/) as a single package.
There are two PyInstaller configuration files `keeper_folder.spec` and `keeper_file.spec` that build
["One-Folder"](https://pyinstaller.readthedocs.io/en/stable/operating-mode.html#how-the-one-folder-program-works) and 
["One-File"](https://pyinstaller.readthedocs.io/en/stable/operating-mode.html#how-the-one-file-program-works) packages accordingly.
To build a binary package:
```shell script
# create Python environment
python -m venv installer

# activate environment
. installer/bin/activate
cd Commander

# install base Commander packages
pip install -r requirements.txt

# install optional packages 
pip install -r extra_dependencies.txt

# build one-folder package
pyinstaller keeper-folder.spec

# or build one-file package
pyinstaller keeper-file.spec

# your packages are in dist/ folder
``` 
