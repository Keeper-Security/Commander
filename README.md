![Keeper Commander Header](https://github.com/user-attachments/assets/a690bcd6-95b2-4792-b17a-8ff1389c2b27)

![Keeper Commander](https://raw.githubusercontent.com/Keeper-Security/Commander/master/images/commander-black.png)

### About Keeper Commander
Keeper Commander is a command-line and terminal UI interface to Keeper® Password Manager and KeeperPAM. Commander can be used to access and control your Keeper vault, perform administrative actions (managing users, teams, roles, SSO, privileged access resources, device approvals, data import/export), launch sessions, rotate passwords, integrate with developer tools, eliminate hardcoded passwords, run as a REST service and more. Keeper Commander is an open source project with contributions from Keeper's engineering team, customers and partners.

### Windows and macOS Binaries
See the [Releases](https://github.com/Keeper-Security/Commander/releases)

### Linux / Python using PIP
```
python3 -m venv keeper-env
source keeper-env/bin/activate
pip install keepercommander
```

### Running from Source
```
git clone https://github.com/Keeper-Security/Commander
cd Commander
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -e .
pip install -e '.[email]'
```

### Starting Commander
For a list of all available commands:
```
keeper help
```

To launch the interactive command shell:

```
keeper shell
```

or for a full terminal vault user interface
```
keeper supershell
```

Once logged in, check out the `this-device` command to set up persistent login sessions, logout timer and 2FA frequency. Also check out the `biometric register` command to enable biometric authentication on supported platforms.

### Documentation
- [Commander Documentation Home](https://docs.keeper.io/en/keeperpam/commander-cli/overview)
- [Installation](https://docs.keeper.io/en/keeperpam/commander-cli/commander-installation-setup)
- [Full Command Reference](https://docs.keeper.io/en/keeperpam/commander-cli/command-reference)
- [Service Mode REST API](https://docs.keeper.io/en/keeperpam/commander-cli/service-mode-rest-api)
- [Commander SDK](https://docs.keeper.io/en/keeperpam/commander-sdk/keeper-commander-sdks)
- [All Keeper Documentation](https://docs.keeper.io/)

### About Keeper Security
Keeper Security is the creator of KeeperPAM - the zero-trust and zero-knowledge privileged access management ("PAM") platform for securing and managing access to your critical infrastructure.
- [Keeper Security Homepage](https://keepersecurity.com)
- [Privileged Access Management](https://www.keepersecurity.com/privileged-access-management/)
- [Endpoint Privilege Manager](https://www.keepersecurity.com/endpoint-privilege-management/)
- [Encryption and Security Model](https://docs.keeper.io/en/enterprise-guide/keeper-encryption-model)
- [Downloads](https://www.keepersecurity.com/download.html?t=d)

