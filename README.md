![Keeper Commander Header](https://github.com/user-attachments/assets/a690bcd6-95b2-4792-b17a-8ff1389c2b27)

![Keeper Commander](https://raw.githubusercontent.com/Keeper-Security/Commander/master/images/commander-black.png)

### About Keeper Commander
Keeper Commander is a command-line and terminal UI interface to Keeper® Password Manager and KeeperPAM. Commander can be used to access and control your Keeper vault, perform administrative actions (managing users, teams, roles, SSO, privileged access resources, device approvals, data import/export), launch sessions, rotate passwords, integrate with developer tools, eliminate hardcoded passwords, run as a REST service and more. Keeper Commander is an open source project with contributions from Keeper's engineering team, customers and partners.

### Windows, macOS and Linux Binaries

**Install script** (per-user, no administrator rights needed)

macOS and Linux (x86_64 and arm64):
```
curl -fsSL https://github.com/Keeper-Security/Commander/releases/latest/download/install.sh | bash
```

Windows (PowerShell):
```
irm https://github.com/Keeper-Security/Commander/releases/latest/download/install.ps1 | iex
```

The script downloads the build for your platform from the latest release, verifies its SHA-256 checksum and installs it next to any earlier version. It does not need `sudo`.

| | macOS / Linux | Windows |
|---|---|---|
| Install location | `~/.local/share/keeper-commander` | `%LOCALAPPDATA%\keeper-commander` |
| Command | `~/.local/bin/keeper` (add `~/.local/bin` to `PATH` if the script tells you to) | `keeper` (the folder is added to your user `PATH`; open a new terminal) |

Linux builds need glibc. Alpine and other musl-based systems are not supported; use `pip` or the Docker image there.

**Update**

Run `update` inside Commander (or `keeper update`) to check for and install a newer version. When you close an interactive shell and a new version is available, Commander asks once per version whether to update now. Set `KEEPER_NO_UPDATE_PROMPT=1` to turn the question off. Running the install command again also updates. The previous version is kept so you can go back to it.

If Commander was installed another way (installer, Homebrew, pip, Docker), `update` shows the right update instructions for that method.

**Uninstall**

macOS and Linux:
```
curl -fsSL https://github.com/Keeper-Security/Commander/releases/latest/download/install.sh | bash -s -- --uninstall
```

Windows (PowerShell):
```
$env:KEEPER_COMMANDER_UNINSTALL='1'; irm https://github.com/Keeper-Security/Commander/releases/latest/download/install.ps1 | iex
```

This removes the program only. Your configuration and data in `~/.keeper` are kept.

**Options** (environment variables, or flags on macOS/Linux)

| Setting | Meaning |
|---|---|
| `--prefix DIR` / `KEEPER_COMMANDER_HOME` | install folder |
| `--bin-dir DIR` / `KEEPER_COMMANDER_BIN` (macOS/Linux) | where the `keeper` link is created |
| `--meta-url URL` / `KEEPER_COMMANDER_META_URL` | install from a specific release, for example `https://github.com/Keeper-Security/Commander/releases/download/v18.1.10/keeper-commander.meta` |

Use the same `--prefix` and `--bin-dir` when uninstalling a custom install.

**Installers and other options**

Windows and macOS installer packages (`.exe`, `.pkg`) are available on the [Releases](https://github.com/Keeper-Security/Commander/releases) page.

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

