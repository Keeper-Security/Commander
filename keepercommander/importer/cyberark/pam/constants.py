#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander — CyberArk PAM import (split module)

from typing import Dict, Tuple

# Valid CyberArk logon types for self-hosted PVWA (case-insensitive check)
VALID_LOGON_TYPES = {"cyberark", "ldap", "radius", "windows"}

# System safes excluded from migration by default.
# These are internal CyberArk safes that do not contain user-managed accounts.
# Override with --include-system-safes flag.
SYSTEM_SAFES = {
    "System", "VaultInternal", "Notification Engine", "SharedAuth_Internal",
    "PVWAUserPrefs", "PVWAConfig", "PVWAReports", "PVWATaskDefinitions",
    "PVWAPrivateUserPrefs", "PVWAPublicData", "PVWATicketingSystem",
    "AccountsFeed", "PSM", "xRay", "PIMSuRecordings", "xRay_Config",
    "AccountsFeedAcc", "PasswordManager_Pending", "PasswordManagerShared",
    "PasswordManager_workspace", "PasswordManager_ADInternal",
    # Additional system safes found in real environments
    "PasswordManager", "SCIM Config", "PSMSessions", "PSMUnmanagedSessionAccounts",
    "PSMLiveSessions", "PSMNotifications", "PSMRecordings",
}

# Maximum safe name length for Keeper shared folder names
MAX_SAFE_NAME_LENGTH = 28

# Maximum total records per fetch operation (prevent OOM from malicious API)
MAX_FETCH_RECORDS = 50000

# Default CyberArk platformId → KeeperPAM record mapping
DEFAULT_PLATFORM_MAP = {
    # NIX
    "UnixSSH":         {"record_type": "pamMachine", "rotation": "general", "protocol": "ssh",        "port": "22"},
    "UnixSSHKey":      {"record_type": "pamMachine", "rotation": "general", "protocol": "ssh",        "port": "22"},
    "UnixSSHKeys":     {"record_type": "pamMachine", "rotation": "general", "protocol": "ssh",        "port": "22"},
    # Windows
    "WinDomain":       {"record_type": "pamMachine", "rotation": "general", "protocol": "rdp",        "port": "3389"},
    "WinLocalAccount": {"record_type": "pamMachine", "rotation": "general", "protocol": "rdp",        "port": "3389"},
    "WinServerLocal":  {"record_type": "pamMachine", "rotation": "general", "protocol": "rdp",        "port": "3389"},
    "WinDesktopLocal": {"record_type": "pamMachine", "rotation": "general", "protocol": "rdp",        "port": "3389"},
    # Database
    # NOTE on protocol vs database_type:
    #   - pam_settings.connection.protocol accepts ONLY {sql-server,postgresql,mysql}.
    #     Anything else (oracle, mongodb, mssql, ...) is rejected by Keeper and the
    #     entire pam_settings.connection block gets dropped with a warning
    #     ("Connection skipped: unknown protocol ...").
    #   - resource.database_type accepts the broader set
    #     {postgresql,postgresql-flexible,mysql,mysql-flexible,mariadb,
    #      mariadb-flexible,mssql,oracle,mongodb}.
    # For DBs that have no Keeper connection protocol (Oracle, MongoDB) we set
    # protocol=None so account_mapper skips the connection block entirely while
    # still tagging the record with the correct database_type.
    "Oracle":          {"record_type": "pamDatabase", "rotation": "general", "protocol": "sql-server", "port": "1521", "database_type": "oracle"},
    "MySQL":           {"record_type": "pamDatabase", "rotation": "general", "protocol": "mysql",      "port": "3306", "database_type": "mysql"},
    "MSSql":           {"record_type": "pamDatabase", "rotation": "general", "protocol": "sql-server", "port": "1433", "database_type": "mssql"},
    "PostgreSQL":      {"record_type": "pamDatabase", "rotation": "general", "protocol": "postgresql", "port": "5432", "database_type": "postgresql"},
    # Network devices — SSH-managed
    "PaloAltoNetworks":    {"record_type": "pamMachine", "rotation": "general", "protocol": "ssh",    "port": "22"},
    "CiscoIOS":            {"record_type": "pamMachine", "rotation": "general", "protocol": "ssh",    "port": "22"},
    "CiscoIOSEnable":      {"record_type": "pamMachine", "rotation": "general", "protocol": "ssh",    "port": "22"},
    "CiscoASA":            {"record_type": "pamMachine", "rotation": "general", "protocol": "ssh",    "port": "22"},
    "JuniperJunos":        {"record_type": "pamMachine", "rotation": "general", "protocol": "ssh",    "port": "22"},
    "F5BigIP":             {"record_type": "pamMachine", "rotation": "general", "protocol": "ssh",    "port": "22"},
    "CheckPointGAIA":      {"record_type": "pamMachine", "rotation": "general", "protocol": "ssh",    "port": "22"},
    # CyberArk internal — service accounts, import as pamMachine/SSH
    "CyberArk":            {"record_type": "pamMachine", "rotation": "general", "protocol": "ssh",    "port": "22"},
    # Web — login record, NOT pamMachine
    "BusinessWebsite": {"record_type": "login", "rotation": None, "protocol": None, "port": None},
}

# Fallback mapping for accounts with empty or unknown platformId
FALLBACK_PLATFORM_MAP = {"record_type": "pamMachine", "rotation": "general", "protocol": "ssh", "port": "22"}
