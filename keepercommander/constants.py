import enum
import sys
from typing import List, Tuple, Optional
from datetime import timedelta
from urllib.parse import urlparse

ENTERPRISE_FILE_PLANS = [
    (-1, 'NO_STORAGE', 'NO STORAGE'),
    (0, 'STORAGE_TRIAL', 'TRIAL'),
    (1, 'STORAGE_1GB', '1GB'),
    (2, 'STORAGE_10GB', '10GB'),
    (3, 'STORAGE_50GB', '50GB'),
    (4, 'STORAGE_100GB', '100GB'),
    (5, 'STORAGE_250GB', '250GB'),
    (6, 'STORAGE_500GB', '500GB'),
    (7, 'STORAGE_1000GB', '1TB'),
    (8, 'STORAGE_10000GB', '10TB'),
]

MSP_FILE_PLANS = [
    (4, 'STORAGE_100GB', '100GB'),
    (7, 'STORAGE_1000GB', '1TB'),
    (8, 'STORAGE_10000GB', '10TB'),
]

MSP_PLANS = [
    (1, 'business', 'Business', 4),
    (2, 'businessPlus', 'Business Plus', 7),
    (3, 'businessStarter', 'Business Starter', 0),
    (10, 'enterprise', 'Enterprise', 4),
    (11, 'enterprisePlus', 'Enterprise Plus', 7),
]

MSP_ADDONS = [
    ('chat', 'KeeperChat', False, 'Chat'),
    ('enterprise_audit_and_reporting', 'Advanced Reporting & Alerts Module', False, 'ARAM'),
    ('professional_services_silver_add_on', 'Professional Services & Support Silver Plan', False, 'Silver Support'),
    ('gold_professional_services_add_on', 'Professional Services & Support Gold Plan', False, 'Gold Support'),
    ('platinum_professional_services_add_on', 'Professional Services & Support Platinum Plan', False, 'Platinum Support'),
    ('msp_service_and_support', 'MSP Dedicated Service & Support', False, 'MSP Support'),
    ('consumer_breach_watch', 'Consumer BreachWatch', False, 'Consumer BW'),
    ('enterprise_breach_watch', 'Enterprise BreachWatch', False, 'Enterprise BW'),
    ('compliance_report', 'Compliance Reporting', False, 'Compliance'),
    ('secrets_manager', 'Keeper Secrets Manager (KSM)', False, 'KSM'),
    ('connection_manager', 'Keeper Connection Manager (KCM)', True, 'KCM'),
    ('password_rotation', 'Password Rotation', False, 'Rotation'),
    ('remote_browser_isolation', 'Remote Browser Isolation', False, 'Browser Isolation'),
    ('privileged_access_manager', 'Privileged Access Manager (PAM)', True, 'PAM'),
]


class PrivilegeScope(enum.IntEnum):
    All = 1,
    MSP = 2,
    Hidden = 3,


# Managed Role privileges
ROLE_PRIVILEGES = [
    ('Manage Nodes', 'MANAGE_NODES', PrivilegeScope.All),
    ('Manage Users', 'MANAGE_USER', PrivilegeScope.All),
    ('Manage Licences', 'MANAGE_LICENCES', PrivilegeScope.Hidden),
    ('Manage Roles', 'MANAGE_ROLES', PrivilegeScope.All),
    ('Manage Teams', 'MANAGE_TEAMS', PrivilegeScope.All),
    ('Run Security Reports', 'RUN_REPORTS', PrivilegeScope.All),
    ('Manage Bridge/SSO', 'MANAGE_BRIDGE', PrivilegeScope.All),
    ('Perform Device Approvals', 'APPROVE_DEVICE', PrivilegeScope.All),
    ('Manage Record Types in Vault', 'MANAGE_RECORD_TYPES', PrivilegeScope.All),
    ('Run Compliance Reports', 'RUN_COMPLIANCE_REPORTS', PrivilegeScope.All),
    ('Manage Companies', 'MANAGE_COMPANIES', PrivilegeScope.MSP),
    ('Transfer Account', 'TRANSFER_ACCOUNT', PrivilegeScope.All),
    ('Sharing Administrator', 'SHARING_ADMINISTRATOR', PrivilegeScope.All),
]

# Timeout constants
# Set to default value by using timedelta of 0
TIMEOUT_DEFAULT = timedelta(0)
TIMEOUT_MIN = timedelta(minutes=1)
TIMEOUT_DEFAULT_UNIT = 'minutes'
TIMEOUT_ALLOWED_UNITS = (
    ('years', 'y'),
    ('months', 'mo'),
    ('days', 'd'),
    ('hours', 'h'),
    ('minutes', 'mi')
)

EMAIL_PATTERN = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"

# Enforcement constants

_ENFORCEMENT_GROUPS = [
    "LOGIN_SETTINGS",
    "TWO_FACTOR_AUTHENTICATION",
    "PLATFORM_RESTRICTION",
    "VAULT_FEATURES",
    "RECORD_TYPES",
    "SHARING_AND_UPLOADING",
    "CREATING_AND_SHARING",
    "KEEPER_FILL",
    "ACCOUNT_SETTINGS",
    "ALLOW_IP_LIST",
]

_ENFORCEMENTS = [
    ("MASTER_PASSWORD_MINIMUM_LENGTH", 10, "LONG", "LOGIN_SETTINGS"),
    ("MASTER_PASSWORD_MINIMUM_SPECIAL", 11, "LONG", "LOGIN_SETTINGS"),
    ("MASTER_PASSWORD_MINIMUM_UPPER", 12, "LONG", "LOGIN_SETTINGS"),
    ("MASTER_PASSWORD_MINIMUM_LOWER", 13, "LONG", "LOGIN_SETTINGS"),
    ("MASTER_PASSWORD_MINIMUM_DIGITS", 14, "LONG", "LOGIN_SETTINGS"),
    ("MASTER_PASSWORD_RESTRICT_DAYS_BEFORE_REUSE", 16, "LONG", "LOGIN_SETTINGS"),
    ("REQUIRE_TWO_FACTOR", 20, "BOOLEAN", "TWO_FACTOR_AUTHENTICATION"),
    ("MASTER_PASSWORD_MAXIMUM_DAYS_BEFORE_CHANGE", 22, "LONG", "LOGIN_SETTINGS"),
    ("MASTER_PASSWORD_EXPIRED_AS_OF", 23, "LONG", "LOGIN_SETTINGS"),
    ("MINIMUM_PBKDF2_ITERATIONS", 55, "LONG", "ACCOUNT_SETTINGS"),
    ("MAX_SESSION_LOGIN_TIME", 24, "LONG", "ACCOUNT_SETTINGS"),
    ("RESTRICT_PERSISTENT_LOGIN", 25, "BOOLEAN", "ACCOUNT_SETTINGS"),
    ("STAY_LOGGED_IN_DEFAULT", 26, "BOOLEAN", "ACCOUNT_ENFORCEMENTS"),
    ("RESTRICT_SHARING_ALL_OUTGOING", 30, "BOOLEAN", "SHARING_AND_UPLOADING"),
    ("RESTRICT_SHARING_ENTERPRISE_OUTGOING", 31, "BOOLEAN", "SHARING_AND_UPLOADING"),
    ("RESTRICT_EXPORT", 32, "BOOLEAN", "SHARING_AND_UPLOADING"),
    ("RESTRICT_FILE_UPLOAD", 33, "BOOLEAN", "SHARING_AND_UPLOADING"),
    ("REQUIRE_ACCOUNT_SHARE", 34, "ACCOUNT_SHARE", "SHARING_AND_UPLOADING"),
    ("RESTRICT_SHARING_ALL_INCOMING", 36, "BOOLEAN", "SHARING_AND_UPLOADING"),
    ("RESTRICT_SHARING_ENTERPRISE_INCOMING", 37, "BOOLEAN", "SHARING_AND_UPLOADING"),
    ("RESTRICT_IP_ADDRESSES", 40, "IP_WHITELIST", "ALLOW_IP_LIST"),
    ("REQUIRE_DEVICE_APPROVAL", 41, "BOOLEAN", "ACCOUNT_SETTINGS"),
    ("REQUIRE_ACCOUNT_RECOVERY_APPROVAL", 42, "BOOLEAN", "ACCOUNT_SETTINGS"),
    ("RESTRICT_VAULT_IP_ADDRESSES", 43, "IP_WHITELIST", "ALLOW_IP_LIST"),
    ("TIP_ZONE_RESTRICT_ALLOWED_IP_RANGES", 44, "IP_WHITELIST", "ALLOW_IP_LIST"),
    ("AUTOMATIC_BACKUP_EVERY_X_DAYS", 45, "LONG", "ACCOUNT_SETTINGS"),
    ("RESTRICT_OFFLINE_ACCESS", 46, "BOOLEAN", "ACCOUNT_SETTINGS"),
    ("SEND_INVITE_AT_REGISTRATION", 47, "BOOLEAN", "ACCOUNT_SETTINGS"),
    ("RESTRICT_EMAIL_CHANGE", 48, "BOOLEAN", "ACCOUNT_SETTINGS"),
    ("RESTRICT_IOS_FINGERPRINT", 49, "BOOLEAN", "LOGIN_SETTINGS"),
    ("RESTRICT_MAC_FINGERPRINT", 50, "BOOLEAN", "LOGIN_SETTINGS"),
    ("RESTRICT_ANDROID_FINGERPRINT", 51, "BOOLEAN", "LOGIN_SETTINGS"),
    ("LOGOUT_TIMER_WEB", 52, "LONG", "ACCOUNT_SETTINGS"),
    ("LOGOUT_TIMER_MOBILE", 53, "LONG", "ACCOUNT_SETTINGS"),
    ("LOGOUT_TIMER_DESKTOP", 54, "LONG", "ACCOUNT_SETTINGS"),
    ("RESTRICT_WEB_VAULT_ACCESS", 60, "BOOLEAN", "PLATFORM_RESTRICTION"),
    ("RESTRICT_EXTENSIONS_ACCESS", 61, "BOOLEAN", "PLATFORM_RESTRICTION"),
    ("RESTRICT_MOBILE_ACCESS", 62, "BOOLEAN", "PLATFORM_RESTRICTION"),
    ("RESTRICT_DESKTOP_ACCESS", 63, "BOOLEAN", "PLATFORM_RESTRICTION"),
    ("RESTRICT_MOBILE_IOS_ACCESS", 64, "BOOLEAN", "PLATFORM_RESTRICTION"),
    ("RESTRICT_MOBILE_ANDROID_ACCESS", 65, "BOOLEAN", "PLATFORM_RESTRICTION"),
    ("RESTRICT_MOBILE_WINDOWS_PHONE_ACCESS", 66, "BOOLEAN", "PLATFORM_RESTRICTION"),
    ("RESTRICT_DESKTOP_WIN_ACCESS", 67, "BOOLEAN", "PLATFORM_RESTRICTION"),
    ("RESTRICT_DESKTOP_MAC_ACCESS", 68, "BOOLEAN", "PLATFORM_RESTRICTION"),
    ("RESTRICT_CHAT_DESKTOP_ACCESS", 84, "BOOLEAN", "PLATFORM_RESTRICTION"),
    ("RESTRICT_CHAT_MOBILE_ACCESS", 85, "BOOLEAN", "PLATFORM_RESTRICTION"),
    ("RESTRICT_COMMANDER_ACCESS", 88, "BOOLEAN", "PLATFORM_RESTRICTION"),
    ("RESTRICT_TWO_FACTOR_CHANNEL_TEXT", 70, "BOOLEAN", "TWO_FACTOR_AUTHENTICATION"),
    ("RESTRICT_TWO_FACTOR_CHANNEL_GOOGLE", 71, "BOOLEAN", "TWO_FACTOR_AUTHENTICATION"),
    ("RESTRICT_TWO_FACTOR_CHANNEL_DNA", 72, "BOOLEAN", "TWO_FACTOR_AUTHENTICATION"),
    ("RESTRICT_TWO_FACTOR_CHANNEL_DUO", 73, "BOOLEAN", "TWO_FACTOR_AUTHENTICATION"),
    ("RESTRICT_TWO_FACTOR_CHANNEL_RSA", 74, "BOOLEAN", "TWO_FACTOR_AUTHENTICATION"),
    ("TWO_FACTOR_DURATION_WEB", 80, "TWO_FACTOR_DURATION", "TWO_FACTOR_AUTHENTICATION"),
    ("TWO_FACTOR_DURATION_MOBILE", 81, "TWO_FACTOR_DURATION", "TWO_FACTOR_AUTHENTICATION"),
    ("TWO_FACTOR_DURATION_DESKTOP", 82, "TWO_FACTOR_DURATION", "TWO_FACTOR_AUTHENTICATION"),
    ("RESTRICT_WINDOWS_FINGERPRINT", 83, "BOOLEAN", "LOGIN_SETTINGS"),
    ("RESTRICT_TWO_FACTOR_CHANNEL_SECURITY_KEYS", 86, "BOOLEAN", "TWO_FACTOR_AUTHENTICATION"),
    ("TWO_FACTOR_BY_IP", 87, "JSONARRAY"),
    ("RESTRICT_DOMAIN_ACCESS", 90, "STRING", "KEEPER_FILL"),
    ("RESTRICT_DOMAIN_CREATE", 91, "STRING", "KEEPER_FILL"),
    ("RESTRICT_HOVER_LOCKS", 92, "BOOLEAN", "KEEPER_FILL"),
    ("RESTRICT_PROMPT_TO_LOGIN", 93, "BOOLEAN", "KEEPER_FILL"),
    ("RESTRICT_PROMPT_TO_FILL", 94, "BOOLEAN", "KEEPER_FILL"),
    ("RESTRICT_AUTO_SUBMIT", 95, "BOOLEAN", "KEEPER_FILL"),
    ("RESTRICT_PROMPT_TO_SAVE", 96, "BOOLEAN", "KEEPER_FILL"),
    ("RESTRICT_PROMPT_TO_CHANGE", 97, "BOOLEAN", "KEEPER_FILL"),
    ("RESTRICT_AUTO_FILL", 98, "BOOLEAN", "KEEPER_FILL"),
    ("RESTRICT_CREATE_FOLDER", 100, "BOOLEAN", "VAULT_FEATURES"),
    ("RESTRICT_CREATE_FOLDER_TO_ONLY_SHARED_FOLDERS", 101, "BOOLEAN", "CREATING_AND_SHARING"),
    ("RESTRICT_CREATE_IDENTITY_PAYMENT_RECORDS", 102, "BOOLEAN", "VAULT_FEATURES"),
    ("MASK_CUSTOM_FIELDS", 103, "BOOLEAN", "VAULT_FEATURES"),
    ("MASK_NOTES", 104, "BOOLEAN", "VAULT_FEATURES"),
    ("MASK_PASSWORDS_WHILE_EDITING", 105, "BOOLEAN", "VAULT_FEATURES"),
    ("GENERATED_PASSWORD_COMPLEXITY", 106, "PASSWORD_COMPLEXITY", "VAULT_FEATURES"),
    ("GENERATED_SECURITY_QUESTION_COMPLEXITY", 109, "STRING", "VAULT_FEATURES"),
    ("DAYS_BEFORE_DELETED_RECORDS_CLEARED_PERM", 107, "LONG", "VAULT_FEATURES"),
    ("DAYS_BEFORE_DELETED_RECORDS_AUTO_CLEARED", 108, "LONG", "VAULT_FEATURES"),
    ("ALLOW_ALTERNATE_PASSWORDS", 110, "BOOLEAN", "LOGIN_SETTINGS"),
    ("RESTRICT_IMPORT", 111, "BOOLEAN", "SHARING_AND_UPLOADING"),
    ("RESTRICT_CREATE_RECORD", 112, "BOOLEAN", "CREATING_AND_SHARING"),
    ("RESTRICT_CREATE_RECORD_TO_SHARED_FOLDERS", 113, "BOOLEAN", "CREATING_AND_SHARING"),
    ("RESTRICT_CREATE_SHARED_FOLDER", 114, "BOOLEAN", "ACCOUNT_ENFORCEMENTS"),
    ("RESTRICT_SHARING_RECORD_WITH_ATTACHMENTS", 121, "BOOLEAN", "SHARING_AND_UPLOADING"),
    ("RESTRICT_LINK_SHARING", 122, "BOOLEAN", "SHARING_ENFORCEMENTS"),
    ("RESTRICT_SHARING_OUTSIDE_OF_ISOLATED_NODES", 123, "BOOLEAN", "SHARING_ENFORCEMENTS"),
    ("RESTRICT_SHARING_RECORD_TO_SHARED_FOLDERS", 124, "BOOLEAN", "SHARING_ENFORCEMENTS"),
    ("DISABLE_SETUP_TOUR", 140, "BOOLEAN", "VAULT_FEATURES"),
    ("RESTRICT_PERSONAL_LICENSE", 141, "BOOLEAN", "ACCOUNT_SETTINGS"),
    ("DISABLE_ONBOARDING", 142, "BOOLEAN", "ACCOUNT_SETTINGS"),
    ("DISALLOW_V2_CLIENTS", 143, "BOOLEAN", "ACCOUNT_SETTINGS"),
    ("RESTRICT_IP_AUTOAPPROVAL", 144, "BOOLEAN", "ACCOUNT_SETTINGS"),
    ("SEND_BREACH_WATCH_EVENTS", 200, "BOOLEAN", "VAULT_FEATURES"),
    ("RESTRICT_BREACH_WATCH", 201, "BOOLEAN", "VAULT_FEATURES"),
    ("RESEND_ENTERPRISE_INVITE_IN_X_DAYS", 202, "LONG", "ACCOUNT_SETTINGS"),
    ("MASTER_PASSWORD_REENTRY", 203, "JSON"),
    ("RESTRICT_ACCOUNT_RECOVERY", 204, "BOOLEAN", "ACCOUNT_SETTINGS"),
    ("KEEPER_FILL_HOVER_LOCKS", 205, "TERNARY_DEN", "KEEPER_FILL"),
    ("KEEPER_FILL_AUTO_FILL", 206, "TERNARY_DEN", "KEEPER_FILL"),
    ("KEEPER_FILL_AUTO_SUBMIT", 207, "TERNARY_DEN", "KEEPER_FILL"),
    ("KEEPER_FILL_MATCH_ON_SUBDOMAIN", 208, "TERNARY_EDN", "KEEPER_FILL"),
    ("RESTRICT_PROMPT_TO_DISABLE", 209, "BOOLEAN", "KEEPER_FILL"),
    ("RESTRICT_HTTP_FILL_WARNING", 210, "BOOLEAN", "KEEPER_FILL"),
    ("RESTRICT_RECORD_TYPES", 211, "RECORD_TYPES", "RECORD_TYPES"),
    ("ALLOW_SECRETS_MANAGER", 212, "BOOLEAN", "VAULT_FEATURES"),
    ("REQUIRE_SELF_DESTRUCT", 213, "BOOLEAN", "ACCOUNT_ENFORCEMENTS"),
    ("KEEPER_FILL_AUTO_SUGGEST", 214, "TERNARY_DEN", "KEEPER_FILL"),
    ("MAXIMUM_RECORD_SIZE", 215, "LONG", "ACCOUNT_ENFORCEMENTS"),
    ("ALLOW_PAM_ROTATION", 218, "BOOLEAN", "ACCOUNT_ENFORCEMENTS"),
    ("ALLOW_PAM_DISCOVERY", 219, "BOOLEAN", "ACCOUNT_ENFORCEMENTS"),
    ("RESTRICT_IMPORT_SHARED_FOLDERS", 220, "BOOLEAN", "ACCOUNT_ENFORCEMENTS"),
    ("REQUIRE_SECURITY_KEY_PIN", 221, "BOOLEAN", "ACCOUNT_ENFORCEMENTS"),
    ("DISABLE_CREATE_DUPLICATE", 224, "BOOLEAN", "ACCOUNT_ENFORCEMENTS"),
    ("ALLOW_PAM_GATEWAY", 225, "BOOLEAN", "ACCOUNT_ENFORCEMENTS"),
    ("ALLOW_CONFIGURE_ROTATION_SETTINGS", 226, "BOOLEAN", "ACCOUNT_ENFORCEMENTS"),
    ("ALLOW_ROTATE_CREDENTIALS", 227, "BOOLEAN", "ACCOUNT_ENFORCEMENTS"),
    ("ALLOW_CONFIGURE_PAM_CLOUD_CONNECTION_SETTINGS", 228, "BOOLEAN", "ACCOUNT_ENFORCEMENTS"),
    ("ALLOW_LAUNCH_PAM_ON_CLOUD_CONNECTION", 229, "BOOLEAN", "ACCOUNT_ENFORCEMENTS"),
    ("ALLOW_CONFIGURE_PAM_TUNNELING_SETTINGS", 230, "BOOLEAN", "ACCOUNT_ENFORCEMENTS"),
    ("ALLOW_LAUNCH_PAM_TUNNELS", 231, "BOOLEAN", "ACCOUNT_ENFORCEMENTS"),
    ("ALLOW_LAUNCH_RBI", 232, "BOOLEAN", "ACCOUNT_ENFORCEMENTS"),
    ("ALLOW_CONFIGURE_RBI", 233, "BOOLEAN", "ACCOUNT_ENFORCEMENTS"),
    ("ALLOW_VIEW_KCM_RECORDINGS", 234, "BOOLEAN", "ACCOUNT_ENFORCEMENTS"),
    ("RESTRICT_TOTP_FIELD", 235, "BOOLEAN", "ACCOUNT_ENFORCEMENTS"),
    ("ALLOW_VIEW_RBI_RECORDINGS", 236, "BOOLEAN", "ACCOUNT_ENFORCEMENTS"),
    ("RESTRICT_MANAGE_TLA", 238, "BOOLEAN", "ACCOUNT_ENFORCEMENTS"),
    ("RESTRICT_SELF_DESTRUCT_RECORDS", 239, "BOOLEAN", "ACCOUNT_ENFORCEMENTS"),
    ("RESTRICT_PERSONAL_USING_BUSINESS_DOMAINS", 240, "STRING", "ACCOUNT_ENFORCEMENTS"),
    ("RESTRICT_BUSINESS_USING_PERSONAL_USERNAME", 241, "LONG", "ACCOUNT_ENFORCEMENTS"),
    ("WARN_PERSONAL_USING_BUSINESS_DOMAINS", 242, "STRING", "ACCOUNT_ENFORCEMENTS"),
    ("RESTRICT_PERSONAL_USING_BUSINESS_SITES", 243, "STRING", "ACCOUNT_ENFORCEMENTS"),
    ("WARN_PERSONAL_USING_BUSINESS_SITES", 244, "STRING", "ACCOUNT_ENFORCEMENTS"),
    ("RESTRICT_ACCOUNT_SWITCHING", 245, "BOOLEAN", "AUTHENTICATION_ENFORCEMENTS"),
    ("RESTRICT_PASSKEY_LOGIN", 246, "BOOLEAN", "ACCOUNT_ENFORCEMENTS"),
    ("RESTRICT_CAN_EDIT_EXTERNAL_SHARES", 247, "BOOLEAN", "ACCOUNT_ENFORCEMENTS"),
]

_COMPOUND_ENFORCEMENTS = [
    ("RESTRICT_SHARING_ALL", (30, 36), "BOOLEAN", "SHARING_AND_UPLOADING"),
    ("RESTRICT_SHARING_ENTERPRISE", (31, 37), "BOOLEAN", "SHARING_AND_UPLOADING"),
]


def enforcement_list():  # type: () -> List[Tuple[str, str, str]]
    groups = {x[1]: x[0] for x in enumerate(_ENFORCEMENT_GROUPS)}
    enforcements = [(x[3], x[0], x[1], x[2]) for x in [*_ENFORCEMENTS, *_COMPOUND_ENFORCEMENTS] if len(x) >= 4 and x[3]]
    enforcements.sort(key=lambda x: (groups[x[0]] if x[0] in groups else 100) * 1000 + (x[2] if isinstance(x[2], int) else next(iter(x[2])) - 0.5))
    return [(x[0].title().replace('_', ' '), x[1].lower(), x[3].lower()) for x in enforcements]


ENFORCEMENTS = {e[0].lower(): e[2].lower() for e in [*_ENFORCEMENTS, *_COMPOUND_ENFORCEMENTS]}

week_days = ('SUNDAY', 'MONDAY', 'TUESDAY', 'WEDNESDAY', 'THURSDAY', 'FRIDAY', 'SATURDAY')
occurrences = ('FIRST', 'SECOND', 'THIRD', 'FOURTH', 'LAST')
months = ('JANUARY', 'FEBRUARY', 'MARCH', 'APRIL', 'MAY', 'JUNE', 'JULY', 'AUGUST', 'SEPTEMBER', 'OCTOBER',
          'NOVEMBER', 'DECEMBER')


def get_cron_week_day(text):   # type: (Optional[str]) -> Optional[int]
    if isinstance(text, str):
        try:
            return week_days.index(text.upper())
        except:
            pass


def get_cron_occurrence(text):  # type: (Optional[str]) -> Optional[int]
    if isinstance(text, str):
        try:
            idx = occurrences.index(text.upper())
            idx += 1
            if idx > 4:
                idx = 4
            return idx
        except:
            pass


def get_cron_month(text):  # type: (Optional[str]) -> Optional[int]
    if isinstance(text, str):
        try:
            m = months.index(text.upper())
            return m + 1
        except:
            pass


def get_cron_month_day(text):  # type: (Optional[str]) -> Optional[int]
    if isinstance(text, str) and text.isnumeric():
        day = int(text)
        if day < 1:
            day = 1
        elif day > 28:
            day = 28
        return day


# OS dependent constants
if sys.platform.startswith('win'):
    OS_WHICH_CMD = 'where'
else:
    OS_WHICH_CMD = 'which'


KEEPER_PUBLIC_HOSTS = {
    'US': 'keepersecurity.com',
    'EU': 'keepersecurity.eu',
    'AU': 'keepersecurity.com.au',
    'CA': 'keepersecurity.ca',
    'JP': 'keepersecurity.jp',
    'GOV': 'govcloud.keepersecurity.us'
}


def get_abbrev_by_host(host):
    # Return abbreviation of the Keeper's public host

    if host.startswith('https:'):
        host = urlparse(host).netloc    # https://keepersecurity.com/api/v2/ --> keepersecurity.com

    keys = [k for k, v in KEEPER_PUBLIC_HOSTS.items() if v == host]
    if keys:
        return keys[0]
    return None


# Messages
# Account Transfer
ACCOUNT_TRANSFER_MSG = """
Your Keeper administrator has enabled the ability to transfer your vault records
in accordance with company operating procedures and policies.
Please acknowledge this change in account settings by typing 'Accept'.
If you do not accept this change by {0}, you will be locked out of your account.
"""

PBKDF2_ITERATIONS = 1_000_000
