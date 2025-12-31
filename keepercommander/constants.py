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
    ('keeper_endpoint_privilege_manager', 'Keeper Endpoint Privilege Manager (KEPM)', True, 'KEPM'),
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
    ("RESTRICT_SNAPSHOT_TOOL", 248, "BOOLEAN", "ACCOUNT_ENFORCEMENTS"),
    ("RESTRICT_FORCEFIELD", 249, "BOOLEAN", "ACCOUNT_ENFORCEMENTS"),
    ("RESTRICT_CLIPBOARD_EXPIRE_IN_X_SECS", 251, "LONG", "ACCOUNT_ENFORCEMENTS"),
    ("RESTRICT_SF_RECORD_REMOVAL", 252, "BOOLEAN", "SHARING_ENFORCEMENTS"),
    ("RESTRICT_SF_FOLDER_DELETION", 253, "BOOLEAN", "SHARING_ENFORCEMENTS"),
    ("RESTRICT_PLATFORM_PASSKEY_LOGIN", 254, "BOOLEAN", "ACCOUNT_ENFORCEMENTS"),
    ("RESTRICT_CROSS_PLATFORM_PASSKEY_LOGIN", 255, "BOOLEAN", "ACCOUNT_ENFORCEMENTS"),
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

RMD_BENCHMARK_MAPPING = {
        "SB_CREATE_AT_LEAST_TWO_KEEPER_ADMINISTRATORS":
        {
            "title": "Create at least two Keeper Administrators",
            "description": "Keeper Administrators hold the encryption keys used to access the Admin Console, provision users, manage enforcement policies and perform day to day user administration. The Keeper Administrator role should have at least two users in that role. We strongly recommend adding a secondary admin to this role in case one account is lost, the person leaves the organization or the employee is terminated. The Keeper support team cannot elevate a user to an administrative role or reset an administrator's Master Password, by design. By design, if all of the Keeper Administrators lose access, Keeper's support team cannot elevate privilege, and Keepers support team cannot approve SSO user devices. Make sure you have a break glass account with root level Keeper Administrator access."
            },
    "SB_ENSURE_TWO_FACTOR_AUTHENTICATION_ADMIN_USERS":
  {
    "title": "Enforce 2FA on the Keeper Administrator role",
    "description": "Keeper Administrators have elevated privilege in the platform and must be protected against both outside attacks, identity provider attacks and insider attack vectors. Ensure that the Keeper Administrator role and any other role with administrative privilege is enforcing the use of 2FA. If an admin is logging in to Keeper with an SSO provider, we still recommend adding the additional layer of 2FA on the Keeper side for any administrative role. This protects against IdP account takeover or other insider threats."
  },
    "SB_ENSURE_OUTSIDE_SSO_ADMINISTRATOR_EXISTS":
  {
    "title": "Ensure an administrator exists outside of SSO",
    "description": "Keeper SSO Connect Cloud provides customers with the ability to provision and authenticate users with their preferred SAML 2.0 identity provider. While Keeper supports the ability for admins to login to the Keeper Admin Console with SSO, it is important that at least one Admin account is able to login to Keeper with a Master Password. This is because a situation could occur in which all admins rely on SSO, and there may be no admins to approve a new device. Or, the SSO provider could have an outage which then locks everyone out. We recommend creating an Admin \"service account\" which uses a strong Master Password, 2FA and (optionally) IP AllowListing to optimally lock down this account. In the situation where all admins use SSO, and all admins are on new devices (unable to approve them) Keeper support will not be able to help recover. By design, Keeper is a zero knowledge platform and our support team has no ability to approve SSO-enabled devices, or recover Device-Encrypted Data Keys for users."
  },
    "SB_REDUCE_ADMINISTRATOR_PRIVILEGE":
  {
    "title": "Reduce administrator privilege",
    "description": "Keeper's role enforcement policies allow customers to create administrative roles within nodes and sub-nodes. It is important to always ensure least privilege for administrators. Reduce the total number of Admins to the minimum required to operate efficiently. Reduce privilege within Administrative roles. For example, if an Admin does not require the ability to manage roles, remove that privilege. Don't leave old admin accounts from former employees in an locked state longer than necessary to transfer the contents of the vault."
  },
    "SB_LOCK_DOWN_SSO_PROVIDER":
  {
    "title": "Lock down your SSO provider",
    "description": "If you are integrating Keeper with your SSO identity provider, ensure that your IdP is locked down with MFA policies and reduced privilege. Follow the guidance and best practices of your identity provider to ensure that administrative accounts are minimized with the least amount of privilege necessary to perform their jobs. The https://docs.keeper.io/v/sso-connect-cloud/device-approvals/automator provides Cloud SSO-enabled users with a frictionless experience when accessing their vault on a new or unrecognized device. While this improves the user experience, it also requires that your SSO identity provider is protected against unauthorized access. If you enable the Keeper Automator service, you are placing full trust in the identity provider authentication and the user provisioning process. For additional security, the Automator service can limit automated approvals to specific IP ranges, or it can be left disabled completely to force users to manually approve new devices."
  },
    "SB_DISABLE_ACCOUNT_RECOVERY":
  {
    "title": "Disable account recovery when appropriate",
    "description": "As with any SaaS platform, account recovery provides end-users with a route to restore access to their account, if the primary authentication methods are lost or forgotten. In Keeper, by default the user has an ability to configure a Recovery Phrase - a simple, auto-generated set of 24 words that can be used to restore access to their Keeper Vault. The recovery phrase encrypts the user's Data Key using a key derivation similar to the Master Password method. If you are deploying to users with a single sign-on product like Azure or Okta, account recovery may not be necessary or warranted, since authentication is delegated to your identity provider. Therefore, it is best to simply not have account recovery as an option, if this is acceptable to your users. To disable account recovery, visit the Role > Enforcement Policies > Account Settings > select \"Disable Recovery Phrase for account recovery\". Account recovery can be enabled if the affected users store their Recovery Phrase in a safe location."
  },
    "SB_ENFORCE_STRONG_MASTER_PASSWORD":
  {
    "title": "Enforce a strong Master Password",
    "description": "For users who login with a Master Password, the key to decrypt and encrypt the Data Key is derived from the user's Master Password using the password-based key derivation function (PBKDF2), with 1,000,000 iterations by default. After the user types their Master Password, the key is derived locally and then unwraps the Data Key. After the Data Key is decrypted, it is used to unwrap the individual record keys and folder keys. The Record Key then decrypts each of the stored record contents locally. Keeper implements several mitigations against unauthorized access, device verification, throttling and other protections in the Amazon AWS environment. Enforcing a strong Master Password complexity significantly reduces any risk of offline brute force attack on a user's encrypted vault. The National Institute of Standards and Technology (NIST) provides password guidelines in: https://pages.nist.gov/800-63-3/sp800-63b.html The guidelines promote a balance between usability and security; Or in other words, passwords should be easy to remember but hard to guess. The NIST instruction recommends an eight character minimum but a higher value will ultimately result in a harder to guess/crack password. Keeper enforces at least 12 characters. We recommend increasing this to 16 or more. Password complexity can be configured on a per role-basis. See the https://docs.keeper.io/v/enterprise-guide/roles#master-password-complexity enforcement setting in the guide."
  },
  "SB_ENSURE_TWO_FACTOR_AUTHENTICATION_FOR_END_USERS":
  {
    "title": "Enforce Two-Factor Authentication for end-users",
    "description": "Two-Factor Authentication (2FA), also commonly referred to as multi-factor authentication (MFA), adds an additional layer of security to access the vault. The first layer is something your users know; their Master Password or SSO. The second layer is something they have. It can be either their mobile device (SMS text or a TOTP application) or by using a hardware device such as YubiKey or Google Titan key. While Keeper's cloud infrastructure implements several mitigations against brute force attack, adding a second means of authentication will makes it considerably more difficult for an attacker to gain access a user's vault. Using a role based enforcement can ensure all users of the enterprise are mandated to configure 2FA on their vault account. SSO-enabled users should ensure 2FA is configured with their IdP at a minimum. Keeper checks for a signed assertion from the identity provider during SSO authentication. For additional security, 2FA can be enabled on the Keeper side in addition to the IdP. To set up 2FA See the section in the guide: https://docs.keeper.io/v/enterprise-guide/two-factor-authentication."
  },
  "SB_CONFIGURE_IP_ALLOWLISTING":
  {
    "title": "Configure IP Allowlisting",
    "description": "To prevent users from accessing their work vault outside of approved locations and networks, administrators should consider activating IP Address Allowlisting.  This is a role-based enforcement setting that designated users can only access their vaults when their device is on an approved network. At minimum, users with Administrative privileges in Keeper should be locked down to specific IPs or IP ranges. This prevents malicious insider attacks as well as identity provider takeover attack vectors. If this is not possible, ensure that MFA is enforced. Visit the section on https://docs.keeper.io/v/enterprise-guide/ip-allow-keeper for more information on configuring roles to include this feature."
  },
  "SB_ENABLE_ACCOUNT_TRANSFER_POLICY":
  {
    "title": "Enable Account Transfer policy when necessary",
    "description": "Account Transfer provides a mechanism for a designated administrator to recover the contents of a user's vault, in case the employee suddenly leaves or is terminated. This is an optional feature that must be configured by the Keeper Administrator during the initial deployment phase of the Keeper rollout, because it requires specific steps to escrow the user's encryption keys. For step by step details visit the https://docs.keeper.io/v/enterprise-guide/account-transfer-policy. The Account Transfer policy is recommended if users are authenticating with a Master Password, and if the enterprise has concerns regarding the loss of specific user vaults. The Account Transfer policy gives admins with the assigned privilege to perform transfers of a Keeper vault for their managed users. If you have users (such as C-level executives or root-level admins) that do not want their vault transferred under any circumstances, these users can be placed into a role that does not have the transfer policy enabled."
  },
  "SB_CREATE_ALERTS":
  {
    "title": "Create alerts",
    "description": "Keeper's Advanced Reporting System provides built-in Alerting capabilities that will notify users and Administrators for important events. As a best practice, we have https://docs.keeper.io/v/enterprise-guide/recommended-alerts that can be configured by the Keeper Administrator. Alerts should be enabled on key administrative events to notify any suspicious activity coming from both external and insider threats."
  },
  "SB_PREVENT_INSTALLATION_OF_UNTRUSTED_EXTENSIONS":
  {
    "title": "Prevent installation of untrusted extensions",
    "description": "As a general security practice, we recommend that Enterprise customers limit the ability of end-users to install unapproved third-party browser extensions. Browser extensions with elevated permissions could have the ability to access any information within any website or browser-based application. Please refer to your device management software to ensure that Keeper is allowed, and unapproved extensions are blocked or removed."
  },
    "SB_DEPLOY_ACROSS_ENTIRE_ORGANIZATION":
  {
    "title": "Deploy across your entire organization",
    "description": "To protect all of your users across all of their devices, applications and websites, Keeper should be deployed to all users in your entire organization who handle privileged credentials. Any administrator or privileged user who does not use a secure password manager can put your organization at risk."
  },
    "SB_DISABLE_BROWSER_PASSWORD_MANAGERS":
  {
    "title": "Disable built-in browser password managers",
    "description": "Modern browsers typically have their own versions of a password manager. In addition to being less robust and secure than Keeper, these password managers can conflict with Keeper, causing login issues or even security contradictions.  To prevent conflicts and harden security, Keeper recommends disabling built-in browser password managers."
  },
    "SB_ENFORCE_LEAST_PRIVILEGE_POLICY":
  {
    "title": "Enforce least privilege policy on managed devices",
    "description": "Apply least privilege access controls for all managed devices to minimize attack surface and prevent unauthorized system access. Keeper Endpoint Privilege Manager “Least Privilege” policy reduces the risk of lateral movement, privilege escalation, and data breaches while supporting regulatory compliance frameworks like SOC 2, NIST, and ISO 27001."
  }
}

AUDIT_EVENT_STATE_MAPPING = {
        "account_recovery": "Account Recovery Requested",
        "alias_added": "Added alternative email",
        "change_email": "Changed Email",
        "change_master_password": "Changed Master Password",
        "change_security_question": "Changed Security Question",
        "device_user_passkey_add": "Biometric passkey add",
        "device_user_passkey_remove": "Biometric passkey removal",
        "set_alternate_master_password": "Alternate Master Password Set",
        "set_biometric_access": "Biometric Access Set",
        "admin_permission_added": "Add Administrative Permission",
        "admin_permission_removed": "Remove Administrative Permission",
        "bw_record_high_risk": "BreachWatch detected high-risk record password",
        "bw_record_ignored": "User ignored detected high-risk record password",
        "bw_record_resolved": "User resolved detected high-risk record password",
        "chat_contact_added": "Added Contact on Chat",
        "chat_file_attached": "Sent File on Chat",
        "chat_login": "Chat Login",
        "chat_login_failed": "Chat Login Failure",
        "chat_message_destruct": "Self-Destructed Chat Message",
        "chat_message_received": "Received Chat Message",
        "chat_message_sent": "Sent Chat Message",
        "compliance_report_deleted": "Deleted Compliance Report",
        "compliance_report_downloaded": "Downloaded Compliance Report",
        "compliance_report_exported": "Exported Compliance Report",
        "compliance_report_run": "Generated Compliance Report",
        "compliance_report_saved": "Saved Compliance Report",
        "saved_criteria_deleted": "Deleted Compliance Report Criteria",
        "saved_criteria_edited": "Edited Compliance Report Criteria",
        "saved_criteria_saved": "Saved Compliance Report Criteria",
        "unsaved_compliance_report_exported": "Unsaved Compliance Report Exported",
        "agent_added_collection_link": "Agent added collection link",
        "agent_added_to_collection": "Agent added to collection",
        "agent_authentication_failed": "Agent Auth Failed",
        "agent_created_collection": "Agent created collection",
        "agent_removed": "Removed agent",
        "agent_removed_from_collection": "Agent removed from collection",
        "agent_unregistered": "Agent Unregistered",
        "agent_updated": "Updated agent",
        "approval_request_created": "Agent created approval request",
        "approval_request_removed": "Removed approval request",
        "approval_request_status_changed": "Changed approval request status",
        "collection_created": "Created collection",
        "collection_link_added": "Added collection link",
        "collection_link_removed": "Removed collection link",
        "collection_removed": "Removed collection",
        "collection_updated": "Updated collection",
        "deployment_authentication_failed": "Deployment Auth Failed",
        "deployment_created": "Created deployment",
        "deployment_removed": "Removed deployment",
        "deployment_updated": "Updated deployment",
        "policy_created": "Created policy",
        "policy_removed": "Removed policy",
        "policy_updated": "Updated policy",
        "register_agent": "Registered agent",
        "keeper_ai_critical_risk_level_detected": "KeeperAI Detected Critical Risk",
        "keeper_ai_high_risk_level_detected": "KeeperAI Detected High Risk",
        "keeper_ai_medium_risk_level_detected": "KeeperAI Detected Medium Risk",
        "keeper_ai_pam_configuration_feature_disabled": "Disabled KeeperAI in the PAM Config",
        "keeper_ai_pam_configuration_feature_enabled": "event_keeper_ai_pam_configuration_feature_enabled",
        "keeper_ai_recording_disabled": "KeeperAI Recording Disabled",
        "keeper_ai_recording_enabled": "KeeperAI Recording Enabled",
        "keeper_ai_session_locked_by_ai_critical": "Session Locked by KeeperAI (Critical Threat)",
        "keeper_ai_session_locked_by_ai_high": "Session Locked by KeeperAI (High Threat)",
        "keeper_ai_session_locked_by_ai_medium": "Session Locked by KeeperAI (Medium Threat)",
        "keeper_ai_session_terminate_disabled": "KeeperAI Terminate Session Disabled",
        "keeper_ai_session_terminate_enabled": "KeeperAI Terminate Session Enabled",
        "keeper_ai_session_unlocked_by_user": "Session Unlocked by User",
        "pam_session_recording_downloaded": "Session Recording Files Downloaded",
        "app_client_access": "Accessed Secrets Manager from App",
        "app_client_access_denied": "Denied access to Secrets Manager from Client Device",
        "app_client_added": "Added Client Device to Secrets Manager App",
        "app_client_connected": "Initialized Client Device on Secrets Manager App",
        "app_client_expired": "Secrets Manager Client Device Access Expired",
        "app_client_folder_create": "Created Folder from Secrets Manager device",
        "app_client_folder_delete": "Deleted Folder from Secrets Manager device",
        "app_client_folder_remove_record": "Record removed from shared folder by Secrets Manager device",
        "app_client_folder_update": "Updated Folder from Secrets Manager device",
        "app_client_record_create": "Record created by Secrets Manager device",
        "app_client_record_delete": "Record deleted by Secrets Manager device",
        "app_client_record_update": "Record updated by Secrets Manager device",
        "app_client_removed": "Removed Client Device from Secrets Manager App",
        "app_folder_removed": "Folder removed from Secrets Manager",
        "app_folder_share_changed": "Changed folder permission to Secrets Manager",
        "app_folder_shared": "Folder shared with Secrets Manager",
        "app_record_removed": "Record removed from Secrets Manager",
        "app_record_share_changed": "Changed record permission to Secrets Manager",
        "app_record_shared": "Record Shared with Secrets Manager App",
        "pam_configuration_created": "PAM Configuration Created",
        "pam_configuration_deleted": "PAM Configuration Deleted",
        "pam_configuration_updated": "PAM Configuration Updated",
        "pam_gateway_created": "Gateway Created",
        "pam_gateway_offline": "Gateway Offline",
        "pam_gateway_online": "Gateway Online",
        "pam_gateway_removed": "Gateway Removed",
        "record_rotation_created": "Rotation Settings added to Record",
        "record_rotation_disabled": "Rotation Disabled on Record",
        "record_rotation_on_demand_fail": "On Demand Rotation Failed",
        "record_rotation_on_demand_ok": "On Demand Rotation Successful",
        "record_rotation_scheduled_fail": "Scheduled Rotation Failed",
        "record_rotation_scheduled_ok": "Scheduled Rotation Successful",
        "record_rotation_updated": "Rotation Settings Changed on Record",
        "login": "Logged In",
        "login_console": "Console Login",
        "login_failure": "Failed Login",
        "enterprise_addon_added": "Added add-on",
        "enterprise_addon_removed": "Removed add-on",
        "enterprise_created": "Created enterprise",
        "enterprise_deleted": "Deleted enterprise",
        "enterprise_file_plan_changed": "Changed File Plan",
        "msp_changes_mc_plan": "Changed MC Plan",
        "msp_changes_mc_seats": "Changed MC Maximum license count",
        "gradient_connection_remove": "Gradient MSP remove",
        "gradient_connection_setup": "Gradient MSP setup",
        "gradient_mappings_setup": "Gradient MSP mappings",
        "gradient_sync_fail": "Gradient MSP sync fail",
        "msp_activated": "MSP Activated",
        "msp_attaches_mc": "Attached to node",
        "msp_creates_mc": "Registered Managed Company",
        "msp_deactivated": "MSP Deactivated",
        "msp_deletes_mc": "Deleted Managed Company",
        "msp_pauses_mc": "Paused Managed Company",
        "msp_removes_mc": "Removed Managed Company",
        "msp_renames_mc": "Renamed Managed Company",
        "msp_resumes_mc": "Resumed Managed Company",
        "agent_removed_approval_request": "Agent Removed Approval Request",
        "audit_alert_created": "Created Alert",
        "audit_alert_deleted": "Deleted Alert",
        "audit_alert_paused": "Paused Alert",
        "audit_alert_resumed": "Resumed Alert",
        "audit_sync_removed": "Removed Audit Log Sync",
        "audit_sync_setup": "Setup Audit Log Sync",
        "bridge_activated": "Activated AD Bridge",
        "bridge_deleted": "Deleted AD Bridge",
        "bridge_updated": "Updated AD Bridge",
        "email_provisioning_activated": "Activated Email Provisioning",
        "email_provisioning_deleted": "Deleted Email Provisioning",
        "node_created": "Created Node",
        "node_deleted": "Deleted Node",
        "out_of_seats": "License reached maximum",
        "record_type_created": "Created Record Type",
        "record_type_deleted": "Deleted Record Type",
        "record_type_updated": "Updated Record Type",
        "report_created": "Created Report",
        "report_deleted": "Deleted Report",
        "report_modified": "Modified Report",
        "role_created": "Created Role",
        "role_deleted": "Deleted Role",
        "role_enforcement_changed": "Changed Role Policy",
        "scim_activated": "Activated SCIM",
        "scim_deleted": "Deleted SCIM",
        "scim_updated": "Activated SCIM",
        "set_2fa_configuration": "Set 2FA Configuration",
        "set_custom_email_content": "Set Custom Email",
        "set_custom_email_logo": "Set Email Logo",
        "set_custom_header_logo": "Set Vault Logo",
        "ssh_agent_approved": "Approved the SSH agent",
        "ssh_agent_started": "Started the SSH agent",
        "ssh_agent_stopped": "Stopped the SSH agent",
        "sso_activated": "Activated SSO Connect",
        "sso_deleted": "Deleted SSO Connect",
        "sso_updated": "Updated SSO Connect",
        "team_created": "Created Team",
        "team_deleted": "Deleted Team",
        "team_provisioned_by_scim": "SCIM Provisioned Team",
        "create_public_api_token_in_days": "Admin created an API token",
        "revoke_public_api_token": "Deleted Public API Token",
        "role_managed_node_added": "Add A Manage Node To A Role",
        "role_managed_node_removed": "Remove A Manage Node From A Role",
        "role_managed_node_updated": "Change Cascade Node Permission",
        "accept_invitation": "Accepted Invitation",
        "accept_transfer": "Accepted Transfer Consent",
        "account_recovery_decline": "Recovery Phrase Set Declined",
        "account_recovery_setup": "Recovery Phrase Set",
        "add_security_key": "Added Security Key",
        "added_admin_key": "Granted Admin Permissions",
        "added_to_role": "Added User to Role",
        "auto_invite_user": "Auto-Invited User",
        "clear_security_data": "Cleared security audit data",
        "create_user": "Created User",
        "decline_invitation": "Declined Invitation",
        "delete_pending_user": "Deleted Pending User",
        "delete_security_key": "Deleted Security Key",
        "delete_user": "Deleted User",
        "device_admin_account_locked": "Admin locked device account",
        "device_admin_account_unlocked": "Admin unlocked device account",
        "device_admin_approval_requested": "Admin approval for device requested",
        "device_admin_locked": "Admin locked device",
        "device_admin_loggedout": "Admin Logged Out device",
        "device_admin_removed": "Admin removed device",
        "device_admin_unlocked": "Admin unlocked device",
        "device_approved": "Device approved",
        "device_approved_by_admin": "Device approved by admin",
        "device_user_approval_requested": "User requested self approval for device",
        "device_user_blocked": "User Blocked Device",
        "device_user_linked": "User Linked Devices",
        "device_user_locked": "User Locked Device",
        "device_user_loggedout": "User Logged Out Device",
        "device_user_removed": "User Removed Device",
        "device_user_renamed": "User Renamed Device",
        "device_user_unblocked": "User Unblocked Device",
        "device_user_unlinked": "User Unlinked Devices",
        "device_user_unlocked": "User Unlocked Device",
        "enable_user": "Enabled User",
        "enterprise_2fa_disabled_by_admin": "Disabled 2FA By Admin",
        "enterprise_product_changed": "Changed plan",
        "enterprise_to_consumption_billing": "Converted to Consumption billing",
        "expire_password": "Expired Master Password",
        "lock_user": "Locked User",
        "login_failed_console": "Failed Console Login",
        "login_failed_ip_whitelist": "IP Blocked",
        "payment_method_updated": "Payment Method Updated",
        "pending_added_to_role": "Added Pending User to Role",
        "pending_removed_from_role": "Removed Pending User from Role",
        "reauthentication_reprompt_success": "Master password reprompt success",
        "reauthentication_reprompt_throttle": "Re-authentication prompt throttled",
        "removed_from_role": "Removed User from Role",
        "role_team_add": "Added Role to Team",
        "role_team_remove": "Removed Role from Team",
        "scim_access_failure": "SCIM access failure",
        "send_invitation": "Invited User",
        "set_two_factor_off": "Disabled Two-Factor Auth",
        "set_two_factor_on": "Enabled Two-Factor Auth",
        "two_factor_code_invalid": "The Two-Factor code is invalid",
        "two_factor_disabled_by_support": "Disabled 2FA By Keeper Support",
        "vault_transferred": "Transferred Vault",
        "sb_configure_ip_allowlisting": "Configure IP Allowlisting",
        "sb_create_alerts": "Create alerts",
        "sb_create_at_least_two_keeper_administrators": "Create at least two Keeper Administrators",
        "sb_deploy_across_entire_organization": "Deploy Across Your Entire Organization",
        "sb_disable_account_recovery": "Disable Account Recovery",
        "sb_disable_browser_password_managers": "Disable Browser Password Managers",
        "sb_enable_account_transfer_policy": "Enable Account Transfer Policy",
        "sb_enforce_least_privilege_policy": "Enforce Least Privileged Policy",
        "sb_enforce_strong_master_password": "Enforce a strong Master Password",
        "sb_ensure_outside_sso_administrator_exists": "Ensure Outside SSO Administrator Exists",
        "sb_ensure_two_factor_authentication_admin_users": "Ensure Two-Factor Authentication For Admin Users",
        "sb_ensure_two_factor_authentication_for_end_users": "Ensure Two-Factor Authentication For End Users",
        "sb_lock_down_sso_provider": "Lock down your SSO provider",
        "sb_prevent_installation_of_untrusted_extensions": "Prevent Installation of Untrusted Extensions",
        "sb_reduce_administrator_privilege": "Reduce Administrator Privilege",
        "accept_share": "Accepted Share Request",
        "added_shared_folder": "Added Shared Folder",
        "added_to_team": "Added User to Team",
        "cancel_share": "Rejected Share Request",
        "change_share": "Changed Record Share",
        "deleted_shared_folder": "Deleted Shared Folder",
        "ext_share_access": "One-Time Share Re-opened",
        "ext_share_added": "One-Time Share Added",
        "ext_share_connected": "One-Time Share Opened",
        "ext_share_expired": "One-Time Share Expired",
        "ext_share_removed": "One-Time Share Removed",
        "folder_add_outside_user": "Folder Shared Outside",
        "folder_add_record": "Added Record to Shared Folder",
        "folder_add_team": "Added Team to Folder",
        "folder_add_user": "Added User to Folder",
        "folder_change_record": "Changed Record Permissions",
        "folder_change_team": "Changed Team Permissions",
        "folder_change_user": "Changed User Permissions",
        "folder_remove_record": "Removed Record from Shared Folder",
        "folder_remove_team": "Removed Team from Folder",
        "folder_remove_user": "Removed User from Folder",
        "record_share_outside_user": "Record Shared Outside",
        "remove_share": "Removed Record Share",
        "removed_from_team": "Removed User from Team",
        "share": "Shared Record",
        "shared_folder_folder_record_restored": "Shared Folder Folder Record Restored",
        "shared_folder_folder_restored": "Shared Folder Folder Restored",
        "shared_folder_record_restored": "Shared Folder Record Restored",
        "shared_folder_restored": "Shared Folder Restored",
        "transfer_owner": "Transferred Record Ownership",
        "added_folder": "Added Folder",
        "added_identity": "Added Identity",
        "added_payment_card": "Added Payment Card",
        "audit_alert_sent": "Sent Audit Alert",
        "audit_sync_failed": "Failed Audit Log Sync",
        "audit_sync_paused": "Paused Audit Log Sync",
        "audit_sync_restored": "Restored Audit Log Sync",
        "audit_sync_resumed": "Resumed Audit Log Sync",
        "changed_identity": "Changed Identity",
        "changed_payment_card": "Changed Payment Card",
        "copy_password": "Copied Password to Clipboard",
        "deleted_folder": "Deleted Folder",
        "duplicate_record": "Duplicated Record",
        "empty_trash": "Emptied Trash Bin",
        "exported_records": "Exported Records",
        "fast_fill": "Filled Record",
        "file_attachment_deleted": "Deleted File Attachment",
        "file_attachment_downloaded": "Downloaded File Attachment",
        "file_attachment_exported": "Exported File Attachment",
        "file_attachment_uploaded": "Uploaded File Attachment",
        "file_attachment_viewed": "Viewed File Attachment",
        "imported_records": "Imported Records",
        "open_record": "Opened Record",
        "record_add": "Added Record",
        "record_delete": "Deleted Record",
        "record_password_change": "Record Password Changed",
        "record_restored": "Deleted Record Restored",
        "record_update": "Updated Record",
        "reused_password": "Created Re-used Password",
        "revision_restored": "Record Revision Restored",
        "discovery_job_completed": "Completed Discovery",
        "discovery_job_started": "Started Discovery",
        "ksm_app_shared": "Secrets Manager Application Shared",
        "pam_kcm_connection_started": "Started Connection",
        "pam_kcm_connection_stopped": "Stopped Connection",
        "pam_kcm_connection_terminated": "Terminated Connection",
        "pam_rbi_started": "Started Remote Browser Isolation",
        "pam_rbi_stopped": "Stopped Remote Browser Isolation",
        "pam_rbi_terminated": "Terminated Remote Browser Isolation",
        "pam_session_rbi_recording_started": "Remote Browser Isolation with recording started",
        "pam_session_rbi_recording_stopped": "Remote Browser Isolation with recording stopped",
        "pam_session_recording_started": "Connection with recording started",
        "pam_session_recording_stopped": "Connection with recording stopped",
        "pam_tunnel_started": "Started Tunnel",
        "pam_tunnel_stopped": "Stopped Tunnel",
        "pam_tunnel_terminated": "Terminated Tunnel",
}
