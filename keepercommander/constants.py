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

RMD_BENCHMARK_MAPPING = {
        "SB_CREATE_AT_LEAST_TWO_KEEPER_ADMINISTRATORS":
        {
            "title": "Create at least two Keeper Administrators",
            "description": "Keeper Administrators hold the encryption keys used to access the Admin Console, provision users, manage enforcement policies and perform day to day user administration.\n\nThe Keeper Administrator role should have at least two users in that role. We strongly recommend adding a secondary admin to this role in case one account is lost, the person leaves the organization or the employee is terminated. The Keeper support team cannot elevate a user to an administrative role or reset an administrator's Master Password, by design.\n\nBy design, if all of the Keeper Administrators lose access, Keeper's support team cannot elevate privilege, and Keepers support team cannot approve SSO user devices. Make sure you have a break glass account with root level Keeper Administrator access."
            },
    "SB_ENSURE_TWO_FACTOR_AUTHENTICATION_ADMIN_USERS":
  {
    "title": "Enforce 2FA on the Keeper Administrator role",
    "description": "Keeper Administrators have elevated privilege in the platform and must be protected against both outside attacks, identity provider attacks and insider attack vectors. Ensure that the Keeper Administrator role and any other role with administrative privilege is enforcing the use of 2FA.\n\nIf an admin is logging in to Keeper with an SSO provider, we still recommend adding the additional layer of 2FA on the Keeper side for any administrative role. This protects against IdP account takeover or other insider threats."
  },
    "SB_ENSURE_OUTSIDE_SSO_ADMINISTRATOR_EXISTS":
  {
    "title": "Ensure an administrator exists outside of SSO",
    "description": "Keeper SSO Connect Cloud provides customers with the ability to provision and authenticate users with their preferred SAML 2.0 identity provider.\n\nWhile Keeper supports the ability for admins to login to the Keeper Admin Console with SSO, it is important that at least one Admin account is able to login to Keeper with a Master Password. This is because a situation could occur in which all admins rely on SSO, and there may be no admins to approve a new device. Or, the SSO provider could have an outage which then locks everyone out. We recommend creating an Admin \"service account\" which uses a strong Master Password, 2FA and (optionally) IP AllowListing to optimally lock down this account.\n\nIn the situation where all admins use SSO, and all admins are on new devices (unable to approve them) Keeper support will not be able to help recover. By design, Keeper is a zero knowledge platform and our support team has no ability to approve SSO-enabled devices, or recover Device-Encrypted Data Keys for users."
  },
    "SB_REDUCE_ADMINISTRATOR_PRIVILEGE":
  {
    "title": "Reduce administrator privilege",
    "description": "Keeper's role enforcement policies allow customers to create administrative roles within nodes and sub-nodes. It is important to always ensure least privilege for administrators.\n\nReduce the total number of Admins to the minimum required to operate efficiently.\n\nReduce privilege within Administrative roles. For example, if an Admin does not require the ability to manage roles, remove that privilege.\n\nDon't leave old admin accounts from former employees in an locked state longer than necessary to transfer the contents of the vault."
  },
    "SB_LOCK_DOWN_SSO_PROVIDER":
  {
    "title": "Lock down your SSO provider",
    "description": "If you are integrating Keeper with your SSO identity provider, ensure that your IdP is locked down with MFA policies and reduced privilege. Follow the guidance and best practices of your identity provider to ensure that administrative accounts are minimized with the least amount of privilege necessary to perform their jobs.\n\nThe https://docs.keeper.io/v/sso-connect-cloud/device-approvals/automator provides Cloud SSO-enabled users with a frictionless experience when accessing their vault on a new or unrecognized device. While this improves the user experience, it also requires that your SSO identity provider is protected against unauthorized access. If you enable the Keeper Automator service, you are placing full trust in the identity provider authentication and the user provisioning process. For additional security, the Automator service can limit automated approvals to specific IP ranges, or it can be left disabled completely to force users to manually approve new devices."
  },
    "SB_DISABLE_ACCOUNT_RECOVERY":
  {
    "title": "Disable account recovery when appropriate",
    "description": "As with any SaaS platform, account recovery provides end-users with a route to restore access to their account, if the primary authentication methods are lost or forgotten. In Keeper, by default the user has an ability to configure a Recovery Phrase - a simple, auto-generated set of 24 words that can be used to restore access to their Keeper Vault. The recovery phrase encrypts the user's Data Key using a key derivation similar to the Master Password method.\n\nIf you are deploying to users with a single sign-on product like Azure or Okta, account recovery may not be necessary or warranted, since authentication is delegated to your identity provider. Therefore, it is best to simply not have account recovery as an option, if this is acceptable to your users.\n\nTo disable account recovery, visit the Role > Enforcement Policies > Account Settings > select \"Disable Recovery Phrase for account recovery\".\n\nAccount recovery can be enabled if the affected users store their Recovery Phrase in a safe location."
  },
    "SB_ENFORCE_STRONG_MASTER_PASSWORD":
  {
    "title": "Enforce a strong Master Password",
    "description": "For users who login with a Master Password, the key to decrypt and encrypt the Data Key is derived from the user's Master Password using the password-based key derivation function (PBKDF2), with 1,000,000 iterations by default. After the user types their Master Password, the key is derived locally and then unwraps the Data Key. After the Data Key is decrypted, it is used to unwrap the individual record keys and folder keys. The Record Key then decrypts each of the stored record contents locally.\n\nKeeper implements several mitigations against unauthorized access, device verification, throttling and other protections in the Amazon AWS environment. Enforcing a strong Master Password complexity significantly reduces any risk of offline brute force attack on a user's encrypted vault.\n\nThe National Institute of Standards and Technology (NIST) provides password guidelines in: https://pages.nist.gov/800-63-3/sp800-63b.html The guidelines promote a balance between usability and security; Or in other words, passwords should be easy to remember but hard to guess. The NIST instruction recommends an eight character minimum but a higher value will ultimately result in a harder to guess/crack password. Keeper enforces at least 12 characters. We recommend increasing this to 16 or more.\n\nPassword complexity can be configured on a per role-basis. See the https://docs.keeper.io/v/enterprise-guide/roles#master-password-complexity enforcement setting in the guide."
  },
  "SB_ENSURE_TWO_FACTOR_AUTHENTICATION_FOR_END_USERS":
  {
    "title": "Enforce Two-Factor Authentication for end-users",
    "description": "Two-Factor Authentication (2FA), also commonly referred to as multi-factor authentication (MFA), adds an additional layer of security to access the vault. The first layer is something your users know; their Master Password or SSO. The second layer is something they have. It can be either their mobile device (SMS text or a TOTP application) or by using a hardware device such as YubiKey or Google Titan key.\n\nWhile Keeper's cloud infrastructure implements several mitigations against brute force attack, adding a second means of authentication will makes it considerably more difficult for an attacker to gain access a user's vault. Using a role based enforcement can ensure all users of the enterprise are mandated to configure 2FA on their vault account.\n\nSSO-enabled users should ensure 2FA is configured with their IdP at a minimum. Keeper checks for a signed assertion from the identity provider during SSO authentication. For additional security, 2FA can be enabled on the Keeper side in addition to the IdP.\n\nTo set up 2FA See the section in the guide: https://docs.keeper.io/v/enterprise-guide/two-factor-authentication."
  },
  "SB_CONFIGURE_IP_ALLOWLISTING":
  {
    "title": "Configure IP Allowlisting",
    "description": "To prevent users from accessing their work vault outside of approved locations and networks, administrators should consider activating IP Address Allowlisting.  This is a role-based enforcement setting that designated users can only access their vaults when their device is on an approved network.\n\nAt minimum, users with Administrative privileges in Keeper should be locked down to specific IPs or IP ranges. This prevents malicious insider attacks as well as identity provider takeover attack vectors. If this is not possible, ensure that MFA is enforced.\n\nVisit the section on https://docs.keeper.io/v/enterprise-guide/ip-allow-keeper for more information on configuring roles to include this feature."
  },
  "SB_ENABLE_ACCOUNT_TRANSFER_POLICY":
  {
    "title": "Enable Account Transfer policy when necessary",
    "description": "Account Transfer provides a mechanism for a designated administrator to recover the contents of a user's vault, in case the employee suddenly leaves or is terminated. This is an optional feature that must be configured by the Keeper Administrator during the initial deployment phase of the Keeper rollout, because it requires specific steps to escrow the user's encryption keys.\n\nFor step by step details visit the https://docs.keeper.io/v/enterprise-guide/account-transfer-policy.\n\nThe Account Transfer policy is recommended if users are authenticating with a Master Password, and if the enterprise has concerns regarding the loss of specific user vaults.\n\nThe Account Transfer policy gives admins with the assigned privilege to perform transfers of a Keeper vault for their managed users. If you have users (such as C-level executives or root-level admins) that do not want their vault transferred under any circumstances, these users can be placed into a role that does not have the transfer policy enabled."
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
