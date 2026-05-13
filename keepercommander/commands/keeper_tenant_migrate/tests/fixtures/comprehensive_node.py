"""Programmatic fixture builders for VERIFICATION_GAPS comprehensive node.

Each builder returns either a single fixture dict or a (source, expected)
pair the test consumes. Fixtures are deterministic — no time/random reads.
The naming intentionally mirrors the unchecked items in
VERIFICATION_GAPS.md so the addressed-by mapping is obvious.

The fixtures here are fakes-only: they exercise the inventory → structure
→ users → records → verify pipeline using the existing Fake* clients in
this package, never a live Commander session. Live rehearsals (Phase
B/C in ROADMAP) cover anything the fakes can't observe (real network
errors, real pending invitations, vault crypto).
"""

# Stable naming so fixture combinators below stay decoupled from string drift.
SCOPE_NODE = 'MIGRATION-TEST-NODE'
SOURCE_ROOT = 'My company'
TARGET_ROOT = 'Keeperdemo'
PREFIX = 'MIGTEST-'


# ─── Node fixtures ──────────────────────────────────────────────────────────


def node_with_custom_name():
    """Node with a non-trivial display name under MIGRATION-TEST-NODE."""
    src = {
        'id': '101', 'name': 'MIGTEST-CustomName',
        'parent': SCOPE_NODE, 'isolated': False,
    }
    expected = {'name': 'MIGTEST-CustomName', 'parent': SCOPE_NODE,
                'isolated': False}
    return src, expected


def node_nested_child():
    """A child node nested two levels under the scope root."""
    parent = {
        'id': '110', 'name': 'MIGTEST-Branch',
        'parent': SCOPE_NODE, 'isolated': False,
    }
    child = {
        'id': '111', 'name': 'MIGTEST-Leaf',
        'parent': 'MIGTEST-Branch', 'isolated': False,
    }
    expected = [
        {'name': 'MIGTEST-Branch', 'parent': SCOPE_NODE, 'isolated': False},
        {'name': 'MIGTEST-Leaf', 'parent': 'MIGTEST-Branch', 'isolated': False},
    ]
    return [parent, child], expected


def node_isolated():
    """Isolated node — `toggle_node_isolated` must be invoked on target."""
    src = {
        'id': '120', 'name': 'MIGTEST-Isolated',
        'parent': SCOPE_NODE, 'isolated': True,
    }
    expected = {'name': 'MIGTEST-Isolated', 'parent': SCOPE_NODE,
                'isolated': True}
    return src, expected


# ─── Team fixtures ──────────────────────────────────────────────────────────


def team_with_restrict_edit():
    src = {
        'uid': 't-edit', 'name': 'MIGTEST-EditOnly',
        'restricts': 'R',  # R=edit per restricts_flags()
        'node': f'{SOURCE_ROOT}\\{SCOPE_NODE}',
        'user_count': 0, 'role_count': 0,
    }
    expected = {'name': 'MIGTEST-EditOnly', 'restricts': 'R'}
    return src, expected


def team_with_restrict_share():
    src = {
        'uid': 't-share', 'name': 'MIGTEST-ShareOnly',
        'restricts': 'S',
        'node': f'{SOURCE_ROOT}\\{SCOPE_NODE}',
        'user_count': 0, 'role_count': 0,
    }
    expected = {'name': 'MIGTEST-ShareOnly', 'restricts': 'S'}
    return src, expected


def team_with_restrict_view():
    src = {
        'uid': 't-view', 'name': 'MIGTEST-ViewOnly',
        'restricts': 'W',
        'node': f'{SOURCE_ROOT}\\{SCOPE_NODE}',
        'user_count': 0, 'role_count': 0,
    }
    expected = {'name': 'MIGTEST-ViewOnly', 'restricts': 'W'}
    return src, expected


def team_with_all_three_restrictions():
    src = {
        'uid': 't-all', 'name': 'MIGTEST-FullLockdown',
        'restricts': 'R W S',
        'node': f'{SOURCE_ROOT}\\{SCOPE_NODE}',
        'user_count': 0, 'role_count': 0,
    }
    expected = {'name': 'MIGTEST-FullLockdown', 'restricts': 'R W S'}
    return src, expected


def team_with_no_restrictions():
    src = {
        'uid': 't-open', 'name': 'MIGTEST-Open',
        'restricts': '',
        'node': f'{SOURCE_ROOT}\\{SCOPE_NODE}',
        'user_count': 0, 'role_count': 0,
    }
    expected = {'name': 'MIGTEST-Open', 'restricts': ''}
    return src, expected


def team_with_users_assigned():
    """Team carries two users in queued_users; verify users.run() picks them."""
    src = {
        'uid': 't-users', 'name': 'MIGTEST-Members',
        'restricts': '',
        'node': f'{SOURCE_ROOT}\\{SCOPE_NODE}',
        'user_count': 2, 'role_count': 0,
        'queued_users': [
            {'username': 'alice@migtest.example'},
            {'username': 'bob@migtest.example'},
        ],
    }
    expected = {
        'name': 'MIGTEST-Members',
        'queued_emails': ['alice@migtest.example', 'bob@migtest.example'],
    }
    return src, expected


def team_with_role_assignment():
    """Team is assigned to a non-admin role (admin roles reject team adds)."""
    team_src = {
        'uid': 't-with-role', 'name': 'MIGTEST-RoleTeam',
        'restricts': '', 'node': f'{SOURCE_ROOT}\\{SCOPE_NODE}',
        'user_count': 0, 'role_count': 1,
    }
    role_src = {
        'role_id': '700', 'name': 'MIGTEST-PlainRole',
        'node': f'{SOURCE_ROOT}\\{SCOPE_NODE}',
        'managed_nodes': [],  # non-admin
        'teams': [{'team_name': 'MIGTEST-RoleTeam'}],
    }
    expected = {'team': 'MIGTEST-RoleTeam', 'role': 'MIGTEST-PlainRole',
                'is_admin': False}
    return (team_src, role_src), expected


# ─── Role fixtures ──────────────────────────────────────────────────────────


# Privileges Commander supports for managed_node bindings (12 — covers the
# 11-privilege fan-out used by the source reference Keeper Admin role).
ALL_MANAGED_PRIVILEGES = [
    'MANAGE_NODES', 'MANAGE_USER', 'MANAGE_ROLES', 'MANAGE_TEAMS',
    'MANAGE_REPORTS', 'MANAGE_SSO', 'DEVICE_APPROVAL', 'MANAGE_BRIDGE',
    'RUN_COMPLIANCE_REPORTS', 'TRANSFER_ACCOUNT', 'SHARING_ADMINISTRATOR',
    'MANAGE_RECORD_TYPES',
]


def role_with_new_user_default():
    """Role flagged as the default for new user invites."""
    src = {
        'role_id': '500', 'name': 'MIGTEST-NewUserDefault',
        'node': f'{SOURCE_ROOT}\\{SCOPE_NODE}',
        'default_role': True,
        'managed_nodes': [], 'enforcements': {},
        'users': [], 'teams': [],
    }
    expected = {'name': 'MIGTEST-NewUserDefault', 'new_user': 'on',
                'default_role': True}
    return src, expected


def role_with_managed_node_all_privileges():
    """Role admins MIGRATION-TEST-NODE with every privilege Commander knows."""
    src = {
        'role_id': '501', 'name': 'MIGTEST-FullAdmin',
        'node': f'{SOURCE_ROOT}\\{SCOPE_NODE}',
        'managed_nodes': [{
            'node_name': f'{SOURCE_ROOT}\\{SCOPE_NODE}',
            'cascade': True,
            'privileges': list(ALL_MANAGED_PRIVILEGES),
        }],
        'enforcements': {}, 'users': [], 'teams': [],
    }
    expected = {
        'name': 'MIGTEST-FullAdmin',
        'managed_node': f'{TARGET_ROOT}\\{SCOPE_NODE}',
        'cascade': 'on',
        'privileges': list(ALL_MANAGED_PRIVILEGES),
    }
    return src, expected


def role_with_every_boolean_enforcement():
    """Role with the boolean (require_*/restrict_*) enforcement family populated."""
    booleans = {
        'require_two_factor': True,
        'restrict_persistent_login': True,
        'stay_logged_in_default': False,
        'restrict_export': True,
        'restrict_file_upload': False,
        'restrict_offline_access': True,
        'restrict_email_change': True,
        'require_device_approval': True,
        'send_invite_at_registration': False,
    }
    src = {
        'role_id': '502', 'name': 'MIGTEST-AllBooleans',
        'node': f'{SOURCE_ROOT}\\{SCOPE_NODE}',
        'managed_nodes': [], 'enforcements': dict(booleans),
        'users': [], 'teams': [],
    }
    expected = {'name': 'MIGTEST-AllBooleans',
                'enforcements': dict(booleans)}
    return src, expected


def role_with_long_enforcements():
    """Role with integer enforcements (length / count / minutes types)."""
    longs = {
        'master_password_minimum_length': 16,
        'master_password_minimum_special': 2,
        'master_password_minimum_digits': 2,
        'master_password_minimum_lower': 2,
        'master_password_minimum_upper': 2,
        'logout_timer_desktop': 600,
        'minimum_pbkdf2_iterations': 600000,
    }
    src = {
        'role_id': '503', 'name': 'MIGTEST-LongEnforcements',
        'node': f'{SOURCE_ROOT}\\{SCOPE_NODE}',
        'managed_nodes': [], 'enforcements': dict(longs),
        'users': [], 'teams': [],
    }
    expected = {'name': 'MIGTEST-LongEnforcements',
                'enforcements': dict(longs)}
    return src, expected


def role_with_string_enforcements():
    """Role with string-shaped enforcements (domain / message values)."""
    strings = {
        'restrict_domain_access': 'example.com,migtest.example',
        'restrict_domain_create': 'migtest.example',
        'restrict_personal_using_business_domains':
            'migtest.example,partner.example',
    }
    src = {
        'role_id': '504', 'name': 'MIGTEST-StringEnforcements',
        'node': f'{SOURCE_ROOT}\\{SCOPE_NODE}',
        'managed_nodes': [], 'enforcements': dict(strings),
        'users': [], 'teams': [],
    }
    expected = {'name': 'MIGTEST-StringEnforcements',
                'enforcements': dict(strings)}
    return src, expected


def role_with_ternary_enforcements():
    """Role enforcement ternary handling.

    Commander's ENFORCEMENTS dict in v17.2.13 has zero `ternary`-typed
    keys — the type exists in Commander source but isn't used by any
    current enforcement. We assert the type-system keeps working: any
    ternary keys discovered in the dict at runtime are exposed via the
    expected payload. Today the list is empty; a future Commander
    upgrade that adds ternary keys will populate it automatically and
    keep this test honest.
    """
    # Commander is a hard install dep of keepercommander.commands.keeper_tenant_migrate, so the
    # import is unconditional here — we resolve the live ENFORCEMENTS
    # dict so the fixture stays honest if Commander adds ternary keys
    # in a future release.
    from keepercommander.constants import ENFORCEMENTS
    ternary_keys = sorted(k for k, v in ENFORCEMENTS.items()
                          if v == 'ternary')
    enfs = {k: 'enable' for k in ternary_keys}
    src = {
        'role_id': '505', 'name': 'MIGTEST-TernaryEnforcements',
        'node': f'{SOURCE_ROOT}\\{SCOPE_NODE}',
        'managed_nodes': [], 'enforcements': enfs,
        'users': [], 'teams': [],
    }
    expected = {'name': 'MIGTEST-TernaryEnforcements',
                'ternary_keys_known': ternary_keys,
                'enforcements': enfs}
    return src, expected


def role_with_ip_whitelist():
    """Role gates login by IP — value is a comma-list of CIDR blocks."""
    src = {
        'role_id': '506', 'name': 'MIGTEST-IPGated',
        'node': f'{SOURCE_ROOT}\\{SCOPE_NODE}',
        'managed_nodes': [], 'enforcements': {
            'restrict_ip_addresses':
                '10.0.0.0/8,192.168.0.0/16,203.0.113.42/32',
        },
        'users': [], 'teams': [],
    }
    expected = {'name': 'MIGTEST-IPGated',
                'restrict_ip_addresses':
                    '10.0.0.0/8,192.168.0.0/16,203.0.113.42/32'}
    return src, expected


def role_with_two_factor_duration():
    """Role enforces 2FA with a non-default `stay logged in` duration."""
    src = {
        'role_id': '507', 'name': 'MIGTEST-2FATimer',
        'node': f'{SOURCE_ROOT}\\{SCOPE_NODE}',
        'managed_nodes': [], 'enforcements': {
            'require_two_factor': True,
            'two_factor_duration_desktop': 30,  # days
            'two_factor_duration_mobile': 30,
            'two_factor_duration_web': 0,       # every session
        },
        'users': [], 'teams': [],
    }
    expected = {'name': 'MIGTEST-2FATimer',
                'require_two_factor': True,
                'two_factor_duration_desktop': 30,
                'two_factor_duration_mobile': 30,
                'two_factor_duration_web': 0}
    return src, expected


def role_with_password_complexity_file():
    """Role with `generated_password_complexity` — routed through Phase-C FILE."""
    complexity = {
        'minLength': 16, 'requireDigits': True, 'requireUpper': True,
        'requireLower': True, 'requireSpecial': True, 'maxLength': 64,
    }
    src = {
        'role_id': '508', 'name': 'MIGTEST-Complexity',
        'node': f'{SOURCE_ROOT}\\{SCOPE_NODE}',
        'managed_nodes': [], 'enforcements': {
            'generated_password_complexity': complexity,
        },
        'users': [], 'teams': [],
    }
    expected = {'name': 'MIGTEST-Complexity',
                'complexity_phase': 'FILE',
                'complexity_value': complexity}
    return src, expected


def role_with_require_account_share():
    """Role's require_account_share resolves to its OWN role_id (self-ref)."""
    role_id = '509'
    src = {
        'role_id': role_id, 'name': 'MIGTEST-AcctShare',
        'node': f'{SOURCE_ROOT}\\{SCOPE_NODE}',
        'managed_nodes': [], 'enforcements': {
            'require_account_share': role_id,
        },
        'users': [], 'teams': [],
    }
    expected = {'name': 'MIGTEST-AcctShare',
                'require_account_share_role_name': 'MIGTEST-AcctShare'}
    return src, expected


def role_with_restrict_record_types():
    """Role restricts which record types its users can create."""
    src = {
        'role_id': '510', 'name': 'MIGTEST-RestrictedTypes',
        'node': f'{SOURCE_ROOT}\\{SCOPE_NODE}',
        'managed_nodes': [], 'enforcements': {
            'restrict_record_types': 'login,bankAccount,sshKeys',
        },
        'users': [], 'teams': [],
    }
    expected = {'name': 'MIGTEST-RestrictedTypes',
                'restrict_record_types': 'login,bankAccount,sshKeys'}
    return src, expected


def role_with_user_assignments():
    """Role with explicit user (username) assignments."""
    src = {
        'role_id': '511', 'name': 'MIGTEST-RoleWithUsers',
        'node': f'{SOURCE_ROOT}\\{SCOPE_NODE}',
        'managed_nodes': [], 'enforcements': {},
        'users': [
            {'username': 'alice@migtest.example'},
            {'username': 'bob@migtest.example'},
        ],
        'teams': [],
    }
    expected = {
        'name': 'MIGTEST-RoleWithUsers',
        'user_emails': ['alice@migtest.example', 'bob@migtest.example'],
    }
    return src, expected


def role_with_team_assignments():
    """Non-admin role with team assignments (admin roles reject team adds)."""
    src = {
        'role_id': '512', 'name': 'MIGTEST-RoleWithTeams',
        'node': f'{SOURCE_ROOT}\\{SCOPE_NODE}',
        'managed_nodes': [],  # non-admin
        'enforcements': {},
        'users': [],
        'teams': [
            {'team_name': 'MIGTEST-Open'},
            {'team_name': 'MIGTEST-Members'},
        ],
    }
    expected = {
        'name': 'MIGTEST-RoleWithTeams',
        'team_names': ['MIGTEST-Open', 'MIGTEST-Members'],
        'is_admin': False,
    }
    return src, expected


# ─── Shared folder fixtures ────────────────────────────────────────────────


def sf_at_root_level():
    """Shared folder created at the personal-vault root (no parent)."""
    src = {
        'uid': 'sf-root', 'name': 'MIGTEST-RootSF',
        'type': 'shared_folder',
        'parent_uid': '', 'parent_chain': [],
        'default_manage_users': False,
        'default_manage_records': False,
        'default_can_edit': False,
        'default_can_share': False,
    }
    expected = {'name': 'MIGTEST-RootSF', 'parent_uid': '',
                'type': 'shared_folder'}
    return src, expected


def sf_inside_user_folder():
    """User folder → shared folder hierarchy. Parent must land before child."""
    parent_uf = {
        'uid': 'uf-1', 'name': 'MIGTEST-UF-Parent',
        'type': 'user_folder', 'parent_uid': '', 'parent_chain': [],
    }
    sf = {
        'uid': 'sf-nested', 'name': 'MIGTEST-NestedSF',
        'type': 'shared_folder',
        'parent_uid': 'uf-1', 'parent_chain': ['uf-1'],
        'default_manage_users': False,
        'default_manage_records': False,
        'default_can_edit': False,
        'default_can_share': False,
    }
    expected = {'sf_name': 'MIGTEST-NestedSF',
                'parent_uf_name': 'MIGTEST-UF-Parent'}
    return [parent_uf, sf], expected


def sf_with_slash_in_name():
    """SF whose name contains a literal `/` — Commander escapes as `//`."""
    src = {
        'uid': 'sf-slash', 'name': 'MIGTEST-Path/With/Slash',
        'type': 'shared_folder',
        'parent_uid': '', 'parent_chain': [],
        'default_manage_users': False,
        'default_manage_records': False,
        'default_can_edit': False,
        'default_can_share': False,
    }
    expected = {'name': 'MIGTEST-Path/With/Slash'}
    return src, expected


def sf_with_multiple_user_members():
    """SF with three users at distinct permission tiers."""
    src = {
        'uid': 'sf-multi-users', 'name': 'MIGTEST-MultiUserSF',
        'type': 'shared_folder',
        'parent_uid': '', 'parent_chain': [],
        'default_manage_users': False,
        'default_manage_records': False,
        'default_can_edit': False,
        'default_can_share': False,
        'users': [
            {'username': 'admin@migtest.example',
             'manage_users': True, 'manage_records': True,
             'can_edit': True, 'can_share': True},
            {'username': 'editor@migtest.example',
             'manage_users': False, 'manage_records': False,
             'can_edit': True, 'can_share': False},
            {'username': 'viewer@migtest.example',
             'manage_users': False, 'manage_records': False,
             'can_edit': False, 'can_share': False},
        ],
        'teams': [],
        'records': [],
    }
    expected = {'name': 'MIGTEST-MultiUserSF',
                'user_perms': src['users']}
    return src, expected


def sf_with_team_members():
    """SF with team-level grants instead of per-user grants."""
    src = {
        'uid': 'sf-team', 'name': 'MIGTEST-TeamSF',
        'type': 'shared_folder',
        'parent_uid': '', 'parent_chain': [],
        'default_manage_users': False,
        'default_manage_records': False,
        'default_can_edit': False,
        'default_can_share': False,
        'users': [],
        'teams': [
            {'name': 'MIGTEST-FullLockdown',
             'manage_users': True, 'manage_records': True},
            {'name': 'MIGTEST-Open',
             'manage_users': False, 'manage_records': False},
        ],
        'records': [],
    }
    expected = {'name': 'MIGTEST-TeamSF',
                'team_perms': src['teams']}
    return src, expected


def sf_with_subfolders():
    """SF containing two shared_folder_folder children (broker/, data/)."""
    sf = {
        'uid': 'sf-parent', 'name': 'MIGTEST-WithSubs',
        'type': 'shared_folder',
        'parent_uid': '', 'parent_chain': [],
        'default_manage_users': False,
        'default_manage_records': False,
        'default_can_edit': False,
        'default_can_share': False,
    }
    broker = {
        'uid': 'sff-broker', 'name': 'MIGTEST-broker',
        'type': 'shared_folder_folder',
        'parent_uid': 'sf-parent', 'parent_chain': ['sf-parent'],
        'shared_folder_uid': 'sf-parent',
    }
    data = {
        'uid': 'sff-data', 'name': 'MIGTEST-data',
        'type': 'shared_folder_folder',
        'parent_uid': 'sf-parent', 'parent_chain': ['sf-parent'],
        'shared_folder_uid': 'sf-parent',
    }
    expected = {
        'sf_name': 'MIGTEST-WithSubs',
        'subfolder_names': ['MIGTEST-broker', 'MIGTEST-data'],
    }
    return [sf, broker, data], expected


def sf_with_records_inside():
    """SF that holds two records — record_uid carriage tested via uid_map."""
    sf = {
        'uid': 'sf-records', 'name': 'MIGTEST-WithRecords',
        'type': 'shared_folder',
        'parent_uid': '', 'parent_chain': [],
        'default_manage_users': False,
        'default_manage_records': False,
        'default_can_edit': False,
        'default_can_share': False,
        'users': [], 'teams': [],
        'records': [
            {'record_uid': 'rec-A', 'can_edit': True, 'can_share': False},
            {'record_uid': 'rec-B', 'can_edit': False, 'can_share': False},
        ],
    }
    expected = {'sf_name': 'MIGTEST-WithRecords',
                'record_uids': ['rec-A', 'rec-B']}
    return sf, expected


def sf_with_default_permissions():
    """SF where default_manage_* / default_can_* are all opted in."""
    src = {
        'uid': 'sf-defaults', 'name': 'MIGTEST-DefaultsAllOn',
        'type': 'shared_folder',
        'parent_uid': '', 'parent_chain': [],
        'default_manage_users': True,
        'default_manage_records': True,
        'default_can_edit': True,
        'default_can_share': True,
    }
    expected = {'name': 'MIGTEST-DefaultsAllOn',
                'default_manage_users': True,
                'default_manage_records': True,
                'default_can_edit': True,
                'default_can_share': True}
    return src, expected


# ─── User fixtures ─────────────────────────────────────────────────────────


def user_active_with_master_password():
    """Standard active user — Category D from transition plan (already-on-target)."""
    src = {
        'id': 'u1', 'email': 'mp.user@migtest.example',
        'status': 'active', 'transfer_status': '',
        'node': f'{SOURCE_ROOT}\\{SCOPE_NODE}',
        'teams': [], 'roles': [],
        'aliases': [], '2fa_enabled': False,
        'job_title': 'MIGTEST Engineer',
        'is_sso': False,
    }
    expected = {'email': 'mp.user@migtest.example',
                'status': 'active',
                'job_title': 'MIGTEST Engineer'}
    return src, expected


def user_in_specific_node():
    """User attached to a non-root node — leaf-of(node) is the --node arg."""
    src = {
        'id': 'u2', 'email': 'leaf.user@migtest.example',
        'status': 'active', 'transfer_status': '',
        'node': f'{SOURCE_ROOT}\\{SCOPE_NODE}\\MIGTEST-Branch',
        'teams': [], 'roles': [],
        'aliases': [], '2fa_enabled': False,
        'job_title': '',
    }
    expected = {'email': 'leaf.user@migtest.example',
                'expected_node_leaf': 'MIGTEST-Branch'}
    return src, expected


def user_with_team_membership():
    src = {
        'id': 'u3', 'email': 'team.user@migtest.example',
        'status': 'active', 'transfer_status': '',
        'node': f'{SOURCE_ROOT}\\{SCOPE_NODE}',
        'teams': ['MIGTEST-Open', 'MIGTEST-Members'],
        'roles': [],
        'aliases': [], '2fa_enabled': False,
        'job_title': '',
    }
    expected = {'email': 'team.user@migtest.example',
                'teams': ['MIGTEST-Open', 'MIGTEST-Members']}
    return src, expected


def user_with_role_assignment():
    src = {
        'id': 'u4', 'email': 'role.user@migtest.example',
        'status': 'active', 'transfer_status': '',
        'node': f'{SOURCE_ROOT}\\{SCOPE_NODE}',
        'teams': [],
        'roles': ['MIGTEST-PlainRole', 'MIGTEST-RoleWithUsers'],
        'aliases': [], '2fa_enabled': False,
        'job_title': '',
    }
    expected = {'email': 'role.user@migtest.example',
                'roles': ['MIGTEST-PlainRole', 'MIGTEST-RoleWithUsers']}
    return src, expected


def user_transfer_acceptance_accepted():
    """User where transfer_acceptance_status='accepted' on source side."""
    src = {
        'id': 'u5', 'email': 'transfer.ok@migtest.example',
        'status': 'active', 'transfer_status': 'accepted',
        'node': f'{SOURCE_ROOT}\\{SCOPE_NODE}',
        'teams': [], 'roles': [],
        'aliases': [], '2fa_enabled': False,
        'job_title': '',
    }
    expected = {'email': 'transfer.ok@migtest.example',
                'transfer_status': 'accepted'}
    return src, expected


def user_invited_never_activated():
    """User in the invited-but-pending state (Category E)."""
    src = {
        'id': 'u6', 'email': 'pending.invite@migtest.example',
        'status': 'invited', 'transfer_status': '',
        'node': f'{SOURCE_ROOT}\\{SCOPE_NODE}',
        'teams': [], 'roles': [],
        'aliases': [], '2fa_enabled': False,
        'job_title': '',
    }
    expected = {'email': 'pending.invite@migtest.example',
                'status': 'invited'}
    return src, expected


# ─── Record fixtures ───────────────────────────────────────────────────────


def record_login_full_fields():
    """Login record with title/login/password/URL/notes populated."""
    src = {
        'record_uid': 'rec-login-full',
        'type': 'login',
        'title': 'MIGTEST-LoginFull',
        'fields': [
            {'type': 'login', 'value': ['svcacct@migtest.example']},
            {'type': 'password', 'value': ['CorrectHorseBatteryStaple']},
            {'type': 'url', 'value': ['https://app.migtest.example/login']},
        ],
        'custom': [],
        'notes': 'Production credentials — rotate quarterly.',
    }
    expected = {
        'title': 'MIGTEST-LoginFull',
        'login': 'svcacct@migtest.example',
        'password': 'CorrectHorseBatteryStaple',
        'login_url': 'https://app.migtest.example/login',
        'notes': 'Production credentials — rotate quarterly.',
    }
    return src, expected


def record_with_custom_fields():
    """Record carrying labelled custom fields — values must round-trip."""
    src = {
        'record_uid': 'rec-cf',
        'type': 'login',
        'title': 'MIGTEST-CustomFields',
        'fields': [{'type': 'login', 'value': ['user@migtest.example']}],
        'custom': [
            {'type': 'text', 'label': 'Environment',
             'value': ['production']},
            {'type': 'text', 'label': 'Owner',
             'value': ['platform-team']},
            {'type': 'text', 'label': 'TicketId',
             'value': ['MIGTEST-1234']},
        ],
        'notes': '',
    }
    expected = {
        'title': 'MIGTEST-CustomFields',
        'custom_fields': {
            'Environment': 'production',
            'Owner': 'platform-team',
            'TicketId': 'MIGTEST-1234',
        },
    }
    return src, expected


def record_with_attachment():
    """Record with two fileRef attachments — attachment_count must be 2."""
    src = {
        'record_uid': 'rec-attach',
        'type': 'login',
        'title': 'MIGTEST-WithAttachments',
        'fields': [
            {'type': 'login', 'value': ['user@migtest.example']},
            {'type': 'fileRef',
             'value': ['file-uid-1', 'file-uid-2']},
        ],
        'custom': [],
        'notes': '',
    }
    expected = {'title': 'MIGTEST-WithAttachments',
                'attachment_count': 2}
    return src, expected


def record_with_totp_seed():
    """Record carrying an oneTimeCode (otpauth://) value."""
    seed = ('otpauth://totp/MIGTEST:svc?secret=JBSWY3DPEHPK3PXP'
            '&issuer=MIGTEST')
    src = {
        'record_uid': 'rec-totp',
        'type': 'login',
        'title': 'MIGTEST-WithTOTP',
        'fields': [
            {'type': 'login', 'value': ['svc@migtest.example']},
            {'type': 'oneTimeCode', 'value': [seed]},
        ],
        'custom': [],
        'notes': '',
    }
    expected = {'title': 'MIGTEST-WithTOTP',
                'has_totp': True,
                'totp_secret': seed}
    return src, expected


def record_in_shared_folder():
    """Record placed in a top-level SF — uid_map links source to target SF."""
    sf = {
        'uid': 'sf-rec-direct', 'name': 'MIGTEST-RecDirectSF',
        'type': 'shared_folder',
        'parent_uid': '', 'parent_chain': [],
        'default_manage_users': False,
        'default_manage_records': False,
        'default_can_edit': False,
        'default_can_share': False,
    }
    record = {
        'record_uid': 'rec-in-sf',
        'type': 'login',
        'title': 'MIGTEST-RecInSF',
        'fields': [{'type': 'login', 'value': ['x@migtest.example']}],
        'custom': [],
        'notes': '',
        'folder_uid': 'sf-rec-direct',
    }
    expected = {'record_title': 'MIGTEST-RecInSF',
                'folder_name': 'MIGTEST-RecDirectSF'}
    return (sf, record), expected


def record_in_subfolder_of_shared_folder():
    """Record placed in shared_folder_folder under SF (subfolder hierarchy)."""
    sf = {
        'uid': 'sf-deep', 'name': 'MIGTEST-DeepSF',
        'type': 'shared_folder',
        'parent_uid': '', 'parent_chain': [],
        'default_manage_users': False,
        'default_manage_records': False,
        'default_can_edit': False,
        'default_can_share': False,
    }
    sub = {
        'uid': 'sff-deep', 'name': 'MIGTEST-DeepSub',
        'type': 'shared_folder_folder',
        'parent_uid': 'sf-deep', 'parent_chain': ['sf-deep'],
        'shared_folder_uid': 'sf-deep',
    }
    record = {
        'record_uid': 'rec-deep',
        'type': 'login',
        'title': 'MIGTEST-DeepRecord',
        'fields': [{'type': 'login', 'value': ['x@migtest.example']}],
        'custom': [],
        'notes': '',
        'folder_uid': 'sff-deep',
    }
    expected = {'record_title': 'MIGTEST-DeepRecord',
                'folder_name': 'MIGTEST-DeepSub',
                'sf_name': 'MIGTEST-DeepSF'}
    return (sf, sub, record), expected


def record_owned_by_specific_user():
    """Record whose owner is a non-admin user (recorded in user_permissions)."""
    src = {
        'record_uid': 'rec-owner',
        'type': 'login',
        'title': 'MIGTEST-OwnedByUser',
        'fields': [{'type': 'login', 'value': ['x@migtest.example']}],
        'custom': [],
        'notes': '',
        'user_permissions': [
            {'username': 'role.user@migtest.example',
             'owner': True, 'editable': True, 'shareable': True},
        ],
    }
    expected = {'title': 'MIGTEST-OwnedByUser',
                'owner_email': 'role.user@migtest.example'}
    return src, expected


def record_directly_shared_to_user():
    """Record with non-owner share grants — extract_direct_shares must see them."""
    src = {
        'record_uid': 'rec-shared',
        'type': 'login',
        'title': 'MIGTEST-DirectShare',
        'fields': [{'type': 'login', 'value': ['svc@migtest.example']}],
        'custom': [],
        'notes': '',
        'user_permissions': [
            {'username': 'admin@migtest.example',
             'owner': True, 'editable': True, 'shareable': True},
            {'username': 'reader@migtest.example',
             'owner': False, 'editable': False, 'shareable': False,
             'share_admin': False},
            {'username': 'editor@migtest.example',
             'owner': False, 'editable': True, 'shareable': True,
             'share_admin': False},
        ],
    }
    expected = {
        'title': 'MIGTEST-DirectShare',
        'direct_shares': [
            {'username': 'reader@migtest.example',
             'editable': False, 'shareable': False, 'share_admin': False},
            {'username': 'editor@migtest.example',
             'editable': True, 'shareable': True, 'share_admin': False},
        ],
    }
    return src, expected


# ─── Combined fixture for end-to-end test ─────────────────────────────────


def combined_inventory():
    """Build one inventory dict that exercises every fixture above.

    Returns the inventory dict (keyed exactly like InventoryAssembler.build()
    output) plus a vault_folders list ready for StructureRestore.
    step_vault_folders.
    """
    nodes = [
        # Scope root itself.
        {'id': '100', 'name': SCOPE_NODE, 'parent': SOURCE_ROOT,
         'isolated': False},
    ]
    custom_node, _ = node_with_custom_name()
    nodes.append(custom_node)
    nested_nodes, _ = node_nested_child()
    nodes.extend(nested_nodes)
    iso_node, _ = node_isolated()
    nodes.append(iso_node)

    teams = []
    for fn in (team_with_restrict_edit, team_with_restrict_share,
                team_with_restrict_view, team_with_all_three_restrictions,
                team_with_no_restrictions, team_with_users_assigned):
        team_src, _ = fn()
        teams.append(team_src)
    (team_with_role_src, role_with_team_src), _ = team_with_role_assignment()
    teams.append(team_with_role_src)

    roles = []
    for fn in (role_with_new_user_default,
                role_with_managed_node_all_privileges,
                role_with_every_boolean_enforcement,
                role_with_long_enforcements,
                role_with_string_enforcements,
                role_with_ternary_enforcements,
                role_with_ip_whitelist,
                role_with_two_factor_duration,
                role_with_password_complexity_file,
                role_with_require_account_share,
                role_with_restrict_record_types,
                role_with_user_assignments,
                role_with_team_assignments):
        role_src, _ = fn()
        roles.append(role_src)
    roles.append(role_with_team_src)

    users = []
    for fn in (user_active_with_master_password, user_in_specific_node,
                user_with_team_membership, user_with_role_assignment,
                user_transfer_acceptance_accepted,
                user_invited_never_activated):
        user_src, _ = fn()
        users.append(user_src)

    # Shared folders inventory dict (passed to validator phase_shared_folders).
    sf_inventory = []
    for fn in (sf_at_root_level, sf_with_slash_in_name,
                sf_with_multiple_user_members, sf_with_team_members,
                sf_with_default_permissions):
        sf_src, _ = fn()
        sf_inventory.append(sf_src)
    sf_records_src, _ = sf_with_records_inside()
    sf_inventory.append(sf_records_src)

    # vault_folders list (for step_vault_folders).
    vault_folders = []
    for fn in (sf_at_root_level, sf_with_slash_in_name,
                sf_with_default_permissions):
        vf_src, _ = fn()
        vault_folders.append(vf_src)
    nested_pair, _ = sf_inside_user_folder()
    vault_folders.extend(nested_pair)
    sub_chain, _ = sf_with_subfolders()
    vault_folders.extend(sub_chain)
    vault_folders.append(sf_records_src)

    # Records inventory entries (post-summarize_record shape).
    records = []
    for fn in (record_login_full_fields, record_with_custom_fields,
                record_with_attachment, record_with_totp_seed):
        rec_src, _ = fn()
        records.append(_summarize_for_inventory(rec_src))
    sf_pair, _ = record_in_shared_folder()
    rec_in_sf = _summarize_for_inventory(sf_pair[1])
    records.append(rec_in_sf)
    deep_triple, _ = record_in_subfolder_of_shared_folder()
    rec_deep = _summarize_for_inventory(deep_triple[2])
    records.append(rec_deep)
    rec_owner, _ = record_owned_by_specific_user()
    records.append(_summarize_for_inventory(rec_owner))
    rec_share, _ = record_directly_shared_to_user()
    records.append(_summarize_for_inventory(rec_share))

    inventory = {
        'source_user': 'admin@migtest.example',
        'source_root': SOURCE_ROOT,
        'target_root': TARGET_ROOT,
        'scope_node': SCOPE_NODE,
        'prefix_filter': PREFIX,
        'entities': {
            'nodes': nodes, 'teams': teams, 'roles': roles,
            'users': users, 'shared_folders': sf_inventory,
            'records': records,
        },
        'vault_folders': vault_folders,
    }
    return inventory


def _summarize_for_inventory(rec):
    """Mirror inventory.summarize_record(include_fields=True) so the
    end-to-end test compares apples to apples against validator output."""
    from keepercommander.commands.keeper_tenant_migrate.inventory import summarize_record
    return summarize_record(rec, include_fields=True)
