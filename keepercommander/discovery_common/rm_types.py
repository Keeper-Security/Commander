from __future__ import annotations
from pydantic import BaseModel
from typing import Optional, List


class RmResponse(BaseModel):
    """
    Generic response for action.

    :param notes: A list of notes on what happened in the action.
    """
    notes: List[str] = []


class RmScriptResponse(BaseModel):
    """
    The response from running a script

    :param script: The script with all placeholders replaced.
    :param stdout: The STDOUT from running the script.
    :param stderr: The STDERR from running the script.
    """
    script: str
    stdout: Optional[str] = None
    stderr: Optional[str] = None


class RmKeyValue(BaseModel):
    """
    A key/values pair.

    :param key: The key for the value.
    :param value: The value stored a string.
    """
    key: str
    value: str


class RmInformation(BaseModel):
    name: str
    record_type: str
    version: Optional[str] = None
    version_number: Optional[str] = None
    supports_groups: bool = False
    supports_roles: bool = False
    can_create_users: bool = False
    can_delete_users: bool = False
    can_run_scripts: bool = False
    settings: List[RmKeyValue] = []


class RmUser(BaseModel):
    id: str
    name: str
    desc: Optional[str] = None


class RmNewUser(BaseModel):
    id: str
    name: str
    desc: Optional[str] = None
    password: Optional[str] = None
    private_key: Optional[str] = None
    public_key: Optional[str] = None
    private_key_passphrase: Optional[str] = None
    connect_database: Optional[str] = None
    mode: Optional[str] = None
    dn: Optional[str] = None
    uid: Optional[str] = None
    home_dir: Optional[str] = None


class RmRole(BaseModel):
    id: str
    name: Optional[str] = None
    desc: Optional[str] = None
    users: List[RmUser] = []


class RmGroup(BaseModel):
    id: str
    name: Optional[str] = None
    desc: Optional[str] = None
    users: List[RmUser] = []


class RmMetaBase(BaseModel):
    pass


class RmStubMeta(RmMetaBase):
    pass


class RmAwsUserAddMeta(RmMetaBase):
    console_access:  Optional[bool] = True
    path: Optional[str] = "/"
    permission_boundary_arn: Optional[str] = None
    password_reset_required: Optional[bool] = False
    tags: List[RmKeyValue] = []
    roles: List[str] = []
    groups: List[str] = []
    policies: List[str] = []


class RmAwsRoleAddMeta(RmMetaBase):
    path: Optional[str] = None
    trust_policy_json: Optional[str] = None
    duration_seconds: Optional[int] = None
    attach_policy_arns: List[str] = []
    permission_boundary_arn: Optional[str] = None
    description: Optional[str] = None
    tags: List[RmKeyValue] = []


class RmAwsGroupAddMeta(RmMetaBase):
    path: Optional[str] = None
    inline_policy_json: List[str] = []
    attach_policy_arns: List[str] = []


class RmAzureUserAddMeta(RmMetaBase):
    account_enabled: Optional[bool] = True
    display_name: Optional[str] = None
    on_premise_immutable_id: Optional[str] = None
    password_reset_required: Optional[bool] = False
    password_reset_required_with_mfa: Optional[bool] = False
    roles: List[str] = []
    groups: List[str] = []


class RmAzureRoleAddMeta(RmMetaBase):
    custom_role_json: str
    description: Optional[str] = None


class RmAzureGroupAddMeta(RmMetaBase):
    mail_enabled: bool = False
    mail_nickname: Optional[str] = None
    security_enabled: bool = True
    group_types: List[str] = []


class RmGcpUserAddMeta(RmMetaBase):
    account_enabled: Optional[bool] = True
    display_name: Optional[str] = None
    password_reset_required: Optional[bool] = False
    password_reset_required_with_mfa: Optional[bool] = False
    groups: List[str] = []


class RmGcpGroupAddMeta(RmMetaBase):
    group_types: List[str] = []


class RmOktaUserAddMeta(RmMetaBase):
    account_enabled: Optional[bool] = True
    display_name: Optional[str] = None
    password_reset_required: Optional[bool] = False
    password_reset_required_with_mfa: Optional[bool] = False
    groups: List[str] = []


class RmOktaGroupAddMeta(RmMetaBase):
    group_types: List[str] = []


class RmDomainUserAddMeta(RmMetaBase):
    roles: List[str] = []
    groups: List[str] = []

# DATABASE


class RmMySQLBaseAddMeta(RmMetaBase):

    """
    Shared model for MySQL and MariaDB of the common GRANT attributes.
    """

    # MariaDB will give all expect GRANT OPTION
    grant_all_privileges: List[str] = []

    # DATA
    grant_select: List[str] = ["*"]
    grant_insert: List[str] = ["*"]
    grant_update: List[str] = ["*"]
    grant_delete: List[str] = ["*"]

    # STRUCTURE
    grant_create: List[str] = []
    grant_alter: List[str] = []
    grant_drop: List[str] = []
    grant_index: List[str] = []
    grant_create_view: List[str] = []
    grant_show_view: List[str] = []
    grant_create_routine: List[str] = []
    grant_alter_routine: List[str] = []
    grant_trigger: List[str] = []
    grant_references: List[str] = []

    # TEMP TABLE
    grant_create_temp_tables: List[str] = []

    # EVENTS AND PROCEDURES
    grant_event: List[str] = []
    grant_execute: List[str] = []

    # LOCK
    grant_lock_tables: List[str] = []

    # ADMIN
    grant_grant_option: List[str] = []
    grant_create_user: List[str] = []
    grant_reload: List[str] = []
    grant_shutdown: List[str] = []
    grant_process: List[str] = []
    grant_file: List[str] = []
    grant_show_databases: List[str] = []
    grant_super: List[str] = []
    grant_rep_client: List[str] = []
    grant_rep_slave: List[str] = []
    grant_create_tablespace: List[str] = []


class RmMySQLUserAddMeta(RmMySQLBaseAddMeta):
    """
    MySQL user add meta information

    engine_type: mysql

    :param failed_login_attempts: Number of fail login attempts before locking the account.
    :param password_lockout_time: Number of days to wait before unlocking the account.
                                  Set to 0 to prevent unlock.
                                  Set to UNBOUNDED is lock forever.
    :param password_expire_days: Number of days before password is expired.
    :param password_history_count: Number of prior passwords that cannot be reused.
    :param password_history_days: Cannot reuse passwords used within N days.
    :param password_req_current: Current password is required to change password.
    :param password_req_ssl: Connection requires SSL.
    :param authentication_plugin: Authentication plugin.
    :param authentication_value: For the authentication plugin, additional required value.
    """

    failed_login_attempts: Optional[int] = None
    # days or UNBOUNDED
    password_lockout_time: Optional[str] = None
    password_expire_days: Optional[int] = None
    password_history_count: Optional[int] = None
    password_history_days: Optional[int] = None
    password_req_current: bool = False
    password_req_ssl: bool = False
    authentication_plugin: Optional[str] = None
    authentication_value: Optional[str] = None
    roles: List[str] = []


class RmMySQLRoleAddMeta(RmMetaBase):
    grant_script: Optional[str] = None


class RmMariaDbRoleAddMeta(RmMetaBase):

    with_admin: str = "CURRENT_USER"
    grant_script: Optional[str] = None


class RmMariaDbUserAddMeta(RmMySQLBaseAddMeta):
    authentication_plugin: Optional[str] = None
    authentication_value: Optional[str] = None
    roles: List[str] = []


# TODO: H
class RmMariaDbLUserAddMeta(RmMariaDbUserAddMeta):
    pass


class RmPostgreSqlUserAddMeta(RmMetaBase):
    """
    PostgreSQL user add meta information

    engine_type: postgres

    :param superuser: Make the user a superuser.
    :param create_db: Make can create databases.
    :param create_role: Make can create roles.
    """

    superuser: Optional[bool] = False
    create_db: Optional[bool] = False
    create_role: Optional[bool] = False
    inherit: Optional[bool] = False
    login: Optional[bool] = True
    replication: Optional[bool] = False
    bypass_rls: Optional[bool] = False
    connection_limit: Optional[int] = None
    valid_until: Optional[str] = None
    roles: List[str] = []
    inc_in_roles: List[str] = []
    inc_in_roles_as_admin: List[str] = []
    sysid: Optional[str] = None


class RmPostgreSqlRoleAddMeta(RmMetaBase):

    # Same as users
    superuser: Optional[bool] = False
    create_db: Optional[bool] = False
    create_role: Optional[bool] = False
    inherit: Optional[bool] = False
    login: Optional[bool] = False
    replication: Optional[bool] = False
    bypass_rls: Optional[bool] = False
    connection_limit: Optional[int] = None
    valid_until: Optional[str] = None
    roles: List[str] = []
    inc_in_roles: List[str] = []
    inc_in_roles_as_admin: List[str] = []
    sysid: Optional[str] = None

    # SQL to creat GRANTS
    grant_script: Optional[str] = None


class RmSqlServerUserAddMeta(RmMetaBase):
    allow_login: bool = True
    use_windows_auth: bool = False
    is_reader: bool = True
    is_writer: bool = True
    roles: List[str] = []


class RmSqlServerRoleAddMeta(RmMetaBase):
    """
    Meta information for adding a Sql Server role.

    :param authorization: The login that will own the new server role.
                          If no login is specified, the server role will be owned by the login that executes
                            CREATE SERVER ROLE.
    :param grant_script: The STDOUT from running the script.
    """

    authorization: Optional[str] = None
    grant_script: Optional[str] = None


class RmOracleGrant(BaseModel):
    """
    For system and role grants, there is an option to have ADMIN OPTION
    """

    allow: bool = False
    admin_option: bool = False


class RmOracleGrantObject(BaseModel):
    """
    For object grants.
    Allows object columns.
    """

    columns: List[str] = []
    object: str


class RmOracleUserAddMeta(RmMetaBase):

    """
    Oracle user add meta information

    :param profile: User uses this profile for resource limits and password policies.
    :param identified_externally: User uses OS authentication (IDENTIFIED EXTERNALLY).
    :param identified_globally: User uses directory authentication (IDENTIFIED GLOBALLY AS 'directory_DN').
    :param identified_globally_as: The 'directory_DN' used for identified_globally.

    """
    profile: Optional[str] = None
    identified_externally: bool = False
    identified_globally: bool = False
    identified_globally_as: Optional[str] = None

    # SYSTEM
    grant_create_session: RmOracleGrant = RmOracleGrant()
    grant_create_table: RmOracleGrant = RmOracleGrant()
    grant_create_view: RmOracleGrant = RmOracleGrant()
    grant_create_procedure: RmOracleGrant = RmOracleGrant()
    grant_create_sequence: RmOracleGrant = RmOracleGrant()
    grant_create_trigger: RmOracleGrant = RmOracleGrant()
    grant_create_synonym: RmOracleGrant = RmOracleGrant()
    grant_create_public_synonym: RmOracleGrant = RmOracleGrant()
    grant_create_materialized_view: RmOracleGrant = RmOracleGrant()
    grant_create_index: RmOracleGrant = RmOracleGrant()
    grant_create_type: RmOracleGrant = RmOracleGrant()
    grant_create_role: RmOracleGrant = RmOracleGrant()
    grant_create_user: RmOracleGrant = RmOracleGrant()
    grant_alter_user: RmOracleGrant = RmOracleGrant()
    grant_drop_user: RmOracleGrant = RmOracleGrant()
    grant_alter_system: RmOracleGrant = RmOracleGrant()
    grant_alter_database: RmOracleGrant = RmOracleGrant()
    grant_create_tablespace: RmOracleGrant = RmOracleGrant()
    grant_alter_tablespace: RmOracleGrant = RmOracleGrant()
    grant_drop_tablespace: RmOracleGrant = RmOracleGrant()
    grant_select_any_table: RmOracleGrant = RmOracleGrant()
    grant_insert_any_table: RmOracleGrant = RmOracleGrant()
    grant_update_any_table: RmOracleGrant = RmOracleGrant()
    grant_delete_any_table: RmOracleGrant = RmOracleGrant()
    grant_drop_any_table: RmOracleGrant = RmOracleGrant()
    grant_create_any_table: RmOracleGrant = RmOracleGrant()
    grant_alter_any_table: RmOracleGrant = RmOracleGrant()
    grant_create_any_index: RmOracleGrant = RmOracleGrant()
    grant_drop_any_index: RmOracleGrant = RmOracleGrant()
    grant_create_any_view: RmOracleGrant = RmOracleGrant()
    grant_drop_any_view: RmOracleGrant = RmOracleGrant()
    grant_execute_any_procedure: RmOracleGrant = RmOracleGrant()
    grant_create_any_procedure: RmOracleGrant = RmOracleGrant()
    grant_drop_any_procedure: RmOracleGrant = RmOracleGrant()
    grant_create_any_sequence: RmOracleGrant = RmOracleGrant()
    grant_drop_any_sequence: RmOracleGrant = RmOracleGrant()
    grant_grant_any_privilege: RmOracleGrant = RmOracleGrant()
    grant_grant_any_role: RmOracleGrant = RmOracleGrant()
    grant_grant_any_object_privilege: RmOracleGrant = RmOracleGrant()
    grant_unlimited_tablespace: RmOracleGrant = RmOracleGrant()
    grant_manage_tablespace: RmOracleGrant = RmOracleGrant()
    grant_audit_any: RmOracleGrant = RmOracleGrant()
    grant_analyze_any: RmOracleGrant = RmOracleGrant()
    grant_comment_any_table: RmOracleGrant = RmOracleGrant()
    grant_flashback_any_table: RmOracleGrant = RmOracleGrant()
    grant_debug_any_procedure: RmOracleGrant = RmOracleGrant()
    grant_administer_database_trigger: RmOracleGrant = RmOracleGrant()

    # OBJECT
    grant_select: List[RmOracleGrantObject] = []
    grant_insert: List[RmOracleGrantObject] = []
    grant_update: List[RmOracleGrantObject] = []
    grant_delete: List[RmOracleGrantObject] = []
    grant_alter: List[RmOracleGrantObject] = []
    grant_index: List[RmOracleGrantObject] = []
    grant_references: List[RmOracleGrantObject] = []
    grant_execute: List[RmOracleGrantObject] = []
    grant_read: List[RmOracleGrantObject] = []
    grant_write: List[RmOracleGrantObject] = []
    grant_debug: List[RmOracleGrantObject] = []
    grant_flashback: List[RmOracleGrantObject] = []
    grant_on_commit_refresh: List[RmOracleGrantObject] = []
    grant_query_rewrite: List[RmOracleGrantObject] = []
    grant_under: List[RmOracleGrantObject] = []

    # PREDEFINED
    grant_connect: RmOracleGrant = RmOracleGrant(allow=True)
    grant_resource: RmOracleGrant = RmOracleGrant(allow=True)
    grant_dba: RmOracleGrant = RmOracleGrant()
    grant_select_catalog_role: RmOracleGrant = RmOracleGrant()
    grant_execute_catalog_role: RmOracleGrant = RmOracleGrant()
    grant_delete_catalog_role: RmOracleGrant = RmOracleGrant()
    grant_exp_full_database: RmOracleGrant = RmOracleGrant()
    grant_imp_full_database: RmOracleGrant = RmOracleGrant()
    grant_recovery_catalog_owner: RmOracleGrant = RmOracleGrant()
    grant_scheduler_admin: RmOracleGrant = RmOracleGrant()
    grant_aq_administrator_role: RmOracleGrant = RmOracleGrant()
    grant_datapump_exp_full_database: RmOracleGrant = RmOracleGrant()
    grant_datapump_imp_full_database: RmOracleGrant = RmOracleGrant()

    roles: List[str] = []


class RmOracleRoleAddMeta(RmMetaBase):
    not_identified: bool = False
    identified_by_password: Optional[str] = None
    identified_using: Optional[str] = None
    identified_externally: bool = False
    identified_globally: bool = False
    identified_globally_as: Optional[str] = None
    container: Optional[str] = None

    grant_script: Optional[str] = None


class RmMongoDbUserAddMeta(RmMetaBase):
    roles: List[str] = []


class RmMongoDbRoleAddMeta(RmMetaBase):
    js_script: Optional[str] = None


# MACHINE


class RmUserDeleteBaseMeta(RmMetaBase):
    remove_home_dir: Optional[bool] = True


class RmLinuxGroupAddMeta(RmMetaBase):
    gid: Optional[int] = None
    system_group: Optional[bool] = False


class RmMachineUserAddMeta(RmMetaBase):
    use_password: Optional[bool] = True
    use_private_key: Optional[bool] = False
    use_private_key_passphrase: Optional[bool] = False
    use_private_key_type: Optional[str] = "ecdsa_sha2_nistp521"
    private_key: Optional[str] = None
    private_key_passphrase: Optional[str] = None
    authorized_keys: List[str] = []

    # SSH certificate
    # This is used if SSH, on the machine, has a CA private key
    key_id: Optional[str] = None
    serial: int = 0
    valid_principles: List[str] = ["keeper_jit"]
    extensions: Optional[str] = None
    critical_options: Optional[str] = None
    expire_days: int = 30


class RmLinuxUserAddMeta(RmMachineUserAddMeta):
    system_user: Optional[bool] = False
    shell: Optional[str] = None
    no_login:  Optional[bool] = False
    home_dir: Optional[str] = None
    do_not_create_home_dir: Optional[bool] = False
    allow_bad_names: Optional[bool] = False
    gecos_full_name: Optional[str] = None
    gecos_room_number: Optional[str] = None
    gecos_work_phone: Optional[str] = None
    gecos_home_phone: Optional[str] = None
    gecos_other: Optional[str] = None
    group: Optional[str] = None
    groups: List[str] = []
    create_group: Optional[bool] = False
    validate_group: Optional[bool] = True
    uid: Optional[str] = None
    selinux_user_context:  Optional[str] = None
    btrfs_subvolume: Optional[bool] = False
    system_dir_mode: Optional[str] = None
    non_system_dir_mode: Optional[str] = None


class RmLinuxUserDeleteMeta(RmUserDeleteBaseMeta):
    remove_user_group: Optional[bool] = True


class RmWindowsGroupAddMeta(RmMetaBase):
    description: Optional[str] = None


class RmWindowsUserAddMeta(RmMachineUserAddMeta):
    display_name: Optional[str] = None
    description: Optional[str] = None
    disabled: bool = False
    expire_days: int = 0
    groups: List[str] = []


class RmWindowsUserDeleteMeta(RmUserDeleteBaseMeta):
    pass


class RmMacOsUserAddMeta(RmMachineUserAddMeta):
    display_name: Optional[str] = None
    uid: Optional[str] = None
    gid: Optional[str] = None
    shell: Optional[str] = None
    home_dir: Optional[str] = None
    is_admin: bool = False
    is_role_account: bool = False
    groups: List[str] = []


class RmMacOsRoleAddMeta(RmMetaBase):
    display_name: Optional[str] = None
    gid: Optional[str] = None
    record_name: Optional[str] = None


class RmMacOsUserDeleteMeta(RmUserDeleteBaseMeta):
    pass


# DIRECTORY


class RmBaseLdapUserAddMeta(RmMetaBase):
    object_class: List[str] = []
    dn: Optional[str] = None
    base_dn: Optional[str] = None
    auto_uid_number: bool = True
    gid_number_match_uid: bool = True
    home_dir_base: Optional[str] = "/home"
    first_rdn_component: Optional[str] = "CN"
    attributes: Optional[dict] = {}
    groups: List[str] = []


class RmOpenLdapUserAddMeta(RmBaseLdapUserAddMeta):
    """
    Parameters for creating a user for OpenLDAP

    object_type: directories
    engine_type: openldap

    :type: directory,openldap,create,user
    :param object_class: Object classes for the entry.
    :param dn: Full distinguished name for the user.
    :param base_dn: Base part of the distinguished name.
    :param auto_uid_number: Automatically set the UID for the user.
    :param gid_number_match_uid: Set the GID to the UID.
    :param home_dir_base: Absolute home directory path.
    :param first_rdn_component: The Relative Distinguished Name component.
    :param attributes: Key/value pairs of attributes.
    :param groups: Add the user to the follow group DN entries.
    """

    object_class: List[str] = ["top", "inetOrgPerson", "posixAccount"]


class RmAdUserAddMeta(RmBaseLdapUserAddMeta):
    """
    Parameters for creating a user for Active Directory.

    object_type: directories

    engine_type: active_directory

    :type: directory,active_directory,create,user
    :param object_class: Object classes for the entry.
    :param dn: Full distinguished name for the user.
    :param base_dn: Base part of the distinguished name.
    :param auto_uid_number: Automatically set the UID for the user.
    :param gid_number_match_uid: Set the GID to the UID.
    :param home_dir_base: Absolute home directory path.
    :param first_rdn_component: The Relative Distinguished Name component.
    :param attributes: Key/value pairs of attributes.
    :param groups: Add the user to the follow group DN entries.
    :param user_account_control: User account control flag.
    """

    object_class: List[str] = ["top", "person", "organizationalPerson", "user"]
    user_account_control: Optional[int] = 512


class RmBaseLdapGroupAddMeta(RmMetaBase):
    object_class: List[str] = []
    dn: Optional[str] = None
    ou_group: Optional[str] = None
    description: Optional[str] = None

    # Group should use CN, users can use UID, but allow it to be changed; default to CN
    first_rdn_component: str = "CN"

    attributes: Optional[dict] = {}


class RmOpenLdapGroupAddMeta(RmBaseLdapGroupAddMeta):
    object_class: List[str] = ["top", "groupOfNames"]
    ou_group: Optional[str] = "OU=groups"


class RmAdGroupAddMeta(RmBaseLdapGroupAddMeta):
    object_class: List[str] = ["top", "group"]
    ou_group: Optional[str] = "CN=Users"

    # These are fake LDAP attributes.
    # They are using to calculate a group_type.
    group_category: str = "Security"
    group_scope: str = "Global"

    # If this 0, a value will be calculated from the category and scrope.
    # If this is now 0, then his value will be used.
    group_type: int = 0


class RmBaseLdapUserDeleteMeta(RmMetaBase):
    orphan_check: Optional[bool] = False
    delete_orphans: Optional[bool] = True


class RmOpenLdapUserDeleteMeta(RmBaseLdapUserDeleteMeta):
    pass


class RmAdUserDeleteMeta(RmBaseLdapUserDeleteMeta):
    pass
