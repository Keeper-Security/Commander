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
    private_key_passphrase: Optional[str] = None
    connect_database: Optional[str] = None
    dn: Optional[str] = None


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


class RmDomainUserAddMeta(RmMetaBase):
    roles: List[str] = []
    groups: List[str] = []

# DATABASE


class RmMySQLUserAddMeta(RmMetaBase):
    authentication_plugin: Optional[str] = None
    authentication_value: Optional[str] = None
    roles: List[str] = []


class RmMySQLRoleAddMeta(RmMetaBase):
    grant_script: Optional[str] = None


class RmMariaDbRoleAddMeta(RmMetaBase):
    with_admin: str = "CURRENT_USER"
    grant_script: Optional[str] = None


class RmMariaDbLUserAddMeta(RmMetaBase):
    authentication_plugin: Optional[str] = None
    authentication_value: Optional[str] = None
    roles: List[str] = []


class RmPostgreSqlUserAddMeta(RmMetaBase):
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


class RmOracleUserAddMeta(RmMetaBase):
    allow_login: bool = True
    allow_resource: bool = True
    roles: List[str] = []


class RmOracleRoleAddMeta(RmMetaBase):
    not_identified: bool = False,
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


class RmLinuxUserDeleteMeta(RmMetaBase):
    remove_home_dir: Optional[bool] = True
    remove_user_group: Optional[bool] = True


class RmWindowsGroupAddMeta(RmMetaBase):
    description: Optional[str] = None


class RmWindowsUserAddMeta(RmMachineUserAddMeta):
    display_name: Optional[str] = None
    description: Optional[str] = None
    disabled: bool = False
    expire_days: int = 0
    groups: List[str] = []


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


# DIRECTORY


class RmBaseLdapUserAddMeta(RmMetaBase):
    object_class: List[str] = []
    dn: Optional[str] = None
    base_dn: Optional[str] = None
    auto_uid_number: bool = True
    gid_number_match_uid: bool = True
    home_dir_base: Optional[str] = "/home"
    first_rdn_component: Optional[str] = None
    attributes: Optional[dict] = {}
    groups: List[str] = []


class RmOpenLdapUserAddMeta(RmBaseLdapUserAddMeta):
    """
    Parameters for creating a user for OpenLDAP

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
    Parameters for creating a user for Active Directory

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
