from __future__ import annotations
from enum import Enum
from pydantic import BaseModel
import time
import datetime
import base64
import json
from keeper_secrets_manager_core.crypto import CryptoUtils
from typing import Any, Union, Optional, List, TYPE_CHECKING

if TYPE_CHECKING:
    from ..keeper_dag.vertex import DAGVertex

# IMPORTANT!!!!!!!!!!!
#
# Do not change attributes.
# This might cause a problem with deserializing existing data.
# It is safe to add attributes that allow blank values.
# There might be some pydantic magic that can be used to make migration with the deserializer.


class BaseEnum(Enum):

    @classmethod
    def find_enum(cls, value: Union[Enum, str, int], default: Optional[Enum] = None):
        if value is not None:
            for e in cls:
                if e == value or e.value == value:
                    return e
            if hasattr(cls, str(value).upper()):
                return getattr(cls, value.upper())
        return default


class CredentialBase(BaseModel):
    # Use Any because it might be a str or Secret, but Secret is defined to discover-and_rotation.
    user: Optional[Any] = None
    dn: Optional[Any] = None
    password: Optional[Any] = None
    private_key: Optional[Any] = None
    private_key_passphrase: Optional[Any] = None
    database: Optional[Any] = None


class Settings(BaseModel):

    """
    credentials: List of Credentials used to test connections for resources.
    default_shared_folder_uid: The default shared folder that should be used when adding records.
    include_azure_aadds - Include Azure AD Domain Service.
    skip_rules: Do not run the rule engine.
    user_map: Map used to map found users to Keeper record UIDs
    skip_machines: Do not discovery machines.
    skip_databases: Do not discovery databases.
    skip_directories: Do not discovery directoires.
    skip_cloud_users - Skip cloud users like AWS IAM, or Azure Tenant users.
    allow_resource_deletion - Allow discovery to remove resources.
    allow_resource_deletion - Allow discovery to remove resources if missing.
    allow_user_deletion - Allow discovery to remove users if missing.
    resource_deletion_limit - Remove resource if not seen for # seconds; 0 will delete right away.
    user_deletion_limit - Remove user right away if not seen for # seconds; 0 will delete right away.
    """

    credentials: List[CredentialBase] = []
    default_shared_folder_uid: Optional[str] = None
    include_azure_aadds: bool = False
    skip_rules: bool = False
    user_map: Optional[List[dict]] = None
    skip_machines: bool = False
    skip_databases: bool = False
    skip_directories: bool = False
    skip_cloud_users: bool = False

    # For now, don't delete anything.
    allow_resource_deletion: bool = False
    allow_user_deletion: bool = False

    resource_deletion_limit: int = 0
    user_deletion_limit: int = 0

    def set_user_map(self, obj):
        if self.user_map is not None:
            obj.user_map = self.user_map

    @property
    def has_credentials(self):
        return len(self.credentials) > 0

# STATUS


class JobItem(BaseModel):
    job_id: str
    start_ts: int
    settings: Settings
    end_ts: Optional[int] = None
    success: Optional[bool] = None
    resource_uid: Optional[str] = None
    conversation_id: Optional[str] = None
    error: Optional[str] = None
    stacktrace: Optional[str] = None

    sync_point: Optional[int] = None

    # Stored chunked, in multiple DATA edges
    delta: Optional[DiscoveryDelta] = None

    @property
    def duration_sec(self) -> Optional[int]:
        if self.end_ts is not None:
            return self.end_ts - self.start_ts
        return None

    @property
    def start_ts_str(self):
        return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.start_ts))

    @property
    def end_ts_str(self):
        if self.end_ts is not None:
            return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.end_ts))
        return ""

    @property
    def duration_sec_str(self):
        if self.is_running is True:
            duration_sec = int(time.time()) - self.start_ts
        else:
            duration_sec = self.duration_sec

        if duration_sec is not None:
            return str(datetime.timedelta(seconds=int(duration_sec)))
        else:
            return ""

    @property
    def is_running(self):
        # If no end timestamp, and there is a start timestamp, and the job has not been processed, and there is no
        # success is running.
        return self.end_ts is None and self.start_ts is not None and self.success is None


class JobContent(BaseModel):
    active_job_id: Optional[str] = None
    job_history: List[JobItem] = []


class DiscoveryDeltaItem(BaseModel):
    uid: str
    version: int
    record_uid: Optional[str] = None
    changes: Optional[dict] = None

    @property
    def has_record(self) -> bool:
        return self.record_uid is not None


class DiscoveryDelta(BaseModel):
    added: List[DiscoveryDeltaItem] = []
    changed: List[DiscoveryDeltaItem] = []
    deleted: List[DiscoveryDeltaItem] = []

# RULES


class RuleTypeEnum(BaseEnum):
    ACTION = "action"
    SCHEDULE = "schedule"
    COMPLEXITY = "complexity"


class RuleActionEnum(BaseEnum):
    PROMPT = "prompt"
    ADD = "add"
    IGNORE = "ignore"


class Statement(BaseModel):
    field: str
    operator: str
    value: Union[str, bool, float]


class RuleItem(BaseModel):
    added_ts: Optional[int] = None
    rule_id: Optional[str] = None
    enabled: bool = True
    priority: int = 0
    case_sensitive: bool = True
    statement: List[Statement]

    # Do not set this.
    # This needs to be here for the RuleEngine.
    # The RuleEngine will set this to its self.
    engine_rule: Optional[object] = None

    @property
    def added_ts_str(self):
        return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.added_ts))

    def search(self, search: str) -> bool:
        for item in self.statement:
            if search in item.field or search in item.value:
                return True

        if search in self.rule_id.lower() or search == self.rule_action.value or search == str(self.priority):
            return True

        return False


class ActionRuleItem(RuleItem):
    action: RuleActionEnum = RuleActionEnum.PROMPT
    shared_folder_uid: Optional[str] = None


class ScheduleRuleItem(RuleItem):
    tag: str


class ComplexityRuleItem(RuleItem):
    tag: str


class RuleSet(BaseModel):
    pass


class ActionRuleSet(RuleSet):
    rules: List[ActionRuleItem] = []


class ScheduleRuleSet(RuleSet):
    rules: List[ScheduleRuleItem] = []


class ComplexityRuleSet(RuleSet):
    rules: List[ComplexityRuleItem] = []


# INFRASTRUCTURE

class UserRelEnum(BaseEnum):
    """
    The relationship a pamUser has with a resource, or provider

    * BELONGS_TO - The pamUser's credentials are rotated on this resource.
    * USER - The pamUser has access to this resource.
    * ADMIN - The pamUser is the admin on this resource.
    * INACTIVE - The pamUser has access to this resource, however, no longer does.
    """

    BELONGS_TO = "belongs_to"
    USER = "user"
    ADMIN = "admin"
    INACTIVE = "inactive"


class RecordStatus(BaseEnum):
    NONE = "none"
    EXISTS = "exists"
    ADD = "add"
    IGNORE = "ignore"


class RecordField(BaseModel):
    type: str
    label: Optional[str] = None
    value: List[Any] = []
    required: bool = False


class UserAclRotationSettings(BaseModel):
    # Base64 JSON schedule
    schedule: Optional[str] = ""

    # Base64 JSON, encrypted
    pwd_complexity: Optional[str] = ""

    disabled: bool = False

    # If true, do not rotate the username/password on remote system, if it exists.
    noop: bool = False

    # A list of SaaS Record configuration records.
    saas_record_uid_list: List[str] = []

    def set_pwd_complexity(self, complexity: Union[dict, str, bytes], record_key_bytes: bytes):
        if isinstance(complexity, dict):
            complexity = json.dumps(complexity)
        if isinstance(complexity, str):
            complexity = complexity.encode()

        if not isinstance(complexity, bytes):
            raise ValueError("The complexity is not a dictionary, string or is bytes.")

        self.pwd_complexity = base64.b64encode(CryptoUtils.encrypt_aes(complexity, record_key_bytes)).decode()

    def get_pwd_complexity(self, record_key_bytes: bytes) -> Optional[dict]:
        if self.pwd_complexity is None or self.pwd_complexity == "":
            return None
        complexity_enc_bytes = base64.b64decode(self.pwd_complexity.encode())
        complexity_bytes = CryptoUtils.decrypt_aes(complexity_enc_bytes, record_key_bytes)
        return json.loads(complexity_bytes)

    def set_schedule(self, schedule: Union[dict, str]):
        if isinstance(schedule, dict):
            schedule = json.dumps(schedule)
        self.schedule = schedule

    def get_schedule(self) -> Optional[dict]:
        if self.pwd_complexity is None or self.pwd_complexity == "":
            return None
        return json.loads(self.schedule)


class UserAcl(BaseModel):
    # Is this user's password/private key managed by this resource?
    # This should be unique for all the ACL edges of this user vertex; only one ACL edge should have a True value.
    belongs_to: bool = False

    # Is this user an admin for the resource?
    # This can be set True for multiple ACL edges; a user can be admin on multiple resources.
    is_admin: bool = False

    # Is this user a cloud-based user?
    # This will only be True if the ACL of the PAM User connects to a configuration vertex.
    is_iam_user: Optional[bool] = False

    rotation_settings: Optional[UserAclRotationSettings] = None

    @staticmethod
    def default():
        """
        Make an empty UserAcl that contains all the default values for the attributes.
        """
        return UserAcl(
            rotation_settings=UserAclRotationSettings()
        )


class DiscoveryItem(BaseModel):
    pass


class DiscoveryConfiguration(DiscoveryItem):
    """
    This is very general.
    We are not going to make a class for each configuration/provider.
    Populate a dictionary for the important information (i.e., Network CIDR)
    """
    type: str
    info: dict

    # Configurations never allows an admin user.
    # This should always be False.
    allows_admin: bool = False


class DiscoveryUser(DiscoveryItem):
    user: Optional[str] = None
    dn: Optional[str] = None
    database: Optional[str] = None
    managed: bool = False

    # These are for directory services.
    active: bool = True
    expired: bool = False
    source: Optional[str] = None

    # Normally these do not get set, except for the access_user.
    password: Optional[str] = None
    private_key: Optional[str] = None
    private_key_passphrase: Optional[str] = None

    # Simple flag, for access user in discovery, that states could connect with creds.
    # Local connection might not have passwords, so this is our flag to indicate that the user connected.
    could_login: Optional[bool] = False


class FactsDirectory(BaseModel):
    domain: str
    software: Optional[str] = None
    login_format: Optional[str] = None


class FactsId(BaseModel):
    machine_id: Optional[str] = None
    product_id: Optional[str] = None
    board_serial: Optional[str] = None


class FactsNameUser(BaseModel):
    name: str
    user: str


class Facts(BaseModel):
    name: Optional[str] = None
    directories: List[FactsDirectory] = []
    id: Optional[FactsId] = None
    services: List[FactsNameUser] = []
    tasks: List[FactsNameUser] = []
    iis_pools: List[FactsNameUser] = []

    @property
    def has_services(self):
        return self.services is not None and len(self.services) > 0

    @property
    def has_tasks(self):
        return self.tasks is not None and len(self.tasks) > 0

    @property
    def has_iis_pools(self):
        return self.iis_pools is not None and len(self.iis_pools) > 0

    @property
    def has_service_items(self):
        return self.has_services or self.has_tasks or self.has_iis_pools


class DiscoveryMachine(DiscoveryItem):
    host: str
    ip: str
    port: Optional[int] = None
    os: Optional[str] = None
    provider_region: Optional[str] = None
    provider_group: Optional[str] = None
    is_gateway: bool = False
    allows_admin: bool = True
    admin_reason: Optional[str] = None
    facts: Optional[Facts] = None


class DiscoveryDatabase(DiscoveryItem):
    host: str
    ip: str
    port: int
    type: str
    use_ssl: bool = False
    database: Optional[str] = None
    provider_region: Optional[str] = None
    provider_group: Optional[str] = None
    allows_admin: bool = True
    admin_reason: Optional[str] = None


class DiscoveryDirectory(DiscoveryItem):
    host: str
    ip: str
    ips: List[str] = []
    port: int
    type: str
    use_ssl: bool = False
    provider_region: Optional[str] = None
    provider_group: Optional[str] = None
    allows_admin: bool = True
    admin_reason: Optional[str] = None


class DiscoveryObject(BaseModel):
    uid: str
    id: str
    object_type_value: str
    record_uid: Optional[str] = None
    parent_record_uid: Optional[str] = None
    record_type: str
    fields: List[RecordField]
    ignore_object: bool = False
    action_rules_result: Optional[str] = None
    shared_folder_uid: Optional[str] = None
    name: str
    title: str
    description: str
    notes: List[str] = []
    error: Optional[str] = None
    stacktrace: Optional[str] = None

    # If the object is missing, this will show a timestamp on when it went missing.
    missing_since_ts: Optional[int] = None

    # Should this object be deleted? This does not prevent user from deleting, but prevents automated processed from
    #  deleting.
    allow_delete: bool = False

    # This is not the official admin.
    # This is the user discovery used to access to the resource.
    # This will be used to help the user create an admin user.
    access_user: Optional[DiscoveryUser] = None

    # Specific information for a record type.
    item: Union[DiscoveryConfiguration, DiscoveryUser, DiscoveryMachine, DiscoveryDatabase, DiscoveryDirectory]

    @property
    def record_exists(self):
        return self.record_uid is not None

    def get_field_value(self, label):
        for field in self.fields:
            if field.label == label or field.type == label:
                value = field.value
                if len(value) == 0:
                    return None
                return field.value[0]
        return None

    def set_field_value(self, label, value):
        if not isinstance(value, list):
            value = [value]
        for field in self.fields:
            if field.label == label or field.type == label:
                field.value = value
                return
        raise ValueError(f"Cannot not find field with label {label}")

    @staticmethod
    def get_discovery_object(vertex: DAGVertex) -> DiscoveryObject:
        """
        Get DiscoveryObject with correct item instance.

        Pydantic doesn't like Unions on the item attribute.
        Item needs to be validated using the correct class.

        :param vertex:
        :return:
        """

        mapping = {
            "pamUser": DiscoveryUser,
            "pamDirectory": DiscoveryDirectory,
            "pamMachine": DiscoveryMachine,
            "pamDatabase": DiscoveryDatabase
        }

        content_dict = vertex.content_as_dict

        if content_dict is None:
            raise Exception(f"The discovery vertex {vertex.uid} does not have any content data.")
        record_type = content_dict.get("record_type")
        if record_type in mapping:
            content_dict["item"] = mapping[record_type].model_validate(content_dict["item"])
        else:
            content_dict["item"] = DiscoveryConfiguration.model_validate(content_dict["item"])

        return DiscoveryObject.model_validate(content_dict)  # type: DiscoveryObject

# PROCESS


class PromptActionEnum(BaseEnum):
    ADD = "add"
    IGNORE = "ignore"
    SKIP = "skip"


class DirectoryInfo(BaseModel):
    directory_record_uids: List[str] = []
    directory_user_record_uids: List[str] = []

    def has_directories(self) -> bool:
        return len(self.directory_record_uids) > 0


class NormalizedRecord(BaseModel):
    """
    This class attempts to normalize KeeperRecord, TypedRecord, KSM Record into a normalized record.
    """
    record_uid: str
    record_type: str
    title: str
    fields: List[RecordField] = []
    note: Optional[str] = None

    def _field(self, field_type, label) -> Optional[RecordField]:
        for field in self.fields:
            value = field.value
            if value is None or len(value) == 0:
                continue
            if field.label == field_type and value[0].lower() == label.lower():
                return field
        return None

    def find_user(self, user):

        from .utils import split_user_and_domain

        res = self._field("login", user)
        if res is None:
            user, _ = split_user_and_domain(user)
            res = self._field("login", user)

        return res

    def find_dn(self, user):
        return self._field("distinguishedName", user)

      
class PromptResult(BaseModel):

    # "add" and "ignore" are the only action
    action: PromptActionEnum

    # The acl is only needs for pamUser record.
    acl: Optional[UserAcl] = None

    # If the discovery object content has been modified, set it here.
    content: Optional[DiscoveryObject] = None

    # Existing record that should be the admin.
    record_uid: Optional[str] = None

    # Is this is a pamUser and a directory user?
    is_directory_user: bool = False

    # Note to include with record
    note:  Optional[str] = None


class SummaryItem(BaseModel):
    vertex_uid: str
    record_type: str


class Summary(BaseModel):
    ignored: List[SummaryItem] = []
    auto_add: List[SummaryItem] = []
    prompt: List[SummaryItem] = []

    @property
    def total_found(self):
        return len(self.auto_add) + len(self.prompt)

    @property
    def total_ignored(self):
        return len(self.ignored)


class BulkRecordAdd(BaseModel):

    # The title of the record.
    # This is used for debug reasons.
    title: str

    # Record note
    note: Optional[str] = None

    # This could be a Commander KeeperRecord, Commander RecordAdd, NormalizedRecord, or KSM Record
    record: Any
    record_type: str

    # Normal record UID strings
    record_uid: str
    parent_record_uid: Optional[str] = None

    # The shared folder UID where the record should be created.
    shared_folder_uid: str


class BulkRecordConvert(BaseModel):
    record_uid: str
    parent_record_uid: Optional[str] = None

    # Record note
    note: Optional[str] = None


class BulkRecordSuccess(BaseModel):
    title: str
    record_uid: str


class BulkRecordFail(BaseModel):
    title: str
    error: str


class BulkProcessResults(BaseModel):
    success: List[BulkRecordSuccess] = []
    failure: List[BulkRecordFail] = []

    @property
    def has_failures(self) -> bool:
        return len(self.failure) > 0

    @property
    def num_results(self) -> int:
        return self.failure_count + self.success_count

    @property
    def failure_count(self) -> int:
        return len(self.failure)

    @property
    def success_count(self) -> int:
        return len(self.success)


# Service/Schedule Task/IIS Pool

class ServiceAcl(BaseModel):
    is_service: bool = False
    is_task: bool = False
    is_iis_pool: bool = False

    def is_used(self):
        return self.is_service or self.is_task or self.is_iis_pool
