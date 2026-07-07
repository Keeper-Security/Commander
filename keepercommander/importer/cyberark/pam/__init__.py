#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander — CyberArk PAM import (split module)

"""CyberArk → KeeperPAM import library (organized subpackage)."""

from .account_mapper import AccountMapper
from .application_mapper import ApplicationMapper
from .client import CyberArkPVWAClient
from .constants import (
    DEFAULT_PLATFORM_MAP,
    FALLBACK_PLATFORM_MAP,
    MAX_FETCH_RECORDS,
    MAX_SAFE_NAME_LENGTH,
    SYSTEM_SAFES,
    VALID_LOGON_TYPES,
)
from .import_builder import (
    build_extend_json,
    build_import_json,
    build_report,
    build_safe_folders,
    build_shared_folder_permissions,
    format_duration,
    strip_credentials,
    validate_import_data,
)
from .dependents import (
    _normalize_dependent_type,
    resolve_account_dependents,
)
from .idempotency import (
    ExistingRecordIndex,
    IdempotencyDecision,
    PartitionSummary,
    RecordDecision,
    annotate_record_with_marker,
    build_existing_index,
    format_id_marker,
    parse_id_marker,
    partition_records,
    strip_id_marker,
    summarize,
)
from .linked_accounts import (
    detect_dual_account,
    pick_admin_credentials,
    pick_launch_credentials,
    resolve_linked_accounts,
)
from .master_policy_mapper import MasterPolicyMapper
from .permission_mapper import PermissionMapper
from .platform_mapping import _guess_platform_mapping
from .record_kind import RecordKind, discriminate_record_kind
from .safe_folder_mapper import SafeFolderMapper
from .safe_utils import (
    apply_safe_filter,
    deduplicate_safe_names,
    exclude_system_safes,
    sanitize_safe_name,
)
from .session_recording import SessionRecordingResolver
from .throttler import AdaptiveThrottler
from .ui import _esc
from .user_team_matcher import UserTeamMatcher

__all__ = [
    "AccountMapper",
    "AdaptiveThrottler",
    "ApplicationMapper",
    "CyberArkPVWAClient",
    "DEFAULT_PLATFORM_MAP",
    "ExistingRecordIndex",
    "FALLBACK_PLATFORM_MAP",
    "IdempotencyDecision",
    "MasterPolicyMapper",
    "PartitionSummary",
    "RecordDecision",
    "MAX_FETCH_RECORDS",
    "MAX_SAFE_NAME_LENGTH",
    "PermissionMapper",
    "RecordKind",
    "SafeFolderMapper",
    "SessionRecordingResolver",
    "SYSTEM_SAFES",
    "UserTeamMatcher",
    "VALID_LOGON_TYPES",
    "_esc",
    "_guess_platform_mapping",
    "_normalize_dependent_type",
    "annotate_record_with_marker",
    "apply_safe_filter",
    "build_existing_index",
    "build_extend_json",
    "build_import_json",
    "build_report",
    "build_safe_folders",
    "build_shared_folder_permissions",
    "deduplicate_safe_names",
    "detect_dual_account",
    "discriminate_record_kind",
    "exclude_system_safes",
    "format_duration",
    "format_id_marker",
    "parse_id_marker",
    "partition_records",
    "pick_admin_credentials",
    "pick_launch_credentials",
    "resolve_account_dependents",
    "resolve_linked_accounts",
    "sanitize_safe_name",
    "strip_credentials",
    "strip_id_marker",
    "summarize",
    "validate_import_data",
]
