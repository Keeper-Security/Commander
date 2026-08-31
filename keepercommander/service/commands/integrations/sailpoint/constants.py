#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
# Contact: commander@keepersecurity.com
#

"""SailPoint Service Mode constants."""

# Bound onto KeeperParams when SailPoint mode is active (SailPoint config record UID)
PARAMS_ATTR = 'sailpoint_record_uid'

# Docker config record UID (service settings / -ur)
DOCKER_RECORD_ENV = 'COMMANDER_RECORD'

# Dedicated SailPoint config record UID (marker, scope, poll interval, pending JSON)
SAILPOINT_RECORD_ENV = 'SAILPOINT_RECORD'

SAILPOINT_MARKER_FIELD = 'sailpoint_integration'
PENDING_ENTITLEMENTS_FIELD = 'pending_entitlements'
ALLOW_FOLDERS_FIELD = 'allow_folders'
ALLOW_RECORDS_FIELD = 'allow_records'
ALLOW_ROLES_FIELD = 'allow_roles'
ALLOW_TEAMS_FIELD = 'allow_teams'
TRANSFER_TARGET_EMAIL_FIELD = 'transfer_target_email'
POLL_INTERVAL_FIELD = 'poll_interval_seconds'

DEFAULT_POLL_INTERVAL_SECONDS = 60
MIN_POLL_INTERVAL_SECONDS = 15

SAILPOINT_ALLOWED_COMMANDS = (
    'whoami',
    'sync-down',
    'enterprise-info',
    'enterprise-user',
    'enterprise-down',
    'transfer-user',
    'share-folder',
    'share-record',
    'nsf-share-folder',
    'nsf-share-record',
    'tree',
)

SAILPOINT_BANNED_COMMANDS = frozenset({
    'get',
    'nsf-get',
    'clipboard-copy',
    'find-password',
    'totp',
    'download-attachment',
    'upload-attachment',
    'export',
    'import',
    'ksm',
    'record-history',
    'one-time-share',
    'connect',
    'ssh',
})
