#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

API_ENDPOINTS = {
    'list_domains': 'enterprise/list_domains',
    'reserve_domain': 'enterprise/reserve_domain',
    'get_domain_alias': 'enterprise/get_domain_alias',
    'create_domain_alias': 'enterprise/create_domain_alias',
    'delete_domain_alias': 'enterprise/delete_domain_alias',
}



MAX_DOMAIN_LENGTH = 253
MAX_LABEL_LENGTH = 63
MIN_TLD_LENGTH = 2
DOMAIN_PATTERN = r'^(?!-)([a-z0-9-]{1,63})(?<!-)(\.(?!-)([a-z0-9-]{1,63})(?<!-))*$'



NOTICE_MSG = 'Notice: This feature is not in production yet. It will be available soon.'

ALIAS_ACCESS_DENIED_MSG = (
    'Access denied: You must be an Admin with "Manage Users" permission to manage domain aliases.'
)

ERROR_MESSAGES = {
    'bad_request': 'Domain not specified or invalid',
    'access_denied': 'Access denied: You must be a Root Admin to manage domains',
    'forbidden': 'Access denied: You must be a Root Admin to manage domains',
    'domain_already_taken': 'Domain "{domain}" is already reserved by a different enterprise',
    'verification_failed': (
        'DNS verification failed for domain "{domain}". Please ensure the TXT record '
        'is correctly added and DNS has propagated (may take up to 48 hours).'
    ),
    'invalid_domain': 'Invalid domain format: "{domain}"',
    'rate_limit': 'Too many requests. Please wait a moment and try again.',
    'too_many_requests': 'Too many requests. Please wait a moment and try again.',
}

CREATE_ALIAS_STATUS_MESSAGES = {
    0: 'Success',
    1: 'Duplicate; already exists',
    2: 'Not allowed; domain or alias not owned by the enterprise',
}

DELETE_ALIAS_STATUS_MESSAGES = {
    0: 'Success',
    1: 'Not allowed or does not exist',
    2: 'does not exist',
}
