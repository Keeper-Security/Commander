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

import json
from typing import Any, Union

# Sensitive field types that should be masked in logs
SENSITIVE_FIELD_TYPES = frozenset({
    'password', 'login', 'secret', 'onetimecode', 'pincode', 'keypair',
    'privatekey', 'passphrase', 'paymentcard', 'bankaccount',
    'securityquestion', 'passkey', 'accountnumber', 'routingnumber',
    'cardnumber', 'cardsecuritycode', 'privatekey', 'publickey', 'licensenumber',
    'encryptednote'
})

SENSITIVE_DICT_KEYS = frozenset({'password', 'login', 'secret', 'token', 'key',
                                  'accountnumber', 'routingnumber', 'cardnumber',
                                  'cardsecuritycode', 'privatekey', 'publickey',
                                  'licensenumber', 'keypair', 'encryptednote'}) | SENSITIVE_FIELD_TYPES


def mask_field_value(value: Any) -> Union[str, list, dict]:
    """Mask a Keeper record field's `value`, preserving its container shape."""
    if isinstance(value, list):
        return ['***' for _ in value]
    if isinstance(value, dict):
        return {k: '***' for k in value}
    return '***'


def sanitize_nested_data(data: Any) -> Any:
    """Recursively sanitize nested data structures for logging."""
    if isinstance(data, dict):
        field_type = data.get('type')
        if isinstance(field_type, str) and field_type.lower() in SENSITIVE_FIELD_TYPES and 'value' in data:
            sanitized = dict(data)
            sanitized['value'] = mask_field_value(data['value'])
            return sanitized

        sanitized = {}
        for key, value in data.items():
            if key.lower() in SENSITIVE_DICT_KEYS:
                if isinstance(value, str) and len(value) > 0:
                    sanitized[key] = '*' * min(len(value), 15)
                else:
                    sanitized[key] = '***'
            else:
                sanitized[key] = sanitize_nested_data(value)
        return sanitized
    elif isinstance(data, list):
        return [sanitize_nested_data(item) for item in data]
    else:
        return data


def sanitize_protobuf_json(json_str: str) -> str:
    """Sanitize sensitive data from protobuf JSON before logging."""
    try:
        data = json.loads(json_str)
        sanitized = sanitize_nested_data(data)
        return json.dumps(sanitized)
    except (json.JSONDecodeError, TypeError):
        return json_str
