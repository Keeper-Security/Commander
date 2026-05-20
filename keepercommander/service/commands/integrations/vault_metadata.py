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

from typing import Optional

from ...decorators.logging import logger
from ....params import KeeperParams


SERVICE_URL_FIELD = 'service_url'
API_KEY_FIELD = 'api_key'
VAULT_METADATA_MAX_ATTEMPTS = 3
_STALE_REVISION_HINTS = ('out_of_sync', 'no longer exists')


def get_existing_api_key(params: KeeperParams, record_uid: str) -> Optional[str]:
    try:
        from .... import vault

        record = vault.KeeperRecord.load(params, record_uid)
        if not isinstance(record, vault.TypedRecord) or not record.custom:
            return None

        for field in record.custom:
            if field.label == API_KEY_FIELD:
                value = field.get_default_value()
                if value:
                    return value
        return None
    except Exception as e:
        logger.debug(f"Could not read vault record {record_uid} to reuse API key: {e}")
        return None


def write_service_metadata(params: KeeperParams, record_uid: str, service_url: str, api_key: str) -> None:
    from .... import vault, record_management, api

    last_error: Optional[Exception] = None

    for attempt in range(1, VAULT_METADATA_MAX_ATTEMPTS + 1):
        try:
            params.sync_data = True
            api.sync_down(params)

            record = vault.KeeperRecord.load(params, record_uid)
            if not isinstance(record, vault.TypedRecord):
                raise RuntimeError(f"Vault record {record_uid} is missing or not a typed record")

            preserved = [f for f in (record.custom or []) if f.label not in (SERVICE_URL_FIELD, API_KEY_FIELD)]
            record.custom = preserved + [
                vault.TypedField.new_field('url', service_url, SERVICE_URL_FIELD),
                vault.TypedField.new_field('secret', api_key, API_KEY_FIELD),
            ]

            record_management.update_record(params, record)
            params.sync_data = True
            api.sync_down(params)
            return

        except Exception as e:
            last_error = e
            is_stale = any(hint in str(e).lower() for hint in _STALE_REVISION_HINTS)
            if not is_stale or attempt == VAULT_METADATA_MAX_ATTEMPTS:
                break
            logger.warning(f"Stale revision on vault record {record_uid}; retrying ({attempt}/{VAULT_METADATA_MAX_ATTEMPTS})")

    logger.error(f"Failed to update vault record {record_uid}: {last_error}")
