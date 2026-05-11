#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2024 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#
# Shared utilities for cloud-provider secret import commands
# (Azure Key Vault, GCP Secret Manager, and AWS Secrets Manager).

import json
import logging
from typing import Dict, List, Optional, Tuple

from .. import api, utils, vault, record_management
from ..error import CommandError
from ..params import KeeperParams
from ..proto import record_pb2

# Maximum records per vault/records_add API call.
BATCH_SIZE = 999


def add_filter_args(parser):
    """Attach the standard five filter arguments to *parser*."""
    group = parser.add_argument_group(
        'filters',
        'Restrict which secrets are imported. All provided filters must match (AND logic).'
    )
    group.add_argument(
        '--name', dest='filter_name', action='store', metavar='NAME',
        help='Import only the secret with this exact name'
    )
    group.add_argument(
        '--name-starts-with', dest='filter_name_starts_with', action='store', metavar='PREFIX',
        help='Import only secrets whose name starts with PREFIX'
    )
    group.add_argument(
        '--name-ends-with', dest='filter_name_ends_with', action='store', metavar='SUFFIX',
        help='Import only secrets whose name ends with SUFFIX'
    )
    group.add_argument(
        '--name-contains', dest='filter_name_contains', action='store', metavar='SUBSTRING',
        help='Import only secrets whose name contains SUBSTRING'
    )
    group.add_argument(
        '--tags', dest='filter_tags', action='store', metavar='KEY=VALUE[,KEY=VALUE,...]',
        help='Import only secrets tagged/labelled with ALL specified key=value pairs '
             '(e.g. --tags Env=prod,Team=ops)'
    )


class CloudImportMixin:
    """
    Mixin for cloud-to-Keeper secret import commands.

    Provides secret-string parsing, Keeper record building, filter evaluation,
    and the main import loop. Concrete commands inherit this alongside Command
    and supply cloud-specific list/fetch implementations.
    """

    # ------------------------------------------------------------------
    # Secret value parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_secret_string(secret_string):
        # type: (str) -> Dict[str, str]
        """
        Parse a secret string into name/value pairs.

        Supported formats (in priority order):
          1. JSON object  -> {"key": "value", ...}
          2. KEY=VALUE lines (one per line, shell-style)
          3. Fallback: whole string stored under a field named "value"
        """
        secret_string = (secret_string or '').strip()
        if not secret_string:
            return {}

        if secret_string.startswith('{'):
            try:
                obj = json.loads(secret_string)
                if isinstance(obj, dict):
                    return {str(k): str(v) for k, v in obj.items()}
            except (json.JSONDecodeError, ValueError):
                pass

        pairs = {}
        parsed_as_kv = False
        for line in secret_string.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '=' in line:
                key, _, val = line.partition('=')
                pairs[key.strip()] = val.strip()
                parsed_as_kv = True
            else:
                parsed_as_kv = False
                break

        if parsed_as_kv and pairs:
            return pairs

        return {'value': secret_string}

    # ------------------------------------------------------------------
    # Keeper record builder
    # ------------------------------------------------------------------

    @staticmethod
    def _build_keeper_record(title, fields, record_type='login'):
        # type: (str, Dict[str, str], str) -> vault.TypedRecord
        """
        Build a TypedRecord from a title and a dict of field name/value pairs.

        Known Keeper field types (login, password, url, …) are placed in the
        typed fields list; everything else lands in custom fields.
        """
        KNOWN_TYPED_FIELDS = {'login', 'password', 'url', 'email', 'text', 'note'}

        record = vault.TypedRecord()
        record.type_name = record_type
        record.title = title

        for field_name, field_value in fields.items():
            keeper_type = 'text'
            if field_name.lower() in ('username', 'user', 'login'):
                keeper_type = 'login'
            elif field_name.lower() in ('password', 'pass', 'secret', 'secret_value'):
                keeper_type = 'password'
            elif field_name.lower() in ('url', 'endpoint', 'host'):
                keeper_type = 'url'

            if keeper_type in KNOWN_TYPED_FIELDS:
                record.fields.append(vault.TypedField.new_field(keeper_type, field_value, field_name))
            else:
                record.custom.append(vault.TypedField.new_field('text', field_value, field_name))

        return record

    # ------------------------------------------------------------------
    # Filter helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_tag_filter(tags_str, command_name):
        # type: (str, str) -> List[Tuple[str, str]]
        """Parse 'Key1=Val1,Key2=Val2' into [(Key1, Val1), (Key2, Val2)]."""
        pairs = []
        for token in tags_str.split(','):
            token = token.strip()
            if not token:
                continue
            if '=' not in token:
                raise CommandError(
                    command_name,
                    f'Invalid --tags format: "{token}". Expected KEY=VALUE pairs separated by commas.'
                )
            key, _, value = token.partition('=')
            pairs.append((key.strip(), value.strip()))
        return pairs

    @staticmethod
    def _matches_name_filters(name, filter_name, filter_starts, filter_ends, filter_contains):
        # type: (str, Optional[str], Optional[str], Optional[str], Optional[str]) -> bool
        if filter_name is not None and name != filter_name:
            return False
        if filter_starts is not None and not name.startswith(filter_starts):
            return False
        if filter_ends is not None and not name.endswith(filter_ends):
            return False
        if filter_contains is not None and filter_contains not in name:
            return False
        return True

    @staticmethod
    def _matches_tag_filters(secret_tags, required_tags):
        # type: (Dict[str, str], List[Tuple[str, str]]) -> bool
        """
        Check that *secret_tags* (a plain dict) satisfies every (key, value)
        pair in *required_tags*. Azure and GCP both return tags/labels as dicts.
        """
        for tag_key, tag_value in required_tags:
            if secret_tags.get(tag_key) != tag_value:
                return False
        return True

    # ------------------------------------------------------------------
    # Folder validation
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_folder(params, folder_uid, command_name):
        # type: (KeeperParams, str, str) -> None
        if not folder_uid:
            raise CommandError(command_name, 'A shared folder UID is required.')
        if folder_uid not in params.folder_cache:
            raise CommandError(
                command_name,
                f'Folder UID "{folder_uid}" not found in your vault. '
                'Use "list-sf" to find the correct shared folder UID.'
            )

    # ------------------------------------------------------------------
    # Shared import loop
    # ------------------------------------------------------------------

    def _run_import(self, params, secrets, folder_uid, record_type, filter_name,
                    filter_starts, filter_ends, filter_contains, required_tags,
                    dry_run, command_name):
        # type: (KeeperParams, list, str, str, Optional[str], Optional[str], Optional[str], Optional[str], List[Tuple[str, str]], bool, str) -> None
        """
        Iterate *secrets* — a list of dicts with keys 'name', 'value', and
        'tags' (a plain Dict[str, str]) — apply all filters, and create Keeper
        records in *folder_uid* via batched vault/records_add calls (up to
        BATCH_SIZE records per request).
        """

        # Phase 1 – filter.  Collect matching items; honour dry-run.
        matched = []
        for item in secrets:
            name = item.get('name') or ''
            if not name:
                continue
            if not self._matches_name_filters(name, filter_name, filter_starts,
                                              filter_ends, filter_contains):
                logging.debug('%s: skipping "%s" (name filter mismatch)', command_name, name)
                continue
            if required_tags and not self._matches_tag_filters(item.get('tags') or {}, required_tags):
                logging.debug('%s: skipping "%s" (tag filter mismatch)', command_name, name)
                continue
            if dry_run:
                print(f'  [dry-run] would import: {name}')
                continue
            matched.append(item)

        if dry_run:
            return

        # Phase 2 – build TypedRecord objects and their serialised protobuf
        # representations without touching the Keeper API yet.
        pending = []   # type: List[Tuple[vault.TypedRecord, record_pb2.RecordAdd]]
        for item in matched:
            fields = self._parse_secret_string(item.get('value') or '')
            record = self._build_keeper_record(item['name'], fields, record_type)
            pb = record_management.add_record_to_folder(params, record, folder_uid, pb_only=True)
            if pb is not None:
                pending.append((record, pb))

        if not pending:
            print(f'{command_name}: 0 record(s) created, 0 skipped.')
            return

        # Phase 3 – send in batches of up to BATCH_SIZE to vault/records_add.
        created = 0
        skipped = 0

        for batch_start in range(0, len(pending), BATCH_SIZE):
            batch = pending[batch_start:batch_start + BATCH_SIZE]
            batch_num = batch_start // BATCH_SIZE + 1
            logging.info('%s: sending batch %d (%d record(s))', command_name, batch_num, len(batch))

            rq = api.get_records_add_request(params)
            for _, pb in batch:
                rq.records.append(pb)

            try:
                rs = api.communicate_rest(
                    params, rq, 'vault/records_add',
                    rs_type=record_pb2.RecordsModifyResponse
                )
            except Exception as exc:
                logging.warning('%s: batch %d failed: %s', command_name, batch_num, exc)
                skipped += len(batch)
                continue

            rs_by_uid = {utils.base64_url_encode(r.record_uid): r for r in rs.records}
            for record, _ in batch:
                rs_rec = rs_by_uid.get(record.record_uid)
                if rs_rec is None or rs_rec.status == record_pb2.RS_SUCCESS:
                    logging.info('%s: created record "%s"', command_name, record.title)
                    created += 1
                else:
                    logging.warning('%s: failed to create record "%s": status=%s',
                                    command_name, record.title, rs_rec.status)
                    skipped += 1

        if created:
            params.sync_data = True
        print(f'{command_name}: {created} record(s) created, {skipped} skipped.')
