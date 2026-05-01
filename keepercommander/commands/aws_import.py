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

import argparse
import json
import logging
from typing import Dict, List, Optional, Any, Tuple

from .base import Command
from .. import vault, record_management
from ..error import CommandError
from ..params import KeeperParams

aws_secrets_import_parser = argparse.ArgumentParser(
    prog='aws-secrets-import',
    description='Import secrets from AWS Secrets Manager into a Keeper shared folder.',
    allow_abbrev=False
)
aws_secrets_import_parser.add_argument(
    'folder',
    type=str,
    action='store',
    help='Shared folder UID to import secrets into'
)
aws_secrets_import_parser.add_argument(
    '--access-key', dest='access_key', action='store',
    help='AWS access key ID (overrides credential chain)'
)
aws_secrets_import_parser.add_argument(
    '--secret-key', dest='secret_key', action='store',
    help='AWS secret access key (overrides credential chain)'
)
aws_secrets_import_parser.add_argument(
    '--region', dest='region', action='store',
    help='AWS region name (e.g. us-east-1)'
)
aws_secrets_import_parser.add_argument(
    '--dry-run', dest='dry_run', action='store_true',
    help='List secrets that would be imported without creating records'
)
aws_secrets_import_parser.add_argument(
    '--record-type', dest='record_type', action='store', default='login',
    help='Keeper record type for imported records (default: login)'
)

filter_group = aws_secrets_import_parser.add_argument_group(
    'filters',
    'Restrict which secrets are imported. All provided filters must match (AND logic).'
)
filter_group.add_argument(
    '--name', dest='filter_name', action='store', metavar='NAME',
    help='Import only the secret with this exact name'
)
filter_group.add_argument(
    '--name-starts-with', dest='filter_name_starts_with', action='store', metavar='PREFIX',
    help='Import only secrets whose name starts with PREFIX'
)
filter_group.add_argument(
    '--name-ends-with', dest='filter_name_ends_with', action='store', metavar='SUFFIX',
    help='Import only secrets whose name ends with SUFFIX'
)
filter_group.add_argument(
    '--name-contains', dest='filter_name_contains', action='store', metavar='SUBSTRING',
    help='Import only secrets whose name contains SUBSTRING'
)
filter_group.add_argument(
    '--tags', dest='filter_tags', action='store', metavar='KEY=VALUE[,KEY=VALUE,...]',
    help='Import only secrets tagged with ALL specified key=value pairs '
         '(e.g. --tags Env=prod,Team=ops)'
)


class AwsSecretsImportCommand(Command):
    """Import AWS Secrets Manager secrets as Keeper records into a shared folder."""

    def __init__(self):
        super().__init__()
        self._boto3_clients = {}  # type: Dict[str, Any]
        self._access_key = None   # type: Optional[str]
        self._secret_key = None   # type: Optional[str]
        self.using_session = False

    def get_parser(self):
        return aws_secrets_import_parser

    # ------------------------------------------------------------------
    # boto3 client management (follows architecture guidance)
    # ------------------------------------------------------------------

    def _get_aws_kwargs(self, region_name=None):
        kwargs = {
            'aws_access_key_id': self._access_key,
            'aws_secret_access_key': self._secret_key,
        }
        if region_name:
            kwargs['region_name'] = region_name
        return kwargs

    def get_client(self, client, region_name=None):
        key = f"{client}:{region_name or 'default'}"
        if key in self._boto3_clients:
            return self._boto3_clients[key]

        try:
            import boto3
        except ImportError:
            raise CommandError(
                'aws-secrets-import',
                'boto3 is required. Install it with: pip install boto3'
            )

        session = boto3.Session()
        credentials = session.get_credentials()
        if credentials is not None and self._access_key is None:
            logging.info('aws-secrets-import: using AWS session from attached role or ~/.aws credentials')
            self.using_session = True
            kwargs = {}
            if region_name:
                kwargs['region_name'] = region_name
            client_obj = session.client(client, **kwargs)
        else:
            logging.info('aws-secrets-import: using explicit AWS access key / secret key')
            self.using_session = False
            kwargs = self._get_aws_kwargs(region_name)
            client_obj = boto3.client(client, **kwargs)

        self._boto3_clients[key] = client_obj
        return client_obj

    # ------------------------------------------------------------------
    # AWS Secrets Manager helpers
    # ------------------------------------------------------------------

    def _list_secrets(self, region_name=None):
        """Return a list of all secret metadata dicts from Secrets Manager."""
        sm = self.get_client('secretsmanager', region_name)
        secrets = []
        paginator = sm.get_paginator('list_secrets')
        for page in paginator.paginate():
            secrets.extend(page.get('SecretList', []))
        return secrets

    def _get_secret_value(self, secret_name, region_name=None):
        """Fetch and return the raw secret string for *secret_name*."""
        sm = self.get_client('secretsmanager', region_name)
        response = sm.get_secret_value(SecretId=secret_name)
        return response.get('SecretString') or ''

    # ------------------------------------------------------------------
    # Parsing helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_secret_string(secret_string):
        # type: (str) -> Dict[str, str]
        """
        Parse the secret string into name/value pairs.

        Supported formats (in priority order):
          1. JSON object  -> {"key": "value", ...}
          2. KEY=VALUE lines (one per line, shell-style)
          3. Fallback: store the whole string under a single field named "value"
        """
        secret_string = (secret_string or '').strip()
        if not secret_string:
            return {}

        # Try JSON first
        if secret_string.startswith('{'):
            try:
                obj = json.loads(secret_string)
                if isinstance(obj, dict):
                    return {str(k): str(v) for k, v in obj.items()}
            except (json.JSONDecodeError, ValueError):
                pass

        # Try KEY=VALUE lines
        pairs = {}
        lines = secret_string.splitlines()
        parsed_as_kv = False
        for line in lines:
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

        # Fallback: single field
        return {'value': secret_string}

    # ------------------------------------------------------------------
    # Keeper record builder
    # ------------------------------------------------------------------

    @staticmethod
    def _build_record(title, fields, record_type='login'):
        # type: (str, Dict[str, str], str) -> vault.TypedRecord
        """
        Build a TypedRecord from a title and a dict of field name/value pairs.

        Known Keeper field types (text, login, password, url, …) are placed in
        the typed *fields* list; everything else lands in *custom* fields.
        """
        KNOWN_TYPED_FIELDS = {'login', 'password', 'url', 'email', 'text', 'note'}

        record = vault.TypedRecord()
        record.type_name = record_type
        record.title = title

        for field_name, field_value in fields.items():
            # Map common AWS naming conventions to Keeper field types
            keeper_type = 'text'
            if field_name.lower() in ('username', 'user', 'login'):
                keeper_type = 'login'
            elif field_name.lower() in ('password', 'pass', 'secret', 'secret_value'):
                keeper_type = 'password'
            elif field_name.lower() in ('url', 'endpoint', 'host'):
                keeper_type = 'url'

            if keeper_type in KNOWN_TYPED_FIELDS:
                typed_field = vault.TypedField.new_field(keeper_type, field_value, field_name)
                record.fields.append(typed_field)
            else:
                custom_field = vault.TypedField.new_field('text', field_value, field_name)
                record.custom.append(custom_field)

        return record

    # ------------------------------------------------------------------
    # Filtering helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_tags(tags_str):
        # type: (str) -> List[Tuple[str, str]]
        """Parse 'Key1=Val1,Key2=Val2' into [(Key1, Val1), (Key2, Val2)]."""
        pairs = []
        for token in tags_str.split(','):
            token = token.strip()
            if not token:
                continue
            if '=' not in token:
                raise CommandError(
                    'aws-secrets-import',
                    f'Invalid --tags format: "{token}". Expected KEY=VALUE pairs separated by commas.'
                )
            key, _, value = token.partition('=')
            pairs.append((key.strip(), value.strip()))
        return pairs

    @staticmethod
    def _matches_filters(secret_meta, filter_name, filter_starts, filter_ends,
                         filter_contains, required_tags):
        # type: (dict, Optional[str], Optional[str], Optional[str], Optional[str], List[Tuple[str, str]]) -> bool
        """Return True only if the secret satisfies every provided filter."""
        name = secret_meta.get('Name') or ''

        if filter_name is not None and name != filter_name:
            return False
        if filter_starts is not None and not name.startswith(filter_starts):
            return False
        if filter_ends is not None and not name.endswith(filter_ends):
            return False
        if filter_contains is not None and filter_contains not in name:
            return False

        if required_tags:
            # AWS returns Tags as [{"Key": "...", "Value": "..."}, ...]
            secret_tags = {
                t.get('Key'): t.get('Value')
                for t in (secret_meta.get('Tags') or [])
            }
            for tag_key, tag_value in required_tags:
                if secret_tags.get(tag_key) != tag_value:
                    return False

        return True

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def execute(self, params, **kwargs):  # type: (KeeperParams, Any) -> None
        folder_uid = kwargs.get('folder') or ''
        access_key = kwargs.get('access_key')
        secret_key = kwargs.get('secret_key')
        region = kwargs.get('region')
        dry_run = kwargs.get('dry_run', False)
        record_type = kwargs.get('record_type') or 'login'

        filter_name = kwargs.get('filter_name') or None
        filter_starts = kwargs.get('filter_name_starts_with') or None
        filter_ends = kwargs.get('filter_name_ends_with') or None
        filter_contains = kwargs.get('filter_name_contains') or None
        tags_str = kwargs.get('filter_tags') or ''
        required_tags = []   # type: List[Tuple[str, str]]
        if tags_str:
            required_tags = self._parse_tags(tags_str)

        if not folder_uid:
            raise CommandError('aws-secrets-import', 'A shared folder UID is required.')

        # Verify the UID exists in the vault folder cache
        if folder_uid not in params.folder_cache:
            raise CommandError(
                'aws-secrets-import',
                f'Folder UID "{folder_uid}" not found in your vault. '
                'Use "list-sf" to find the correct shared folder UID.'
            )

        # Store credentials for use in get_client / _get_aws_kwargs
        self._access_key = access_key or None
        self._secret_key = secret_key or None
        self._boto3_clients.clear()

        if access_key and not secret_key:
            raise CommandError('aws-secrets-import', '--secret-key is required when --access-key is provided.')
        if secret_key and not access_key:
            raise CommandError('aws-secrets-import', '--access-key is required when --secret-key is provided.')

        # Fetch all secret metadata
        logging.info('aws-secrets-import: listing secrets from AWS Secrets Manager…')
        try:
            secrets = self._list_secrets(region)
        except Exception as exc:
            raise CommandError('aws-secrets-import', f'Failed to list secrets from AWS: {exc}')

        if not secrets:
            logging.warning('aws-secrets-import: no secrets found in AWS Secrets Manager.')
            return

        logging.info('aws-secrets-import: found %d secret(s).', len(secrets))

        created = 0
        skipped = 0

        for secret_meta in secrets:
            secret_name = secret_meta.get('Name') or ''
            if not secret_name:
                continue

            if not self._matches_filters(
                secret_meta, filter_name, filter_starts, filter_ends,
                filter_contains, required_tags
            ):
                logging.debug('aws-secrets-import: skipping "%s" (filter mismatch)', secret_name)
                continue

            if dry_run:
                print(f'  [dry-run] would import: {secret_name}')
                continue

            # Fetch the actual secret value
            try:
                secret_string = self._get_secret_value(secret_name, region)
            except Exception as exc:
                logging.warning('aws-secrets-import: skipping "%s" – could not retrieve value: %s', secret_name, exc)
                skipped += 1
                continue

            fields = self._parse_secret_string(secret_string)

            record = self._build_record(secret_name, fields, record_type)

            try:
                record_management.add_record_to_folder(params, record, folder_uid)
                logging.info('aws-secrets-import: created record "%s"', secret_name)
                created += 1
            except Exception as exc:
                logging.warning('aws-secrets-import: failed to create record for "%s": %s', secret_name, exc)
                skipped += 1

        if not dry_run:
            if created:
                params.sync_data = True
            print(f'aws-secrets-import: {created} record(s) created, {skipped} skipped.')
