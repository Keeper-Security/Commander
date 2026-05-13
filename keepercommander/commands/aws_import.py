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
import logging
from typing import Dict, List, Optional, Any, Tuple

from .base import Command
from ._cloud_import_base import CloudImportMixin, add_filter_args
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
add_filter_args(aws_secrets_import_parser)


class AwsSecretsImportCommand(Command, CloudImportMixin):
    """Import AWS Secrets Manager secrets as Keeper records into a shared folder."""

    def __init__(self):
        super().__init__()
        self._boto3_clients = {}  # type: Dict[str, Any]
        self._access_key = None   # type: Optional[str]
        self._secret_key = None   # type: Optional[str]

    def get_parser(self):
        return aws_secrets_import_parser

    # ------------------------------------------------------------------
    # boto3 client management
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
                'boto3 is required. Install it with: pip install keeper-commander[aws]'
            )

        session = boto3.Session()
        credentials = session.get_credentials()
        if credentials is not None and self._access_key is None:
            logging.info('aws-secrets-import: using AWS session from attached role or ~/.aws credentials')
            kwargs = {}
            if region_name:
                kwargs['region_name'] = region_name
            client_obj = session.client(client, **kwargs)
        elif self._access_key is not None:
            logging.info('aws-secrets-import: using explicit AWS access key / secret key')
            kwargs = self._get_aws_kwargs(region_name)
            client_obj = boto3.client(client, **kwargs)
        else:
            raise CommandError(
                'aws-secrets-import',
                'No AWS credentials found. Provide --access-key and --secret-key, '
                'set the AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables, '
                'or configure ~/.aws/credentials.'
            )

        self._boto3_clients[key] = client_obj
        return client_obj

    # ------------------------------------------------------------------
    # AWS Secrets Manager helpers
    # ------------------------------------------------------------------

    def _list_secret_metadata(self, region_name=None):
        # type: (Optional[str]) -> List[dict]
        """
        Return normalised secret metadata: [{'name': str, 'tags': {k: v}}].

        AWS tags are converted from the native list-of-dicts format
        ([{'Key': k, 'Value': v}]) to a plain dict so filters work the same
        way as for Azure and GCP.
        """
        sm = self.get_client('secretsmanager', region_name)
        results = []
        paginator = sm.get_paginator('list_secrets')
        for page in paginator.paginate():
            for secret in page.get('SecretList', []):
                name = secret.get('Name') or ''
                if not name:
                    continue
                tags = {t.get('Key'): t.get('Value')
                        for t in (secret.get('Tags') or [])}
                results.append({'name': name, 'tags': tags})
        return results

    def _get_secret_value(self, secret_name, region_name=None):
        # type: (str, Optional[str]) -> str
        """Fetch and return the raw secret string for *secret_name*."""
        sm = self.get_client('secretsmanager', region_name)
        response = sm.get_secret_value(SecretId=secret_name)
        return response.get('SecretString') or ''

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
            required_tags = self._parse_tag_filter(tags_str, 'aws-secrets-import')

        # Validate credential flags before mutating any instance state.
        if access_key and not secret_key:
            raise CommandError('aws-secrets-import', '--secret-key is required when --access-key is provided.')
        if secret_key and not access_key:
            raise CommandError('aws-secrets-import', '--access-key is required when --secret-key is provided.')

        self._validate_folder(params, folder_uid, 'aws-secrets-import')

        self._access_key = access_key or None
        self._secret_key = secret_key or None
        self._boto3_clients.clear()

        logging.info('aws-secrets-import: listing secrets from AWS Secrets Manager…')
        try:
            secrets = self._list_secret_metadata(region)
        except Exception as exc:
            raise CommandError('aws-secrets-import', f'Failed to list secrets from AWS: {exc}')

        if not secrets:
            logging.warning('aws-secrets-import: no secrets found in AWS Secrets Manager.')
            return

        logging.info('aws-secrets-import: found %d secret(s).', len(secrets))

        self._run_import(
            params, secrets, folder_uid, record_type,
            filter_name, filter_starts, filter_ends, filter_contains,
            required_tags, dry_run, 'aws-secrets-import',
            value_fetcher=lambda name: self._get_secret_value(name, region)
        )
