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
from typing import Any, List, Optional, Tuple

from .base import Command
from ._cloud_import_base import CloudImportMixin, add_filter_args
from ..error import CommandError
from ..params import KeeperParams

gcp_secrets_import_parser = argparse.ArgumentParser(
    prog='gcp-secrets-import',
    description='Import secrets from Google Cloud Secret Manager into a Keeper shared folder.',
    allow_abbrev=False
)
gcp_secrets_import_parser.add_argument(
    'folder',
    type=str,
    action='store',
    help='Shared folder UID to import secrets into'
)
gcp_secrets_import_parser.add_argument(
    '--project-id', dest='project_id', action='store', required=True,
    help='GCP project ID that owns the secrets'
)
gcp_secrets_import_parser.add_argument(
    '--service-account-file', dest='service_account_file', action='store',
    metavar='PATH',
    help='Path to a GCP service account JSON key file. '
         'Uses Application Default Credentials when omitted.'
)
gcp_secrets_import_parser.add_argument(
    '--dry-run', dest='dry_run', action='store_true',
    help='List secrets that would be imported without creating records'
)
gcp_secrets_import_parser.add_argument(
    '--record-type', dest='record_type', action='store', default='login',
    help='Keeper record type for imported records (default: login)'
)
add_filter_args(gcp_secrets_import_parser)


class GcpSecretsImportCommand(Command, CloudImportMixin):
    """Import GCP Secret Manager secrets as Keeper records into a shared folder."""

    def get_parser(self):
        return gcp_secrets_import_parser

    # ------------------------------------------------------------------
    # GCP client / credential resolution
    # ------------------------------------------------------------------

    @staticmethod
    def _get_client(service_account_file):
        # type: (Optional[str]) -> Any
        try:
            from google.cloud import secretmanager
        except ImportError:
            raise CommandError(
                'gcp-secrets-import',
                'google-cloud-secret-manager is required. '
                'Install it with: pip install keeper-commander[gcp]'
            )

        if service_account_file:
            try:
                from google.oauth2 import service_account
            except ImportError:
                raise CommandError(
                    'gcp-secrets-import',
                    'google-auth is required for service-account authentication. '
                    'Install it with: pip install keeper-commander[gcp]'
                )
            logging.info('gcp-secrets-import: using service account key file "%s"', service_account_file)
            credentials = service_account.Credentials.from_service_account_file(
                service_account_file,
                scopes=['https://www.googleapis.com/auth/cloud-platform'],
            )
            return secretmanager.SecretManagerServiceClient(credentials=credentials)

        logging.info('gcp-secrets-import: using Application Default Credentials')
        return secretmanager.SecretManagerServiceClient()

    # ------------------------------------------------------------------
    # GCP Secret Manager helpers
    # ------------------------------------------------------------------

    def _list_secret_metadata(self, client, project_id):
        # type: (Any, str) -> List[dict]
        """
        Return secret metadata only — no values fetched.
        Result: [{'name': str, 'tags': Dict[str, str]}]

        GCP labels (the equivalent of tags) are a plain dict on each Secret.
        Value fetching is deferred until after filtering so that --dry-run
        does not trigger cloud API calls or generate audit-log entries.
        """
        parent = f'projects/{project_id}'
        results = []
        for secret in client.list_secrets(request={'parent': parent}):
            short_name = secret.name.split('/')[-1]
            results.append({'name': short_name, 'tags': dict(secret.labels or {})})
        return results

    def _get_secret_value(self, client, full_resource_name):
        # type: (Any, str) -> str
        """
        Fetch and return the payload of the latest version of a secret.

        *full_resource_name* is the GCP resource path
        ``projects/{project}/secrets/{secret-id}/versions/latest``.

        Raises CommandError if the payload is binary (non-UTF-8), since Keeper
        text fields cannot represent arbitrary bytes.
        """
        from google.api_core.exceptions import NotFound, PermissionDenied

        secret_name = full_resource_name.split('/')[-1]
        version_name = f'{full_resource_name}/versions/latest'
        try:
            response = client.access_secret_version(request={'name': version_name})
        except NotFound:
            raise ValueError(f'no accessible version for "{secret_name}"')
        except PermissionDenied:
            raise PermissionError(f'permission denied accessing "{secret_name}"')

        try:
            return response.payload.data.decode('utf-8')
        except UnicodeDecodeError:
            raise CommandError(
                'gcp-secrets-import',
                f'"{secret_name}" contains binary data which is not supported. '
                'Only text secrets can be imported.'
            )

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def execute(self, params, **kwargs):  # type: (KeeperParams, Any) -> None
        folder_uid = kwargs.get('folder') or ''
        project_id = kwargs.get('project_id') or ''
        service_account_file = kwargs.get('service_account_file')
        dry_run = kwargs.get('dry_run', False)
        record_type = kwargs.get('record_type') or 'login'

        filter_name = kwargs.get('filter_name') or None
        filter_starts = kwargs.get('filter_name_starts_with') or None
        filter_ends = kwargs.get('filter_name_ends_with') or None
        filter_contains = kwargs.get('filter_name_contains') or None
        tags_str = kwargs.get('filter_tags') or ''
        required_tags = []  # type: List[Tuple[str, str]]
        if tags_str:
            required_tags = self._parse_tag_filter(tags_str, 'gcp-secrets-import')

        if not project_id:
            raise CommandError('gcp-secrets-import', '--project-id is required.')

        self._validate_folder(params, folder_uid, 'gcp-secrets-import')

        client = self._get_client(service_account_file)

        logging.info('gcp-secrets-import: listing secrets in project "%s"…', project_id)
        try:
            secrets = self._list_secret_metadata(client, project_id)
        except CommandError:
            raise
        except Exception as exc:
            raise CommandError('gcp-secrets-import', f'Failed to list secrets from GCP Secret Manager: {exc}')

        if not secrets:
            logging.warning('gcp-secrets-import: no accessible secrets found in project "%s".', project_id)
            return

        logging.info('gcp-secrets-import: found %d secret(s).', len(secrets))

        def _fetch_value(name):
            full_name = f'projects/{project_id}/secrets/{name}'
            return self._get_secret_value(client, full_name)

        self._run_import(
            params, secrets, folder_uid, record_type,
            filter_name, filter_starts, filter_ends, filter_contains,
            required_tags, dry_run, 'gcp-secrets-import',
            value_fetcher=_fetch_value
        )
