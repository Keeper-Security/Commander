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

azure_secrets_import_parser = argparse.ArgumentParser(
    prog='azure-secrets-import',
    description='Import secrets from Azure Key Vault into a Keeper shared folder.',
    allow_abbrev=False
)
azure_secrets_import_parser.add_argument(
    'vault_name',
    type=str,
    action='store',
    help='Azure Key Vault name (e.g. my-vault → https://my-vault.vault.azure.net/)'
)
azure_secrets_import_parser.add_argument(
    'folder',
    type=str,
    action='store',
    help='Shared folder UID to import secrets into'
)
azure_secrets_import_parser.add_argument(
    '--tenant-id', dest='tenant_id', action='store',
    help='Azure AD tenant ID for service-principal authentication'
)
azure_secrets_import_parser.add_argument(
    '--client-id', dest='client_id', action='store',
    help='Azure AD application (client) ID for service-principal authentication'
)
azure_secrets_import_parser.add_argument(
    '--client-secret', dest='client_secret', action='store',
    help='Azure AD client secret for service-principal authentication'
)
azure_secrets_import_parser.add_argument(
    '--dry-run', dest='dry_run', action='store_true',
    help='List secrets that would be imported without creating records'
)
azure_secrets_import_parser.add_argument(
    '--record-type', dest='record_type', action='store', default='login',
    help='Keeper record type for imported records (default: login)'
)
add_filter_args(azure_secrets_import_parser)


class AzureSecretsImportCommand(Command, CloudImportMixin):
    """Import Azure Key Vault secrets as Keeper records into a shared folder."""

    def get_parser(self):
        return azure_secrets_import_parser

    # ------------------------------------------------------------------
    # Azure credential resolution
    # ------------------------------------------------------------------

    @staticmethod
    def _get_credential(tenant_id, client_id, client_secret):
        try:
            from azure.identity import ClientSecretCredential, DefaultAzureCredential
        except ImportError:
            raise CommandError(
                'azure-secrets-import',
                'azure-identity is required. Install it with: pip install keeper-commander[azure]'
            )

        if tenant_id and client_id and client_secret:
            logging.info('azure-secrets-import: using service-principal credentials')
            return ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret,
            )

        if any([tenant_id, client_id, client_secret]):
            missing = [n for n, v in [('--tenant-id', tenant_id), ('--client-id', client_id),
                                       ('--client-secret', client_secret)] if not v]
            raise CommandError(
                'azure-secrets-import',
                f'Service-principal authentication requires all three flags. Missing: {", ".join(missing)}'
            )

        logging.info('azure-secrets-import: using DefaultAzureCredential '
                     '(environment variables, managed identity, or Azure CLI)')
        return DefaultAzureCredential()

    # ------------------------------------------------------------------
    # Azure Key Vault helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _make_client(vault_name, credential):
        # type: (str, Any) -> Any
        try:
            from azure.keyvault.secrets import SecretClient
        except ImportError:
            raise CommandError(
                'azure-secrets-import',
                'azure-keyvault-secrets is required. Install it with: pip install keeper-commander[azure]'
            )
        vault_url = f'https://{vault_name}.vault.azure.net/'
        return SecretClient(vault_url=vault_url, credential=credential)

    def _list_secret_metadata(self, client):
        # type: (Any) -> List[dict]
        """
        Return secret metadata only — no values fetched.
        Result: [{'name': str, 'tags': Dict[str, str]}]

        Disabled secrets are excluded.  Value fetching is deferred until
        after filtering so that --dry-run does not trigger cloud API calls.
        """
        results = []
        for prop in client.list_properties_of_secrets():
            if not prop.enabled:
                logging.debug('azure-secrets-import: skipping disabled secret "%s"', prop.name)
                continue
            results.append({'name': prop.name, 'tags': dict(prop.tags or {})})
        return results

    def _get_secret_value(self, client, name):
        # type: (Any, str) -> str
        """Fetch and return the value of a single secret."""
        secret = client.get_secret(name)
        return secret.value or ''

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def execute(self, params, **kwargs):  # type: (KeeperParams, Any) -> None
        vault_name = kwargs.get('vault_name') or ''
        folder_uid = kwargs.get('folder') or ''
        tenant_id = kwargs.get('tenant_id')
        client_id = kwargs.get('client_id')
        client_secret = kwargs.get('client_secret')
        dry_run = kwargs.get('dry_run', False)
        record_type = kwargs.get('record_type') or 'login'

        filter_name = kwargs.get('filter_name') or None
        filter_starts = kwargs.get('filter_name_starts_with') or None
        filter_ends = kwargs.get('filter_name_ends_with') or None
        filter_contains = kwargs.get('filter_name_contains') or None
        tags_str = kwargs.get('filter_tags') or ''
        required_tags = []  # type: List[Tuple[str, str]]
        if tags_str:
            required_tags = self._parse_tag_filter(tags_str, 'azure-secrets-import')

        if not vault_name:
            raise CommandError('azure-secrets-import', 'An Azure Key Vault name is required.')

        self._validate_folder(params, folder_uid, 'azure-secrets-import')

        credential = self._get_credential(tenant_id, client_id, client_secret)
        client = self._make_client(vault_name, credential)

        logging.info('azure-secrets-import: listing secrets from vault "%s"…', vault_name)
        try:
            secrets = self._list_secret_metadata(client)
        except CommandError:
            raise
        except Exception as exc:
            raise CommandError('azure-secrets-import', f'Failed to list secrets from Azure Key Vault: {exc}')

        if not secrets:
            logging.warning('azure-secrets-import: no enabled secrets found in vault "%s".', vault_name)
            return

        logging.info('azure-secrets-import: found %d secret(s).', len(secrets))

        self._run_import(
            params, secrets, folder_uid, record_type,
            filter_name, filter_starts, filter_ends, filter_contains,
            required_tags, dry_run, 'azure-secrets-import',
            value_fetcher=lambda name: self._get_secret_value(client, name)
        )
