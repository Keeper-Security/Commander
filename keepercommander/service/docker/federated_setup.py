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

"""Federated-login provisioning helpers for Docker Service Mode setup."""

import base64
import contextlib
import io
import json
import math
import os
import shlex
import stat
import tempfile
import time
import uuid
from dataclasses import dataclass
from typing import Dict, Optional

from ... import api, attachment, record_management, utils, vault
from ...commands.ksm import KSMCommand
from ...error import CommandError
from .models import DockerSetupConstants
from .printer import DockerSetupPrinter


@dataclass(frozen=True)
class FederatedSetupOptions:
    """User-provided information needed to register a federated client."""

    token_path: str
    issuer: str
    subject: str
    jwks_uri: Optional[str] = None


def read_jwt_claims(token_path: str, command_name: str) -> Dict:
    """Read unverified JWT claims for setup-time confirmation only.

    Keeper remains responsible for signature and claim validation during token
    exchange. This helper only decodes the payload to prefill issuer/subject and
    to catch obviously expired or malformed input before creating vault objects.
    """
    path = os.path.abspath(os.path.expanduser(token_path or ''))
    if not os.path.isfile(path):
        raise CommandError(command_name, f'OIDC token file not found: {path}')
    if os.name == 'posix':
        try:
            token_permissions = stat.S_IMODE(os.stat(path).st_mode)
        except OSError as e:
            raise CommandError(command_name, f'Unable to inspect OIDC token file permissions: {e}')
        if token_permissions & 0o077:
            DockerSetupPrinter.print_warning(
                'The OIDC JWT file is readable by group/other users. To restrict access, run: '
                f'chmod 600 {shlex.quote(path)}'
            )

    try:
        with open(path, 'r', encoding='utf-8') as token_file:
            token = token_file.read().strip()
        parts = token.split('.')
        if len(parts) != 3 or not all(parts):
            raise ValueError('expected a three-part JWT')
        payload = parts[1]
        payload += '=' * (-len(payload) % 4)
        claims = json.loads(base64.b64decode(
            payload.encode('ascii'), altchars=b'-_', validate=True
        ))
        if not isinstance(claims, dict):
            raise ValueError('JWT payload must be an object')
    except (OSError, ValueError) as e:
        raise CommandError(command_name, f'Unable to read OIDC JWT claims: {e}')

    for claim_name in ('iss', 'sub'):
        claim_value = claims.get(claim_name)
        if claim_value is not None and (
            not isinstance(claim_value, str) or not claim_value
        ):
            raise CommandError(
                command_name,
                f'OIDC JWT has an invalid "{claim_name}" claim',
            )

    exp = claims.get('exp')
    if exp is not None:
        if isinstance(exp, bool) or not isinstance(exp, (int, float)):
            raise CommandError(command_name, 'OIDC JWT has an invalid exp claim')
        try:
            finite_exp = math.isfinite(exp)
        except OverflowError:
            finite_exp = False
        if not finite_exp:
            raise CommandError(command_name, 'OIDC JWT has an invalid exp claim')
        if exp <= time.time():
            raise CommandError(command_name, 'The supplied OIDC JWT is already expired')
        if exp <= time.time() + 24 * 60 * 60:
            DockerSetupPrinter.print_warning(
                'The OIDC JWT expires within 24 hours. Replace its Keeper attachment and restart '
                'the container before expiry; the running container cannot refresh the provider JWT.'
            )

    return claims


def create_federated_config(params, app_uid: str, options: FederatedSetupOptions,
                            command_name: str, output_dir: Optional[str] = None) -> str:
    """Register a vault-session federated client and write its config privately."""
    config_path = None
    try:
        config_dir = output_dir or utils.get_default_path()
        os.makedirs(config_dir, mode=0o700, exist_ok=True)
        fd, config_path = tempfile.mkstemp(
            prefix='federated-config-', suffix='.json', dir=config_dir
        )
        os.close(fd)
        os.chmod(config_path, 0o600)

        client_name = _unique_federated_client_name(params, app_uid, command_name)
        with contextlib.redirect_stdout(io.StringIO()):
            KSMCommand.add_federated_client(
                params=params,
                app_name_or_uid=app_uid,
                issuer=options.issuer,
                subject=options.subject,
                jwks_uri=options.jwks_uri or None,
                access_type='vault-session',
                client_name=client_name,
                config_init='json',
                include_data_key=True,
                config_file=config_path,
                force=True,
            )

        if not os.path.isfile(config_path) or os.path.getsize(config_path) == 0:
            raise CommandError(command_name, 'Federated client config was not generated')
        os.chmod(config_path, 0o600)
        DockerSetupPrinter.print_success('Federated vault-session client created')
        DockerSetupPrinter.print_warning(
            'The federated config contains the vault data key and grants full-vault access. '
            'Protect the Keeper record and KSM bootstrap credentials.'
        )
        return config_path
    except CommandError:
        if config_path and os.path.exists(config_path):
            os.unlink(config_path)
        raise
    except Exception as e:
        if config_path and os.path.exists(config_path):
            os.unlink(config_path)
        raise CommandError(command_name, f'Failed to create federated client: {e}')


def upload_federated_artifacts(params, record_uid: str, config_path: str,
                               token_path: str, command_name: str) -> None:
    """Replace managed login attachments on the Docker config record."""
    try:
        record = vault.KeeperRecord.load(params, record_uid)
        if not isinstance(record, vault.TypedRecord):
            raise CommandError(command_name, 'Invalid record type for OIDC attachments')

        remove_managed_login_artifacts(record, params)

        upload_tasks = []
        for path, name in (
            (config_path, DockerSetupConstants.FEDERATED_CONFIG_FILENAME),
            (token_path, DockerSetupConstants.OIDC_TOKEN_FILENAME),
        ):
            task = attachment.FileUploadTask(path)
            task.name = name
            task.title = name
            upload_tasks.append(task)

        attachment.upload_attachments(params, record, upload_tasks)
        record_management.update_record(params, record)
        params.sync_data = True
        api.sync_down(params)
        DockerSetupPrinter.print_success('Federated config and OIDC token uploaded')
    except CommandError:
        raise
    except Exception as e:
        raise CommandError(command_name, f'Failed to upload OIDC attachments: {e}')


def remove_managed_login_artifacts(record, params) -> None:
    """Remove setup-managed login files and fields before writing a new flow."""
    _remove_managed_attachments(record, params)
    if record.custom:
        record.custom = [
            field for field in record.custom
            if getattr(field, 'label', None) != 'config_json'
        ]


def _unique_federated_client_name(params, app_uid: str, command_name: str) -> str:
    """Use a stable readable name where possible and avoid duplicate-name failures."""
    base_name = DockerSetupConstants.DEFAULT_FEDERATED_CLIENT_NAME
    app_info = KSMCommand.get_app_info(params, app_uid)
    existing_names = {
        getattr(client, 'id', '')
        for info in (app_info or [])
        for client in getattr(info, 'clients', [])
        if getattr(client, 'id', '')
    }
    if base_name not in existing_names:
        return base_name
    for _ in range(5):
        candidate = f'{base_name} {uuid.uuid4().hex[:8]}'
        if candidate not in existing_names:
            return candidate
    raise CommandError(command_name, 'Could not find an unused federated client name')


def _remove_managed_attachments(record, params) -> None:
    """Unlink only attachments managed by the Docker setup commands."""
    from ...record_facades import FileRefRecordFacade

    facade = FileRefRecordFacade()
    facade.record = record
    managed_names = {
        'config.json',
        DockerSetupConstants.FEDERATED_CONFIG_FILENAME.lower(),
        DockerSetupConstants.OIDC_TOKEN_FILENAME.lower(),
    }
    remove_uids = []
    for file_uid in list(facade.file_ref):
        if file_uid not in params.record_cache:
            continue
        file_record = vault.KeeperRecord.load(params, file_uid)
        if not isinstance(file_record, vault.FileRecord):
            continue
        names = {
            str(getattr(file_record, 'name', '') or '').lower(),
            str(getattr(file_record, 'title', '') or '').lower(),
        }
        if names & managed_names:
            remove_uids.append(file_uid)

    for file_uid in remove_uids:
        facade.file_ref.remove(file_uid)
    if remove_uids:
        DockerSetupPrinter.print_success(
            f'Removed {len(remove_uids)} previous managed login attachment(s)'
        )
