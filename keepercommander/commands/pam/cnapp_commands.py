#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander — CNAPP user-facing commands
# Copyright 2026 Keeper Security Inc.
#
"""argparse-driven CLI surface for the krouter CNAPP REST endpoints.

The commands here are intentionally thin: parse args, call into `cnapp_helper`, format
the typed response. All wire concerns (encryption, retries, transport errors) live in
`router_helper._post_request_to_router`.

Command tree (registered under `pam`):

    pam cnapp config set       — create/update provider configuration
    pam cnapp config test      — validate creds without persisting
    pam cnapp config test-encrypter — health-check customer-deployed encrypter
    pam cnapp config read      — read the persisted configuration
    pam cnapp config delete    — remove the configuration

    pam cnapp queue list       — list queued issues for a network
    pam cnapp queue associate  — link a vault record to a queue item
    pam cnapp queue remediate  — dispatch a remediation action to the gateway
    pam cnapp queue set-status — update issue status (notifies provider best-effort)
    pam cnapp queue delete     — remove a queue item

Output is human-readable text by default; list/read commands accept `--format json` for
scripting.
"""

import argparse
import base64
import binascii
import json
import logging
from datetime import datetime, timezone

from keeper_secrets_manager_core.utils import bytes_to_base64

from . import cnapp_helper
from ..base import Command, GroupCommand, dump_report_data
from ... import vault
from ...display import bcolors
from ...error import CommandError

logger = logging.getLogger(__name__)

# Mirror of CnappQueueStatus in krouter CnappModels.kt (and keeper.cnapp_queue_status in
# vault). TODO(KC-1290): lift into cnapp.proto like CnappProvider so Commander cannot drift.
QUEUE_STATUS_BY_NAME = {
    'pending': 1,
    'in_progress': 2,
    'resolved': 3,
    'failed': 4,
    'cancelled': 5,
}
QUEUE_STATUS_BY_ID = {v: k.upper() for k, v in QUEUE_STATUS_BY_NAME.items()}


# Custom-field label on the CNAPP "encrypter" record (a secure note linked from the
# CNAPP configuration's `cnappConfigRecordUid`). Mirrors `CNAPP_ENCRYPTION_KEY_FIELD_LABEL`
# in vault/cloudSecurityUtils.ts — keep the strings in sync.
CNAPP_ENCRYPTION_KEY_LABEL = 'Encryption Key'


def _decode_aes_key(raw):  # type: (str) -> bytes|None
    """Encrypter keys are typically `openssl rand -base64 32`. Try standard base64 first,
    then base64url (legacy notes). 32 bytes only (AES-256) — anything else is rejected so we
    don't pass garbage to AES-GCM."""
    if not raw or not isinstance(raw, str):
        return None
    candidate = raw.strip()
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            padding = '=' * (-len(candidate) % 4)
            data = decoder(candidate + padding)
        except (binascii.Error, ValueError):
            continue
        if len(data) == 32:
            return data
    return None


def _load_encrypter_key(params, config_record_uid):
    """Resolve the AES key from the CNAPP encrypter vault record. Returns None when the
    record can't be loaded or doesn't carry a recognizable key — callers should fall back
    to showing the encrypted payload as-is."""
    if not config_record_uid:
        return None
    try:
        record = vault.KeeperRecord.load(params, config_record_uid)
    except Exception as e:
        logger.debug('CNAPP: failed to load encrypter record %s: %s', config_record_uid, e)
        return None
    if not isinstance(record, vault.TypedRecord):
        return None
    # Match vault/cloudSecurityUtils.ts: prefer `secret` then `note` labeled "Encryption Key",
    # then the first unlabeled `note` field only when no labeled key field exists.
    labeled_raws = []
    secret_field = record.get_typed_field('secret', CNAPP_ENCRYPTION_KEY_LABEL)
    if secret_field and secret_field.value:
        labeled_raws.append(secret_field.value[0])
    note_labeled = record.get_typed_field('note', CNAPP_ENCRYPTION_KEY_LABEL)
    if note_labeled and note_labeled.value:
        labeled_raws.append(note_labeled.value[0])
    for raw in labeled_raws:
        key = _decode_aes_key(raw)
        if key:
            return key
    if labeled_raws:
        logger.warning(
            'CNAPP: "%s" field is present on encrypter record %s but is not a valid AES-256 key; '
            'not using other note fields.',
            CNAPP_ENCRYPTION_KEY_LABEL, config_record_uid,
        )
        return None
    first_note = record.get_typed_field('note')
    if first_note and first_note.value:
        key = _decode_aes_key(first_note.value[0])
        if key:
            return key
    return None


def _decrypt_cnapp_payload(payload_bytes, key):
    """Decrypt a CNAPP queue payload using the Encrypter's AES-256-GCM key.

    Wire format (matches vault's `decryptCnappQueueItem` in cloudSecurityUtils.ts):
        payload_bytes (proto field, base64url-decoded by us) is UTF-8 base64url text
        of a JSON envelope `{"encrypted_payload":"<b64url>","alg":"AES-256-GCM","version":"1"}`.
        encrypted_payload base64url-decodes to `nonce(12) || ciphertext || tag(16)` —
        the standard layout AESGCM.decrypt expects.

    Returns a dict on success; raises Exception on bad envelope / wrong key / bad alg
    so the caller can surface a meaningful warning."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    envelope_b64 = payload_bytes.decode('utf-8')
    envelope_json = base64.urlsafe_b64decode(envelope_b64 + '=' * (-len(envelope_b64) % 4))
    envelope = json.loads(envelope_json)
    alg = envelope.get('alg')
    if alg != 'AES-256-GCM':
        raise ValueError(f"Unsupported or missing CNAPP payload algorithm: {alg!r}")
    ciphertext_b64 = envelope.get('encrypted_payload') or ''
    ciphertext = base64.urlsafe_b64decode(ciphertext_b64 + '=' * (-len(ciphertext_b64) % 4))
    if len(ciphertext) < 12 + 16:
        raise ValueError('CNAPP ciphertext shorter than nonce+tag — corrupt payload')
    nonce, body = ciphertext[:12], ciphertext[12:]
    plaintext = AESGCM(key).decrypt(nonce, body, None)
    return json.loads(plaintext.decode('utf-8'))


def _resolve_status(value, allow_all=True):  # type: (str|int|None, bool) -> int
    """Accept either the numeric status id or its case-insensitive name."""
    if value is None or value == '':
        status_id = 0
    elif isinstance(value, int):
        status_id = value
    else:
        s = str(value).strip().lower()
        if s.lstrip('-').isdigit():
            status_id = int(s)
        elif s in QUEUE_STATUS_BY_NAME:
            status_id = QUEUE_STATUS_BY_NAME[s]
        else:
            raise CommandError(
                'pam cnapp',
                f"Unknown status '{value}'. Valid: {', '.join(QUEUE_STATUS_BY_NAME)} or 0 for ALL.",
            )
    if status_id == 0:
        if allow_all:
            return 0
        raise CommandError('pam cnapp', 'A specific status is required (cannot be 0/ALL).')
    if status_id not in QUEUE_STATUS_BY_ID:
        raise CommandError(
            'pam cnapp',
            f"Unknown status id {status_id}. Valid ids: {', '.join(str(i) for i in sorted(QUEUE_STATUS_BY_ID))}.",
        )
    return status_id


def _format_timestamp(epoch_ms):
    """krouter emits epoch-millis for received/resolved timestamps; render as UTC ISO."""
    if not epoch_ms:
        return ''
    try:
        return datetime.fromtimestamp(int(epoch_ms) / 1000, tz=timezone.utc).isoformat()
    except (ValueError, TypeError, OSError):
        return f'<invalid timestamp: {epoch_ms}>'


class PAMCnappCommand(GroupCommand):
    """Root for the `pam cnapp ...` command tree."""

    def __init__(self):
        super(PAMCnappCommand, self).__init__()
        self.register_command('config', PAMCnappConfigCommand(),
                              'Manage CNAPP provider configuration', 'c')
        self.register_command('queue', PAMCnappQueueCommand(),
                              'Manage CNAPP issue queue', 'q')
        self.default_verb = 'queue'


# ---------------------------------------------------------------------------
# Configuration sub-tree
# ---------------------------------------------------------------------------

class PAMCnappConfigCommand(GroupCommand):

    def __init__(self):
        super(PAMCnappConfigCommand, self).__init__()
        self.register_command('set', PAMCnappConfigSetCommand(),
                              'Create or update CNAPP provider configuration')
        self.register_command('test', PAMCnappConfigTestCommand(),
                              'Validate CNAPP provider credentials without saving')
        self.register_command('test-encrypter', PAMCnappConfigTestEncrypterCommand(),
                              'Health-check the customer Encrypter at /health')
        self.register_command('read', PAMCnappConfigReadCommand(),
                              'Read the persisted CNAPP configuration for a network')
        self.register_command('delete', PAMCnappConfigDeleteCommand(),
                              'Delete the CNAPP configuration on a network')
        self.default_verb = ''


def _add_configuration_args(parser, require_secret=True, optional_secret_on_set=False):
    parser.add_argument('--network-uid', '-n', required=True, dest='network_uid',
                        help='Network record UID (base64url).')
    parser.add_argument('--provider', '-p', required=True, dest='provider',
                        help='CNAPP provider keyword: wiz (case-insensitive).')
    parser.add_argument('--client-id', required=True, dest='client_id',
                        help='Provider API client ID / app ID.')
    if optional_secret_on_set:
        parser.add_argument('--client-secret', required=False, default=None, dest='client_secret',
                            help='Provider API client secret. Omit on `config set` to keep the existing secret.')
    else:
        parser.add_argument('--client-secret', required=require_secret, dest='client_secret',
                            help='Provider API client secret.')
    parser.add_argument('--api-endpoint', required=True, dest='api_endpoint_url',
                        help='Provider API endpoint URL (e.g. https://api.us1.app.wiz.io/graphql).')
    parser.add_argument('--auth-endpoint', required=True, dest='auth_endpoint_url',
                        help='Provider OAuth2 token endpoint URL (e.g. https://auth.app.wiz.io/oauth/token).')


class PAMCnappConfigSetCommand(Command):
    parser = argparse.ArgumentParser(prog='pam cnapp config set')
    _add_configuration_args(parser, optional_secret_on_set=True)
    parser.add_argument('--config-record', required=True, dest='cnapp_config_record_uid',
                        help='UID of the vault record holding the Encrypter URL + key.')

    def get_parser(self):
        return PAMCnappConfigSetCommand.parser

    def execute(self, params, **kwargs):
        provider = cnapp_helper.provider_from_name(kwargs.get('provider'))
        response = cnapp_helper.set_cnapp_configuration(
            params,
            network_uid=kwargs.get('network_uid'),
            provider=provider,
            client_id=kwargs.get('client_id'),
            client_secret='' if kwargs.get('client_secret') is None else kwargs.get('client_secret'),
            api_endpoint_url=kwargs.get('api_endpoint_url'),
            cnapp_config_record_uid=kwargs.get('cnapp_config_record_uid'),
            auth_endpoint_url=kwargs.get('auth_endpoint_url'),
        )
        print(f"{bcolors.OKGREEN}CNAPP configuration saved.{bcolors.ENDC}")
        if response is not None:
            _print_configuration(response)
        return None


class PAMCnappConfigTestCommand(Command):
    parser = argparse.ArgumentParser(prog='pam cnapp config test')
    _add_configuration_args(parser, require_secret=True)

    def get_parser(self):
        return PAMCnappConfigTestCommand.parser

    def execute(self, params, **kwargs):
        provider = cnapp_helper.provider_from_name(kwargs.get('provider'))
        cnapp_helper.test_cnapp_configuration(
            params,
            network_uid=kwargs.get('network_uid'),
            provider=provider,
            client_id=kwargs.get('client_id'),
            client_secret=kwargs.get('client_secret'),
            api_endpoint_url=kwargs.get('api_endpoint_url'),
            auth_endpoint_url=kwargs.get('auth_endpoint_url'),
        )
        print(f"{bcolors.OKGREEN}CNAPP credentials validated successfully.{bcolors.ENDC}")


class PAMCnappConfigTestEncrypterCommand(Command):
    parser = argparse.ArgumentParser(prog='pam cnapp config test-encrypter')
    parser.add_argument('--url', '-u', required=True, dest='url',
                        help='Base URL of the Encrypter. krouter probes <url>/health.')

    def get_parser(self):
        return PAMCnappConfigTestEncrypterCommand.parser

    def execute(self, params, **kwargs):
        cnapp_helper.test_cnapp_encrypter(params, url_base_encrypter=kwargs.get('url'))
        print(f"{bcolors.OKGREEN}Encrypter is reachable.{bcolors.ENDC}")


class PAMCnappConfigReadCommand(Command):
    parser = argparse.ArgumentParser(prog='pam cnapp config read')
    parser.add_argument('--network-uid', '-n', required=True, dest='network_uid',
                        help='Network record UID (base64url).')
    parser.add_argument('--provider', '-p', required=True, dest='provider',
                        help='CNAPP provider keyword: wiz.')
    parser.add_argument('--format', dest='format', choices=['table', 'json'], default='table',
                        help='Output format.')

    def get_parser(self):
        return PAMCnappConfigReadCommand.parser

    def execute(self, params, **kwargs):
        provider = cnapp_helper.provider_from_name(kwargs.get('provider'))
        response = cnapp_helper.read_cnapp_configuration(
            params,
            network_uid=kwargs.get('network_uid'),
            provider=provider,
        )
        if response is None:
            logger.warning('No CNAPP configuration returned.')
            return None
        if kwargs.get('format') == 'json':
            print(json.dumps(_configuration_to_dict(response), indent=2))
            return None
        _print_configuration(response)
        return None


class PAMCnappConfigDeleteCommand(Command):
    parser = argparse.ArgumentParser(prog='pam cnapp config delete')
    parser.add_argument('--network-uid', '-n', required=True, dest='network_uid',
                        help='Network record UID (base64url).')

    def get_parser(self):
        return PAMCnappConfigDeleteCommand.parser

    def execute(self, params, **kwargs):
        cnapp_helper.delete_cnapp_configuration(params, network_uid=kwargs.get('network_uid'))
        print(f"{bcolors.OKGREEN}CNAPP configuration deleted.{bcolors.ENDC}")


# ---------------------------------------------------------------------------
# Queue sub-tree
# ---------------------------------------------------------------------------

class PAMCnappQueueCommand(GroupCommand):

    def __init__(self):
        super(PAMCnappQueueCommand, self).__init__()
        self.register_command('list', PAMCnappQueueListCommand(), 'List CNAPP queue items', 'l')
        self.register_command('associate', PAMCnappQueueAssociateCommand(),
                              'Attach a vault record to a queue item', 'a')
        self.register_command('remediate', PAMCnappQueueRemediateCommand(),
                              'Trigger a remediation action against the gateway', 'r')
        self.register_command('set-status', PAMCnappQueueSetStatusCommand(),
                              'Update local queue item status (notifies provider best-effort)', 's')
        self.register_command('delete', PAMCnappQueueDeleteCommand(), 'Delete a queue item', 'd')
        self.default_verb = 'list'


class PAMCnappQueueListCommand(Command):
    parser = argparse.ArgumentParser(prog='pam cnapp queue list')
    parser.add_argument('--network-uid', '-n', required=True, dest='network_uid',
                        help='Network record UID (base64url).')
    parser.add_argument('--status', '-s', required=False, dest='status', default=0,
                        help='Filter by status name or id (pending/in_progress/resolved/failed/cancelled). Default: all.')
    parser.add_argument('--provider', '-p', required=False, dest='provider', default='wiz',
                        help='CNAPP provider keyword for the config lookup (default: wiz).')
    parser.add_argument('--config-record', required=False, dest='config_record_uid',
                        help='Explicit encrypter vault record UID. Overrides the lookup via `config read`.')
    parser.add_argument('--no-decrypt', dest='no_decrypt', action='store_true',
                        help="Skip payload decryption — show the raw encrypted envelope's metadata only.")
    parser.add_argument('--format', dest='format', choices=['table', 'json'], default='table',
                        help='Output format. Table and JSON are mutually exclusive.')

    def get_parser(self):
        return PAMCnappQueueListCommand.parser

    def _resolve_encrypter_key(self, params, kwargs):
        """Resolve the AES key: --config-record wins; otherwise fetch `config read` to get
        the cnappConfigRecordUid and load the encrypter record from the local vault."""
        if kwargs.get('no_decrypt'):
            return None, None
        config_record_uid = kwargs.get('config_record_uid')
        if not config_record_uid:
            try:
                provider = cnapp_helper.provider_from_name(kwargs.get('provider') or 'wiz')
                config = cnapp_helper.read_cnapp_configuration(
                    params, network_uid=kwargs.get('network_uid'), provider=provider)
            except Exception as e:
                logger.debug('CNAPP: could not read configuration for decryption: %s', e)
                return None, None
            if config is None or not config.cnappConfigRecordUid:
                return None, None
            config_record_uid = bytes_to_base64(config.cnappConfigRecordUid)
        key = _load_encrypter_key(params, config_record_uid)
        return key, config_record_uid

    @staticmethod
    def _decrypted_summary(decrypted):
        """Compact human-readable summary for the table column. Mirrors the columns the
        vault Cloud Security view shows: severity, title, resource."""
        if not isinstance(decrypted, dict):
            return ''
        issue = decrypted.get('issue') or {}
        resource = decrypted.get('resource') or {}
        control = decrypted.get('control') or {}
        bits = []
        sev = issue.get('severity')
        if sev:
            bits.append(str(sev).upper())
        title = control.get('name') or issue.get('id')
        if title:
            bits.append(str(title))
        resource_name = resource.get('name') or resource.get('id')
        if resource_name:
            bits.append(f"on {resource_name}")
        return ' · '.join(bits)

    def execute(self, params, **kwargs):
        status_filter = _resolve_status(kwargs.get('status'))
        response = cnapp_helper.list_cnapp_queue(
            params,
            network_uid=kwargs.get('network_uid'),
            status_filter=status_filter,
        )
        items = list(response.items) if response is not None else []
        has_more = bool(response.hasMore) if response is not None else False

        encrypter_key, encrypter_uid = self._resolve_encrypter_key(params, kwargs)
        decrypted_by_id = {}
        decrypt_errors = {}  # type: dict[int, str]
        if encrypter_key:
            for item in items:
                if not item.payload:
                    continue
                try:
                    decrypted_by_id[item.cnappQueueId] = _decrypt_cnapp_payload(item.payload, encrypter_key)
                except Exception as e:
                    decrypt_errors[item.cnappQueueId] = str(e)

        if kwargs.get('format') == 'json':
            json_items = []
            for item in items:
                d = _queue_item_to_dict(item)
                d.pop('payload', None)
                if item.cnappQueueId in decrypted_by_id:
                    d['decryptedPayload'] = decrypted_by_id[item.cnappQueueId]
                elif item.cnappQueueId in decrypt_errors:
                    d['decryptError'] = decrypt_errors[item.cnappQueueId]
                json_items.append(d)
            payload = {'items': json_items, 'hasMore': has_more}
            print(json.dumps(payload, indent=2, default=str))
            return None

        if not items:
            print('No CNAPP queue items.')
            return None

        if encrypter_key is None and not kwargs.get('no_decrypt'):
            print(f"{bcolors.WARNING}No encrypter key resolved — payloads will be shown as 'encrypted'. "
                  f"Pass --config-record <UID> or run after `pam cnapp config read` succeeds.{bcolors.ENDC}")

        headers = ['Queue ID', 'Provider', 'Status', 'Received (UTC)', 'Resolved (UTC)', 'Record UID', 'Issue']
        rows = []
        for item in items:
            if item.cnappQueueId in decrypted_by_id:
                issue_cell = self._decrypted_summary(decrypted_by_id[item.cnappQueueId])
            elif not item.payload:
                issue_cell = ''
            elif kwargs.get('no_decrypt'):
                issue_cell = '<skipped>'
            else:
                issue_cell = f"{bcolors.WARNING}<encrypted>{bcolors.ENDC}"
            rows.append([
                item.cnappQueueId,
                cnapp_helper.CnappProvider.Name(item.cnappProviderId),
                QUEUE_STATUS_BY_ID.get(item.cnappQueueStatusId, str(item.cnappQueueStatusId)),
                _format_timestamp(item.receivedAt),
                _format_timestamp(item.resolvedAt),
                bytes_to_base64(item.recordUid) if item.recordUid else '',
                issue_cell,
            ])
        dump_report_data(rows, headers, fmt='table', filename='', row_number=False)
        for queue_id, msg in decrypt_errors.items():
            print(f"{bcolors.WARNING}Queue item {queue_id}: failed to decrypt payload ({msg}).{bcolors.ENDC}")
        if has_more:
            print(f"{bcolors.WARNING}More queue items exist (hasMore=true). "
                  f"CLI paging is not available yet — resolve or delete returned items to see more.{bcolors.ENDC}")
        return None


class PAMCnappQueueAssociateCommand(Command):
    parser = argparse.ArgumentParser(prog='pam cnapp queue associate')
    parser.add_argument('--queue-id', '-q', required=True, type=int, dest='cnapp_queue_id',
                        help='Queue item ID (from `pam cnapp queue list`).')
    parser.add_argument('--record-uid', '-r', required=True, dest='record_uid',
                        help='Vault record UID to associate (base64url).')

    def get_parser(self):
        return PAMCnappQueueAssociateCommand.parser

    def execute(self, params, **kwargs):
        cnapp_helper.associate_cnapp_record(
            params,
            cnapp_queue_id=kwargs.get('cnapp_queue_id'),
            record_uid=kwargs.get('record_uid'),
        )
        print(f"{bcolors.OKGREEN}Record associated with queue item {kwargs.get('cnapp_queue_id')}.{bcolors.ENDC}")


class PAMCnappQueueRemediateCommand(Command):
    parser = argparse.ArgumentParser(prog='pam cnapp queue remediate')
    parser.add_argument('--queue-id', '-q', required=True, type=int, dest='cnapp_queue_id',
                        help='Queue item ID.')
    parser.add_argument('--action', '-a', required=True, dest='action_type',
                        help='Remediation action: rotate_credentials, manage_access, jit_access, remove_standing_privilege.')
    parser.add_argument('--provider', '-p', required=False, dest='provider',
                        help='Provider keyword (wiz). Optional — krouter resolves from queue item if omitted.')
    parser.add_argument('--config-record', required=False, dest='cnapp_config_record_uid',
                        help='Configuration record UID (only required for some action types).')
    parser.add_argument('--resource-ref', required=False, dest='resource_ref',
                        help='Resource reference UID for the action.')
    parser.add_argument('--pwd-complexity', required=False, dest='pwd_complexity',
                        help='Password complexity JSON (rotate_credentials).')
    parser.add_argument('--controller-uid', required=False, dest='controller_uid',
                        help='Override gateway UID.')
    parser.add_argument('--message-uid', required=False, dest='message_uid',
                        help='Client-generated conversation UID for streaming responses.')
    parser.add_argument('--group-name', required=False, dest='group_name',
                        help='Group name (remove_standing_privilege only).')

    def get_parser(self):
        return PAMCnappQueueRemediateCommand.parser

    def execute(self, params, **kwargs):
        action = cnapp_helper.action_from_name(kwargs.get('action_type'))
        provider = None
        if kwargs.get('provider'):
            provider = cnapp_helper.provider_from_name(kwargs.get('provider'))
        response = cnapp_helper.remediate_cnapp_queue_item(
            params,
            cnapp_queue_id=kwargs.get('cnapp_queue_id'),
            action_type=action,
            provider=provider,
            cnapp_config_record_uid=kwargs.get('cnapp_config_record_uid'),
            resource_ref=kwargs.get('resource_ref'),
            pwd_complexity=kwargs.get('pwd_complexity'),
            controller_uid=kwargs.get('controller_uid'),
            message_uid=kwargs.get('message_uid'),
            group_name=kwargs.get('group_name'),
        )
        if response is None:
            print(f"{bcolors.OKGREEN}Remediation dispatched.{bcolors.ENDC}")
            return None
        action_name = cnapp_helper.CnappRemediationAction.Name(response.actionType)
        status_name = QUEUE_STATUS_BY_ID.get(response.cnappQueueStatusId, str(response.cnappQueueStatusId))
        print(f"{bcolors.OKGREEN}Remediation dispatched.{bcolors.ENDC}")
        print(f"  Action: {action_name}")
        print(f"  Status: {status_name}")
        if response.result:
            print(f"  Result: {response.result}")
        return None


class PAMCnappQueueSetStatusCommand(Command):
    parser = argparse.ArgumentParser(prog='pam cnapp queue set-status')
    parser.add_argument('--queue-id', '-q', required=True, type=int, dest='cnapp_queue_id',
                        help='Queue item ID.')
    parser.add_argument('--status', '-s', required=True, dest='status',
                        help='New status: pending/in_progress/resolved/failed/cancelled, or its numeric id.')
    parser.add_argument('--reason', required=False, dest='reason',
                        help='Free-form reason (forwarded to provider notification).')

    def get_parser(self):
        return PAMCnappQueueSetStatusCommand.parser

    def execute(self, params, **kwargs):
        status_id = _resolve_status(kwargs.get('status'), allow_all=False)
        response = cnapp_helper.set_cnapp_queue_status(
            params,
            cnapp_queue_id=kwargs.get('cnapp_queue_id'),
            cnapp_queue_status_id=status_id,
            reason=kwargs.get('reason'),
        )
        applied = response.cnappQueueStatusId if response is not None else status_id
        print(f"{bcolors.OKGREEN}Status applied: {QUEUE_STATUS_BY_ID.get(applied, applied)}.{bcolors.ENDC}")
        return None


class PAMCnappQueueDeleteCommand(Command):
    parser = argparse.ArgumentParser(prog='pam cnapp queue delete')
    parser.add_argument('--queue-id', '-q', required=True, type=int, dest='cnapp_queue_id',
                        help='Queue item ID to delete.')

    def get_parser(self):
        return PAMCnappQueueDeleteCommand.parser

    def execute(self, params, **kwargs):
        cnapp_helper.delete_cnapp_queue_item(params, cnapp_queue_id=kwargs.get('cnapp_queue_id'))
        print(f"{bcolors.OKGREEN}Queue item {kwargs.get('cnapp_queue_id')} deleted.{bcolors.ENDC}")


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def _configuration_to_dict(config):
    return {
        'networkUid': bytes_to_base64(config.networkUid) if config.networkUid else '',
        'provider': cnapp_helper.CnappProvider.Name(config.provider),
        'clientId': config.clientId,
        'apiEndpointUrl': config.apiEndpointUrl,
        'authEndpointUrl': config.authEndpointUrl,
        'cnappConfigRecordUid': bytes_to_base64(config.cnappConfigRecordUid) if config.cnappConfigRecordUid else '',
    }


def _queue_item_to_dict(item):
    return {
        'cnappQueueId': item.cnappQueueId,
        'cnappProviderId': cnapp_helper.CnappProvider.Name(item.cnappProviderId),
        'cnappQueueStatusId': item.cnappQueueStatusId,
        'cnappQueueStatusName': QUEUE_STATUS_BY_ID.get(item.cnappQueueStatusId, str(item.cnappQueueStatusId)),
        'receivedAt': item.receivedAt,
        'resolvedAt': item.resolvedAt,
        'networkId': bytes_to_base64(item.networkId) if item.networkId else '',
        'recordUid': bytes_to_base64(item.recordUid) if item.recordUid else '',
    }


def _uid_display(uid_bytes):
    return bytes_to_base64(uid_bytes) if uid_bytes else '(none)'


def _print_configuration(config):
    print(f"{bcolors.OKBLUE}CNAPP Configuration{bcolors.ENDC}")
    print(f"  Network UID    : {_uid_display(config.networkUid)}")
    print(f"  Provider       : {cnapp_helper.CnappProvider.Name(config.provider)}")
    print(f"  Client ID      : {config.clientId or '(none)'}")
    print(f"  API Endpoint   : {config.apiEndpointUrl or '(none)'}")
    print(f"  Auth Endpoint  : {config.authEndpointUrl or '(none)'}")
    print(f"  Config Record  : {_uid_display(config.cnappConfigRecordUid)}")
