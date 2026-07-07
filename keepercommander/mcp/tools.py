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
"""MCP tool handlers.

Each handler has the signature ``handler(params, config, grant, args) -> dict``.
Read-oriented handlers query the Commander data model directly; mutating/PAM handlers
reuse the existing Commander commands via :func:`run_cli_command`, so Commander's own
validation and enforcement stay in the loop. Scope, self-protection, and guardrails are
enforced here (and centrally in the server) before any Commander code runs.
"""

import io
import logging
import shlex
import sys
from typing import Optional

from . import guardrails
from .guardrails import MCPAccessError
from .. import vault, vault_extensions
from ..params import KeeperParams


def run_cli_command(params, command):  # type: (KeeperParams, str) -> str
    """Run a Commander command and return its output.

    Captures stdout, stderr, and log output (mirrors the service-mode adapter). Many
    commands report failures/warnings through logging or stderr rather than stdout, so
    returning stdout alone would hide errors from the agent (e.g. a blocked record-add
    would look like an empty success). We therefore return stdout when it is non-empty
    (this keeps JSON-emitting commands parseable), and otherwise fall back to the
    combined stderr + log text so the agent sees why nothing happened.
    """
    from .. import cli

    out_buf, err_buf, log_buf = io.StringIO(), io.StringIO(), io.StringIO()
    log_handler = logging.StreamHandler(log_buf)
    log_handler.setFormatter(logging.Formatter('%(message)s'))
    root_logger = logging.getLogger()
    old_level = root_logger.level
    old_stdout, old_stderr = sys.stdout, sys.stderr
    old_service_mode = getattr(params, 'service_mode', False)

    sys.stdout, sys.stderr = out_buf, err_buf
    params.service_mode = True
    root_logger.addHandler(log_handler)
    if old_level > logging.INFO or old_level == logging.NOTSET:
        root_logger.setLevel(logging.INFO)
    try:
        cli.do_command(params, command)
    finally:
        sys.stdout, sys.stderr = old_stdout, old_stderr
        params.service_mode = old_service_mode
        root_logger.removeHandler(log_handler)
        root_logger.setLevel(old_level)
        log_handler.close()

    stdout = out_buf.getvalue().strip()
    if stdout:
        return stdout
    # No stdout: surface stderr/log so failures and warnings are not silently swallowed.
    diagnostics = '\n'.join(s for s in (err_buf.getvalue().strip(), log_buf.getvalue().strip()) if s)
    return diagnostics


def _join(parts):  # type: (list) -> str
    return ' '.join(shlex.quote(str(p)) for p in parts if p is not None)


def _parsed_result(output):  # type: (str) -> dict
    """Return JSON-decoded command output when possible, else wrap the raw text."""
    import json
    text = (output or '').strip()
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return {'result': text}


def _resolve_record_uid(params, identifier):  # type: (KeeperParams, str) -> Optional[str]
    """Resolve a record UID from a UID or an exact/searchable title."""
    if not identifier:
        return None
    if identifier in params.record_cache:
        return identifier
    for record in vault_extensions.find_records(params, identifier):
        return record.record_uid
    return None


# --------------------------------------------------------------------------------------
# Read-oriented handlers (direct data-model access)
# --------------------------------------------------------------------------------------

def search_records(params, config, grant, args):
    query = (args.get('query') or '').strip() or None
    try:
        limit = int(args.get('limit') or 50)
    except (TypeError, ValueError):
        limit = 50
    out = []
    for record in vault_extensions.find_records(params, query):
        # Self-protection: the config record is never surfaced.
        if config.config_record_uid and record.record_uid == config.config_record_uid:
            continue
        if not guardrails.record_in_scope(params, grant, record.record_uid):
            continue
        out.append({'uid': record.record_uid, 'title': record.title, 'type': record.record_type})
        if len(out) >= limit:
            break
    return {'count': len(out), 'records': out}


def read_secret(params, config, grant, args):
    identifier = (args.get('record') or '').strip()
    uid = _resolve_record_uid(params, identifier)
    if not uid:
        raise MCPAccessError(f'Record not found: {identifier}')
    guardrails.assert_not_config_record(config, uid)
    guardrails.assert_record_in_scope(params, grant, uid)

    record = vault.KeeperRecord.load(params, uid)
    if record is None:
        raise MCPAccessError(f'Record not found: {identifier}')

    fields = {}
    for name, value in record.enumerate_fields():
        if value not in (None, '', []):
            fields[name] = value

    field_filter = (args.get('field') or '').strip().lower()
    if field_filter:
        matched = {k: v for k, v in fields.items() if field_filter in k.lower()}
        return {'uid': uid, 'title': record.title, 'fields': matched}
    return {'uid': uid, 'title': record.title, 'type': record.record_type, 'fields': fields}


# --------------------------------------------------------------------------------------
# Mutating vault handlers (reuse Commander commands)
# --------------------------------------------------------------------------------------

def create_record(params, config, grant, args):
    title = args.get('title')
    if not title:
        raise MCPAccessError('"title" is required to create a record.')
    record_type = args.get('record_type') or 'login'
    folder = args.get('folder')
    if folder:
        guardrails.assert_folder_in_scope(params, grant, folder)

    parts = ['record-add', '--title', title, f'--record-type={record_type}']
    if folder:
        parts += ['--folder', folder]
    if args.get('notes'):
        parts += ['--notes', args['notes']]
    command = _join(parts)
    # Field tokens (e.g. "login=user@example.com", "password=...") are passed through verbatim.
    for token in (args.get('fields') or []):
        command += ' ' + shlex.quote(str(token))
    return {'result': run_cli_command(params, command)}


def update_record(params, config, grant, args):
    identifier = (args.get('record') or '').strip()
    uid = _resolve_record_uid(params, identifier)
    if not uid:
        raise MCPAccessError(f'Record not found: {identifier}')
    guardrails.assert_not_config_record(config, uid)
    guardrails.assert_record_in_scope(params, grant, uid)

    parts = ['record-update', '--record', uid]
    if args.get('title'):
        parts += ['--title', args['title']]
    if args.get('notes'):
        parts += ['--notes', args['notes']]
    command = _join(parts)
    for token in (args.get('fields') or []):
        command += ' ' + shlex.quote(str(token))
    return {'result': run_cli_command(params, command)}


def share_record(params, config, grant, args):
    identifier = (args.get('record') or '').strip()
    uid = _resolve_record_uid(params, identifier)
    if not uid:
        raise MCPAccessError(f'Record not found: {identifier}')
    guardrails.assert_not_config_record(config, uid)
    guardrails.assert_record_in_scope(params, grant, uid)

    if args.get('one_time'):
        parts = ['one-time-share', 'create', '--name', args.get('name') or 'mcp-share']
        if args.get('expire'):
            parts += ['--expire', args['expire']]
        parts.append(uid)
        return {'result': run_cli_command(params, _join(parts))}

    email = args.get('email')
    if not email:
        raise MCPAccessError('"email" is required to share a record.')
    parts = ['share-record', '--email', email, '--action', args.get('action') or 'grant']
    if args.get('can_edit'):
        parts.append('--can-edit')
    if args.get('can_share'):
        parts.append('--can-share')
    parts.append(uid)
    return {'result': run_cli_command(params, _join(parts))}


def share_folder(params, config, grant, args):
    folder = (args.get('folder') or '').strip()
    if not folder:
        raise MCPAccessError('"folder" is required to share a folder.')
    guardrails.assert_folder_in_scope(params, grant, folder)
    parts = ['share-folder', '--action', args.get('action') or 'grant']
    if args.get('email'):
        parts += ['--user', args['email']]
    if args.get('can_edit'):
        parts += ['--manage-records', 'on']
    parts.append(folder)
    return {'result': run_cli_command(params, _join(parts))}


# --------------------------------------------------------------------------------------
# KSM handler
# --------------------------------------------------------------------------------------

def ksm_manage_app(params, config, grant, args):
    action = (args.get('action') or '').strip()
    if action == 'app-create':
        name = args.get('name')
        if not name:
            raise MCPAccessError('"name" is required to create a Secrets Manager application.')
        return {'result': run_cli_command(params, _join(['secrets-manager', 'app', 'create', name]))}
    if action == 'client-add':
        app = args.get('app')
        if not app:
            raise MCPAccessError('"app" is required to add a client.')
        return {'result': run_cli_command(params, _join(['secrets-manager', 'client', 'add', '--app', app]))}
    if action == 'share':
        app = args.get('app')
        secret = args.get('secret')
        if not app or not secret:
            raise MCPAccessError('"app" and "secret" are required to share.')
        return {'result': run_cli_command(params, _join(['secrets-manager', 'share', 'add', '--app', app, '--secret', secret]))}
    raise MCPAccessError(f'Unknown ksm action: {action!r}. Use app-create, client-add, or share.')


# --------------------------------------------------------------------------------------
# PAM handlers (high-risk; guardrails enforced)
#
# Verb mapping reconciled against discoveryrotation.py::GatewayActionCommand and
# tunnel_and_connections.py::PAMTunnelCommand:
#   pam_rotate         -> "pam action rotate --record-uid <uid> [--dry-run]"
#   pam_launch_session -> "pam tunnel start <uid> [--reason ... --ticket ...]"
#   pam_exec_command   -> "pam action exec  --record-uid <uid> --command <c>"
#   pam_db_query       -> "pam action query --record-uid <uid> --query <q>"
#
# "pam action exec" and "pam action query" are currently stub commands returning synthetic
# data (see PAMGatewayActionExecCommand / PAMGatewayActionQueryCommand). _require_pam_action_verb
# still guards them, so if a build ever drops those verbs the tools return a clear, auditable
# "not available" error instead of failing obscurely. These two are the ideal channel for
# running DB queries / remote commands against protected resources, since every call flows
# through the gateway with full auditing.
# --------------------------------------------------------------------------------------

def _pam_action_verbs(params):  # type: (KeeperParams) -> set
    """Return the set of verbs currently registered under "pam action"."""
    try:
        from ..commands import commands as registry
        pam = registry.get('pam')
        action = pam.subcommands.get('action') if pam else None
        return set(action.subcommands.keys()) if action else set()
    except Exception:
        return set()


def _require_pam_action_verb(params, verb):  # type: (KeeperParams, str) -> None
    if verb not in _pam_action_verbs(params):
        raise MCPAccessError(
            f'The "pam action {verb}" command is not available in this version of Commander.')


def pam_rotate(params, config, grant, args):
    uid = (args.get('record_uid') or '').strip()
    if not uid:
        raise MCPAccessError('"record_uid" is required to rotate a credential.')
    guardrails.assert_not_config_record(config, uid)
    parts = ['pam', 'action', 'rotate', '--record-uid', uid]
    if guardrails.is_dry_run_only(grant) or args.get('dry_run'):
        parts.append('--dry-run')
    return {'result': run_cli_command(params, _join(parts))}


def pam_exec_command(params, config, grant, args):
    uid = (args.get('record_uid') or '').strip()
    command_text = args.get('command')
    if not uid or not command_text:
        raise MCPAccessError('"record_uid" and "command" are required.')
    guardrails.assert_not_config_record(config, uid)
    host = args.get('host') or ''
    guardrails.assert_host_allowed(grant, host)
    _require_pam_action_verb(params, 'exec')
    parts = ['pam', 'action', 'exec', '--record-uid', uid, '--command', command_text, '--format', 'json']
    return _parsed_result(run_cli_command(params, _join(parts)))


def pam_db_query(params, config, grant, args):
    uid = (args.get('record_uid') or '').strip()
    query = args.get('query')
    if not uid or not query:
        raise MCPAccessError('"record_uid" and "query" are required.')
    guardrails.assert_not_config_record(config, uid)
    _require_pam_action_verb(params, 'query')
    parts = ['pam', 'action', 'query', '--record-uid', uid, '--query', query, '--format', 'json']
    return _parsed_result(run_cli_command(params, _join(parts)))


def pam_launch_session(params, config, grant, args):
    uid = (args.get('record_uid') or '').strip()
    if not uid:
        raise MCPAccessError('"record_uid" is required to launch a session.')
    guardrails.assert_not_config_record(config, uid)
    host = args.get('host') or ''
    guardrails.assert_host_allowed(grant, host)
    parts = ['pam', 'tunnel', 'start', uid]
    # JIT access-request workflow is part of tunnel/launch, not a standalone command.
    if args.get('reason'):
        parts += ['--reason', args['reason']]
    if args.get('ticket'):
        parts += ['--ticket', args['ticket']]
    return {'result': run_cli_command(params, _join(parts))}
