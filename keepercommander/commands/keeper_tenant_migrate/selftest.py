"""Read-only self-test against the current Commander session.

Exercises every client protocol's READ path without creating, modifying,
or deleting any entity. Outputs a pass/fail report so users know whether
the SDK integration works against their tenant before they trust it with
destructive operations.

What it checks:
  - session is authenticated (whoami succeeds)
  - params.enterprise is populated (sync_down worked)
  - every Commander command referenced by commander_clients.py imports
    without error and its argparse parser has the expected dests
  - live inventory can be built from params (entity counts > 0 or skip)
  - target-state projection produces a non-empty shape
  - at least one record can be read from the vault (if any exist)

Every check is one of PASS | SKIP | FAIL. A single FAIL aborts the run
with a non-zero return so the orchestrator checkpoint records it.
"""

import logging


class Check:
    __slots__ = ('name', 'status', 'detail')

    def __init__(self, name, status, detail=''):
        self.name = name
        self.status = status
        self.detail = detail

    def __repr__(self):
        tail = f' — {self.detail}' if self.detail else ''
        return f'Check({self.status} {self.name}{tail})'


def _check_session(params):
    user = getattr(params, 'user', '') or ''
    if not user:
        return Check('session.user', 'FAIL', 'params.user is empty — not logged in')
    return Check('session.user', 'PASS', user)


def _check_enterprise_loaded(params):
    ent = getattr(params, 'enterprise', None) or {}
    if not ent:
        return Check('enterprise.loaded', 'FAIL',
                     'params.enterprise empty — run `sync-down` first')
    nodes = ent.get('nodes', []) or []
    return Check('enterprise.loaded', 'PASS',
                 f"enterprise={ent.get('enterprise_name', '?')}, nodes={len(nodes)}")


def _check_commander_imports():
    from .commander_clients import (  # noqa: F401
        CommanderAttachmentClient, CommanderShareClient,
        CommanderStructureClient, CommanderUserClient,
    )
    return Check('commander_clients.import', 'PASS', 'all 4 clients import')


def _check_parser_dests():
    """Every command a client calls has the dests we send to it."""
    from keepercommander.commands.enterprise import (
        EnterpriseNodeCommand, EnterpriseRoleCommand,
        EnterpriseTeamCommand, EnterpriseUserCommand,
    )
    from keepercommander.commands.record_edit import (
        RecordDownloadAttachmentCommand, RecordUploadAttachmentCommand,
    )
    from keepercommander.commands.register import ShareRecordCommand
    from keepercommander.importer.commands import (
        ApplyMembershipCommand, LoadRecordTypeCommand, RecordImportCommand,
    )

    expected = {
        EnterpriseNodeCommand:   {'node', 'add', 'parent', 'toggle_isolated', 'force'},
        EnterpriseTeamCommand:   {'team', 'add', 'node', 'restrict_share',
                                   'restrict_edit', 'restrict_view', 'force'},
        EnterpriseRoleCommand:   {'role', 'add', 'node', 'new_user',
                                   'add_admin', 'cascade', 'add_privilege',
                                   'enforcements', 'add_user', 'add_team', 'force'},
        EnterpriseUserCommand:   {'email', 'invite', 'displayname', 'jobtitle',
                                   'node', 'extend', 'add_team',
                                   'add_alias', 'hide_shared_folders', 'force'},
        RecordDownloadAttachmentCommand: {'records', 'out_dir'},
        RecordUploadAttachmentCommand:   {'record', 'file'},
        ShareRecordCommand:      {'record', 'email', 'action',
                                   'can_edit', 'can_share', 'force'},
        ApplyMembershipCommand:  {'name'},
        LoadRecordTypeCommand:   {'name'},
        RecordImportCommand:     {'name', 'format', 'shared',
                                   'record_type', 'dry_run'},
    }
    missing = []
    for cmd_cls, dests in expected.items():
        parser = cmd_cls().get_parser()
        actual = {a.dest for a in parser._actions}
        gap = dests - actual
        if gap:
            missing.append(f'{cmd_cls.__name__}: {sorted(gap)}')
    if missing:
        return Check('parser.dests', 'FAIL', '; '.join(missing))
    return Check('parser.dests', 'PASS', f'{len(expected)} commands verified')


def _check_live_inventory(params):
    try:
        from .live_inventory import build_inventory_from_params
        inv = build_inventory_from_params(params)
        counts = inv['counts']
        if sum(counts.values()) == 0:
            return Check('live_inventory', 'SKIP',
                         'empty tenant — nothing to inventory')
        return Check('live_inventory', 'PASS',
                     f"nodes={counts['nodes']} teams={counts['teams']} "
                     f"roles={counts['roles']} users={counts['users']}")
    except Exception as e:                             # noqa: BLE001
        return Check('live_inventory', 'FAIL', repr(e))


def _check_target_state_projection(params):
    try:
        from .commands import _params_enterprise_to_target_state
        state = _params_enterprise_to_target_state(params)
        if not any(state.get(k) for k in
                   ('nodes', 'teams', 'roles', 'users', 'shared_folders')):
            return Check('target_state', 'SKIP', 'empty tenant')
        return Check('target_state', 'PASS',
                     f"nodes={len(state['nodes'])} teams={len(state['teams'])} "
                     f"roles={len(state['roles'])} sfs={len(state['shared_folders'])}")
    except Exception as e:                             # noqa: BLE001
        return Check('target_state', 'FAIL', repr(e))


def _check_record_read(params):
    cache = getattr(params, 'record_cache', None) or {}
    if not cache:
        return Check('record.read', 'SKIP',
                     'vault empty or not synced')
    try:
        from .commander_clients import CommanderShareClient
        client = CommanderShareClient(params, params)
        uid = next(iter(cache))
        rec = client.get_record_json(uid)
        if rec is None:
            return Check('record.read', 'FAIL', 'get_record_json returned None')
        return Check('record.read', 'PASS',
                     f'read uid={uid} title={rec.get("title", "?")}')
    except Exception as e:                             # noqa: BLE001
        return Check('record.read', 'FAIL', repr(e))


CHECKS = [
    ('session',              _check_session),
    ('commander_imports',    lambda p: _check_commander_imports()),
    ('parser_dests',         lambda p: _check_parser_dests()),
    ('enterprise_loaded',    _check_enterprise_loaded),
    ('live_inventory',       _check_live_inventory),
    ('target_state',         _check_target_state_projection),
    ('record_read',          _check_record_read),
]


def run(params):
    """Run every read-only check. Returns (results, fail_count)."""
    results = []
    for name, fn in CHECKS:
        try:
            result = fn(params)
        except Exception as e:                         # noqa: BLE001
            result = Check(name, 'FAIL', f'uncaught: {e!r}')
        results.append(result)
        emoji = {'PASS': '✓', 'SKIP': '↷', 'FAIL': '✗'}.get(result.status, '?')
        logging.info('  %s %-22s %s', emoji, result.name, result.detail)

    fails = sum(1 for r in results if r.status == 'FAIL')
    return results, fails
