"""Commander-SDK-backed client implementations of the protocols.

Each client wraps the Commander command classes and invokes their
.execute() methods with kwargs that match the argparse `dest` names
(not always the flag names — e.g. --name dest is 'displayname').

All methods return bool (True on success) so they compose with the Fake
clients used in tests. Exceptions are caught and logged, never propagated
— the drivers already record failure status per item.

Every kwarg name in this file was verified against the Commander
argparse definitions in:
  keepercommander.commands.enterprise
  keepercommander.commands.register
  keepercommander.commands.record_edit
  keepercommander.commands.recordv3
  keepercommander.importer.commands
"""

import logging
import os

from keepercommander import api


_PURGE_MIN_VERSION = (17, 2, 14)


def _purge_supported():
    """True iff the installed `keepercommander` exposes `rm --purge`
    (KC-625, v17.2.14). Errors parsing the version string fall back to
    False so we never silently downgrade safety: pre-v17.2.14 the kwarg
    is unknown and would raise; post-v17.2.14 missing it makes `rm`
    only unlink instead of hard-delete."""
    try:
        from keepercommander import __version__ as v
        parts = []
        for p in str(v).split('.')[:3]:
            digits = ''
            for ch in p:
                if ch.isdigit():
                    digits += ch
                else:
                    break
            if not digits:
                return False
            parts.append(int(digits))
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts) >= _PURGE_MIN_VERSION
    except Exception:
        return False
from keepercommander.commands.folder import FolderMakeCommand
from keepercommander.commands.enterprise import (
    EnterpriseNodeCommand,
    EnterpriseRoleCommand,
    EnterpriseTeamCommand,
    EnterpriseUserCommand,
)
from keepercommander.commands.record_edit import (
    RecordDownloadAttachmentCommand,
    RecordUploadAttachmentCommand,
)
from keepercommander.commands.register import ShareFolderCommand, ShareRecordCommand
from keepercommander.error import CommandError
from keepercommander.importer.commands import (
    ApplyMembershipCommand,
    LoadRecordTypeCommand,
)

from .attachments import AttachmentClient
from .cleanup import CleanupClient
from .decommission import DecommissionClient
from .sf_reconcile import SFReconcileClient
from .shares import ShareClient
from .structure import StructureClient
from .take_ownership import OwnershipClient
from .take_ownership_restore import RestoreClient
from .transfer_user import TransferUserClient
from .undo import UndoClient
from .users import UserClient


_LAST_CALL_ERROR = ''
# Module-level stash so callers that need the actual Commander error
# text (e.g. structure.StructureRestore recording a per-entity failure
# reason into StepResult.notes) can fetch it after a False return from
# _call. Single-threaded Commander usage makes this safe; avoids
# changing the 28-site _call signature. Cleared on every successful
# call.


def get_last_call_error():
    """Return the error text from the most recent _call that returned
    False. Empty string when the last call succeeded."""
    return _LAST_CALL_ERROR


def _call(cmd, params, **kwargs):
    from .backoff import is_transient
    from .throttle import (
        AdaptiveThrottle,
        SilentFailureCapture,
        ThrottleLogCapture,
        is_throttle_exception,
    )
    global _LAST_CALL_ERROR
    throttle = AdaptiveThrottle.for_params(params)
    throttle.acquire()   # burst-bound: block until a token is free
    throttle.begin_call()
    hit = False
    silent = SilentFailureCapture()
    try:
        with ThrottleLogCapture(throttle), silent:
            try:
                cmd.execute(params, **kwargs)
                # Check for silent Commander skip ("invalid privilege",
                # "X is not found: Skipping" etc.) — these log a
                # warning and return success, so without this check
                # we'd record them as SUCCESS on the plugin side.
                if silent.message:
                    _LAST_CALL_ERROR = silent.message
                    return False
                _LAST_CALL_ERROR = ''
                return True
            except CommandError as e:
                msg = f'{cmd.__class__.__name__}: {e}'
                logging.warning('%s', msg)
                _LAST_CALL_ERROR = str(e)
                hit = is_throttle_exception(e)
                return False
            except Exception as e:                     # noqa: BLE001
                # Transient errors (HTTP 429 / session expired /
                # connection reset) must bubble up so the runner's
                # Retry wrapper can pause and retry. Persistent errors
                # stay swallowed — the per-item status machinery
                # records them as failures.
                if is_transient(e):
                    hit = hit or is_throttle_exception(e)
                    raise
                msg = (f'{cmd.__class__.__name__} raised: '
                       f'{type(e).__name__}: {e}')
                logging.warning('%s', msg)
                _LAST_CALL_ERROR = f'{type(e).__name__}: {e}'
                return False
    finally:
        throttle.end_call(hit=hit)
        throttle.sleep()


def sync_down(params):
    from .throttle import AdaptiveThrottle, ThrottleLogCapture, is_throttle_exception
    throttle = AdaptiveThrottle.for_params(params)
    throttle.acquire()
    throttle.begin_call()
    hit = False
    try:
        with ThrottleLogCapture(throttle):
            api.query_enterprise(params, True)
            api.sync_down(params)
            return True
    except Exception as e:                             # noqa: BLE001
        hit = is_throttle_exception(e)
        logging.warning('sync_down failed: %r', e)
        return False
    finally:
        throttle.end_call(hit=hit)
        throttle.sleep()


# ─── Structure client ────────────────────────────────────────────────────────


class CommanderStructureClient(StructureClient):
    def __init__(self, params):
        self.params = params
        self._node_cmd = EnterpriseNodeCommand()
        self._team_cmd = EnterpriseTeamCommand()
        self._role_cmd = EnterpriseRoleCommand()
        self._user_cmd = EnterpriseUserCommand()
        self._load_rt_cmd = LoadRecordTypeCommand()
        self._apply_membership_cmd = ApplyMembershipCommand()

    def load_record_types(self, path):
        # load-record-types takes `name` positional → file path.
        return _call(self._load_rt_cmd, self.params, name=path)

    def create_node(self, name, parent_name):
        # Bug 73 — direct `node_add` API call, bypassing Commander's
        # `enterprise-node --add` CLI. Commander's CLI does a tenant-
        # wide name-dedup (commands/enterprise.py:1147-1161) and
        # silently logs "Node X already exists: Skipping" when the
        # leaf name collides with any pre-existing node — even one
        # under a different parent. Source topologies that legitimately
        # have e.g. 'Finance' under multiple 'Subsidiary N' parents
        # then end up with only 1 of N created on target. The CLI
        # also returns success on the silent-skip path so the plugin
        # records SUCCESS for non-creates (false positive in
        # structure_results.csv).
        #
        # The bypass uses the same `node_add` payload Commander itself
        # builds (enterprise.py:1180-1188): displayname encrypted with
        # the tenant's tree key, parent_id resolved by name from
        # params.enterprise. Works in MC scope and direct-enterprise
        # scope because both flow `params.enterprise` through the
        # same shape (MCContext rotates tree_key + nodes for the
        # active MC).
        from .backoff import is_transient
        from .throttle import (
            AdaptiveThrottle, ThrottleLogCapture, is_throttle_exception,
        )
        from keepercommander import crypto, utils
        from keepercommander import api as _kapi
        from keepercommander.commands.enterprise_common import EnterpriseCommand
        import json as _json
        global _LAST_CALL_ERROR

        throttle = AdaptiveThrottle.for_params(self.params)
        throttle.acquire()
        throttle.begin_call()
        hit = False
        try:
            with ThrottleLogCapture(throttle):
                ent = getattr(self.params, 'enterprise', None) or {}
                tree_key = ent.get('unencrypted_tree_key')
                if not tree_key:
                    _LAST_CALL_ERROR = ('enterprise tree_key missing — '
                                        'session may not be loaded')
                    logging.warning('create_node[%s]: %s',
                                    name, _LAST_CALL_ERROR)
                    return False

                parent_id = self._resolve_node_id_by_name(ent, parent_name)
                if parent_id is None:
                    _LAST_CALL_ERROR = (
                        f'parent node {parent_name!r} not found in current '
                        f'enterprise data')
                    logging.warning('create_node[%s]: %s',
                                    name, _LAST_CALL_ERROR)
                    return False

                try:
                    new_node_id = EnterpriseCommand.get_enterprise_id(self.params)
                except Exception as e:                  # noqa: BLE001
                    if is_transient(e):
                        hit = is_throttle_exception(e)
                        raise
                    _LAST_CALL_ERROR = f'allocate_ids failed: {e}'
                    logging.warning('create_node[%s]: %s',
                                    name, _LAST_CALL_ERROR)
                    return False

                payload = _json.dumps({'displayname': name})
                encrypted_data = crypto.encrypt_aes_v1(
                    payload.encode('utf-8'), tree_key)
                rq = {
                    'command': 'node_add',
                    'node_id': new_node_id,
                    'parent_id': parent_id,
                    'encrypted_data': utils.base64_url_encode(encrypted_data),
                }

                try:
                    rss = _kapi.execute_batch(self.params, [rq])
                except Exception as e:                  # noqa: BLE001
                    if is_transient(e):
                        hit = is_throttle_exception(e)
                        raise
                    _LAST_CALL_ERROR = f'{type(e).__name__}: {e}'
                    logging.warning('create_node[%s]: %s',
                                    name, _LAST_CALL_ERROR)
                    return False

                rs = (rss or [None])[0]
                if not rs or rs.get('result') != 'success':
                    _LAST_CALL_ERROR = (
                        rs.get('message') if rs else 'no response from node_add')
                    logging.warning('create_node[%s]: node_add failed: %s',
                                    name, _LAST_CALL_ERROR)
                    return False

                # Refresh enterprise tree so subsequent
                # create_node / list_node_names calls see this new node
                # (parent resolution + isolated-flag toggle).
                try:
                    _kapi.query_enterprise(self.params, True)
                except Exception as e:                  # noqa: BLE001
                    # Non-fatal: the node IS created server-side. A
                    # transient sync failure just means later calls
                    # will re-sync. Log + proceed.
                    logging.warning('create_node[%s]: post-create '
                                    'query_enterprise failed: %r — '
                                    'node was created, continuing', name, e)

                _LAST_CALL_ERROR = ''
                return True
        finally:
            throttle.end_call(hit=hit)
            throttle.sleep()

    @staticmethod
    def _resolve_node_id_by_name(ent, parent_name):
        """Resolve `parent_name` → `node_id` from `params.enterprise`.

        Mirrors Commander's enterprise-node CLI parent lookup
        (case-insensitive on displayname, or the rootless node when
        the name matches `enterprise_name`). Bug 73 caveat: when the
        parent name itself is duplicated across the tree, this picks
        the first match — a separate edge case that's not in scope
        for the current fix (rehearsal-14 only had collisions on
        leaf-level Finance/HR, not on parent Subsidiary nodes).
        """
        if not parent_name:
            return None
        target = parent_name.lower().strip()
        ent_name = (ent.get('enterprise_name') or '').lower().strip()
        for n in ent.get('nodes', []) or []:
            data = n.get('data') or {}
            disp = (data.get('displayname') or '').lower().strip()
            if not disp and not n.get('parent_id'):
                disp = ent_name
            if disp == target:
                return n.get('node_id')
        return None

    def toggle_node_isolated(self, name):
        return _call(self._node_cmd, self.params,
                     node=[name], toggle_isolated=True, force=True)

    def create_team(self, name, node, restrict_share, restrict_edit, restrict_view):
        # enterprise-team: positional `team` (nargs='+'); restrict_* dest names
        # are restrict_share/restrict_edit/restrict_view (store 'on'/'off').
        return _call(self._team_cmd, self.params,
                     team=[name], add=True, force=True,
                     node=node,
                     restrict_share=restrict_share,
                     restrict_edit=restrict_edit,
                     restrict_view=restrict_view)

    def create_role(self, name, node, new_user):
        # enterprise-role: positional `role` (nargs='+'), --new-user takes 'on'/'off'.
        kwargs = {'role': [name], 'add': True, 'force': True, 'node': node}
        if new_user == 'on':
            kwargs['new_user'] = 'on'
        return _call(self._role_cmd, self.params, **kwargs)

    def add_role_managed_node(self, role_name, node_name, cascade):
        # -aa/--add-admin dest=add_admin (append list); --cascade dest=cascade ('on'/'off')
        return _call(self._role_cmd, self.params, role=[role_name],
                     add_admin=[node_name], cascade=cascade, force=True)

    def add_role_privilege(self, role_name, privilege, node_name):
        # -ap/--add-privilege dest=add_privilege (append list). --node REQUIRED per
        # enterprise.py:2681.
        return _call(self._role_cmd, self.params, role=[role_name],
                     add_privilege=[privilege], node=node_name, force=True)

    def set_role_enforcement_simple(self, role_name, key, value):
        # --enforcement dest=enforcements (PLURAL, append list).
        return _call(self._role_cmd, self.params, role=[role_name],
                     enforcements=[f'{key}:{value}'], force=True)

    def set_role_enforcements_simple_batch(self, role_name, pairs):
        """Batched version — one API call applies N enforcements on a
        single role. Commander's enterprise-role --enforcement flag is
        already plural (argparse append), and its parser uses
        `continue` on bad values (enterprise.py:2339, 2382) so one bad
        key doesn't kill the whole batch.

        Expected 10x speedup on structure's step_enforcements:
          - Before: 579 calls (1 per enforcement) at ~5 cpm → 2h+
          - After:  51 calls (1 per role) at same rate → ~10 min
        """
        if not pairs:
            return True
        encoded = [f'{k}:{v}' for k, v in pairs]
        return _call(self._role_cmd, self.params, role=[role_name],
                     enforcements=encoded, force=True)

    def set_role_enforcement_file(self, role_name, key, file_path):
        return _call(self._role_cmd, self.params, role=[role_name],
                     enforcements=[f'{key}:$FILE={file_path}'], force=True)

    def assign_user_to_node(self, email, node_name):
        # enterprise-user: email is positional nargs='+'; --node dest=node
        return _call(self._user_cmd, self.params, email=[email],
                     node=node_name, force=True)

    def add_user_to_team(self, email, team_name):
        # --add-team dest=add_team (append list)
        return _call(self._user_cmd, self.params, email=[email],
                     add_team=[team_name], force=True)

    def add_user_to_role(self, role_name, email):
        # enterprise-role -au dest=add_user (append list)
        return _call(self._role_cmd, self.params, role=[role_name],
                     add_user=[email], force=True)

    def add_team_to_role(self, role_name, team_name):
        # enterprise-role -at dest=add_team (append list)
        return _call(self._role_cmd, self.params, role=[role_name],
                     add_team=[team_name], force=True)

    def apply_membership(self, path):
        # apply-membership: positional `name` (nargs='?') → file path
        return _call(self._apply_membership_cmd, self.params, name=path)

    # ── Vault folder mutators (PR-B — preserve source folder types on
    #    target; Commander's import format can't represent mixed
    #    user_folder/shared_folder chains, so structure pre-creates the
    #    hierarchy with correct types before records-import fires).

    def _find_folder_uid_by_name(self, name, parent_uid):
        """Scan params.folder_cache for a direct child of parent_uid
        whose name matches. Used to recover the new UID after mkdir +
        sync_down, since FolderMakeCommand doesn't return it."""
        for uid, f in (getattr(self.params, 'folder_cache', {}) or {}).items():
            if getattr(f, 'name', '') != name:
                continue
            if (getattr(f, 'parent_uid', '') or '') != (parent_uid or ''):
                continue
            return uid
        return ''

    # Commander's mkdir reserves '/' as the path separator — a raw '/'
    # inside a folder name hits `CommandError('mkdir', 'Character "/"
    # is reserved. Use "//" inside folder name')`. Names like
    # `MIGTEST-SF-With/Slash` or `KSM / KCM / PAM /Folder Emulation`
    # must double the slashes before submission.
    @staticmethod
    def _escape_folder_name(name):
        return (name or '').replace('/', '//')

    def _mkdir_with_parent(self, *, name, parent_uid, shared=False,
                            defaults=None):
        """Run `mkdir` inside parent_uid's context, return new folder
        UID (empty on failure). Preserves params.current_folder so we
        don't break the session's cd state."""
        if not name:
            return ''
        defaults = defaults or {}
        original_cur = getattr(self.params, 'current_folder', None)
        try:
            # cd context: set current_folder to parent_uid, or None for
            # vault root.
            self.params.current_folder = parent_uid or None
            # Already-exists short-circuit — saves an API call + avoids
            # the "already exists" warning noise when a rerun passes
            # through an existing hierarchy. Match against the raw
            # source name, not the escaped name (folder_cache stores
            # names as the user sees them).
            existing = self._find_folder_uid_by_name(name, parent_uid)
            if existing:
                return existing
            escaped = self._escape_folder_name(name)
            kwargs = {'folder': escaped}
            if shared:
                kwargs['shared_folder'] = True
                kwargs.update({
                    'manage_users': bool(defaults.get('default_manage_users')),
                    'manage_records': bool(defaults.get('default_manage_records')),
                    'can_edit': bool(defaults.get('default_can_edit')),
                    'can_share': bool(defaults.get('default_can_share')),
                })
            else:
                kwargs['user_folder'] = True
            cmd = FolderMakeCommand()
            cmd.execute(self.params, **kwargs)
            sync_down(self.params)
            return self._find_folder_uid_by_name(name, parent_uid)
        except Exception as e:                          # noqa: BLE001
            logging.error('mkdir %r under parent=%r failed: %r',
                          name, parent_uid, e)
            return ''
        finally:
            self.params.current_folder = original_cur

    def add_user_folder(self, name, parent_uid=''):
        return self._mkdir_with_parent(name=name, parent_uid=parent_uid,
                                        shared=False)

    def add_shared_folder(self, name, parent_uid='', *,
                           default_manage_users=False,
                           default_manage_records=False,
                           default_can_edit=False,
                           default_can_share=False):
        return self._mkdir_with_parent(
            name=name, parent_uid=parent_uid, shared=True,
            defaults={
                'default_manage_users': default_manage_users,
                'default_manage_records': default_manage_records,
                'default_can_edit': default_can_edit,
                'default_can_share': default_can_share,
            },
        )

    def add_subfolder(self, name, parent_sf_folder_uid):
        # Commander routes `mkdir -uf` inside a shared_folder parent to
        # a shared_folder_folder automatically (see FolderMakeCommand).
        # parent_sf_folder_uid must point at a shared_folder or an
        # existing shared_folder_folder UID.
        if not parent_sf_folder_uid:
            logging.error(
                'add_subfolder: parent_sf_folder_uid required '
                '(name=%r) — subfolders cannot sit at vault root.', name,
            )
            return ''
        return self._mkdir_with_parent(name=name,
                                        parent_uid=parent_sf_folder_uid,
                                        shared=False)

    def count_nodes(self, scope_node=''):
        return self._count('nodes', scope_node)

    def count_teams(self, scope_node=''):
        return self._count('teams', scope_node)

    def count_roles(self, scope_node=''):
        return self._count('roles', scope_node)

    def count_users(self, scope_node=''):
        return self._count('users', scope_node)

    def _count(self, kind, scope_node):
        ent = getattr(self.params, 'enterprise', None) or {}
        items = ent.get(kind, []) or []
        if not scope_node:
            return len(items)
        # Scope-filter by descending from the named node
        from .live_inventory import _compute_descendants
        descendants = _compute_descendants(ent, scope_node) or set()
        if kind == 'users':
            return sum(1 for u in items if u.get('node_id') in descendants)
        return sum(1 for e in items if e.get('node_id') in descendants)

    # ── Resume projections (G7) ────────────────────────────────────
    # All read params.enterprise after sync_down — single API call
    # already paid by structure._run before steps fire. Each method
    # returns the same shape its FakeClient counterpart returns.

    def _enterprise(self):
        return getattr(self.params, 'enterprise', None) or {}

    def _node_id_to_name(self):
        from .live_inventory import _node_displayname
        ent = self._enterprise()
        enterprise_name = ent.get('enterprise_name', '')
        return {
            n.get('node_id'): _node_displayname(n, enterprise_name)
            for n in ent.get('nodes', []) or []
        }

    def _scope_descendants(self, scope_node):
        if not scope_node:
            return None
        from .live_inventory import _compute_descendants
        return _compute_descendants(self._enterprise(), scope_node) or set()

    def list_node_names(self, scope_node=''):
        ent = self._enterprise()
        descendants = self._scope_descendants(scope_node)
        id_to_name = self._node_id_to_name()
        names = set()
        for n in ent.get('nodes', []) or []:
            nid = n.get('node_id')
            if descendants is not None and nid not in descendants:
                continue
            name = id_to_name.get(nid)
            if name:
                names.add(name)
        return names

    def list_team_names(self, scope_node=''):
        ent = self._enterprise()
        descendants = self._scope_descendants(scope_node)
        names = set()
        for t in ent.get('teams', []) or []:
            if (descendants is not None
                    and t.get('node_id') not in descendants):
                continue
            name = (t.get('name') or '').strip()
            if name:
                names.add(name)
        return names

    def list_role_names(self, scope_node=''):
        ent = self._enterprise()
        descendants = self._scope_descendants(scope_node)
        names = set()
        for r in ent.get('roles', []) or []:
            if (descendants is not None
                    and r.get('node_id') not in descendants):
                continue
            data = r.get('data') or {}
            name = (data.get('displayname') or r.get('name') or '').strip()
            if name:
                names.add(name)
        return names

    def list_isolated_node_names(self, scope_node=''):
        ent = self._enterprise()
        descendants = self._scope_descendants(scope_node)
        id_to_name = self._node_id_to_name()
        out = set()
        for n in ent.get('nodes', []) or []:
            nid = n.get('node_id')
            if descendants is not None and nid not in descendants:
                continue
            if not n.get('restrict_visibility'):
                continue
            name = id_to_name.get(nid)
            if name:
                out.add(name)
        return out

    def _role_id_by_name(self):
        ent = self._enterprise()
        out = {}
        for r in ent.get('roles', []) or []:
            data = r.get('data') or {}
            name = (data.get('displayname') or r.get('name') or '').strip()
            rid = r.get('role_id')
            if name and rid is not None:
                out[name] = rid
        return out

    def list_role_managed_nodes(self, role_name):
        rid = self._role_id_by_name().get(role_name)
        if rid is None:
            return set()
        ent = self._enterprise()
        id_to_name = self._node_id_to_name()
        out = set()
        for mn in ent.get('managed_nodes', []) or []:
            if mn.get('role_id') != rid:
                continue
            node_name = id_to_name.get(mn.get('managed_node_id'), '')
            if not node_name:
                continue
            cascade = ('on'
                       if mn.get('cascade_node_management', False) else 'off')
            out.add((node_name, cascade))
        return out

    def list_role_privileges(self, role_name):
        rid = self._role_id_by_name().get(role_name)
        if rid is None:
            return set()
        ent = self._enterprise()
        id_to_name = self._node_id_to_name()
        out = set()
        for rp in ent.get('role_privileges', []) or []:
            if rp.get('role_id') != rid:
                continue
            priv = rp.get('privilege', '')
            node = id_to_name.get(rp.get('managed_node_id'), '')
            if priv and node:
                out.add((priv, node))
        return out

    def list_role_enforcements(self, role_name):
        rid = self._role_id_by_name().get(role_name)
        if rid is None:
            return {}
        ent = self._enterprise()
        merged = {}
        for re_ in ent.get('role_enforcements', []) or []:
            if re_.get('role_id') != rid:
                continue
            merged.update(re_.get('enforcements', {}) or {})
        return merged

    def list_user_node_assignments(self):
        ent = self._enterprise()
        id_to_name = self._node_id_to_name()
        out = {}
        for u in ent.get('users', []) or []:
            email = (u.get('username') or u.get('email') or '').strip().lower()
            if not email:
                continue
            node_name = id_to_name.get(u.get('node_id'), '')
            if node_name:
                out[email] = node_name
        return out

    def list_user_team_memberships(self):
        ent = self._enterprise()
        team_by_uid = {
            t.get('team_uid'): (t.get('name') or '').strip()
            for t in ent.get('teams', []) or []
        }
        users_by_id = {
            u.get('enterprise_user_id'):
                (u.get('username') or u.get('email') or '').strip().lower()
            for u in ent.get('users', []) or []
        }
        out = {}
        for tu in ent.get('team_users', []) or []:
            email = users_by_id.get(tu.get('enterprise_user_id'), '')
            team = team_by_uid.get(tu.get('team_uid'), '')
            if email and team:
                out.setdefault(email, set()).add(team)
        return out

    def list_role_user_memberships(self):
        ent = self._enterprise()
        role_id_to_name = {}
        for r in ent.get('roles', []) or []:
            data = r.get('data') or {}
            name = (data.get('displayname') or r.get('name') or '').strip()
            rid = r.get('role_id')
            if rid is not None and name:
                role_id_to_name[rid] = name
        users_by_id = {
            u.get('enterprise_user_id'):
                (u.get('username') or u.get('email') or '').strip().lower()
            for u in ent.get('users', []) or []
        }
        out = {}
        for ru in ent.get('role_users', []) or []:
            role_name = role_id_to_name.get(ru.get('role_id'), '')
            email = users_by_id.get(ru.get('enterprise_user_id'), '')
            if role_name and email:
                out.setdefault(role_name, set()).add(email)
        return out

    def list_role_team_memberships(self):
        ent = self._enterprise()
        role_id_to_name = {}
        for r in ent.get('roles', []) or []:
            data = r.get('data') or {}
            name = (data.get('displayname') or r.get('name') or '').strip()
            rid = r.get('role_id')
            if rid is not None and name:
                role_id_to_name[rid] = name
        team_by_uid = {
            t.get('team_uid'): (t.get('name') or '').strip()
            for t in ent.get('teams', []) or []
        }
        out = {}
        for rt in ent.get('role_teams', []) or []:
            role_name = role_id_to_name.get(rt.get('role_id'), '')
            team = team_by_uid.get(rt.get('team_uid'), '')
            if role_name and team:
                out.setdefault(role_name, set()).add(team)
        return out

    def list_shared_folder_names(self):
        cache = getattr(self.params, 'shared_folder_cache', None) or {}
        out = set()
        for sf in cache.values():
            name = getattr(sf, 'name', '') or ''
            if isinstance(sf, dict):
                name = sf.get('name', '') or ''
            if name:
                out.add(name)
        return out

    def find_folder_uid(self, name, parent_uid):
        return self._find_folder_uid_by_name(name, parent_uid)


# ─── User client ─────────────────────────────────────────────────────────────


class CommanderUserClient(UserClient):
    def __init__(self, params):
        self.params = params
        self._user_cmd = EnterpriseUserCommand()
        self._role_cmd = EnterpriseRoleCommand()
        self._team_cmd = EnterpriseTeamCommand()

    def user_exists(self, email):
        ent = getattr(self.params, 'enterprise', None) or {}
        for u in ent.get('users', []) or []:
            if u.get('username', '').lower() == email.lower():
                return True
        return False

    def invite_user(self, email, full_name, node, job_title=''):
        # --name dest=displayname, --job-title dest=jobtitle
        kwargs = {
            'email': [email], 'invite': True,
            'displayname': full_name,
            'node': node, 'force': True,
        }
        if job_title:
            kwargs['jobtitle'] = job_title
        ok = _call(self._user_cmd, self.params, **kwargs)
        return ok, ''

    def extend_user_invite(self, email):
        return _call(self._user_cmd, self.params, email=[email],
                     extend=True, force=True)

    def set_user_job_title(self, email, job_title):
        # --job-title dest=jobtitle
        return _call(self._user_cmd, self.params, email=[email],
                     jobtitle=job_title, force=True)

    def add_user_alias(self, email, alias_email):
        # --add-alias dest=add_alias action=STORE (single str, not list)
        return _call(self._user_cmd, self.params, email=[email],
                     add_alias=alias_email, force=True)

    def add_user_team(self, email, team_name, hsf_on=False):
        # --hide-shared-folders/-hsf dest=hide_shared_folders ('on'/'off')
        kwargs = {'email': [email], 'add_team': [team_name], 'force': True}
        if hsf_on:
            kwargs['hide_shared_folders'] = 'on'
        return _call(self._user_cmd, self.params, **kwargs)

    def add_user_role(self, email, role_name):
        return _call(self._role_cmd, self.params, role=[role_name],
                     add_user=[email], force=True)

    def approve_team_queue_user(self, email, team_name):
        # `enterprise-team TEAM_NAME -au EMAIL`: Commander's execute() checks
        # the user's active state and emits team_enterprise_user_add when the
        # user is now active (pre-queued users are promoted). If the user is
        # still inactive the add is re-queued — harmless idempotent.
        return _call(self._team_cmd, self.params,
                     team=[team_name], add_user=[email], force=True)

    def list_team_names(self):
        # Backed by the same enterprise cache CommanderStructureClient
        # uses. No scope filter here: UserRunner doesn't carry one, and
        # team names need to match user.teams entries from inventory.
        ent = getattr(self.params, 'enterprise', None) or {}
        names = set()
        for t in ent.get('teams', []) or []:
            n = (t.get('name') or '').strip()
            if n:
                names.add(n)
        return names

    def list_role_names(self):
        ent = getattr(self.params, 'enterprise', None) or {}
        names = set()
        for r in ent.get('roles', []) or []:
            data = r.get('data') or {}
            n = (data.get('displayname') or r.get('name') or '').strip()
            if n:
                names.add(n)
        return names


# ─── Attachment client ───────────────────────────────────────────────────────


class CommanderAttachmentClient(AttachmentClient):
    def __init__(self, params):
        self.params = params
        self._download_cmd = RecordDownloadAttachmentCommand()
        self._upload_cmd = RecordUploadAttachmentCommand()

    def download_attachments(self, source_uid, out_dir):
        os.makedirs(out_dir, exist_ok=True)
        # download_parser: positional `records` nargs='*', dest=records (list)
        # --out-dir dest=out_dir
        before = set(os.listdir(out_dir))
        _call(self._download_cmd, self.params,
              records=[source_uid], out_dir=out_dir)
        after = set(os.listdir(out_dir))
        return [os.path.join(out_dir, f) for f in sorted(after - before)]

    def upload_attachment(self, target_uid, file_path):
        # upload_parser: positional `record` store (single), --file dest=file (append list)
        return _call(self._upload_cmd, self.params,
                     record=target_uid, file=[file_path])


# ─── Share client ────────────────────────────────────────────────────────────


class CommanderDecommissionClient(DecommissionClient):
    """Lock + delete source-tenant users via enterprise-user."""

    def __init__(self, params):
        self.params = params
        self._user_cmd = EnterpriseUserCommand()

    def lock_user(self, email):
        return _call(self._user_cmd, self.params,
                     email=[email], lock=True, force=True)

    def delete_user(self, email):
        return _call(self._user_cmd, self.params,
                     email=[email], delete=True, force=True)

    def is_user_present(self, email):
        """Query params.enterprise.users to verify deletion actually
        happened. enterprise-user --delete calls api.query_enterprise
        at the end of its execute path, so params is fresh.

        Case-insensitive match because Commander normalizes emails
        internally."""
        target = (email or '').strip().lower()
        if not target:
            return False
        enterprise = getattr(self.params, 'enterprise', None) or {}
        for u in enterprise.get('users') or []:
            username = (u.get('username') or '').strip().lower()
            if username == target:
                return True
        return False


class CommanderCleanupClient(CleanupClient):
    """Delete teams, roles, nodes from the current session."""

    def __init__(self, params):
        self.params = params
        self._team_cmd = EnterpriseTeamCommand()
        self._role_cmd = EnterpriseRoleCommand()
        self._node_cmd = EnterpriseNodeCommand()

    def delete_team(self, name):
        return _call(self._team_cmd, self.params,
                     team=[name], delete=True, force=True)

    def delete_role(self, name):
        return _call(self._role_cmd, self.params,
                     role=[name], delete=True, force=True)

    def delete_node(self, name):
        return _call(self._node_cmd, self.params,
                     node=[name], delete=True, force=True)

    def delete_record(self, uid):
        """Delete a record by UID via Commander's `rm`. Force=True to
        bypass the interactive confirm prompt.

        v17.2.14 (KC-625) split `rm` semantics: plain `rm` now only
        unlinks from the caller's vault; the new `--purge` flag is what
        hard-deletes for all users (owner-only). To preserve the
        pre-v17.2.14 behavior the cleanup driver expects, forward
        `purge=True` whenever the installed Commander supports it.
        """
        # SEC-2 fix 2026-05-08: route through _call so SilentFailureCapture
        # catches Commander silent-no-op deletes (logged warning, no raise,
        # would otherwise be reported as SUCCESS by this client).
        # Direct violation of CLAUDE.md Critical Rule #7 pre-fix:
        # "Destructive subcommands with verify-after-delete: cleanup
        # (nodes/teams/roles/records) and decommission (users). Silent
        # Commander no-ops now count as errors."
        from keepercommander.commands.record import RecordRemoveCommand
        kwargs = {'record': uid, 'force': True}
        if _purge_supported():
            kwargs['purge'] = True
        return _call(RecordRemoveCommand(), self.params, **kwargs)

    def delete_shared_folder(self, uid):
        """Delete a shared folder by UID via Commander's `rmdir -f`.
        FolderRemoveCommand resolves the UID via folder_match_strings
        (which iterates name + uid), so a bare UID matches the SF.

        Bug 25 — SFs survive cleanup pre-fix, blocking Bug 22 fresh
        validation across e2e runs. `force=True` skips the interactive
        prompt; the server cascades record/folder unlinks within the
        SF subtree.

        SEC-2 fix 2026-05-08: route through _call (same rationale as
        delete_record above — bare try/except bypassed
        SilentFailureCapture). sync_down is still called on success
        so subsequent reads see the updated state.
        """
        from keepercommander.commands.folder import FolderRemoveCommand
        ok = _call(
            FolderRemoveCommand(), self.params,
            pattern=[uid], force=True, quiet=True,
        )
        if ok:
            sync_down(self.params)
        return ok

    def list_entities(self):
        """Project params.enterprise + record_cache into
        {kind: [{name, parent}, ...]} shape."""
        ent = getattr(self.params, 'enterprise', None) or {}
        enterprise_name = ent.get('enterprise_name', '')
        name_by_id = {}
        node_entries = []
        for n in ent.get('nodes') or []:
            data = n.get('data') or {}
            nm = data.get('displayname') or ''
            if not nm and not n.get('parent_id'):
                nm = enterprise_name
            name_by_id[n.get('node_id')] = nm
            node_entries.append({'node': n, 'name': nm})
        nodes = []
        for entry in node_entries:
            n = entry['node']
            parent = name_by_id.get(n.get('parent_id'), '')
            nodes.append({'name': entry['name'], 'parent': parent})
        teams = [{'name': t.get('name', ''),
                  'parent': name_by_id.get(t.get('node_id'), '')}
                 for t in ent.get('teams') or []]
        roles = [{'name': (r.get('data') or {}).get('displayname') or r.get('name', ''),
                  'parent': name_by_id.get(r.get('node_id'), '')}
                 for r in ent.get('roles') or []]

        # Records come from the record cache, not enterprise. Only
        # include them when the caller asked for include_records —
        # but since the projection shape is stable, we always emit
        # the list; matching_entities() only looks at it when asked.
        records = []
        cache = getattr(self.params, 'record_cache', None) or {}
        for uid, cached in cache.items():
            try:
                from keepercommander import api
                rec = api.get_record(self.params, uid)
                title = getattr(rec, 'title', '') if rec else ''
            except Exception:                           # noqa: BLE001
                title = ''
            if title:
                records.append({'uid': uid, 'title': title})

        # Shared folders (Bug 25) — always emitted; matching_entities
        # filters by prefix. Prefer the human-readable name from
        # folder_cache; the SF cache stores raw/encrypted blobs until
        # vault decrypt. Skips entries whose name is still encrypted-
        # looking (bytes / non-printable) so prefix-match doesn't
        # match unrelated SFs by accident.
        shared_folders = []
        sf_cache = getattr(self.params, 'shared_folder_cache', None) or {}
        folder_cache = getattr(self.params, 'folder_cache', None) or {}
        for sf_uid, sf in sf_cache.items():
            fc_entry = folder_cache.get(sf_uid)
            name = ''
            if fc_entry is not None:
                name = getattr(fc_entry, 'name', '') or ''
            if not name:
                # Fall back to sf.name; if it's bytes/encrypted, skip —
                # we can't safely prefix-match against an undecrypted
                # blob.
                raw = sf.get('name', '') if isinstance(sf, dict) else ''
                if isinstance(raw, str) and raw.isprintable():
                    name = raw
            if not name:
                continue
            shared_folders.append({'uid': sf_uid, 'name': name})

        return {'teams': teams, 'roles': roles, 'nodes': nodes,
                'records': records, 'shared_folders': shared_folders}


class CommanderTransferUserClient(TransferUserClient):
    """Path-B vault transfer via transfer-user command.

    Parser: email (nargs='+'), target_user, force.
    transfer_account.py auto-locks the source user on success.
    """

    def __init__(self, params):
        self.params = params

    def transfer_user_vault(self, email, target_admin):
        from keepercommander.commands.transfer_account import (
            EnterpriseTransferUserCommand,
        )
        return _call(EnterpriseTransferUserCommand(), self.params,
                     email=[email], target_user=target_admin, force=True)

    def sync_down(self):
        return sync_down(self.params)


class CommanderRestoreClient(RestoreClient):
    """Hand folder ownership back to the original user via share-record."""

    def __init__(self, params):
        self.params = params

    def grant_folder_ownership(self, folder_path, new_owner_email):
        return _call(ShareRecordCommand(), self.params,
                     record=folder_path, email=[new_owner_email],
                     action='owner', recursive=True, force=True)


class CommanderOwnershipClient(OwnershipClient):
    """Path-A ownership transfer via ShareRecordCommand + ImporterCommand (for export)."""

    def __init__(self, params):
        self.params = params

    def export_folder_json(self, folder_path, output_path):
        """Export the folder subtree as v3 JSON.

        Commander's `export` command lives in importer.commands. Parser:
          --format (csv|json|...), --folder FOLDER_PATH, positional `name`=output.
        """
        from keepercommander.importer.commands import RecordExportCommand
        return _call(RecordExportCommand(), self.params,
                     format='json', folder=folder_path, name=output_path)

    def take_folder_ownership(self, folder_path, new_owner_email):
        """share-record -e EMAIL -a owner -f -R FOLDER.

        Positional `record` accepts a folder path when combined with --recursive.
        """
        return _call(ShareRecordCommand(), self.params,
                     record=folder_path, email=[new_owner_email],
                     action='owner', recursive=True, force=True)


class CommanderShareClient(ShareClient):
    def __init__(self, source_params, target_params):
        self.source_params = source_params
        self.target_params = target_params

    def get_record_json(self, source_uid):
        """Return a dict with `user_permissions` and `title` — enough for share
        restoration.

        `sync_down` populates `record_cache[uid]` but DOES NOT include
        the `shares` field — that requires a separate
        `vault/get_records_details` call (Commander's
        `api.get_record_shares()`). Without this lazy fetch every
        records-shares run silently SKIPs because cached.shares is {}.
        Bug 19, surfaced 2026-04-27 e2e."""
        cache = getattr(self.source_params, 'record_cache', None) or {}
        cached = cache.get(source_uid)
        if not cached:
            return None
        # Lazy-populate shares if missing. The fetch updates
        # record_cache[source_uid]['shares'] in place.
        if 'shares' not in cached or not cached.get('shares'):
            try:
                api.get_record_shares(self.source_params, [source_uid])
                cached = cache.get(source_uid) or cached
            except Exception:                            # noqa: BLE001
                # Probe failed (offline / proto unavailable). Fall
                # through to read whatever's in cache; the empty path
                # produces SKIP rather than crashing the migration.
                pass
        out = {'record_uid': source_uid}
        shares = cached.get('shares', {}) or {}
        out['user_permissions'] = (shares.get('user_permissions') or [])[:]
        # Title for logging comes from Record if available
        rec = api.get_record(self.source_params, source_uid)
        if rec is not None and hasattr(rec, 'title'):
            out['title'] = rec.title
        return out

    def share_record(self, target_uid, email, editable, shareable):
        # share_record_parser: positional `record` nargs='?' (single);
        # --email dest=email (append list);
        # -w/--write dest=can_edit; -s/--share dest=can_share
        kwargs = {
            'record': target_uid,
            'email': [email],
            'action': 'grant', 'force': True,
        }
        if editable:
            kwargs['can_edit'] = True
        if shareable:
            kwargs['can_share'] = True
        try:
            ShareRecordCommand().execute(self.target_params, **kwargs)
            return 'OK'
        except CommandError as e:
            msg = str(e).lower()
            if 'invitation' in msg and 'sent' in msg:
                return 'PENDING_INVITATION'
            if 'not found' in msg or 'no such user' in msg:
                return 'USER_NOT_FOUND'
            return 'FAIL'
        except Exception as e:                         # noqa: BLE001
            logging.warning('share_record raised: %r', e)
            return 'FAIL'


class CommanderRecordReferenceClient:
    """Bug 33 (v1.5.1) — adapter so ``ReferencesRewriter`` can load and
    persist v3 record fields without importing Commander's vault module
    inside :mod:`references_rewrite`.

    ``load_field_values`` materializes a ``vault.TypedRecord`` from the
    target session's ``record_cache`` and wraps its TypedField objects
    as plain dicts so the rewriter can mutate ``value`` lists without
    touching SDK internals.

    ``persist`` re-mutates the underlying ``TypedField`` instances with
    the new values from the wrapper, then routes through
    ``record_management.update_record`` — the same write path Commander
    uses for ``record-edit``.

    Errors during load/persist are caught and surfaced as ``None`` /
    ``False`` so the rewriter's per-record tally stays accurate. The
    operator's run report shows ``load_failures`` / ``persist_failures``
    counters.
    """

    def __init__(self, params):
        self.params = params

    def load_field_values(self, record_uid):
        from .references_rewrite import LoadedRecord
        try:
            from keepercommander import vault
            storage = self.params.record_cache.get(record_uid)
            if not storage:
                return None
            record = vault.KeeperRecord.load(self.params, storage)
            if record is None or not hasattr(record, 'fields'):
                return None
            # vault.TypedField has attributes (.type, .label, .value).
            # Wrap each as a plain dict so the rewriter can mutate the
            # `value` slot. Keep a parallel list of native fields so
            # persist() can copy back into the original objects.
            fields = [{'type': f.type, 'label': f.label, 'value': list(f.value)}
                      for f in (record.fields or [])]
            custom = [{'type': f.type, 'label': f.label, 'value': list(f.value)}
                      for f in (record.custom or [])]
            return LoadedRecord(
                record_uid=record_uid,
                record_type=getattr(record, 'type_name', '') or '',
                fields=fields, custom=custom,
                _native=record,
            )
        except Exception as e:                              # noqa: BLE001
            logging.warning('load_field_values(%s) failed: %r',
                             record_uid, e)
            return None

    def persist(self, record_uid, loaded):
        try:
            from keepercommander import record_management
            record = loaded._native
            if record is None:
                logging.error('persist: loaded._native is None for %s',
                               record_uid)
                return False
            # Copy mutated values back onto the native TypedField list,
            # matched by position (load_field_values preserves order).
            for native, wrapped in zip(record.fields or [],
                                        loaded.fields or []):
                native.value = list(wrapped.get('value') or [])
            for native, wrapped in zip(record.custom or [],
                                        loaded.custom or []):
                native.value = list(wrapped.get('value') or [])
            record_management.update_record(self.params, record)
            return True
        except Exception as e:                              # noqa: BLE001
            logging.warning('persist(%s) failed: %r', record_uid, e)
            return False


class CommanderUndoClient(UndoClient):
    """Inverse operations dispatched to Commander on the CURRENT session.

    Each method wraps a single Commander SDK command class directly.
    Exceptions are turned into False so the `undo.execute_plans` loop
    can tally failures without aborting the whole rollback.
    """

    def __init__(self, params):
        self.params = params

    def _run(self, cmd_factory, kwargs, description):
        """Run a Commander SDK command for an undo operation.

        HIGH-1 fix 2026-05-08: was bare try/except, bypassing
        SilentFailureCapture exactly like SEC-2 (commander_clients.py
        delete_record / delete_shared_folder pre-fix bba414c). Result:
        Commander silent-no-op on a rollback (e.g. user already
        unlocked, role already absent, share already revoked) returned
        True from this client — undo loop counted it as 'reversed'
        when in fact nothing happened. Now routes through _call so
        silent paths produce False and the loop tallies as 'failed',
        which is the truthful state.
        """
        ok = _call(cmd_factory(), self.params, **kwargs)
        if not ok:
            logging.warning('%s failed: %s', description,
                            get_last_call_error() or 'unknown')
        return ok

    def lock_user(self, email):
        from keepercommander.commands.enterprise import EnterpriseUserCommand
        return self._run(
            EnterpriseUserCommand,
            {'email': [email], 'lock': True},
            f'lock_user({email})',
        )

    def delete_user(self, email):
        from keepercommander.commands.enterprise import EnterpriseUserCommand
        return self._run(
            EnterpriseUserCommand,
            {'email': [email], 'delete': True, 'force': True},
            f'delete_user({email})',
        )

    def delete_node(self, name):
        from keepercommander.commands.enterprise import EnterpriseNodeCommand
        return self._run(
            EnterpriseNodeCommand,
            {'node': [name], 'delete': True, 'force': True},
            f'delete_node({name})',
        )

    def delete_team(self, name):
        from keepercommander.commands.enterprise import EnterpriseTeamCommand
        return self._run(
            EnterpriseTeamCommand,
            {'team': [name], 'delete': True, 'force': True},
            f'delete_team({name})',
        )

    def delete_role(self, name):
        from keepercommander.commands.enterprise import EnterpriseRoleCommand
        return self._run(
            EnterpriseRoleCommand,
            {'role': [name], 'delete': True, 'force': True},
            f'delete_role({name})',
        )

    def delete_shared_folder(self, uid):
        # FolderRemoveCommand takes a `pattern` (path OR UID) and a
        # `force` flag — `ShareFolderCommand(action='remove')` removes
        # a user/team FROM a folder, NOT the folder itself.
        #
        # HIGH-1 fix 2026-05-08: refactored to route through _run (now
        # itself routed through _call) so silent-no-op rollbacks are
        # caught. Pre-fix this method had its own bare try/except,
        # bypassing _call exactly like SEC-2.
        from keepercommander.commands.folder import FolderRemoveCommand
        return self._run(
            FolderRemoveCommand,
            {'pattern': uid, 'force': True, 'quiet': True},
            f'delete_shared_folder({uid})',
        )

    def revoke_record_share(self, target_uid, email):
        # HIGH-1 fix 2026-05-08: route through _run (now itself routed
        # through _call). Pre-fix had bare try/except splitting on
        # CommandError vs generic Exception; both branches returned
        # False, neither caught silent-no-op (a re-revoke of an already-
        # revoked share is a Commander silent path).
        return self._run(
            ShareRecordCommand,
            {'record': target_uid, 'email': [email],
             'action': 'revoke', 'force': True},
            f'revoke_record_share({target_uid}, {email})',
        )

    def delete_attachment(self, record_uid, file_name):
        # Commander's delete-attachment needs the attachment's fileRef UID;
        # we record the filename in summary, so resolution has to happen
        # at undo time. For now we emit a manual action.
        #
        # HIGH-5 fix 2026-05-08: pre-fix this returned False, which the
        # undo loop tallied as a generic failure — indistinguishable
        # from a Commander rejection. Operators reading the undo
        # summary saw "X failed" with no signal that those Xs were
        # actually "human action required" rather than runtime errors.
        # Now raises ManualActionRequired; loop catches and tallies
        # as `manual` (separate column in the summary).
        from .undo import ManualActionRequired
        raise ManualActionRequired(
            f'delete_attachment({record_uid}, {file_name}): cannot '
            f'resolve fileRef UID from filename alone — delete manually '
            f'on target via the web UI or via "keeper get {record_uid}" '
            f'to find the file UID first.'
        )


class CommanderSFReconcileClient(SFReconcileClient):
    """Target-session queries + share-folder adds for the SF reconciler.

    Assumes sync_down has run on `params` so enterprise.users and the
    shared-folder caches are fresh — the reconcile command enforces
    that before building the client.
    """

    def __init__(self, params):
        self.params = params

    def list_sf_memberships(self):
        out = {}
        enterprise = getattr(self.params, 'enterprise', None) or {}

        # Enterprise-managed shared folders (preferred source — carries
        # authoritative membership list).
        sfs = enterprise.get('shared_folders') or []
        users = {u.get('enterprise_user_id'): (u.get('username') or '').lower()
                 for u in enterprise.get('users') or []}
        sf_users = enterprise.get('shared_folder_users') or []
        for row in sf_users:
            sf_uid = row.get('shared_folder_uid')
            uid = row.get('enterprise_user_id')
            email = users.get(uid, '')
            if not (sf_uid and email):
                continue
            sf_meta = next((s for s in sfs
                            if s.get('shared_folder_uid') == sf_uid), None)
            if not sf_meta:
                continue
            name = (sf_meta.get('name') or '').strip()
            if name:
                out.setdefault(name, set()).add(email)

        # Include SFs that currently have zero members too, so a "SF exists"
        # check doesn't misfire as "SF not found on target".
        for s in sfs:
            name = (s.get('name') or '').strip()
            if name and name not in out:
                out[name] = set()

        return out

    def list_user_statuses(self):
        enterprise = getattr(self.params, 'enterprise', None) or {}
        out = {}
        for u in enterprise.get('users') or []:
            email = (u.get('username') or '').strip().lower()
            if not email:
                continue
            # Commander's `status` is the raw enum:
            # 'active', 'invited', 'locked', 'expired', 'blocked'.
            status = (u.get('status') or '').strip().lower()
            out[email] = status or 'unknown'
        return out

    def add_user_to_sf(self, sf_name, email):
        try:
            ShareFolderCommand().execute(
                self.params, folder=[sf_name],
                action='grant', user=[email], force=True,
            )
            return 'OK'
        except CommandError as e:
            msg = str(e).lower()
            if 'already' in msg and 'member' in msg:
                return 'ALREADY_MEMBER'
            if 'not found' in msg and 'folder' in msg:
                return 'SF_NOT_FOUND'
            if 'not found' in msg or 'no such user' in msg:
                return 'USER_NOT_FOUND'
            logging.warning('add_user_to_sf %s→%s: %s', sf_name, email, e)
            return 'FAIL'
        except Exception as e:                         # noqa: BLE001
            logging.warning('add_user_to_sf raised: %r', e)
            return 'FAIL'

    def remove_user_from_sf(self, sf_name, email):
        """--prune path. Revokes SF membership via share-folder
        action='remove'. Idempotent at the Keeper layer: removing a
        non-member is a no-op."""
        try:
            ShareFolderCommand().execute(
                self.params, folder=[sf_name],
                action='remove', user=[email], force=True,
            )
            return 'OK'
        except CommandError as e:
            msg = str(e).lower()
            if 'not' in msg and 'member' in msg:
                return 'NOT_MEMBER'
            if 'not found' in msg and 'folder' in msg:
                return 'SF_NOT_FOUND'
            logging.warning('remove_user_from_sf %s→%s: %s',
                            sf_name, email, e)
            return 'FAIL'
        except Exception as e:                         # noqa: BLE001
            logging.warning('remove_user_from_sf raised: %r', e)
            return 'FAIL'
