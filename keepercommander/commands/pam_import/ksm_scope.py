#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

"""The records and folders a KSM application (and therefore the Gateway) can see.

Rules (verified on QA 2026-11-11 with a plain KSM client, the Gateway only calls the
KSM SDK ``get_secrets()``):

* A classic shared folder (SHF) shared to the app covers all its subfolders (SHFF) and
  every record added to them later: they all use the one SHF key. Walked recursively.
* A Nested Shared Folder (NSF) shared to the app covers ONLY that folder. Every child
  NSF needs its own share, otherwise the app cannot see it. Not walked for scope. The
  children are still read, with ``status == 'unshared'``, so that ``folder_path`` can be
  resolved against the full tree and so that the user is warned.
* A record shared directly to the app (``SHARE_TYPE_RECORD``) has no folder. The KSM API
  returns a record twice when it is shared directly AND through a folder, so everything
  is de-duplicated by record UID and the sources are kept.
* A direct share of an NSF record cannot be created today; it is tagged and skipped.

Nothing here writes to the vault. ``update`` has no fallback for missing app shares;
``extend`` may pass its project-folder fallback roots (``source == 'nested_share_folder'``),
which are reported as ``unconfirmed``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

from .nsf_helpers import get_folder_record_uids, get_record_summary
from .record_matcher import MatchRecord

STATUS_SHARED = 'shared'
STATUS_UNSHARED = 'unshared'
STATUS_UNCONFIRMED = 'unconfirmed'

KIND_SHF = 'shf'
KIND_SHFF = 'shff'
KIND_NSF = 'nsf'

SOURCE_FOLDER = 'folder'
SOURCE_DIRECT = 'direct'

# ``source`` values of the folder dicts built by get_ksm_app_folders / extend
_SOURCE_CLASSIC = 'classic'
_SOURCE_NESTED = 'nested'
_SOURCE_NSF_FALLBACK = 'nested_share_folder'


@dataclass
class AppShares:
    folder_uids: List[str] = field(default_factory=list)
    record_uids: List[str] = field(default_factory=list)
    ok: bool = True


@dataclass
class ScopeFolder:
    uid: str
    name: str
    path: str
    parent_uid: str
    kind: str
    status: str
    nearest_shared_ancestor: str = ''
    readable: bool = True
    record_uids: List[str] = field(default_factory=list)


@dataclass
class ScopeRecord:
    uid: str
    title: str
    record_type: str
    login: str
    folder_uids: List[str] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)
    shared: bool = True


@dataclass
class KsmScope:
    params: object = None
    folders: Dict[str, ScopeFolder] = field(default_factory=dict)
    records: Dict[str, ScopeRecord] = field(default_factory=dict)
    unresolved_shares: int = 0
    skipped_direct_nsf: List[str] = field(default_factory=list)
    unreadable_direct: List[str] = field(default_factory=list)
    unreadable_folders: List[str] = field(default_factory=list)
    app_shares_ok: bool = True

    # ---- views -------------------------------------------------------------------
    def match_records(self) -> List[MatchRecord]:
        """Every record the scope knows (shared or not), for :class:`RecordIndex`."""
        return [MatchRecord(uid=r.uid, title=r.title, record_type=r.record_type, login=r.login,
                            folder_uids=tuple(r.folder_uids), shared=r.shared)
                for r in self.records.values()]

    def record_tuples(self) -> List[Tuple[str, str, str, str]]:
        """(uid, title, record_type, login) of every known record, unique by uid."""
        return [(r.uid, r.title, r.record_type, r.login) for r in self.records.values()]

    def empty_folders(self) -> List[ScopeFolder]:
        return [f for f in self.folders.values() if f.readable and not f.record_uids]

    # ---- text helpers --------------------------------------------------------------
    def folder_label(self, folder_uid: str) -> str:
        folder = self.folders.get(folder_uid)
        if folder:
            return folder.path or folder.name or folder_uid
        chain = _vault_folder_chain(self.params, folder_uid)
        return '/'.join(name for _, name in chain) if chain else folder_uid

    def describe_location(self, record_uid: str) -> str:
        """``folder "A/B/C" (closest shared folder on the path: "B")`` for a record outside the scope."""
        folder_uids = _folders_of_record(self.params, record_uid)
        if not folder_uids:
            return 'the vault (no folder found)'
        chain = _vault_folder_chain(self.params, folder_uids[0])
        path = '/'.join(name for _, name in chain)
        ancestor_name = ''
        for uid, name in reversed(chain[:-1]):
            known = self.folders.get(uid)
            if known and known.status in (STATUS_SHARED, STATUS_UNCONFIRMED):
                ancestor_name = name
                break
        if ancestor_name:
            return f'folder "{path}" (closest shared folder on the path: "{ancestor_name}")'
        return (f'folder "{path}" (no folder on this path is shared to the KSM app - '
                f'was the parent / root folder unshared?)')

    def nsf_warnings(self, ignored: bool = True) -> List[str]:
        """One line per unshared NSF folder below a shared NSF, plus the other scope warnings."""
        lines: List[str] = []
        for f in self.folders.values():
            if f.kind != KIND_NSF:
                continue
            if f.status == STATUS_UNCONFIRMED:
                lines.append(f'WARNING: NSF folder "{f.name}" is not confirmed shared to the KSM app '
                             f'(found as a project folder, not as an app share)')
            elif f.status == STATUS_UNSHARED:
                anc = self.folders.get(f.nearest_shared_ancestor)
                anc_name = anc.name if anc else f.nearest_shared_ancestor
                count = len(f.record_uids)
                effect = (f'its {count} record(s) are ignored' if ignored
                          else f'the Gateway cannot see its {count} record(s)')
                lines.append(f'WARNING: NSF "{f.name}" (child of "{anc_name}", the closest NSF shared to the '
                             f'KSM app) is not shared to the KSM app - {effect}')
        for uid in self.unreadable_folders:
            f = self.folders.get(uid)
            lines.append(f'WARNING: NSF folder "{f.name if f else uid}" cannot be read (no folder key) - '
                         f'its records are not compared')
        if self.unresolved_shares:
            lines.append(f'WARNING: {self.unresolved_shares} KSM app share(s) are not visible to this user - '
                         f'the comparison is incomplete')
        if self.skipped_direct_nsf:
            lines.append(f'WARNING: {len(self.skipped_direct_nsf)} direct share(s) of an NSF record skipped '
                         f'(not supported)')
        if self.unreadable_direct:
            lines.append(f'WARNING: {len(self.unreadable_direct)} record(s) shared directly to the KSM app '
                         f'could not be read')
        return lines


# ---------------------------------------------------------------------------------------
# vault helpers
# ---------------------------------------------------------------------------------------

def _folder_name_parent(params, folder_uid: str) -> Tuple[str, str]:
    nsf = (getattr(params, 'nested_share_folders', None) or {}).get(folder_uid)
    if isinstance(nsf, dict):
        return (nsf.get('name') or folder_uid, nsf.get('parent_uid') or '')
    node = (getattr(params, 'folder_cache', None) or {}).get(folder_uid)
    if node is not None:
        return (getattr(node, 'name', None) or folder_uid, getattr(node, 'parent_uid', None) or '')
    return (folder_uid, '')


def _vault_folder_chain(params, folder_uid: str) -> List[Tuple[str, str]]:
    """[(uid, name)] from the top folder down to *folder_uid*."""
    chain: List[Tuple[str, str]] = []
    seen = set()
    current = folder_uid
    while current and current not in seen:
        seen.add(current)
        name, parent = _folder_name_parent(params, current)
        chain.append((current, name))
        current = parent
    chain.reverse()
    return chain


def _folders_of_record(params, record_uid: str) -> List[str]:
    found: List[str] = []
    for attr in ('subfolder_record_cache', 'nested_share_folder_records'):
        for folder_uid, uids in (getattr(params, attr, None) or {}).items():
            if folder_uid and record_uid in uids and folder_uid not in found:
                found.append(folder_uid)
    return found


def read_app_shares(params, app_uid: str) -> AppShares:
    """Folder and record shares of a KSM application (one server call)."""
    from ..ksm import KSMCommand
    from ... import utils as keeper_utils
    from ...proto import APIRequest_pb2

    shares = AppShares()
    try:
        info_list = KSMCommand.get_app_info(params, app_uid)
        if not info_list:
            return shares
        for share in info_list[0].shares:
            uid = keeper_utils.base64_url_encode(share.secretUid)
            if share.shareType == APIRequest_pb2.SHARE_TYPE_FOLDER:  # pylint: disable=no-member
                shares.folder_uids.append(uid)
            elif share.shareType == APIRequest_pb2.SHARE_TYPE_RECORD:  # pylint: disable=no-member
                shares.record_uids.append(uid)
    except Exception as exc:
        logging.warning('Could not read the shares of KSM application %s: %s', app_uid, exc)
        shares.ok = False
    return shares


# ---------------------------------------------------------------------------------------
# scope
# ---------------------------------------------------------------------------------------

def _roots_from_shares(params, folder_uids: Iterable[str]) -> Tuple[List[dict], int]:
    roots: List[dict] = []
    unresolved = 0
    shared_cache = getattr(params, 'shared_folder_cache', None) or {}
    nsf = getattr(params, 'nested_share_folders', None) or {}
    for uid in folder_uids:
        if uid in shared_cache:
            roots.append({'uid': uid, 'source': _SOURCE_CLASSIC})
        elif uid in nsf:
            roots.append({'uid': uid, 'source': _SOURCE_NESTED})
        else:
            unresolved += 1
    return roots, unresolved


def collect_ksm_scope(params, app_uid: str, folder_roots: Optional[List[dict]] = None,
                      shares: Optional[AppShares] = None) -> KsmScope:
    """Build the scope of *app_uid*.

    ``folder_roots`` are the folder dicts the caller already resolved (``uid`` and ``source``
    as returned by ``get_ksm_app_folders``; ``extend`` also passes its project-folder fallback
    with ``source == 'nested_share_folder'``, reported as unconfirmed). When it is None the
    roots come from the app shares. ``shares`` can be passed to avoid a second server call.
    """
    scope = KsmScope(params=params)
    if shares is None:
        shares = read_app_shares(params, app_uid) if app_uid else AppShares(ok=False)
    scope.app_shares_ok = shares.ok

    if folder_roots is None:
        roots, scope.unresolved_shares = _roots_from_shares(params, shares.folder_uids)
    else:
        roots = list(folder_roots)
        root_uids = {r.get('uid') for r in roots}
        resolvable = set(getattr(params, 'shared_folder_cache', None) or {})
        resolvable.update(getattr(params, 'nested_share_folders', None) or {})
        # a share the caller did not pass as a root but that this user can resolve (for example an NSF folder
        # shared to the app a moment ago) is not "invisible"
        scope.unresolved_shares = sum(1 for uid in shares.folder_uids
                                      if uid not in root_uids and uid not in resolvable)

    shared_nsf = {r['uid'] for r in roots if r.get('source') == _SOURCE_NESTED}
    shared_nsf.update(uid for uid in shares.folder_uids
                      if uid in (getattr(params, 'nested_share_folders', None) or {}))
    unconfirmed_nsf = {r['uid'] for r in roots if r.get('source') == _SOURCE_NSF_FALLBACK} - shared_nsf

    nsf_children = _nsf_children(params)
    for root in roots:
        uid = root.get('uid')
        if not uid or uid in scope.folders:
            continue
        if root.get('source') == _SOURCE_CLASSIC or (
                uid in (getattr(params, 'shared_folder_cache', None) or {}) and uid not in shared_nsf):
            _walk_classic(params, scope, uid)
        else:
            _walk_nsf(params, scope, uid, shared_nsf, unconfirmed_nsf, nsf_children)

    _collect_records(params, scope)
    _add_direct_records(params, scope, shares.record_uids)
    return scope


def _walk_classic(params, scope: KsmScope, root_uid: str) -> None:
    """SHF root and all its subfolders (SHFF): shared, recursive."""
    cache = getattr(params, 'folder_cache', None) or {}
    stack: List[Tuple[str, str, str]] = [(root_uid, '', KIND_SHF)]
    while stack:
        uid, parent_uid, kind = stack.pop(0)
        if uid in scope.folders:
            continue
        node = cache.get(uid)
        name = (getattr(node, 'name', None) or uid) if node is not None else uid
        parent = scope.folders.get(parent_uid)
        path = f'{parent.path}/{name}' if parent else name
        scope.folders[uid] = ScopeFolder(uid=uid, name=name, path=path, parent_uid=parent_uid, kind=kind,
                                         status=STATUS_SHARED)
        for child in (getattr(node, 'subfolders', None) or []) if node is not None else []:
            stack.append((child, uid, KIND_SHFF))


def _nsf_children(params) -> Dict[str, List[str]]:
    children: Dict[str, List[str]] = {}
    for uid, info in (getattr(params, 'nested_share_folders', None) or {}).items():
        parent = (info.get('parent_uid') if isinstance(info, dict) else None) or ''
        if parent:
            children.setdefault(parent, []).append(uid)
    return children


def _walk_nsf(params, scope: KsmScope, root_uid: str, shared_nsf: set, unconfirmed_nsf: set,
              children: Dict[str, List[str]]) -> None:
    """NSF root and its children. Only folders with their own share are 'shared'."""
    nsf = getattr(params, 'nested_share_folders', None) or {}
    stack: List[Tuple[str, str, str]] = [(root_uid, '', '')]
    while stack:
        uid, parent_uid, nearest = stack.pop(0)
        if uid in scope.folders:
            continue
        info = nsf.get(uid) or {}
        name = (info.get('name') if isinstance(info, dict) else None) or uid
        parent = scope.folders.get(parent_uid)
        path = f'{parent.path}/{name}' if parent else name
        if uid in shared_nsf:
            status = STATUS_SHARED
        elif uid in unconfirmed_nsf:
            status = STATUS_UNCONFIRMED
        else:
            status = STATUS_UNSHARED
        readable = bool(isinstance(info, dict) and info.get('folder_key_unencrypted'))
        scope.folders[uid] = ScopeFolder(uid=uid, name=name, path=path, parent_uid=parent_uid, kind=KIND_NSF,
                                         status=status, nearest_shared_ancestor=nearest, readable=readable)
        if not readable:
            scope.unreadable_folders.append(uid)
        child_nearest = uid if status in (STATUS_SHARED, STATUS_UNCONFIRMED) else nearest
        for child in children.get(uid, []):
            stack.append((child, uid, child_nearest))


def _collect_records(params, scope: KsmScope) -> None:
    """Records of the folders, loaded ONCE per record uid (a record in two folders is one record)."""
    folder_of: Dict[str, List[str]] = {}
    for folder in scope.folders.values():
        if not folder.readable:
            continue
        uids = sorted(get_folder_record_uids(params, folder.uid))
        folder.record_uids = uids
        for ruid in uids:
            folder_of.setdefault(ruid, []).append(folder.uid)

    for ruid, folder_uids in folder_of.items():
        summary = get_record_summary(params, ruid)
        if summary is None:
            continue
        _, title, rtype, login = summary
        shared = any(scope.folders[f].status == STATUS_SHARED for f in folder_uids)
        scope.records[ruid] = ScopeRecord(uid=ruid, title=title, record_type=rtype, login=login,
                                          folder_uids=list(folder_uids), sources=[SOURCE_FOLDER], shared=shared)


def _add_direct_records(params, scope: KsmScope, record_uids: Iterable[str]) -> None:
    from ..nested_share_folder.helpers import is_nested_share_record

    for ruid in record_uids:
        if is_nested_share_record(params, ruid):
            scope.skipped_direct_nsf.append(ruid)
            continue
        known = scope.records.get(ruid)
        if known is not None:
            if SOURCE_DIRECT not in known.sources:
                known.sources.append(SOURCE_DIRECT)
            known.shared = True
            continue
        summary = get_record_summary(params, ruid)
        if summary is None:
            scope.unreadable_direct.append(ruid)
            continue
        _, title, rtype, login = summary
        scope.records[ruid] = ScopeRecord(uid=ruid, title=title, record_type=rtype, login=login,
                                          folder_uids=[], sources=[SOURCE_DIRECT], shared=True)
