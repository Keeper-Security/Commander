#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander — Delinea PAM import

from __future__ import annotations

import json
import logging
from typing import Callable, List, Optional, Set

from ... import api
from ...error import CommandError
from ...importer.thycotic.pam.models import FindingLog, Principal, SecretGrantTarget
from ...importer.thycotic.pam.permission_mapper import CLASSIC_RECORD_FLAGS
from .nsf_helpers import get_folder_record_uids

COMMAND = 'pam project delinea-import'


def nsf_available(params) -> bool:
    return not params.is_feature_disallowed('keeper_drive')


def choose_nsf(params, requested: bool, findings: FindingLog) -> bool:
    """Preflight half of the classic failsafe."""
    if requested and not nsf_available(params):
        findings.add('Nested Share Folders', 'keeper_drive is disabled for this account',
                     'Imported in classic shared-folder mode')
        return False
    return requested


def project_config_uids(params, project_name: str) -> Set[str]:
    """UIDs of PAM configurations titled ``{project_name} Configuration`` or ``... #N``,
    in classic and NSF caches (see ``is_matching_title`` and ``find_pam_configuration``)."""
    raise NotImplementedError


def run_with_classic_fallback(params, project_name: str, use_nsf: bool,
                              run: Callable[[bool], None], findings: FindingLog) -> bool:
    """Runtime half of the classic failsafe. Returns the mode that was used.

    An NSF failure is retried once in classic mode only if it happened before
    a new PAM configuration was created; otherwise the partial project is
    left for the admin to remove.
    """
    before = project_config_uids(params, project_name) if use_nsf else set()
    try:
        run(use_nsf)
        return use_nsf
    except Exception as e:
        if not use_nsf:
            raise
        api.sync_down(params)
        if project_config_uids(params, project_name) - before:
            raise CommandError(COMMAND, f'Nested Share Folder import failed after the PAM configuration was '
                               f'created: {e}. Remove the partial project and re-run without --nsf.')
        logging.warning(
            'Nested Share Folder import failed (%s); retrying in classic mode', e)
        findings.add('Nested Share Folders', f'NSF import failed: {e}',
                     'Imported in classic mode; delete any empty NSF folders left from the first attempt')
    run(False)
    return False


def locate_record_uid(params, folder_name: str, title: str) -> Optional[str]:
    """UID of the record titled *title* in ``{folder_name} - Resources`` or ``- Users``
    under the project folder (``get_folder_record_uids`` covers classic and NSF)."""
    wanted = (title or '').strip().casefold()
    if not wanted or not folder_name:
        return None
    names = (
        f'{folder_name} - Users'.casefold(),
        f'{folder_name} - Resources'.casefold(),
    )
    for folder_uid in _folder_uids_named(params, names):
        for record_uid in get_folder_record_uids(params, folder_uid):
            if _record_title(params, record_uid).strip().casefold() == wanted:
                return record_uid
    return None


def apply_secret_grants(params, targets: List[SecretGrantTarget], use_nsf: bool,
                        resolve_email: Callable[[Principal], Optional[str]], findings: FindingLog) -> int:
    """Apply secret-level grants to imported records; returns the number applied.

    NSF: ``share_record_v3(params, record_uid, email, resolve_role_name(role))``.
    Classic: ``CLASSIC_RECORD_FLAGS[role]`` through ``ShareRecordCommand``
    (``can_edit`` / ``can_share``); roles mapped to ``None`` become Findings.
    Unresolved principals and records become Findings; one failure does not
    stop the rest.
    """
    if not targets:
        return 0
    api.sync_down(params)
    owner = (getattr(params, 'user', None) or '').strip().casefold()
    applied = 0
    for target in targets:
        record_uids = _target_record_uids(params, target)
        if not record_uids:
            findings.add('Secret permission', target.record_title,
                         'Imported record was not found')
            continue
        for grant in target.grants:
            email = (resolve_email(grant.principal) or '').strip()
            label = f'{target.record_title}/{grant.principal.name or email or grant.role}'
            if '@' not in email:
                findings.add('Secret permission', label, 'No Keeper user for this principal')
                continue
            if owner and email.casefold() == owner:
                continue
            for record_uid in record_uids:
                try:
                    if use_nsf:
                        if _grant_nsf(params, record_uid, email, grant.role):
                            applied += 1
                        else:
                            findings.add('Secret permission', label, 'Keeper did not apply the share')
                    else:
                        if _grant_classic(params, record_uid, email, grant.role, findings, label):
                            applied += 1
                except Exception as exc:
                    findings.add('Secret permission', label, str(getattr(exc, 'message', exc)))
    return applied


def _target_record_uids(params, target: SecretGrantTarget) -> List[str]:
    """User record and, when the secret became a PAM resource, that resource too."""
    found = []
    for title in (target.record_title, target.resource_title):
        if not title:
            continue
        record_uid = locate_record_uid(params, target.folder_name, title)
        if record_uid and record_uid not in found:
            found.append(record_uid)
    return found


def _folder_uids_named(params, names: tuple) -> List[str]:
    found = []
    for uid, folder in (getattr(params, 'folder_cache', None) or {}).items():
        name = getattr(folder, 'name', None)
        if isinstance(name, str) and name.casefold() in names:
            found.append(uid)
    for uid, folder in (getattr(params, 'nested_share_folders', None) or {}).items():
        name = folder.get('name') if isinstance(folder, dict) else None
        if isinstance(name, str) and name.casefold() in names:
            found.append(uid)
    found.sort(key=lambda uid: 0 if _folder_name(params, uid).casefold().endswith(' - users') else 1)
    return found


def _folder_name(params, folder_uid: str) -> str:
    folder = (getattr(params, 'folder_cache', None) or {}).get(folder_uid)
    name = getattr(folder, 'name', None)
    if isinstance(name, str):
        return name
    nsf = (getattr(params, 'nested_share_folders', None) or {}).get(folder_uid) or {}
    return str(nsf.get('name') or '')


def _record_title(params, record_uid: str) -> str:
    cached = (getattr(params, 'record_cache', None) or {}).get(record_uid)
    if isinstance(cached, dict):
        raw = cached.get('data_unencrypted') or ''
        if isinstance(raw, bytes):
            raw = raw.decode('utf-8', errors='replace')
        if isinstance(raw, str) and raw:
            try:
                return str(json.loads(raw).get('title') or '')
            except (TypeError, ValueError):
                pass
    nsf = (getattr(params, 'nested_share_record_data', None) or {}).get(record_uid) or {}
    data = nsf.get('data_json') if isinstance(nsf, dict) else None
    if isinstance(data, dict):
        return str(data.get('title') or '')
    return ''


def _grant_classic(params, record_uid: str, email: str, role: str, findings: FindingLog, label: str) -> bool:
    flags = CLASSIC_RECORD_FLAGS.get(role)
    if flags is None:
        findings.add('Secret permission', label, 'No classic record permission for this role')
        return False
    from ..register import ShareRecordCommand
    can_edit, can_share = flags
    request = ShareRecordCommand.prep_request(params, {
        'record': record_uid,
        'email': [email],
        'action': 'grant',
        'can_edit': can_edit,
        'can_share': can_share,
    })
    if request is None:
        findings.add('Secret permission', label, 'Keeper could not prepare the share')
        return False
    ShareRecordCommand.send_requests(params, [request])
    return True


def _grant_nsf(params, record_uid: str, email: str, role: str) -> bool:
    from ...nested_share_folder.permissions import resolve_role_name
    from ...nested_share_folder.record_api import share_record_v3
    result = share_record_v3(params, record_uid, email, resolve_role_name(role))
    return bool(result and result.get('success'))
