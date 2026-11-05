#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander — Delinea PAM import

from __future__ import annotations

import logging
from typing import Callable, List, Optional, Set

from ... import api
from ...error import CommandError
from ...importer.thycotic.pam import FindingLog, Principal, SecretGrantTarget

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
    raise NotImplementedError


def apply_secret_grants(params, targets: List[SecretGrantTarget], use_nsf: bool,
                        resolve_email: Callable[[Principal], Optional[str]], findings: FindingLog) -> int:
    """Apply secret-level grants to imported records; returns the number applied.

    NSF: ``share_record_v3(params, record_uid, email, resolve_role_name(role))``.
    Classic: ``CLASSIC_RECORD_FLAGS[role]`` through ``ShareRecordCommand``
    (``can_edit`` / ``can_share``); roles mapped to ``None`` become Findings.
    Unresolved principals and records become Findings; one failure does not
    stop the rest.
    """
    raise NotImplementedError
