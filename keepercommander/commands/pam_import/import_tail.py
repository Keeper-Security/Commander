"""Post–Step 2 import tail (pamConfiguration scripts + domain admin link)."""
from __future__ import annotations

import logging
from typing import Any, List, Optional

from ... import record_management, vault
from ..pam.vault_target import is_nested_share_folder, is_pam_nsf_record, update_pam_record
from .base import PamScriptObject
from .batch_attachments import BatchAttachmentSummary, run_import_tail_config_scripts
from .batch_nsf import project_uses_nsf, sync_down_after_batch
from .record_loader import load_pam_record


def _log_config_script_tail(summary: BatchAttachmentSummary) -> None:
    for uid, reason in summary.warnings:
        logging.warning(f'  Import tail config script warning  {uid}: {reason}')
    for uid, reason in summary.failures:
        logging.warning(f'  Import tail config script failed  {uid}: {reason}')
    if summary.uploaded_count:
        logging.info(
            f'Import tail uploaded {summary.uploaded_count} '
            'pamConfiguration script file(s) via batch pipeline',
        )


def run_pam_config_scripts_tail(
    params,
    pam_cfg_uid: str,
    scripts: List[PamScriptObject],
) -> BatchAttachmentSummary:
    """Batch-upload pamConfiguration cred scripts (warn-only on failure)."""
    cred_scripts = [s for s in scripts if getattr(s, 'record_refs', None)]
    if not cred_scripts:
        return BatchAttachmentSummary()
    sync_down_after_batch(params)
    summary = run_import_tail_config_scripts(params, pam_cfg_uid, cred_scripts)
    _log_config_script_tail(summary)
    return summary


def apply_domain_admin_tail(
    params,
    pam_cfg_uid: str,
    pce: Any,
    tdag,
    *,
    project_options: Optional[dict] = None,
    users_folder_uid: str = '',
) -> None:
    """Update pamDomainConfiguration adminCredentialRef and link domain admin.

    NSF-aware: uses ``load_pam_record`` + ``update_pam_record(..., force_nsf=True)``
    when the config lives under a nested share folder (upstream KC NSF path).
    """
    if not pce or getattr(pce, 'environment', None) != 'domain':
        return
    admin_ref = getattr(pce, 'admin_credential_ref', None)
    if not admin_ref:
        logging.debug(
            f"Unable to resolve domain admin "
            f"'{getattr(pce, 'dom_administrative_credential', '')}' for PAM Domain configuration.",
        )
        return
    pcrec = load_pam_record(params, pam_cfg_uid) if pam_cfg_uid else None
    if not pcrec or not isinstance(pcrec, vault.TypedRecord) or pcrec.version != 6:
        return
    if pcrec.record_type != 'pamDomainConfiguration':
        return
    prf = pcrec.get_typed_field('pamResources')
    if not prf:
        prf = vault.TypedField.new_field('pamResources', {})
        pcrec.fields.append(prf)
    prf.value = prf.value or [{}]
    if not isinstance(prf.value[0], dict):
        logging.error(
            f'Unable to add adminCredentialRef - bad pamResources field in PAM Config {pam_cfg_uid}',
        )
        return
    prf.value[0]['adminCredentialRef'] = admin_ref
    options = project_options or {}
    force_nsf = (
        options.get('use_nsf', False) is True
        or is_nested_share_folder(params, users_folder_uid)
        or is_pam_nsf_record(params, pam_cfg_uid)
    )
    if force_nsf:
        update_pam_record(params, pcrec, command='pam-project-import', force_nsf=True)
    else:
        record_management.update_record(params, pcrec)
    tdag.link_user_to_config_with_options(admin_ref, is_admin='on')


def run_import_tail(
    params,
    pam_cfg_uid: str,
    pce: Optional[Any],
    tdag,
    *,
    scripts: Optional[List[PamScriptObject]] = None,
    project_options: Optional[dict] = None,
    users_folder_uid: str = '',
) -> BatchAttachmentSummary:
    """Run post-engine import tail: cred scripts, then domain admin link."""
    summary = BatchAttachmentSummary()
    script_list = scripts
    if script_list is None and pce is not None:
        scripts_obj = getattr(pce, 'scripts', None)
        script_list = getattr(scripts_obj, 'scripts', None) if scripts_obj else None
    if script_list:
        summary = run_pam_config_scripts_tail(params, pam_cfg_uid, script_list)
    if pce is not None:
        apply_domain_admin_tail(
            params, pam_cfg_uid, pce, tdag,
            project_options=project_options,
            users_folder_uid=users_folder_uid,
        )
    # Tail writes (scripts, domain admin) leave the cache stale; one NSF-key-preserving
    # sync at the end so callers/later commands see them (plain sync_down drops NSF keys).
    if project_uses_nsf(params, {'options': project_options or {}}):
        sync_down_after_batch(params, {'options': project_options or {}})
    return summary
