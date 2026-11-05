"""PAM import/extend batch pipeline — Step 2 PAM wiring on shared deferred TunnelDAG."""
from __future__ import annotations

import logging
from typing import Any, List, Optional

from keepercommander import utils
from ...keeper_dag.types import EdgeType, RefType
from keepercommander.display import bcolors

from .base import (
    LoginUserObject,
    PamRemoteBrowserObject,
    PamUserObject,
    get_admin_credential,
    get_launch_credential,
    is_admin_external,
    parse_command_options,
)
from .keeper_ai_settings import set_resource_jit_settings, set_resource_keeper_ai_settings
from .rotation_throttle import RotationThrottle
from .throttle_retry import IMPORT_ON_EXHAUSTED, call_with_throttle_retry, rest_fail_on_throttle
from .workflow_apply import apply_workflow


def _resource_ref_type(mach) -> RefType:
    _rtype = (getattr(mach, 'type', '') or '').lower()
    if _rtype == 'pamdirectory':
        return RefType.PAM_DIRECTORY
    if _rtype == 'pamdatabase':
        return RefType.PAM_DATABASE
    return RefType.PAM_MACHINE


def _link_nested_user(tdag, user, mach, admin_uid):
    """Link nested pamUser per Web Vault ACL shape.

    - Admin-only (no rotation): is_admin=True, belongs_to=False — no Rotate Now.
    - Rotation target (incl. self-rotating SSH admin): belongs_to=True.
    - Non-admin without rotation (e.g. RDP User): skip ACL (leave unlinked).
    """
    is_admin = bool(admin_uid and admin_uid == user.uid)
    has_rotation = bool(user.rotation_settings)
    if not is_admin and not has_rotation:
        return
    if _user_already_linked(tdag, user.uid, mach.uid):
        logging.debug(f'Skip duplicate link {user.uid} -> {mach.uid}')
        return
    tdag.link_user_to_resource(
        user.uid, mach.uid,
        is_admin=is_admin,
        belongs_to=has_rotation,
    )


def run_step2_full(
    params, tdag, mach, pam_cfg_uid, prc,
    users_folder_uid, resources_folder_uid,
    *,
    rotation_throttle: Optional[RotationThrottle] = None,
):
    """Full Step 2 micro-order for a new resource (mirrors edit.py ~1692–1783)."""
    if getattr(mach, '_extend_tag', 'new') == 'existing':
        return
    admin_uid = get_admin_credential(mach, True)
    if not tdag.resource_belongs_to_config(mach.uid):
        tdag.link_resource_to_config(mach.uid)

    if isinstance(mach, PamRemoteBrowserObject):
        _run_step2_rbi(params, tdag, mach, pam_cfg_uid)
    else:
        _run_step2_machine(params, tdag, mach, pam_cfg_uid, admin_uid)

    nested = getattr(mach, 'users', []) or []
    for user in nested:
        if not isinstance(user, PamUserObject):
            continue
        if getattr(user, '_extend_tag', 'new') == 'existing':
            continue
        if (user.rotation_settings and
                str(user.rotation_settings.rotation).lower() == 'general'):
            user.rotation_settings.resourceUid = mach.uid
        if not tdag.resource_belongs_to_config(mach.uid):
            logging.warning(f'Skipping user link — resource {mach.uid} not in config graph')
            continue
        _link_nested_user(tdag, user, mach, admin_uid)
        if user.rotation_settings and not _rotation_exists(params, user.uid, mach.uid):
            _apply_rotation(
                params, prc, user, mach, admin_uid, pam_cfg_uid,
                rotation_throttle=rotation_throttle,
            )

    # Launch credential (and admin, folded in) via Layer-B set_launch_credentials.
    # Do NOT skip when the user is already linked as belongs_to/admin — that was
    # dropping is_launch_credential for the common case where launch == admin.
    # Admin-only (no launch) still runs: re-asserts the admin as the last write with
    # launch=None (meta v1 — Web Vault does not infer launch from admin; KC-1525).
    if not isinstance(mach, PamRemoteBrowserObject) and tdag.resource_belongs_to_config(mach.uid):
        launch_uid = get_launch_credential(mach, True)
        if launch_uid or admin_uid:
            tdag.set_launch_credentials(
                mach.uid,
                launch_uid=launch_uid or None,
                admin_uid=admin_uid or None,
            )
        # set_launch_credentials can send meta that wipes connections/portForwards
        # on the server. Re-apply resource allowedSettings after launch so the
        # Launch button sticks.
        _apply_machine_allowed_settings(tdag, mach)


def run_step2_extend_existing(
    params, tdag, mach, pam_cfg_uid, prc, admin_uid=None,
    *,
    rotation_throttle: Optional[RotationThrottle] = None,
):
    """Minimal Step 2 for existing machine + new nested users only."""
    if admin_uid is None:
        admin_uid = get_admin_credential(mach, True)
    nested = getattr(mach, 'users', []) or []
    for user in nested:
        if not isinstance(user, PamUserObject):
            continue
        if getattr(user, '_extend_tag', 'new') != 'new':
            continue
        if (user.rotation_settings and
                str(user.rotation_settings.rotation).lower() == 'general'):
            user.rotation_settings.resourceUid = mach.uid
        if not tdag.resource_belongs_to_config(mach.uid):
            logging.warning(
                f'Existing resource {mach.uid} not linked to config — skip nested user {user.uid}',
            )
            continue
        _link_nested_user(tdag, user, mach, admin_uid)
        if user.rotation_settings and not _rotation_exists(params, user.uid, mach.uid):
            _apply_rotation(
                params, prc, user, mach, admin_uid, pam_cfg_uid,
                rotation_throttle=rotation_throttle,
            )

    # Launch credential only when it is one of the NEW users added above — extend does
    # not modify existing launch/admin settings, and no admin-only re-assert (an empty
    # connectUsers would clear launch credentials already set on this resource).
    launch_uid = get_launch_credential(mach, True)
    new_uids = {u.uid for u in nested
                if isinstance(u, PamUserObject) and getattr(u, '_extend_tag', 'new') == 'new'}
    if (launch_uid and launch_uid in new_uids and not isinstance(mach, PamRemoteBrowserObject)
            and tdag.resource_belongs_to_config(mach.uid)):
        tdag.set_launch_credentials(
            mach.uid,
            launch_uid=launch_uid,
            admin_uid=launch_uid if admin_uid == launch_uid else None,
        )


def _user_already_linked(tdag, user_uid, resource_uid) -> bool:
    try:
        return tdag.user_belongs_to_resource(user_uid, resource_uid)
    except Exception:
        return False


def _rotation_exists(params, user_uid, resource_uid) -> bool:
    """True when sync_down already has rotation for this pamUser + resource."""
    from ...vault_extensions import record_has_rotation_configured

    if not record_has_rotation_configured(params, user_uid):
        return False
    rot = (params.record_rotation_cache or {}).get(user_uid) or {}
    cached_resource = rot.get('resource_uid') or ''
    if cached_resource and resource_uid and cached_resource != resource_uid:
        return False
    return True


def _apply_machine_allowed_settings(tdag, mach) -> None:
    """Write DAG allowedSettings for a machine/db/directory (connections, tunnels, …)."""
    args = parse_command_options(mach, False)
    args['meta_version'] = 1
    args['v_type'] = _resource_ref_type(mach)
    tdag.set_resource_allowed(**args)


def _run_step2_rbi(params, tdag, mach, pam_cfg_uid):
    from .tunnel_setup import apply_tunnel_setup_batch

    apply_tunnel_setup_batch(params, tdag, mach, pam_cfg_uid)
    args = parse_command_options(mach, False)
    if args.get('remote_browser_isolation') is True:
        args['connections'] = True
    args['meta_version'] = 1
    args['v_type'] = RefType.PAM_BROWSER
    tdag.set_resource_allowed(**args)
    rbi_wf = getattr(getattr(mach, 'rbi_settings', None), 'workflow', None)
    if rbi_wf:
        apply_workflow(params, mach.uid, mach.title or '', rbi_wf)


def _warn_settings_failed(label, mach):
    logging.warning(
        f'{bcolors.WARNING}Failed to apply {label} settings for '
        f'{mach.title or mach.uid}{bcolors.ENDC}',
    )


def _run_step2_machine(params, tdag, mach, pam_cfg_uid, admin_uid):
    from .tunnel_setup import apply_tunnel_setup_batch

    apply_tunnel_setup_batch(params, tdag, mach, pam_cfg_uid)
    if admin_uid and is_admin_external(mach):
        if not _user_already_linked(tdag, admin_uid, mach.uid):
            tdag.link_user_to_resource(admin_uid, mach.uid, is_admin=True, belongs_to=False)
    # Initial allow — may be re-applied after set_launch_credentials in run_step2_full.
    _apply_machine_allowed_settings(tdag, mach)

    ps = getattr(mach, 'pam_settings', None)
    jit = getattr(ps, 'jit_settings', None) if ps else None
    ai = getattr(ps, 'ai_settings', None) if ps else None
    # Write onto the shared deferred graph: the resource vertex is not on the
    # server until the final flush, so a server-loaded DAG could not find it.
    if jit:
        jit_dag_dict = jit.to_dag_dict()
        if jit_dag_dict and not set_resource_jit_settings(
                params, mach.uid, jit_dag_dict, pam_cfg_uid, graph=tdag.linking_dag):
            _warn_settings_failed('JIT', mach)
    if ai:
        user_id = ''
        if getattr(params, 'account_uid_bytes', None):
            user_id = utils.base64_url_encode(params.account_uid_bytes)
        elif getattr(params, 'user', ''):
            user_id = params.user
        ai_dag_dict = ai.to_dag_dict(user_id=user_id)
        if ai_dag_dict and not set_resource_keeper_ai_settings(
                params, mach.uid, ai_dag_dict, pam_cfg_uid, graph=tdag.linking_dag):
            _warn_settings_failed('KeeperAI', mach)

    ps_wf = getattr(getattr(mach, 'pam_settings', None), 'workflow', None)
    if ps_wf:
        apply_workflow(params, mach.uid, mach.title or '', ps_wf)


def _apply_rotation(
    params, prc, user, mach, admin_uid, pam_cfg_uid,
    *,
    rotation_throttle: Optional[RotationThrottle] = None,
):
    args = {
        'force': True,
        'config': pam_cfg_uid,
        'record_name': user.uid,
        'admin': admin_uid,
        'resource': mach.uid,
    }
    enabled = user.rotation_settings.enabled
    key = {'on': 'enable', 'off': 'disable'}.get(enabled, '')
    if key:
        args[key] = True
    # Schedule type is case-insensitive ("CRON" / "cron" / "on-demand").
    schedule_type = (
        user.rotation_settings.schedule.type
        if user.rotation_settings.schedule and user.rotation_settings.schedule.type else ''
    )
    schedule_type_lc = (schedule_type or '').lower().replace('_', '-')
    if schedule_type_lc == 'on-demand':
        args['on_demand'] = True
    elif schedule_type_lc == 'cron':
        if user.rotation_settings.schedule.cron:
            # Must be a list for parse_schedule_data (CLI uses action=append).
            args['schedule_cron_data'] = [user.rotation_settings.schedule.cron]
        else:
            logging.warning(
                f'{bcolors.WARNING}schedule.type=cron but schedule.cron is empty (skipped){bcolors.ENDC}',
            )
    if user.rotation_settings.password_complexity:
        args['pwd_complexity'] = user.rotation_settings.password_complexity
    if rotation_throttle:
        rotation_throttle.before_call()
    call_with_throttle_retry(
        lambda: prc.execute(params, silent=True, **args),
        max_retries=5,
        label=f'rotation {user.uid}',
        fail_on_throttle=rest_fail_on_throttle(params),
        on_exhausted=IMPORT_ON_EXHAUSTED,
    )


def add_jit_domain_links(tdag, resources) -> bool:
    """Accumulate machine→pamDirectory JIT domain LINK edges on shared tdag."""
    added = False
    for mach in resources:
        if getattr(mach, '_extend_tag', 'new') == 'existing':
            continue
        ps = getattr(mach, 'pam_settings', None)
        jit = getattr(ps, 'jit_settings', None) if ps else None
        if not (mach and jit):
            continue
        dir_uid = getattr(jit, 'pam_directory_uid', None)
        if not dir_uid:
            continue
        dag = tdag.linking_dag
        machine_vertex = dag.get_vertex(mach.uid)
        dir_vertex = dag.get_vertex(dir_uid)
        if machine_vertex and dir_vertex:
            if machine_vertex.has(dir_vertex, EdgeType.LINK):
                logging.debug(
                    f'Skip duplicate JIT domain LINK {mach.uid} -> {dir_uid}',
                )
                continue
            machine_vertex.belongs_to(dir_vertex, EdgeType.LINK, path='domain', content={})
            added = True
    return added
