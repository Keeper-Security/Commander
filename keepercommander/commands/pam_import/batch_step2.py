"""PAM import/extend batch pipeline — Step 2 PAM wiring on shared deferred TunnelDAG."""
from __future__ import annotations

import logging
from typing import Any, List, Optional

from keepercommander import utils
from ...keeper_dag.types import EdgeType, RefType
from keepercommander.display import bcolors

from .base import (
    PamCloudResourceObject,
    SAAS_CONFIG_RECORD_TYPES,
    SAAS_TYPE_LABEL,
    PamMachineObject,
    SaasConfigurationObject,
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
    - Exception, pamDirectory (domain) users: a plain member is linked belongs_to=True even without rotation -
      discovery does the same and the Gateway finds a user's parent directory through that flag
      (tunnel_graph.get_user_parent_directory_uid needs belongs_to).
    """
    is_admin = bool(admin_uid and admin_uid == user.uid)
    has_rotation = bool(user.rotation_settings)
    if not is_admin and not has_rotation:
        if str(getattr(mach, 'type', '') or '').lower() != 'pamdirectory':
            return
        if _user_already_linked(tdag, user.uid, mach.uid):
            return
        tdag.link_user_to_resource(user.uid, mach.uid, is_admin=False, belongs_to=True)
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
    service_queue: Optional[list] = None,
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
        if (_skip_nested_saas(user, mach) or _skip_nested_iam(user, mach)
                or _skip_nested_scripts_only(user, mach)):
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
            # Service accounts are sent LAST (after the deferred graph flush) so a later graph write on the same
            # user->machine ACL edge cannot overwrite controls_services; see apply_service_rotations().
            if service_queue is not None and user.rotation_settings.service_resources:
                service_queue.append((user, mach))

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


_UNSET = object()


def run_step2_extend_existing(
    params, tdag, mach, pam_cfg_uid, prc,
    *,
    rotation_throttle: Optional[RotationThrottle] = None,
    service_queue: Optional[list] = None,
):
    """Step 2 for an EXISTING machine in `pam project extend`: add the NEW nested users only.

    Extend never updates an existing resource (updating is left to a separate update command). It links the new users
    (ACL / belongs_to), applies their rotation and queues their service accounts. It does NOT set or change the
    machine's launch credential or admin credential: `administrative_credentials` / `launch_credentials` in the JSON of
    an existing machine are not applied and no new user is linked as admin. The rotation command is given the machine's
    CURRENT admin read from the graph (not the JSON's): `pam rotation` only uses its admin argument when the machine
    has none, so for a machine with an admin this changes nothing, and for a machine WITHOUT an admin the rotation of
    the new user fails with the command's own "does not have admin credentials" error instead of silently adding one.
    (Documented in the README; deliberately silent.)
    """
    existing_admin = _UNSET     # read lazily, once, only if a new user with a rotation needs it
    nested = getattr(mach, 'users', []) or []
    for user in nested:
        if not isinstance(user, PamUserObject):
            continue
        if getattr(user, '_extend_tag', 'new') != 'new':
            continue
        if (_skip_nested_saas(user, mach) or _skip_nested_iam(user, mach)
                or _skip_nested_scripts_only(user, mach)):
            continue
        if (user.rotation_settings and
                str(user.rotation_settings.rotation).lower() == 'general'):
            user.rotation_settings.resourceUid = mach.uid
        if not tdag.resource_belongs_to_config(mach.uid):
            logging.warning(
                f'Existing resource {mach.uid} not linked to config — skip nested user {user.uid}',
            )
            continue
        _link_nested_user(tdag, user, mach, None)
        if user.rotation_settings and not _rotation_exists(params, user.uid, mach.uid):
            if existing_admin is _UNSET:
                # read-only lookup in the already loaded graph (no request)
                existing_admin = tdag.check_if_resource_has_admin(mach.uid) or None
            _apply_rotation(
                params, prc, user, mach, existing_admin, pam_cfg_uid,
                rotation_throttle=rotation_throttle,
            )
            # Service accounts are sent LAST (after the deferred graph flush) so a later graph write on the same
            # user->machine ACL edge cannot overwrite controls_services; see apply_service_rotations().
            if service_queue is not None and user.rotation_settings.service_resources:
                service_queue.append((user, mach))


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
    cloud_jit = None
    if isinstance(mach, PamCloudResourceObject):
        # Web Vault cloud modal: "Enable RBI" is allowedSettings.connections; the resource meta carries no
        # remoteBrowserIsolation flag. defaultElevationTime lives on the meta edge (JIT tab).
        if args.pop('remote_browser_isolation', None) is True:
            args['connections'] = True
        cloud_jit = mach.jit_settings
        if cloud_jit and cloud_jit.default_elevation_time_ms is not None:
            args['default_elevation_time'] = cloud_jit.default_elevation_time_ms
    elif args.get('remote_browser_isolation') is True:
        args['connections'] = True
    args['meta_version'] = 1
    args['v_type'] = RefType.PAM_BROWSER
    # ORDER MATTERS: the DAG library has no path awareness, so the record's "current" content (the one Commander's
    # own readers - `pam connection ai --show`, `pam connection edit`, get_resource_setting - use as the resource
    # meta) is the DATA edge written LAST. Write jit_settings / ai_settings first and the meta edge last, otherwise
    # those readers see the ai_settings blob and report every allowed setting as "default" (seen in the Q3 QA run).
    if cloud_jit:
        jit_dag_dict = cloud_jit.to_dag_dict()
        if jit_dag_dict and not set_resource_jit_settings(
                params, mach.uid, jit_dag_dict, pam_cfg_uid, graph=tdag.linking_dag):
            _warn_settings_failed('JIT', mach)
    # KeeperAI risk levels (ai_settings edge) - same helper as _run_step2_machine and `pam connection ai`.
    ai = getattr(getattr(mach, 'rbi_settings', None), 'ai_settings', None)
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

    # Initial allow (the resource `meta` edge) - may be re-applied after set_launch_credentials in run_step2_full.
    # ORDER MATTERS: the DAG library has no path awareness, so the record's "current" content (what Commander's own
    # readers - `pam connection ai --show`, `pam connection edit`, get_resource_setting - treat as the resource meta)
    # is the DATA edge written LAST. Write jit_settings / ai_settings first and the meta edge last, otherwise those
    # readers see the ai_settings blob and report every allowed setting as "default".
    _apply_machine_allowed_settings(tdag, mach)

    ps_wf = getattr(getattr(mach, 'pam_settings', None), 'workflow', None)
    if ps_wf:
        apply_workflow(params, mach.uid, mach.title or '', ps_wf)


def _is_saas_rotation(user) -> bool:
    rs = getattr(user, 'rotation_settings', None)
    return bool(rs and str(getattr(rs, 'rotation', '') or '').lower() == 'saas')


def _skip_nested_saas(user, mach) -> bool:
    """`rotation: saas` users must be top-level (global users[]): the Gateway reads the SaaS list from the ACL on the
    user's machine ancestor when it has one, while the router stores it on the PAM-configuration ACL."""
    if not _is_saas_rotation(user):
        return False
    logging.warning(
        f'User "{getattr(user, "title", "") or user.uid}" under "{getattr(mach, "title", "") or mach.uid}": '
        'rotation "saas" is only supported for users in the global users[] list (not nested under a machine) - '
        'user skipped (no link, no rotation).')
    return True


def _is_iam_rotation(user) -> bool:
    rs = getattr(user, 'rotation_settings', None)
    return bool(rs and str(getattr(rs, 'rotation', '') or '').lower() == 'iam_user')


def _skip_nested_iam(user, mach) -> bool:
    """`rotation: iam_user` users must be top-level (global users[]): an IAM user hangs directly off the PAM
    configuration (the Gateway's AWS / Azure / GCP / Domain / Okta provider object) and has no resource - the rotation
    command would unlink it from the machine anyway, and nested it used to be sent as a `general` rotation."""
    if not _is_iam_rotation(user):
        return False
    logging.warning(
        f'User "{getattr(user, "title", "") or user.uid}" under "{getattr(mach, "title", "") or mach.uid}": '
        'rotation "iam_user" is only supported for users in the global users[] list (not nested under a machine) - '
        'user skipped (no link, no rotation).')
    return True


def _is_scripts_only_rotation(user) -> bool:
    rs = getattr(user, 'rotation_settings', None)
    return bool(rs and str(getattr(rs, 'rotation', '') or '').lower() == 'scripts_only')


def _skip_nested_scripts_only(user, mach) -> bool:
    """`rotation: scripts_only` (NOOP) users must be top-level (global users[]): the Gateway runs a NOOP rotation on
    configuration -> virtual resource -> user, so no machine is in the chain and the machine's scripts never run (only
    the user's and the PAM configuration's, on the Gateway). Nested it used to be sent as a real `general` rotation."""
    if not _is_scripts_only_rotation(user):
        return False
    logging.warning(
        f'User "{getattr(user, "title", "") or user.uid}" under "{getattr(mach, "title", "") or mach.uid}": '
        'rotation "scripts_only" (NOOP) is only supported for users in the global users[] list (not nested under a '
        'machine) and never runs the scripts of the machine; use rotation "general" to run the machine scripts (it also '
        'rotates the password) - user skipped (no link, no rotation).')
    return True


def _rotation_common_args(user) -> dict:
    """enable/disable, schedule and password complexity of user.rotation_settings as `pam rotation set` kwargs."""
    args = {}
    enabled = user.rotation_settings.enabled
    key = {'on': 'enable', 'off': 'disable'}.get(enabled, '')
    if key:
        args[key] = True
    schedule_type = (
        user.rotation_settings.schedule.type
        if user.rotation_settings.schedule and user.rotation_settings.schedule.type else ''
    )
    schedule_type_lc = (schedule_type or '').lower().replace('_', '-')
    if schedule_type_lc == 'on-demand':
        args['on_demand'] = True
    elif schedule_type_lc == 'cron':
        if user.rotation_settings.schedule.cron:
            args['schedule_cron_data'] = [user.rotation_settings.schedule.cron]
        else:
            logging.warning(
                f'{bcolors.WARNING}schedule.type=cron but schedule.cron is empty (skipped){bcolors.ENDC}',
            )
    if user.rotation_settings.password_complexity:
        args['pwd_complexity'] = user.rotation_settings.password_complexity
    return args


def _apply_rotation(
    params, prc, user, mach, admin_uid, pam_cfg_uid,
    *,
    rotation_throttle: Optional[RotationThrottle] = None,
    service_uids: Optional[List[str]] = None,
    update_services: Optional[bool] = None,
):
    args = {
        'force': True,
        'config': pam_cfg_uid,
        'record_name': user.uid,
        'admin': admin_uid,
        'resource': mach.uid,
    }
    if service_uids is not None:      # service accounts: controls_services links (authoritative list)
        args['service_resource_uids'] = service_uids
    if update_services is not None:
        args['update_services'] = update_services
    args.update(_rotation_common_args(user))
    if rotation_throttle:
        rotation_throttle.before_call()
    call_with_throttle_retry(
        lambda: prc.execute(params, silent=True, **args),
        max_retries=5,
        label=f'rotation {user.uid}',
        fail_on_throttle=rest_fail_on_throttle(params),
        on_exhausted=IMPORT_ON_EXHAUSTED,
    )


# ---------------------------------------------------------------------------------------------------------------------
# Service accounts (rotation_settings.service_resources) - applied LAST, after the deferred graph flush
# ---------------------------------------------------------------------------------------------------------------------
def _is_valid_uid(value) -> bool:
    return isinstance(value, str) and len(value) == 22 and all(c.isalnum() or c in '-_' for c in value)


def _is_windows(os_value) -> bool:
    return 'windows' in str(os_value or '').lower()


def resolve_service_resource_uids(params, refs, resources, owner_title='') -> List[str]:
    """Machine titles / uids -> pamMachine record uids.

    A reference is looked up in the machines defined in this import first (title or uid), then in the vault
    (exactly one pamMachine with that title or uid). Unknown / ambiguous / non-pamMachine references are skipped
    with a warning (the router does not check the record type; the Web Vault only offers pamMachine records).
    Windows is the only OS whose services/tasks can be rotated: warn otherwise.
    """
    from ...vault_extensions import find_records

    out: List[str] = []
    who = f'User "{owner_title}": ' if owner_title else ''
    for ref in refs or []:
        matches = [m for m in resources
                   if isinstance(m, PamMachineObject) and ref in (getattr(m, 'title', None), getattr(m, 'uid', None))]
        os_value = None
        if len(matches) == 1:
            uid = matches[0].uid
            os_value = getattr(matches[0], 'operatingSystem', None)
        elif len(matches) > 1:
            logging.warning(f'{who}service_resources "{ref}" matches {len(matches)} machines in the import - skipped')
            continue
        else:
            recs = [r for r in find_records(params, search_str=ref, record_type='pamMachine')
                    if ref in (getattr(r, 'title', None), getattr(r, 'record_uid', None))]
            if len(recs) != 1:
                reason = 'not found' if not recs else f'{len(recs)} matches'
                logging.warning(f'{who}service_resources "{ref}": no single pamMachine ({reason}) - skipped')
                continue
            uid = recs[0].record_uid
            os_field = recs[0].get_typed_field('text', 'operatingSystem') if hasattr(recs[0], 'get_typed_field') else None
            os_value = os_field.get_default_value() if os_field else None
        if os_value is not None and not _is_windows(os_value):
            logging.warning(f'{who}service_resources "{ref}": operating system "{os_value}" is not Windows - '
                            'only Windows services / tasks / IIS pools can be rotated')
        if uid not in out:
            out.append(uid)
    return out


def apply_service_rotations(params, prc, queue, resources, pam_cfg_uid, *,
                            rotation_throttle: Optional[RotationThrottle] = None) -> None:
    """Re-send the rotation of every queued (user, machine) with serviceResources / updateServices.

    Done after the final graph flush so nothing written later on the same user->machine ACL edge can clear
    controls_services. The first rotation call already created the rotation; this repeats it idempotently.
    """
    for user, mach in queue or []:
        rs = user.rotation_settings
        uids = resolve_service_resource_uids(params, rs.service_resources, resources,
                                             getattr(user, 'title', '') or user.uid)
        if not uids:
            continue
        rs.service_resource_uids = uids
        _apply_rotation(params, prc, user, mach, get_admin_credential(mach, True), pam_cfg_uid,
                        rotation_throttle=rotation_throttle,
                        service_uids=uids, update_services=rs.update_services)


# ---------------------------------------------------------------------------------------------------------------------
# SaaS rotation (rotation: saas) - global users only
# ---------------------------------------------------------------------------------------------------------------------
def _record_has_saas_type(record) -> bool:
    for field in (getattr(record, 'custom', None) or []):
        if getattr(field, 'label', None) == SAAS_TYPE_LABEL and field.get_default_value():
            return True
    return False


def resolve_saas_config_uid(params, ref, users) -> str:
    """`saas_config` (title or uid) -> record uid of the SaaS configuration, or '' (error logged).

    Search order: SaaS configurations defined in this import (saasConfiguration entries), legacy `login` users of the
    import that carry the custom field "SaaS Type", then the vault (saasConfiguration, or login with "SaaS Type";
    uid first, then exactly one title match). A `login` without "SaaS Type" is never accepted.
    """
    from ...vault_extensions import find_records

    ref = (ref or '').strip()
    if not ref:
        return ''
    candidates = []   # (uid, label)
    for u in users or []:
        if isinstance(u, SaasConfigurationObject):
            if ref in (u.title, u.uid):
                candidates.append((u.uid, u.title))
        elif isinstance(u, LoginUserObject) and ref in (u.title, u.login, u.uid):
            if u.has_saas_type():
                candidates.append((u.uid, u.title))
            else:
                logging.error(f'saas_config "{ref}": login record "{u.title}" has no custom field "{SAAS_TYPE_LABEL}" - '
                              'it is not a SaaS configuration')
                return ''
    if len(candidates) == 1 and candidates[0][0]:
        return candidates[0][0]
    if len(candidates) > 1:
        logging.error(f'saas_config "{ref}" matches {len(candidates)} records in the import - make the titles unique')
        return ''

    recs = [r for r in find_records(params, search_str=ref, record_type=['saasConfiguration', 'login'])
            if ref in (getattr(r, 'title', None), getattr(r, 'record_uid', None))]
    good = [r for r in recs if r.record_type.lower() == 'saasconfiguration' or _record_has_saas_type(r)]
    if len(good) == 1:
        return good[0].record_uid
    if len(good) > 1:
        logging.error(f'saas_config "{ref}" matches {len(good)} vault records - use the record uid')
    elif recs:
        logging.error(f'saas_config "{ref}": the matching login record has no custom field "{SAAS_TYPE_LABEL}"')
    else:
        logging.error(f'saas_config "{ref}": no saasConfiguration record (or login with "{SAAS_TYPE_LABEL}") found')
    return ''


def run_step2_global_saas(params, prc, users, pam_cfg_uid, *,
                          rotation_throttle: Optional[RotationThrottle] = None) -> None:
    """Apply `rotation: saas` for new global users (the only users whose SaaS rotation the Gateway can find).

    Follows the Web Vault / router: set_record_rotation carries saasConfiguration (noop, belongs_to=false, SaaS list
    on the PAM-configuration ACL, router checks access to the SaaS record). Only `saas` is applied here; iam_user /
    scripts_only of global users are applied by `run_step2_global_profile_rotations`.
    """
    for user in users or []:
        if not isinstance(user, PamUserObject) or not _is_saas_rotation(user):
            continue
        if getattr(user, '_extend_tag', 'new') != 'new':
            continue
        rs = user.rotation_settings
        cfg_uid = resolve_saas_config_uid(params, rs.saas_config, users)
        if not cfg_uid:
            logging.error(f'User "{getattr(user, "title", "") or user.uid}": SaaS rotation skipped (no usable saas_config)')
            continue
        rs.saas_config_uid = cfg_uid
        if _rotation_exists(params, user.uid, ''):
            continue
        args = {
            'force': True,
            'config': pam_cfg_uid,
            'record_name': user.uid,
            'rotation_profile': 'saas',
            'saas_config_uid': cfg_uid,
            'saas_in_request': True,
        }
        args.update(_rotation_common_args(user))
        if rotation_throttle:
            rotation_throttle.before_call()
        call_with_throttle_retry(
            lambda: prc.execute(params, silent=True, **args),
            max_retries=5,
            label=f'saas rotation {user.uid}',
            fail_on_throttle=rest_fail_on_throttle(params),
            on_exhausted=IMPORT_ON_EXHAUSTED,
        )


# rotation profiles of GLOBAL users that hang off the PAM configuration (no machine): `pam rotation set
# --rotation-profile`. `general` is not in the list on purpose - a global user with `general` belongs to a machine's
# own users list (edit.py warns about it) and is created by the machine's Step 2.
GLOBAL_PROFILE_ROTATIONS = ('iam_user', 'scripts_only')


def run_step2_global_profile_rotations(params, prc, users, pam_cfg_uid, *,
                                       rotation_throttle: Optional[RotationThrottle] = None) -> None:
    """Apply `rotation: iam_user` / `scripts_only` for new global users.

    Before this pass such rotations were parsed and resolved (resourceUid = PAM configuration) but never sent, so the
    user was created without any rotation. The rotation command does the same thing the Web Vault does: iam_user = a
    rotation with the PAM configuration and an empty resource, scripts_only = a noop rotation linked to the
    configuration. Users that already have a rotation are skipped (re-running extend must not reset them).
    """
    for user in users or []:
        if not isinstance(user, PamUserObject):
            continue
        rs = getattr(user, 'rotation_settings', None)
        profile = str(getattr(rs, 'rotation', '') or '').lower() if rs else ''
        if profile not in GLOBAL_PROFILE_ROTATIONS:
            continue
        if getattr(user, '_extend_tag', 'new') != 'new':
            continue
        if _rotation_exists(params, user.uid, ''):
            continue
        args = {
            'force': True,
            'config': pam_cfg_uid,
            'record_name': user.uid,
            'rotation_profile': profile,
        }
        args.update(_rotation_common_args(user))
        if rotation_throttle:
            rotation_throttle.before_call()
        call_with_throttle_retry(
            lambda: prc.execute(params, silent=True, **args),
            max_retries=5,
            label=f'{profile} rotation {user.uid}',
            fail_on_throttle=rest_fail_on_throttle(params),
            on_exhausted=IMPORT_ON_EXHAUSTED,
        )



def add_jit_domain_links(tdag, resources) -> bool:
    """Accumulate machine→pamDirectory JIT domain LINK edges on shared tdag.

    KRouter's own configure_resource refuses a domain link when the pamDirectory has no is_admin ACL edge
    (RRC_BAD_STATE); this legacy direct write skips that check, so warn when the directory defined in this import
    has no administrative credential (directories that already exist in the vault are not checked here).
    """
    added = False
    directories = {getattr(r, 'uid', None): r for r in resources
                   if str(getattr(r, 'type', '') or '').lower() == 'pamdirectory'}
    warned = set()
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
        dir_obj = directories.get(dir_uid)
        if dir_obj is not None and dir_uid not in warned and not get_admin_credential(dir_obj, True):
            warned.add(dir_uid)
            logging.warning(
                f'JIT domain directory "{getattr(dir_obj, "title", "") or dir_uid}" has no administrative_credentials - '
                'the Web Vault / KRouter require an admin credential on the domain directory for JIT domain accounts '
                '(KRouter returns RRC_BAD_STATE for a domain link without an is_admin ACL).')
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
