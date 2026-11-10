"""Pre-flight checks for `pam project import/extend` (printed by --dry-run).

Everything here is something the LIVE Step 2 would only discover after the records were created (a skipped SaaS
rotation, a rotation that fails because the machine has no admin, a record type the tenant does not have, ...). The
dry-run runs the same lookups first and reports them. Checks are read-only; only the extend graph check reads the PAM
graph (one read, no writes).
"""
import logging
from typing import List, Optional

from ... import vault
from ...recordv3 import RecordV3
from .base import (
    PamCloudResourceObject,
    PamRemoteBrowserObject,
    PamUserObject,
    SaasConfigurationObject,
    rbi_requests_keeperai,
)
from .batch_step2 import (
    _is_iam_rotation,
    _is_saas_rotation,
    _is_scripts_only_rotation,
    resolve_saas_config_uid,
    resolve_service_resource_uids,
)

# PAM configuration record types that can federate an IdP (pamCloudResource is always IdP-provisioned)
IDP_CAPABLE_CONFIG_TYPES = frozenset({
    'pamAwsConfiguration', 'pamGcpConfiguration', 'pamAzureConfiguration',
    'pamDomainConfiguration', 'pamOktaConfiguration',
})

# PAM configuration record types whose Gateway provider accepts a user directly under the configuration (kdnrm
# resource_type.py: Aws Iam User, Azure User, Gcp User, Domain User, Okta IAM User). Network / Local configurations only
# have "Virtual" users (the NOOP / scripts_only case).
IAM_USER_CONFIG_TYPES = frozenset({
    'pamAwsConfiguration', 'pamAzureConfiguration', 'pamGcpConfiguration',
    'pamDomainConfiguration', 'pamOktaConfiguration',
})


def _is_new(obj) -> bool:
    return getattr(obj, '_extend_tag', 'new') == 'new'


def _title(obj) -> str:
    return getattr(obj, 'title', '') or getattr(obj, 'uid', '') or '?'


def _record_type_missing(params, name: str) -> bool:
    try:
        return RecordV3.resolve_record_type_by_name(params, name) is None
    except Exception:  # an unreadable cache must not break the dry-run
        return False


def keeperai_resources(resources) -> list:
    """New RBI / cloud resources that ask for KeeperAI (they need ai_threat_detection on the PAM configuration)."""
    return [r for r in resources or []
            if isinstance(r, PamRemoteBrowserObject) and _is_new(r)
            and rbi_requests_keeperai(getattr(r, 'rbi_settings', None))]


def collect_preflight_warnings(params, users, resources, pam_cfg_uid: str, extend_mode: bool,
                               tdag=None) -> List[str]:
    """Return human readable problems the live run would hit. Never raises."""
    msgs: List[str] = []
    try:
        _collect(params, users or [], resources or [], pam_cfg_uid, extend_mode, tdag, msgs)
    except Exception as err:    # pre-flight is advisory: never make the dry-run itself fail
        logging.debug(f'pre-flight check failed: {err}', exc_info=True)
        msgs.append(f'pre-flight checks could not be completed: {err}')
    return msgs


def _collect(params, users, resources, pam_cfg_uid, extend_mode, tdag, msgs: List[str]) -> None:
    # 1) SaaS rotation: users nested under a machine are skipped; global users need a resolvable saas_config
    for res in resources:
        for user in getattr(res, 'users', None) or []:
            if isinstance(user, PamUserObject) and _is_new(user) and _is_saas_rotation(user):
                msgs.append(f'user "{_title(user)}" under "{_title(res)}": rotation "saas" is only supported for '
                            'users in the global users[] list - the user will be skipped (no link, no rotation)')
    for user in users:
        if isinstance(user, PamUserObject) and _is_new(user) and _is_saas_rotation(user):
            if not resolve_saas_config_uid(params, user.rotation_settings.saas_config, users):
                msgs.append(f'user "{_title(user)}": saas_config "{user.rotation_settings.saas_config}" '
                            'was not found / is ambiguous - the SaaS rotation will be skipped')

    # 1b) IAM rotation: nested users are skipped; global users need a cloud / IdP PAM configuration
    for res in resources:
        for user in getattr(res, 'users', None) or []:
            if isinstance(user, PamUserObject) and _is_new(user) and _is_iam_rotation(user):
                msgs.append(f'user "{_title(user)}" under "{_title(res)}": rotation "iam_user" is only supported for '
                            'users in the global users[] list - the user will be skipped (no link, no rotation)')
    for res in resources:
        for user in getattr(res, 'users', None) or []:
            if isinstance(user, PamUserObject) and _is_new(user) and _is_scripts_only_rotation(user):
                msgs.append(f'user "{_title(user)}" under "{_title(res)}": rotation "scripts_only" (NOOP) is only '
                            'supported for users in the global users[] list and never runs the scripts of the machine - '
                            'the user will be skipped (no link, no rotation); use "general" to run the machine scripts')
    iam_users = [u for u in users if isinstance(u, PamUserObject) and _is_new(u) and _is_iam_rotation(u)]
    if iam_users and pam_cfg_uid:
        cfg = vault.KeeperRecord.load(params, pam_cfg_uid)
        cfg_type = getattr(cfg, 'record_type', '') if cfg is not None else ''
        if cfg is not None and cfg_type not in IAM_USER_CONFIG_TYPES:
            names = ', '.join(f'"{_title(u)}"' for u in iam_users)
            msgs.append(f'iam_user rotation ({names}) needs a cloud / IdP PAM configuration (AWS, Azure, GCP, Domain '
                        f'or Okta); the Gateway cannot rotate it on this one (type "{cfg_type or "?"}")')

    # 2) Service accounts: unknown / non-pamMachine references are skipped
    for res in resources:
        for user in getattr(res, 'users', None) or []:
            rs = getattr(user, 'rotation_settings', None)
            refs = getattr(rs, 'service_resources', None) if rs else None
            if isinstance(user, PamUserObject) and _is_new(user) and refs:
                found = resolve_service_resource_uids(params, refs, resources, _title(user))
                if len(found) < len(refs):
                    msgs.append(f'user "{_title(user)}": {len(refs) - len(found)} of {len(refs)} service_resources '
                                'could not be resolved to a pamMachine and will be skipped')

    # 3) Record types the tenant must know
    wanted = []
    if any(isinstance(r, PamCloudResourceObject) and _is_new(r) for r in resources):
        wanted.append('pamCloudResource')
    if any(isinstance(u, SaasConfigurationObject) and _is_new(u) for u in users):
        wanted.append('saasConfiguration')
    for name in wanted:
        if _record_type_missing(params, name):
            msgs.append(f'record type "{name}" is not available in this vault/tenant - those records cannot be created')

    # 4) pamCloudResource needs an IdP-capable PAM configuration (or identityProviderUid)
    if pam_cfg_uid and any(isinstance(r, PamCloudResourceObject) and _is_new(r) for r in resources):
        cfg = vault.KeeperRecord.load(params, pam_cfg_uid)
        if cfg is not None:
            idp_field = cfg.get_typed_field('text', 'identityProviderUid') \
                if hasattr(cfg, 'get_typed_field') else None
            has_idp_field = bool(idp_field and idp_field.value)
            if getattr(cfg, 'record_type', '') not in IDP_CAPABLE_CONFIG_TYPES and not has_idp_field:
                msgs.append(f'PAM configuration is of type "{getattr(cfg, "record_type", "?")}" without '
                            'identityProviderUid: pamCloudResource JIT / elevation will not work (cloud resources are '
                            'always IdP-provisioned)')

    # 5) KeeperAI on RBI / cloud resources needs ai_threat_detection on the PAM configuration (graph read-only look)
    ai_resources = keeperai_resources(resources)
    if ai_resources and tdag is not None and pam_cfg_uid:
        state = tdag.get_resource_setting(pam_cfg_uid, 'allowedSettings', 'aiEnabled')
        if state != 'on':
            names = ', '.join(f'"{_title(r)}"' for r in ai_resources)
            shown = 'not set' if state in ('', 'default') else state
            msgs.append(f'KeeperAI is requested for {names} but ai_threat_detection is {shown} on the PAM '
                        'configuration - KeeperAI will not run (enable it with '
                        '`pam config edit <config> --ai-threat-detection on`)')

    # 6) Extend only: existing machines that get new users (read-only look at the PAM graph)
    if extend_mode and tdag is not None:
        for res in resources:
            if _is_new(res):
                continue
            new_users = [u for u in (getattr(res, 'users', None) or [])
                         if isinstance(u, PamUserObject) and _is_new(u)]
            if not new_users:
                continue
            if not tdag.resource_belongs_to_config(res.uid):
                msgs.append(f'existing machine "{_title(res)}" is not linked to the PAM configuration - its new '
                            f'user(s) will be skipped')
                continue
            rotating = [u for u in new_users
                        if getattr(u, 'rotation_settings', None) and not _is_saas_rotation(u)]
            if rotating and not tdag.check_if_resource_has_admin(res.uid):
                names = ', '.join(f'"{_title(u)}"' for u in rotating)
                msgs.append(f'existing machine "{_title(res)}" has no admin credential - the rotation of {names} '
                            'will fail ("does not have admin credentials"); extend never sets an admin on an '
                            'existing machine, set it in the Web Vault first')


def load_graph_for_preflight(params, pam_cfg_uid: str) -> Optional[object]:
    """Open the PAM configuration graph read-only (one graph read). Returns None when it cannot be loaded."""
    try:
        from ..tunnel.port_forward.tunnel_helpers import get_keeper_tokens
        from ..tunnel.port_forward.TunnelGraph import TunnelDAG
        session_token, enc_transmission_key, transmission_key = get_keeper_tokens(params)
        return TunnelDAG(params, session_token, enc_transmission_key, pam_cfg_uid, True,
                         transmission_key=transmission_key)
    except Exception as err:
        logging.debug(f'pre-flight: could not load the PAM graph: {err}', exc_info=True)
        return None
