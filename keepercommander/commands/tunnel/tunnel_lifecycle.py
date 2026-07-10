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

import logging
import os
from typing import Dict, List, Optional, Sequence, Tuple

from ..tunnel.port_forward.tunnel_helpers import (
    CloseConnectionReasons,
    get_or_create_tube_registry,
    get_tunnel_session,
    unregister_tunnel_session,
)
from ..tunnel_registry import (
    is_pid_alive,
    list_registered_tunnels,
    stop_tunnel_process,
    unregister_tunnel,
)
from . import pam_state_bridge
from ...display import bcolors
from ...params import KeeperParams

TUNNEL_CONTEXT_REGULAR = 'regular'
TUNNEL_CONTEXT_MSP = 'msp'


def resolve_tunnel_context() -> str:
    """Return the active tunnel visibility context for the current Commander session."""
    from ..msp import current_mc_id

    # Managed-company impersonation is the regular-user view for MSP admins.
    return TUNNEL_CONTEXT_REGULAR if current_mc_id is not None else TUNNEL_CONTEXT_MSP


def resolve_tunnel_account_uid(params: Optional[KeeperParams] = None) -> Optional[str]:
    if params is None:
        params = _resolve_scope_params()
    if params is None:
        return None

    account_bytes = getattr(params, 'account_uid_bytes', None)
    if account_bytes:
        from ... import utils
        return utils.base64_url_encode(account_bytes)
    account_uid = getattr(params, 'account_uid', None)
    return str(account_uid) if account_uid else None


def _resolve_scope_params(primary_params: Optional[KeeperParams] = None) -> Optional[KeeperParams]:
    if primary_params is not None:
        return primary_params
    from ..msp import current_mc_id, mc_params_dict, msp_params

    if current_mc_id is not None and current_mc_id in mc_params_dict:
        return mc_params_dict[current_mc_id]
    if msp_params is not None:
        return msp_params
    return None


def resolve_active_tunnel_scope(params: Optional[KeeperParams] = None) -> Tuple[Optional[str], str]:
    scope_params = _resolve_scope_params(params) if params is None else params
    return resolve_tunnel_account_uid(scope_params), resolve_tunnel_context()


def build_tunnel_ownership(params: Optional[KeeperParams] = None) -> Dict[str, Optional[str]]:
    account_uid, context = resolve_active_tunnel_scope(params)
    return {
        'owning_account_uid': account_uid,
        'owning_context': context,
    }


def apply_tunnel_ownership(target, params: Optional[KeeperParams] = None) -> Dict[str, Optional[str]]:
    ownership = build_tunnel_ownership(params)
    if target is None:
        return ownership
    target.owning_account_uid = ownership['owning_account_uid']
    target.owning_context = ownership['owning_context']
    return ownership


def tunnel_ownership_from_mapping(mapping: Optional[dict]) -> Dict[str, Optional[str]]:
    if not mapping:
        return {}
    return {
        'owning_account_uid': mapping.get('owning_account_uid'),
        'owning_context': mapping.get('owning_context'),
    }


def tunnel_ownership_from_session(session) -> Dict[str, Optional[str]]:
    if session is None:
        return {}
    return {
        'owning_account_uid': getattr(session, 'owning_account_uid', None),
        'owning_context': getattr(session, 'owning_context', None),
    }


def tunnel_matches_scope(
    ownership: Optional[dict],
    scope: Tuple[Optional[str], str],
    *,
    params: Optional[KeeperParams] = None,
    record_uid: Optional[str] = None,
) -> bool:
    account_uid, context = scope
    if not ownership or (
        not ownership.get('owning_account_uid') and not ownership.get('owning_context')
    ):
        return True

    owning_account = ownership.get('owning_account_uid')
    owning_context = ownership.get('owning_context')
    if owning_account and account_uid and owning_account != account_uid:
        return False
    if owning_context and owning_context != context:
        return False
    if record_uid and params is not None and not _record_visible_in_scope(params, record_uid):
        return False
    return True


def _record_visible_in_scope(params: KeeperParams, record_uid: str) -> bool:
    if not record_uid:
        return True
    records = getattr(params, 'records', None) or {}
    return record_uid in records


def collect_session_tunnel_params(primary_params: Optional[KeeperParams] = None) -> List[KeeperParams]:
    from ..msp import mc_params_dict, msp_params

    seen = set()
    collected = []

    def add(candidate):
        if candidate is None:
            return
        candidate_id = id(candidate)
        if candidate_id in seen:
            return
        seen.add(candidate_id)
        collected.append(candidate)

    add(primary_params)
    add(msp_params)
    for mc_params in mc_params_dict.values():
        add(mc_params)
    return collected


def _iter_scoped_in_process_tunnels(
    params_list: Sequence[KeeperParams],
    *,
    scope: Optional[Tuple[Optional[str], str]] = None,
    include_all: bool = False,
    visibility_params: Optional[KeeperParams] = None,
):
    seen_tube_ids = set()
    for params in params_list:
        tube_registry = get_or_create_tube_registry(params)
        if not tube_registry:
            continue
        for tube_id in tube_registry.all_tube_ids():
            if tube_id in seen_tube_ids:
                continue
            session = get_tunnel_session(tube_id)
            ownership = tunnel_ownership_from_session(session)
            if not include_all and scope is not None and not tunnel_matches_scope(
                ownership,
                scope,
            ):
                continue
            seen_tube_ids.add(tube_id)
            yield params, tube_registry, tube_id, session


def _iter_scoped_registry_tunnels(
    *,
    scope: Optional[Tuple[Optional[str], str]] = None,
    include_all: bool = False,
    clean_stale: bool = True,
    visibility_params: Optional[KeeperParams] = None,
):
    for entry in list_registered_tunnels(clean_stale=clean_stale):
        ownership = tunnel_ownership_from_mapping(entry)
        if not include_all and scope is not None and not tunnel_matches_scope(
            ownership,
            scope,
        ):
            continue
        yield entry


def _is_tube_already_stopped(tube_registry, tube_id, *, trust_tube_found=False) -> bool:
    if not tube_registry or not tube_id:
        return True
    if trust_tube_found and hasattr(tube_registry, 'tube_found'):
        try:
            if not tube_registry.tube_found(tube_id):
                return True
        except Exception as err:
            if 'not found' in str(err).lower():
                return True
    if hasattr(tube_registry, 'get_connection_state'):
        try:
            state = tube_registry.get_connection_state(tube_id)
        except Exception as err:
            return 'not found' in str(err).lower()
        return str(state or '').lower() in {'closed', 'not_found'}
    return False


def close_tube_idempotently(tube_registry, tube_id, session=None) -> Tuple[bool, str]:
    """Close a local Rust tube; missing/dead local state is already terminal."""
    if _is_tube_already_stopped(tube_registry, tube_id):
        unregister_tunnel_session(tube_id)
        if session is not None:
            pam_state_bridge.publish_stopped(session)
        return True, 'already_stopped'

    try:
        tube_registry.close_tube(tube_id, reason=CloseConnectionReasons.Normal)
        return True, 'stopped'
    except Exception as exc:
        if 'not found' in str(exc).lower():
            unregister_tunnel_session(tube_id)
            if session is not None:
                pam_state_bridge.publish_stopped(session)
            return True, 'already_stopped'
        return False, str(exc)


def _notice_value(notice, name, default=None):
    if notice is None:
        return default
    if isinstance(notice, dict):
        return notice.get(name, default)
    if hasattr(notice, name):
        return getattr(notice, name)
    kwargs = getattr(notice, 'kwargs', None)
    if isinstance(kwargs, dict):
        return kwargs.get(name, default)
    return default


def _notice_identifiers(notice) -> set:
    return {
        str(value)
        for value in (
            _notice_value(notice, 'pam_session_id'),
            _notice_value(notice, 'tunnel_id'),
            _notice_value(notice, 'resource_handle'),
        )
        if value
    }


def _notice_matches_session(notice_ids: set, tube_id, session) -> bool:
    if not notice_ids:
        return True
    values = {
        str(value)
        for value in (
            tube_id,
            getattr(session, 'tube_id', None),
            getattr(session, 'conversation_id', None),
            getattr(session, 'record_uid', None),
            getattr(session, 'record_title', None),
        )
        if value
    }
    return bool(notice_ids.intersection(values))


def _notice_matches_registry_entry(notice_ids: set, entry) -> bool:
    if not notice_ids:
        return True
    values = {
        str(value)
        for value in (
            entry.get('tube_id'),
            entry.get('record_uid'),
            entry.get('record_title'),
        )
        if value
    }
    return bool(notice_ids.intersection(values))


def _session_registry_keys(tube_id, session) -> set:
    resource = getattr(session, 'record_uid', None) or getattr(session, 'record_title', None) or tube_id
    local = f"{getattr(session, 'host', None) or '127.0.0.1'}:{getattr(session, 'port', None) or '?'}"
    return {
        ('tube_id', tube_id),
        ('record_local', resource, local),
    }


def _registry_entry_keys(entry) -> set:
    resource = entry.get('record_uid') or entry.get('record_title') or entry.get('tube_id') or 'registered tunnel'
    local = f"{entry.get('host') or '127.0.0.1'}:{entry.get('port') or '?'}"
    return {
        ('tube_id', entry.get('tube_id')),
        ('record_local', resource, local),
    }


def _registry_entry_matches_live_tunnel(entry, live_registry_keys: set) -> bool:
    return bool(_registry_entry_keys(entry).intersection(live_registry_keys))


def _unregister_current_process_entry(pid) -> bool:
    if pid != os.getpid():
        return False
    unregister_tunnel(pid)
    logging.debug('Skipped signaling current Commander process while closing PAM tunnel registry entry: pid=%s', pid)
    return True


def _unregister_live_registry_duplicate(entry) -> bool:
    pid = entry.get('pid') if entry else None
    if pid != os.getpid():
        return False
    unregister_tunnel(pid)
    logging.debug('Removed current Commander process registry entry for closed in-process PAM tunnel: pid=%s', pid)
    return True


def handle_desktop_logout_notice(params: Optional[KeeperParams], notice) -> Tuple[int, int]:
    """Apply KDBC logout notice to local Commander tunnel state."""
    notice_ids = _notice_identifiers(notice)
    reason = str(_notice_value(notice, 'reason', 'vault_logout') or 'vault_logout')
    stopped = 0
    failed = 0
    seen_pids = set()
    live_registry_keys = set()

    for _params, tube_registry, tube_id, session in _iter_scoped_in_process_tunnels(
        collect_session_tunnel_params(params),
        include_all=True,
    ):
        if not _notice_matches_session(notice_ids, tube_id, session):
            continue
        live_registry_keys.update(_session_registry_keys(tube_id, session))
        pam_state_bridge.publish_stopping(session)
        ok, message = close_tube_idempotently(tube_registry, tube_id, session)
        if ok:
            stopped += 1
        else:
            failed += 1
            pam_state_bridge.publish_error(
                session,
                {
                    'code': 'desktop_logout_close_failed',
                    'kind': 'internal_error',
                    'message': message,
                },
            )
            logging.debug(
                'Failed to close local PAM tunnel on Desktop logout notice reason=%s tube=%s: %s',
                reason,
                tube_id,
                message,
            )

    for entry in list_registered_tunnels(clean_stale=False):
        if not _notice_matches_registry_entry(notice_ids, entry):
            continue
        if _registry_entry_matches_live_tunnel(entry, live_registry_keys):
            _unregister_live_registry_duplicate(entry)
            continue
        pid = entry.get('pid')
        if not pid or pid in seen_pids:
            continue
        seen_pids.add(pid)
        if _unregister_current_process_entry(pid):
            stopped += 1
            continue
        if is_pid_alive(pid):
            if stop_tunnel_process(pid):
                stopped += 1
            else:
                failed += 1
        else:
            unregister_tunnel(pid)
            stopped += 1

    return stopped, failed


def reconcile_local_tunnel_liveness(params: Optional[KeeperParams] = None) -> int:
    """Prune local tunnel state that is already closed before publishing/relisting."""
    pruned = 0
    for candidate_params in collect_session_tunnel_params(params):
        tube_registry = get_or_create_tube_registry(candidate_params)
        if not tube_registry or not hasattr(tube_registry, 'all_tube_ids'):
            continue
        try:
            tube_ids = list(tube_registry.all_tube_ids())
        except Exception as err:
            logging.debug('Unable to enumerate local PAM tubes during reconciliation: %s', err)
            continue
        for tube_id in tube_ids:
            session = get_tunnel_session(tube_id)
            if _is_tube_already_stopped(tube_registry, tube_id, trust_tube_found=True):
                unregister_tunnel_session(tube_id)
                if session is not None:
                    pam_state_bridge.publish_stopped(session)
                pruned += 1

    # File registry cleanup is already idempotent; this call removes dead PIDs.
    list_registered_tunnels(clean_stale=True)
    return pruned


def stop_scoped_active_pam_tunnels(
    params_list: Sequence[KeeperParams],
    *,
    scope: Optional[Tuple[Optional[str], str]] = None,
    include_all: bool = False,
    verbose: bool = False,
    reason: str = 'user_stop',
) -> Tuple[int, int]:
    stopped_count = 0
    failed_count = 0
    seen_pids = set()
    live_registry_keys = set()

    for _params, tube_registry, tube_id, session in _iter_scoped_in_process_tunnels(
        params_list,
        scope=scope,
        include_all=include_all,
    ):
        live_registry_keys.update(_session_registry_keys(tube_id, session))
        pam_state_bridge.publish_stopping(session)
        ok, message = close_tube_idempotently(tube_registry, tube_id, session)
        if ok:
            if verbose:
                suffix = " (already stopped)" if message == 'already_stopped' else ""
                print(f"  {bcolors.OKGREEN}Stopped: {tube_id}{suffix}{bcolors.ENDC}")
            stopped_count += 1
        else:
            pam_state_bridge.publish_error(
                session,
                {
                    'code': 'local_stop_failed',
                    'kind': 'internal_error',
                    'message': message,
                },
            )
            if verbose:
                print(f"  {bcolors.FAIL}Failed: {tube_id}: {message}{bcolors.ENDC}")
            failed_count += 1

    for projection in pam_state_bridge.list_external_projections(clean_stale=False):
        ownership = tunnel_ownership_from_mapping(projection)
        if not include_all and scope is not None and not tunnel_matches_scope(ownership, scope):
            continue
        requested, message = pam_state_bridge.request_owner_stop(projection, reason=reason)
        if requested:
            stopped_count += 1
            if verbose:
                tunnel_id = projection.get('tunnel_id') or projection.get('resource_handle') or '?'
                print(
                    f"  {bcolors.OKGREEN}Requested Vault/Desktop stop for external tunnel "
                    f"{tunnel_id} ({message}){bcolors.ENDC}"
                )
        else:
            failed_count += 1
            logging.debug('External tunnel owner-stop request failed during %s: %s', reason, message)

    for entry in _iter_scoped_registry_tunnels(scope=scope, include_all=include_all, clean_stale=True):
        if _registry_entry_matches_live_tunnel(entry, live_registry_keys):
            _unregister_live_registry_duplicate(entry)
            continue
        pid = entry.get('pid')
        if not pid or pid in seen_pids:
            continue
        seen_pids.add(pid)
        if _unregister_current_process_entry(pid):
            stopped_count += 1
            continue
        if not is_pid_alive(pid):
            unregister_tunnel(pid)
            if verbose:
                print(f"  {bcolors.OKGREEN}Stopped: PID {pid} was already gone{bcolors.ENDC}")
            stopped_count += 1
        elif stop_tunnel_process(pid):
            if verbose:
                print(
                    f"  {bcolors.OKGREEN}Sent stop signal to PID {pid} "
                    f"({entry.get('mode', '?')} mode, {entry.get('host')}:{entry.get('port')})"
                    f"{bcolors.ENDC}"
                )
            stopped_count += 1
        else:
            if verbose:
                print(f"  {bcolors.FAIL}Failed to signal PID {pid}{bcolors.ENDC}")
            failed_count += 1
            if not is_pid_alive(pid):
                unregister_tunnel(pid)

    return stopped_count, failed_count


def stop_all_active_pam_tunnels(
    params_list: Sequence[KeeperParams],
    *,
    verbose: bool = False,
    reason: str = 'user_stop',
    scope: Optional[Tuple[Optional[str], str]] = None,
    include_all: bool = False,
) -> Tuple[int, int]:
    return stop_scoped_active_pam_tunnels(
        params_list,
        scope=scope,
        include_all=include_all,
        verbose=verbose,
        reason=reason,
    )


def close_pam_tunnels_on_logout(params: Optional[KeeperParams] = None) -> Tuple[int, int]:
    account_uid = resolve_tunnel_account_uid(params)
    if not account_uid:
        return 0, 0

    stopped = 0
    failed = 0
    params_list = collect_session_tunnel_params(params)
    live_registry_keys = set()

    for candidate_params, tube_registry, tube_id, session in _iter_scoped_in_process_tunnels(
        params_list,
        include_all=True,
    ):
        ownership = tunnel_ownership_from_session(session)
        owning_account = ownership.get('owning_account_uid') or resolve_tunnel_account_uid(candidate_params)
        if owning_account != account_uid:
            continue
        live_registry_keys.update(_session_registry_keys(tube_id, session))
        pam_state_bridge.publish_stopping(session)
        ok, _message = close_tube_idempotently(tube_registry, tube_id, session)
        if ok:
            stopped += 1
        else:
            failed += 1

    for projection in pam_state_bridge.list_external_projections(clean_stale=False):
        ownership = tunnel_ownership_from_mapping(projection)
        owning_account = ownership.get('owning_account_uid')
        if owning_account and owning_account != account_uid:
            continue
        requested, _message = pam_state_bridge.request_owner_stop(projection, reason='logout')
        if requested:
            stopped += 1
        else:
            failed += 1

    for entry in list_registered_tunnels(clean_stale=True):
        ownership = tunnel_ownership_from_mapping(entry)
        owning_account = ownership.get('owning_account_uid')
        if owning_account and owning_account != account_uid:
            continue
        if _registry_entry_matches_live_tunnel(entry, live_registry_keys):
            _unregister_live_registry_duplicate(entry)
            continue
        pid = entry.get('pid')
        if pid and _unregister_current_process_entry(pid):
            stopped += 1
            continue
        if pid and not is_pid_alive(pid):
            unregister_tunnel(pid)
            stopped += 1
        elif pid and stop_tunnel_process(pid):
            stopped += 1
        else:
            failed += 1
            if pid and not is_pid_alive(pid):
                unregister_tunnel(pid)

    return stopped, failed


def describe_active_pam_tunnels_on_logout(params: Optional[KeeperParams] = None) -> List[str]:
    account_uid = resolve_tunnel_account_uid(params)
    if not account_uid:
        return []

    descriptions: List[str] = []
    seen = set()
    params_list = collect_session_tunnel_params(params)

    for _candidate_params, _tube_registry, tube_id, session in _iter_scoped_in_process_tunnels(
        params_list,
        include_all=True,
    ):
        ownership = tunnel_ownership_from_session(session)
        owning_account = ownership.get('owning_account_uid') or resolve_tunnel_account_uid(_candidate_params)
        if owning_account != account_uid:
            continue
        key = ('tube', tube_id)
        if key in seen:
            continue
        seen.add(key)
        resource = getattr(session, 'record_uid', None) or getattr(session, 'record_title', None) or tube_id
        local = f"{getattr(session, 'host', None) or '127.0.0.1'}:{getattr(session, 'port', None) or '?'}"
        seen.add(('record_local', resource, local))
        remote_host = getattr(session, 'target_host', None) or '?'
        remote_port = getattr(session, 'target_port', None) or '?'
        descriptions.append(f"{resource} (local {local} -> remote {remote_host}:{remote_port})")

    for projection in pam_state_bridge.list_external_projections(clean_stale=False):
        ownership = tunnel_ownership_from_mapping(projection)
        owning_account = ownership.get('owning_account_uid')
        if owning_account and owning_account != account_uid:
            continue
        key = ('projection', projection.get('pam_session_id') or projection.get('tunnel_id') or projection.get('resource_handle'))
        if key in seen:
            continue
        seen.add(key)
        resource = projection.get('resource_handle') or projection.get('tunnel_id') or 'external tunnel'
        descriptions.append(f"{resource} (Vault/Desktop-owned)")

    for entry in list_registered_tunnels(clean_stale=True):
        ownership = tunnel_ownership_from_mapping(entry)
        owning_account = ownership.get('owning_account_uid')
        if owning_account and owning_account != account_uid:
            continue
        pid = entry.get('pid')
        key = ('pid', pid or entry.get('tube_id') or entry.get('record_uid'))
        if key in seen:
            continue
        seen.add(key)
        resource = entry.get('record_uid') or entry.get('record_title') or entry.get('tube_id') or 'registered tunnel'
        local = f"{entry.get('host') or '127.0.0.1'}:{entry.get('port') or '?'}"
        if ('record_local', resource, local) in seen:
            continue
        descriptions.append(f"{resource} (local {local}, pid {pid or '?'})")

    return descriptions


def iter_visible_in_process_tunnels(params: KeeperParams):
    scope = resolve_active_tunnel_scope(params)
    yield from _iter_scoped_in_process_tunnels(
        collect_session_tunnel_params(params),
        scope=scope,
        visibility_params=params,
    )


def iter_visible_registry_tunnels(params: Optional[KeeperParams] = None):
    scope = resolve_active_tunnel_scope(params)
    visibility_params = params or _resolve_scope_params()
    yield from _iter_scoped_registry_tunnels(
        scope=scope,
        visibility_params=visibility_params,
    )


def iter_visible_external_projections(params: Optional[KeeperParams] = None):
    scope = resolve_active_tunnel_scope(params)
    visibility_params = params or _resolve_scope_params()
    for projection in pam_state_bridge.list_external_projections(clean_stale=True):
        ownership = tunnel_ownership_from_mapping(projection)
        if tunnel_matches_scope(
            ownership,
            scope,
            params=visibility_params,
            record_uid=projection.get('resource_handle'),
        ):
            yield projection
