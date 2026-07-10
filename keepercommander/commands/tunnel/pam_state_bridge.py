import logging
import os
import queue
import hashlib
import threading
import time
import uuid

from ... import rest_api, utils
from ... import __version__


_PUBLISHER_INSTANCE_ID = f"commander:{os.getpid()}:{uuid.uuid4().hex}"
_SEQUENCE_LOCK = threading.Lock()
_SEQUENCE = 0

_KDBC_MODULE = None
_KDBC_IMPORT_ATTEMPTED = False

_WORKER_LOCK = threading.Lock()
_WORKER_THREAD = None
_WORKER_STOP = threading.Event()
_WORKER_PARAMS = None
_EVENT_QUEUE = queue.Queue()
_ACTION_APPROVAL_QUEUE = queue.Queue()
_CONTROL_HANDLER = None
_STATE_SYNC_SESSION = None
_STATE_SYNC_SESSION_ACTIVE = False
_OWNER_STOP_QUEUE = queue.Queue()
_HEARTBEAT_INTERVAL_SECONDS = 20
_HEARTBEAT_LOCK = threading.Lock()
_ACTIVE_HEARTBEATS = {}
_LAST_HEARTBEAT_AT = {}
# Vault-owned projections are same-session/live only in AI-402 v0. They are
# populated from this Commander's approved KDBC state-sync stream and are not a
# global fanout, replay, or cross-process source of truth.
_EXTERNAL_PROJECTION_LOCK = threading.Lock()
_EXTERNAL_PROJECTIONS = {}
_EXTERNAL_PROJECTION_TTL_SECONDS = 90
_TERMINAL_STATES = {"stopped", "error", "failed", "revoked", "stale"}
_OWNER_STOP_CONTRACT_VERSION = 1
_ACTION_APPROVAL_CONTRACT_VERSION = 1
_PAM_TUNNEL_START_ACTION = "pam_tunnel_start"
_PAM_LAUNCH_ACTION = "pam_launch"
_DUPLICATE_ACTIVE_REASON = "duplicate_active_session"
_ACTION_APPROVAL_TIMEOUT_MS = None
DESKTOP_ACCOUNT_MISMATCH_MESSAGE = "Desktop account does not match Vault account"
DESKTOP_ACCOUNT_BINDING_UNAVAILABLE_MESSAGE = "Desktop account binding is unavailable"
_DESKTOP_BRIDGE_ACCOUNT_ALLOWED = True
_DESKTOP_ACCOUNT_BINDING = None


def publisher_instance_id():
    return _PUBLISHER_INSTANCE_ID


def _next_sequence():
    global _SEQUENCE
    with _SEQUENCE_LOCK:
        _SEQUENCE += 1
        return _SEQUENCE


def _kdbc():
    global _KDBC_MODULE, _KDBC_IMPORT_ATTEMPTED
    if not _KDBC_IMPORT_ATTEMPTED:
        _KDBC_IMPORT_ATTEMPTED = True
        try:
            import keeper_desktop_bridge_client as kdbc
            required = (
                "BridgeClient",
                "BridgeClientConfig",
                "PamBridgePeer",
                "PublishPamStateEventRequest",
            )
            missing = [name for name in required if not hasattr(kdbc, name)]
            if missing:
                logging.debug(
                    "KDBC PAM state bridge unavailable: missing %s",
                    ", ".join(missing),
                )
                _KDBC_MODULE = None
            else:
                _KDBC_MODULE = kdbc
        except Exception as err:
            logging.debug("KDBC PAM state bridge unavailable: %s", err)
            _KDBC_MODULE = None
    return _KDBC_MODULE


def _supports_persistent_session(kdbc):
    return _coordinator_supports_leaf_workflow(kdbc)


def _coordinator_class(kdbc):
    return getattr(kdbc, "PamCoordinator", None)


def _coordinator_supports_leaf_workflow(kdbc):
    coordinator_cls = _coordinator_class(kdbc)
    return bool(
        coordinator_cls
        and hasattr(coordinator_cls, "start_state_sync")
        and hasattr(coordinator_cls, "receive_next_frame")
        and hasattr(coordinator_cls, "publish_pam_state_event")
        and hasattr(coordinator_cls, "ack_pam_control")
        and hasattr(coordinator_cls, "fail_pam_control")
        and hasattr(coordinator_cls, "request_pam_action_approval")
        and hasattr(coordinator_cls, "request_owner_stop")
        and hasattr(kdbc, "AckPamControlRequest")
        and hasattr(kdbc, "FailPamControlRequest")
    )


def _socket_override():
    return os.environ.get("KEEPER_BRIDGE_LEAF_SOCKET") or None


def _verification_policy(params=None):
    env_policy = os.environ.get("KDBC_VERIFICATION_POLICY")
    if env_policy:
        return env_policy

    active_params = params or _WORKER_PARAMS
    if getattr(active_params, "via_desktop_login", False) is not True:
        return None

    try:
        from ...auth import desktop_bridge
        return desktop_bridge._resolve_verification_policy(active_params, None)
    except Exception as err:
        logging.debug("Unable to resolve KDBC verification policy from via-desktop params: %s", err)
        return None


def _make_vault_account_binding(kdbc):
    if not _DESKTOP_ACCOUNT_BINDING:
        return None
    binding_cls = getattr(kdbc, "VaultAccountBinding", None)
    if binding_cls is None:
        return None
    return binding_cls(
        _DESKTOP_ACCOUNT_BINDING.get("vault_account_uid"),
        username=_DESKTOP_ACCOUNT_BINDING.get("username"),
        email=_DESKTOP_ACCOUNT_BINDING.get("email"),
    )


def _vault_account_binding_kwargs(kdbc):
    binding = _make_vault_account_binding(kdbc)
    return {"vault_account_binding": binding} if binding is not None else {}


def _make_config(kdbc, params=None):
    kwargs = {
        "socket_override": _socket_override(),
        "verification_policy": _verification_policy(params),
    }
    kwargs.update(_vault_account_binding_kwargs(kdbc))
    try:
        return kdbc.BridgeClientConfig(**kwargs)
    except TypeError:
        kwargs.pop("vault_account_binding", None)
        return kdbc.BridgeClientConfig(**kwargs)


def _action_approval_timeout_ms():
    raw_value = os.environ.get("KDBC_PAM_ACTION_APPROVAL_TIMEOUT_MS")
    if raw_value:
        try:
            return max(1, int(raw_value))
        except ValueError:
            logging.debug("Ignoring invalid KDBC_PAM_ACTION_APPROVAL_TIMEOUT_MS=%r", raw_value)
    return _ACTION_APPROVAL_TIMEOUT_MS


def _make_action_approval_config(kdbc, params=None):
    kwargs = {
        "socket_override": _socket_override(),
        "verification_policy": _verification_policy(params),
    }
    timeout_ms = _action_approval_timeout_ms()
    if timeout_ms is not None:
        kwargs["timeout_millis"] = timeout_ms
    kwargs.update(_vault_account_binding_kwargs(kdbc))
    try:
        return kdbc.BridgeClientConfig(**kwargs)
    except TypeError:
        kwargs.pop("vault_account_binding", None)
        return kdbc.BridgeClientConfig(**kwargs)


def _make_bridge_peer(kdbc):
    return kdbc.PamBridgePeer("commander")


def _make_state_caller(kdbc):
    if not hasattr(kdbc, "PamStateCaller"):
        return None
    return kdbc.PamStateCaller(
        caller_instance_id=_PUBLISHER_INSTANCE_ID,
        display_name="Commander",
    )


def _make_control_caller(kdbc):
    if not hasattr(kdbc, "PamControlCaller"):
        return None
    return kdbc.PamControlCaller(
        caller_instance_id=_PUBLISHER_INSTANCE_ID,
        display_name="Commander",
    )


def _make_client_identity(kdbc):
    if not hasattr(kdbc, "ClientIdentity"):
        return None
    return kdbc.ClientIdentity(
        name="Keeper Commander",
        version=__version__,
        kind="commander",
        ka_client_version=rest_api.CLIENT_VERSION,
    )


def _make_local_endpoint(kdbc, host, port):
    if not host or not port:
        return None
    try:
        return kdbc.PamLocalEndpoint(str(host), int(port))
    except Exception:
        logging.debug("Skipping invalid PAM local endpoint host=%r port=%r", host, port)
        return None


def _make_safe_error(kdbc, error):
    if not error:
        return None
    if isinstance(error, dict):
        code = error.get("code") or "commander_pam_error"
        kind = error.get("kind") or "internal_error"
        message = error.get("message") or code
    else:
        code = "commander_pam_error"
        kind = "internal_error"
        message = str(error)
    try:
        return kdbc.PamSafeError(str(code), str(kind), str(message))
    except Exception:
        logging.debug("Skipping invalid PAM safe error code=%r kind=%r", code, kind)
        return None


def _control_value(control, name, default=None):
    return getattr(control, name, default)


def _message_value(message, name, default=None):
    if isinstance(message, dict):
        return message.get(name, default)
    if hasattr(message, name):
        return getattr(message, name)
    kwargs = getattr(message, "kwargs", None)
    if isinstance(kwargs, dict) and name in kwargs:
        return kwargs.get(name)
    return default


def _endpoint_to_dict(endpoint):
    if not endpoint:
        return None
    host = getattr(endpoint, "host", None)
    port = getattr(endpoint, "port", None)
    if not host or not port:
        return None
    try:
        port = int(port)
    except Exception:
        return None
    return {"host": str(host), "port": port}


def _bridge_peer_to_dict(peer):
    if not peer:
        return None
    safe = {}
    for name in ("peer_id", "pid", "path", "bundle_id", "signed", "signing_subject", "binary_hash"):
        value = getattr(peer, name, None)
        if value is not None:
            safe[name] = value
    return safe or None


def _projection_key(projection):
    return (
        projection.get("publisher_instance_id") or "",
        projection.get("pam_session_id") or "",
        projection.get("tunnel_id") or "",
    )


def _notice_value(notice, name, default=None):
    if notice is None:
        return default
    if isinstance(notice, dict):
        return notice.get(name, default)
    if hasattr(notice, name):
        return getattr(notice, name)
    kwargs = getattr(notice, "kwargs", None)
    if isinstance(kwargs, dict):
        return kwargs.get(name, default)
    return default


def _clear_external_projections_for_logout_notice(notice):
    ids = {
        str(value)
        for value in (
            _notice_value(notice, "pam_session_id"),
            _notice_value(notice, "tunnel_id"),
            _notice_value(notice, "resource_handle"),
        )
        if value
    }
    with _EXTERNAL_PROJECTION_LOCK:
        if not ids:
            count = len(_EXTERNAL_PROJECTIONS)
            _EXTERNAL_PROJECTIONS.clear()
            return count
        removed = 0
        for key, projection in list(_EXTERNAL_PROJECTIONS.items()):
            values = {
                str(value)
                for value in (
                    projection.get("pam_session_id"),
                    projection.get("tunnel_id"),
                    projection.get("resource_handle"),
                )
                if value
            }
            if ids.intersection(values):
                _EXTERNAL_PROJECTIONS.pop(key, None)
                removed += 1
        return removed


def _projection_is_terminal(projection):
    state = (projection.get("state") or "").lower()
    event_type = projection.get("event_type") or ""
    return state in _TERMINAL_STATES or event_type == "pam_session_error"


def _projection_is_fresh(projection, now=None):
    now = now if now is not None else time.time()
    return now - projection.get("last_seen", 0) <= _EXTERNAL_PROJECTION_TTL_SECONDS


def _projection_is_active(projection, now=None):
    return not _projection_is_terminal(projection) and _projection_is_fresh(projection, now)


def _mark_external_projection_owner_stop_requested(projection, control_id, reason):
    if not projection:
        return None
    key = _projection_key(projection)
    if not any(key):
        return None
    now = time.time()
    with _EXTERNAL_PROJECTION_LOCK:
        cached = _EXTERNAL_PROJECTIONS.get(key)
        if not cached:
            return None
        cached["state"] = "stopping"
        cached["event_type"] = "pam_session_state_changed"
        cached["owner_stop_pending"] = True
        cached["owner_stop_control_id"] = control_id
        cached["owner_stop_reason"] = reason or "user_stop"
        cached["owner_stop_requested_at"] = now
        cached["last_seen"] = now
        return dict(cached)


def _cleanup_external_projections(now=None):
    now = now if now is not None else time.time()
    expired = []
    for key, projection in _EXTERNAL_PROJECTIONS.items():
        if not _projection_is_fresh(projection, now):
            expired.append(key)
    for key in expired:
        _EXTERNAL_PROJECTIONS.pop(key, None)


def _upsert_external_projection(event):
    publisher_instance_id = _message_value(event, "publisher_instance_id", "")
    if publisher_instance_id == _PUBLISHER_INSTANCE_ID:
        return None
    if not publisher_instance_id:
        publisher_instance_id = "vault_desktop"

    local_endpoint = _message_value(event, "local_endpoint", None)
    event_type = str(_message_value(event, "event_type", ""))
    state = str(_message_value(event, "state", ""))
    if not state and event_type in {"pam_session_started", "pam_session_heartbeat"}:
        state = "active"
    projection = {
        "external_owner": "vault_desktop",
        "publisher_instance_id": str(publisher_instance_id),
        "pam_session_id": str(_message_value(event, "pam_session_id", "")),
        "tunnel_id": str(_message_value(event, "tunnel_id", "")),
        "resource_handle": str(_message_value(event, "resource_handle", "")),
        "event_type": event_type,
        "state": state,
        "sequence": _message_value(event, "sequence", None),
        "vault_grant_id": _message_value(event, "vault_grant_id", None),
        "bridge_peer": _bridge_peer_to_dict(_message_value(event, "bridge_peer", None)),
        "local_endpoint": _endpoint_to_dict(local_endpoint),
        "last_seen": time.time(),
    }
    for name in (
        "authn_hint",
        "ssh_agent_available",
        "ssh_agent_endpoint",
        "ssh_agent_endpoint_kind",
        "ssh_agent_scope",
    ):
        value = _message_value(event, name, None)
        if value is not None:
            projection[name] = value
    try:
        from .tunnel_lifecycle import build_tunnel_ownership
        projection.update(build_tunnel_ownership())
    except Exception as err:
        logging.debug('Unable to tag external PAM projection ownership: %s', err)
    key = _projection_key(projection)
    if not any(key):
        return None

    with _EXTERNAL_PROJECTION_LOCK:
        if _projection_is_terminal(projection):
            _EXTERNAL_PROJECTIONS.pop(key, None)
        else:
            _cleanup_external_projections(projection["last_seen"])
            existing = _EXTERNAL_PROJECTIONS.get(key)
            if existing:
                projection['owning_account_uid'] = existing.get('owning_account_uid', projection.get('owning_account_uid'))
                projection['owning_context'] = existing.get('owning_context', projection.get('owning_context'))
            _EXTERNAL_PROJECTIONS[key] = projection
    return projection


def list_external_projections(clean_stale=True):
    now = time.time()
    with _EXTERNAL_PROJECTION_LOCK:
        if clean_stale:
            _cleanup_external_projections(now)
        return [dict(p) for p in _EXTERNAL_PROJECTIONS.values() if _projection_is_active(p, now)]


def wait_for_external_projections(timeout_seconds=1.5, interval_seconds=0.05):
    projections = list_external_projections()
    if projections:
        return projections
    with _WORKER_LOCK:
        worker_alive = bool(_WORKER_THREAD and _WORKER_THREAD.is_alive())
    if not worker_alive:
        return projections

    deadline = time.monotonic() + max(0, timeout_seconds)
    while time.monotonic() < deadline:
        time.sleep(interval_seconds)
        projections = list_external_projections()
        if projections:
            return projections
    return projections


def find_external_projection_for_resource(resource_handle):
    if not resource_handle:
        return None
    resource_handle = str(resource_handle)
    matches = []
    for projection in list_external_projections():
        if projection.get("resource_handle") == resource_handle:
            matches.append(projection)
    if not matches:
        return None
    return max(
        matches,
        key=lambda p: (
            p.get("last_seen", 0),
            p.get("sequence") if p.get("sequence") is not None else -1,
        ),
    )


def find_external_projection(identifier):
    if not identifier:
        return None
    identifier = str(identifier)
    matches = []
    for projection in list_external_projections():
        if identifier in (
            projection.get("resource_handle"),
            projection.get("tunnel_id"),
            projection.get("pam_session_id"),
        ):
            matches.append(projection)
    if not matches:
        return None
    return max(
        matches,
        key=lambda p: (
            p.get("last_seen", 0),
            p.get("sequence") if p.get("sequence") is not None else -1,
        ),
    )


def clear_external_projections():
    with _EXTERNAL_PROJECTION_LOCK:
        _EXTERNAL_PROJECTIONS.clear()


def _make_ack_request(kdbc, control):
    now_ms = int(time.time() * 1000)
    extra_kwargs = _vault_account_binding_kwargs(kdbc)
    return kdbc.AckPamControlRequest(
        _control_value(control, "control_id", ""),
        _control_value(control, "pam_session_id", ""),
        _control_value(control, "tunnel_id", ""),
        _control_value(control, "resource_handle", ""),
        _control_value(control, "bridge_peer", None) or _make_bridge_peer(kdbc),
        "stopped",
        vault_grant_id=_control_value(control, "vault_grant_id", None),
        publisher_instance_id=_PUBLISHER_INSTANCE_ID,
        caller=_control_value(control, "caller", None),
        sent_at_unix_ms=now_ms,
        **extra_kwargs,
    )


def _make_fail_request(kdbc, control, error):
    now_ms = int(time.time() * 1000)
    extra_kwargs = _vault_account_binding_kwargs(kdbc)
    return kdbc.FailPamControlRequest(
        _control_value(control, "control_id", ""),
        _control_value(control, "pam_session_id", ""),
        _control_value(control, "tunnel_id", ""),
        _control_value(control, "resource_handle", ""),
        _control_value(control, "bridge_peer", None) or _make_bridge_peer(kdbc),
        _make_safe_error(kdbc, error) or kdbc.PamSafeError(
            "commander_pam_control_failed",
            "internal_error",
            "Commander failed to process PAM control",
        ),
        vault_grant_id=_control_value(control, "vault_grant_id", None),
        publisher_instance_id=_PUBLISHER_INSTANCE_ID,
        caller=_control_value(control, "caller", None),
        sent_at_unix_ms=now_ms,
        **extra_kwargs,
    )


def _make_owner_stop_request(kdbc, projection, reason):
    control_id = str(uuid.uuid4())
    extra_kwargs = _vault_account_binding_kwargs(kdbc)
    return kdbc.RequestPamControlStopRequest(
        control_id,
        projection.get("pam_session_id") or "",
        projection.get("tunnel_id") or "",
        projection.get("resource_handle") or "",
        reason or "user_stop",
        contract_version=_OWNER_STOP_CONTRACT_VERSION,
        vault_grant_id=projection.get("vault_grant_id"),
        publisher_instance_id=_PUBLISHER_INSTANCE_ID,
        caller=_make_control_caller(kdbc),
        sent_at_unix_ms=int(time.time() * 1000),
        **extra_kwargs,
    )


def _owner_stop_result_failed(result):
    if result is None:
        return False
    if isinstance(result, str):
        value = result.lower()
        return value == "timeout" or value.startswith("failed:")
    value = (
        getattr(result, "decision", None)
        or getattr(result, "result", None)
        or getattr(result, "status", None)
    )
    if value is not None and str(value).lower() in {"deny", "failed", "error"}:
        return True
    error = getattr(result, "error", None)
    return error is not None


def _owner_stop_result_message(result):
    if result is None:
        return ""
    if isinstance(result, str):
        if result == "timeout":
            return "Timed out waiting for Vault/Desktop owner stop result"
        if result.startswith("failed:"):
            code = result.split(":", 1)[1] or "unknown"
            return f"Vault/Desktop owner stop failed: {code}"
        return result
    for attr in ("message", "reason", "error"):
        value = getattr(result, attr, None)
        if value:
            return str(value)
    return ""


def _owner_stop_result_terminal(result):
    if result is None:
        return False
    if isinstance(result, str):
        return result.lower() in {"already_stopped", "revoked", "stopped"}
    value = (
        getattr(result, "decision", None)
        or getattr(result, "result", None)
        or getattr(result, "status", None)
    )
    if value is None:
        return False
    return str(value).lower() in {
        "ack",
        "accepted",
        "allow",
        "allow_once",
        "ok",
        "requested",
        "stopped",
        "success",
    }


def _action_approval_request_class(kdbc):
    return (
        getattr(kdbc, "PAMActionApprovalRequest", None)
        or getattr(kdbc, "PamActionApprovalRequest", None)
        or getattr(kdbc, "RequestPamActionApprovalRequest", None)
    )


def _action_approval_method(client):
    return (
        getattr(client, "request_pam_action_approval", None)
        or getattr(client, "request_pam_start_tunnel_approval", None)
    )


def _session_action_approval_method(session):
    return getattr(session, "request_pam_action_approval", None)


def _kdbc_runtime_path(kdbc):
    return getattr(kdbc, "__file__", "") or "<unknown>"


def _kdbc_value(kdbc, name, default):
    return getattr(kdbc, name, default) if kdbc is not None else default


def _binding_value(binding, name):
    if binding is None:
        return None
    if isinstance(binding, dict):
        return binding.get(name)
    return getattr(binding, name, None)


def _normalize_account_uid(value):
    if value is None:
        return None
    if isinstance(value, bytes):
        return utils.base64_url_encode(value)
    value = str(value).strip()
    if not value:
        return None
    try:
        decoded = utils.base64_url_decode(value)
        if decoded:
            return utils.base64_url_encode(decoded)
    except Exception:
        pass
    return value


def _uid_fingerprint(value):
    value = _normalize_account_uid(value)
    if not value:
        return "none"
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
    return f"len={len(value)} sha12={digest}"


def desktop_account_binding_mismatch_diagnostic(params):
    return (
        f"{DESKTOP_ACCOUNT_MISMATCH_MESSAGE} "
        f"(desktop_uid={_uid_fingerprint(getattr(params, 'desktop_account_uid', None))} "
        f"commander_uid={_uid_fingerprint(_active_account_uid(params))})"
    )


def _active_account_uid(params):
    account_uid = getattr(params, "account_uid_bytes", None)
    if account_uid:
        return _normalize_account_uid(account_uid)
    account_uid = getattr(params, "account_uid", None)
    return _normalize_account_uid(account_uid)


def clear_desktop_account_binding(params):
    global _DESKTOP_ACCOUNT_BINDING
    _DESKTOP_ACCOUNT_BINDING = None
    if params is None:
        return
    params.desktop_account_uid = None
    params.desktop_user = ""
    params.desktop_account_username = None
    params.desktop_account_email = None


def _clear_local_state_sync_buffers():
    while True:
        try:
            _EVENT_QUEUE.get_nowait()
        except queue.Empty:
            break
    while True:
        try:
            _ACTION_APPROVAL_QUEUE.get_nowait()
        except queue.Empty:
            break
    while True:
        try:
            _OWNER_STOP_QUEUE.get_nowait()
        except queue.Empty:
            break
    with _HEARTBEAT_LOCK:
        _ACTIVE_HEARTBEATS.clear()
        _LAST_HEARTBEAT_AT.clear()


def suspend_desktop_bridge_state(params=None, clear_binding=False):
    global _DESKTOP_BRIDGE_ACCOUNT_ALLOWED
    _DESKTOP_BRIDGE_ACCOUNT_ALLOWED = False
    stop_state_sync_worker()
    _clear_local_state_sync_buffers()
    clear_external_projections()
    if clear_binding:
        clear_desktop_account_binding(params)


def set_desktop_account_binding(params, binding):
    global _DESKTOP_BRIDGE_ACCOUNT_ALLOWED, _DESKTOP_ACCOUNT_BINDING
    _DESKTOP_ACCOUNT_BINDING = None
    if params is None:
        _DESKTOP_BRIDGE_ACCOUNT_ALLOWED = False
        return False, DESKTOP_ACCOUNT_BINDING_UNAVAILABLE_MESSAGE

    desktop_account_uid = _normalize_account_uid(_binding_value(binding, "vault_account_uid"))
    username = _binding_value(binding, "username")
    email = _binding_value(binding, "email")
    params.desktop_account_uid = desktop_account_uid
    params.desktop_account_username = str(username) if username else None
    params.desktop_account_email = str(email) if email else None
    params.desktop_user = params.desktop_account_email or params.desktop_account_username or ""

    active_account_uid = _active_account_uid(params)
    logging.debug(
        "Desktop account binding compare: desktop_uid=%s commander_uid=%s",
        _uid_fingerprint(desktop_account_uid),
        _uid_fingerprint(active_account_uid),
    )
    if not desktop_account_uid or not active_account_uid:
        suspend_desktop_bridge_state(params, clear_binding=False)
        return False, DESKTOP_ACCOUNT_BINDING_UNAVAILABLE_MESSAGE
    if desktop_account_uid != active_account_uid:
        suspend_desktop_bridge_state(params, clear_binding=False)
        return False, DESKTOP_ACCOUNT_MISMATCH_MESSAGE

    _DESKTOP_ACCOUNT_BINDING = {
        "vault_account_uid": desktop_account_uid,
        "username": params.desktop_account_username,
        "email": params.desktop_account_email,
    }
    _DESKTOP_BRIDGE_ACCOUNT_ALLOWED = True
    return True, None


def desktop_bridge_account_gate(params=None):
    if params is None:
        if _DESKTOP_BRIDGE_ACCOUNT_ALLOWED:
            return True, None
        return False, DESKTOP_ACCOUNT_MISMATCH_MESSAGE
    if getattr(params, "via_desktop_login", False) is not True:
        return False, "Desktop bridge login is not active"
    desktop_account_uid = _normalize_account_uid(getattr(params, "desktop_account_uid", None))
    active_account_uid = _active_account_uid(params)
    if not desktop_account_uid:
        return False, DESKTOP_ACCOUNT_BINDING_UNAVAILABLE_MESSAGE
    if not active_account_uid:
        return False, DESKTOP_ACCOUNT_BINDING_UNAVAILABLE_MESSAGE
    if desktop_account_uid != active_account_uid:
        return False, DESKTOP_ACCOUNT_MISMATCH_MESSAGE
    return True, None


def _action_value(kdbc, action):
    if action == _PAM_LAUNCH_ACTION:
        return _kdbc_value(kdbc, "PAM_ACTION_LAUNCH", _PAM_LAUNCH_ACTION)
    return _kdbc_value(kdbc, "PAM_ACTION_TUNNEL_START", _PAM_TUNNEL_START_ACTION)


def _duplicate_active_reason(kdbc=None):
    return _kdbc_value(kdbc, "PAM_APPROVAL_REASON_DUPLICATE_ACTIVE_SESSION", _DUPLICATE_ACTIVE_REASON)


def _make_start_tunnel_approval_request(
    kdbc,
    *,
    action=_PAM_TUNNEL_START_ACTION,
    resource_handle,
    resource_title=None,
    purpose=None,
    local_host=None,
    local_port=None,
):
    request_cls = _action_approval_request_class(kdbc)
    if request_cls is None:
        return None

    kwargs = {
        "contract_version": _ACTION_APPROVAL_CONTRACT_VERSION,
        "resource_title": resource_title,
        "display_name": resource_title,
        "purpose": purpose,
        "publisher_instance_id": _PUBLISHER_INSTANCE_ID,
        "caller": _make_control_caller(kdbc),
        "client_identity": _make_client_identity(kdbc),
        "local_endpoint": _make_local_endpoint(kdbc, local_host, local_port),
        "sent_at_unix_ms": int(time.time() * 1000),
    }
    kwargs.update(_vault_account_binding_kwargs(kdbc))
    return request_cls(
        request_id=str(uuid.uuid4()),
        action=_action_value(kdbc, action or _PAM_TUNNEL_START_ACTION),
        resource_handle=str(resource_handle),
        **{key: value for key, value in kwargs.items() if value is not None},
    )


def _decision_value(decision):
    if decision is None:
        return None
    value = getattr(decision, "decision", None)
    if value is None and isinstance(decision, dict):
        value = decision.get("decision")
    if value is None and isinstance(decision, str):
        value = decision
    if value is None and getattr(decision, "allowed", None) is True:
        value = "allow"
    return str(value).lower() if value is not None else None


def _decision_reason(decision):
    if decision is None:
        return None
    value = None
    for attr in ("reason", "denial_reason", "error_code", "code", "message"):
        value = getattr(decision, attr, None)
        if value is not None:
            break
    if value is None and isinstance(decision, dict):
        for key in ("reason", "denial_reason", "error_code", "code", "message"):
            value = decision.get(key)
            if value is not None:
                break
    if value is not None:
        normalized = str(value).lower()
        duplicate_reason = _duplicate_active_reason()
        if duplicate_reason in normalized:
            return duplicate_reason
        return normalized
    try:
        rendered = str(decision).lower()
    except Exception:
        rendered = ""
    duplicate_reason = _duplicate_active_reason()
    if duplicate_reason in rendered:
        return duplicate_reason
    return None


def is_duplicate_active_approval_message(message):
    return str(message or "").startswith(f"{_duplicate_active_reason()}:")


def approval_message_display_text(message):
    message = str(message or "")
    if is_duplicate_active_approval_message(message):
        return message.split(":", 1)[1].strip()
    return message


def _approval_exception_display_text(err):
    message = str(err or "")
    if "vault_account_binding is required" in message:
        return DESKTOP_ACCOUNT_BINDING_UNAVAILABLE_MESSAGE
    return f"Desktop approval request failed: {message}"


def _duplicate_active_approval_message(request):
    action = getattr(request, "action", "") or _PAM_TUNNEL_START_ACTION
    resource_handle = getattr(request, "resource_handle", "") or "this record"
    reason = _duplicate_active_reason(_kdbc())
    if action == _PAM_LAUNCH_ACTION:
        return (
            f"{reason}: A PAM launch session is already active "
            f"for record {resource_handle}. Close the active session before "
            "launching another one."
        )
    return (
        f"{reason}: A PAM tunnel is already active "
        f"for record {resource_handle}. Stop the active tunnel before "
        "starting another one."
    )


def _print_action_approval_request(kdbc, request, method_available):
    socket_path = _socket_override() or "<default>"
    timeout_ms = _action_approval_timeout_ms()
    runtime_path = _kdbc_runtime_path(kdbc)
    print(
        "Desktop bridge approval request: "
        f"request_id={getattr(request, 'request_id', '')} "
        f"action={getattr(request, 'action', '')} "
        f"resource_handle={getattr(request, 'resource_handle', '')} "
        f"socket={socket_path} timeout_ms={timeout_ms} "
        f"method_available={method_available} "
        f"kdbc_module={runtime_path}",
        flush=True,
    )
    logging.info(
        "Requesting Vault PAM action approval: request_id=%s action=%s resource_handle=%s "
        "publisher_instance_id=%s socket=%s timeout_ms=%s method_available=%s kdbc_module=%s",
        getattr(request, "request_id", ""),
        getattr(request, "action", ""),
        getattr(request, "resource_handle", ""),
        _PUBLISHER_INSTANCE_ID,
        socket_path,
        timeout_ms,
        method_available,
        runtime_path,
    )


def _print_action_approval_decision(request, decision):
    decision_value = _decision_value(decision)
    decision_reason = _decision_reason(decision)
    reason_text = f" reason={decision_reason}" if decision_reason else ""
    print(
        "Desktop bridge approval decision: "
        f"request_id={getattr(request, 'request_id', '')} "
        f"decision={decision_value or '<none>'}{reason_text}",
        flush=True,
    )
    logging.info(
        "Vault PAM action approval decision: request_id=%s decision=%s resource_handle=%s",
        getattr(request, "request_id", ""),
        decision_value or "",
        getattr(request, "resource_handle", ""),
    )
    if decision_value in {"allow", "allow_once"}:
        return True, decision_value
    if decision_value == "deny":
        if decision_reason == "duplicate_active_session":
            return False, _duplicate_active_approval_message(request)
        return False, "Desktop approval denied"
    return False, "Desktop approval did not allow the PAM tunnel start"


def _complete_action_approval(command, ok, message):
    response_queue = command.get("response_queue")
    if response_queue is None:
        return
    try:
        response_queue.put_nowait((ok, message))
    except queue.Full:
        pass


def _request_start_tunnel_approval_with_client(kdbc, request, params=None):
    client = kdbc.BridgeClient()
    method = _action_approval_method(client)
    if method is None or request is None:
        local_request_id = getattr(request, "request_id", None) or str(uuid.uuid4())
        print(
            "Desktop bridge approval request unavailable: "
            f"request_id={local_request_id} "
            f"action={getattr(request, 'action', _PAM_TUNNEL_START_ACTION)} "
            f"resource_handle={getattr(request, 'resource_handle', '')} "
            f"socket={_socket_override() or '<default>'} "
            f"timeout_ms={_action_approval_timeout_ms()} "
            f"method_available={method is not None} "
            f"request_type_available={request is not None} "
            f"kdbc_module={_kdbc_runtime_path(kdbc)}"
        )
        return False, "Desktop bridge pre-action approval API is unavailable"

    try:
        _print_action_approval_request(kdbc, request, True)
        decision = method(_make_action_approval_config(kdbc, params), request)
    except Exception as err:
        display_error = _approval_exception_display_text(err)
        print(
            "Desktop bridge approval request failed: "
            f"request_id={getattr(request, 'request_id', '')} "
            f"error={display_error}",
            flush=True,
        )
        return False, display_error
    return _print_action_approval_decision(request, decision)


def _request_start_tunnel_approval_with_session(session, kdbc, command):
    request = _make_start_tunnel_approval_request(
        kdbc,
        action=command.get("action") or _PAM_TUNNEL_START_ACTION,
        resource_handle=command.get("resource_handle"),
        resource_title=command.get("resource_title"),
        purpose=command.get("purpose"),
        local_host=command.get("local_host"),
        local_port=command.get("local_port"),
    )
    method = _session_action_approval_method(session)
    if method is None or request is None:
        local_request_id = getattr(request, "request_id", None) or str(uuid.uuid4())
        print(
            "Desktop bridge approval request unavailable: "
            f"request_id={local_request_id} "
            f"action={getattr(request, 'action', command.get('action') or _PAM_TUNNEL_START_ACTION)} "
            f"resource_handle={command.get('resource_handle') or ''} "
            f"socket={_socket_override() or '<default>'} "
            f"timeout_ms={_action_approval_timeout_ms()} "
            f"method_available={method is not None} "
            f"request_type_available={request is not None} "
            f"kdbc_module={_kdbc_runtime_path(kdbc)}"
        )
        return False, "Desktop bridge session pre-action approval API is unavailable"

    try:
        _print_action_approval_request(kdbc, request, True)
        decision = method(request)
    except Exception as err:
        display_error = _approval_exception_display_text(err)
        print(
            "Desktop bridge approval request failed: "
            f"request_id={getattr(request, 'request_id', '')} "
            f"error={display_error}",
            flush=True,
        )
        return False, display_error
    return _print_action_approval_decision(request, decision)


def request_start_tunnel_approval(
    *,
    params=None,
    action=_PAM_TUNNEL_START_ACTION,
    resource_handle,
    resource_title=None,
    purpose=None,
    local_host=None,
    local_port=None,
):
    if not resource_handle:
        return False, "Desktop approval request is missing a resource handle"
    if params is not None:
        allowed, message = desktop_bridge_account_gate(params)
        if not allowed:
            suspend_desktop_bridge_state(params, clear_binding=False)
            return False, message

    kdbc = _kdbc()
    if not kdbc:
        return False, "Desktop bridge client is unavailable for PAM start approval"

    if _is_state_sync_session_active():
        response_queue = queue.Queue(maxsize=1)
        _ACTION_APPROVAL_QUEUE.put(
            {
                "action": action or _PAM_TUNNEL_START_ACTION,
                "resource_handle": resource_handle,
                "resource_title": resource_title,
                "purpose": purpose,
                "local_host": local_host,
                "local_port": local_port,
                "response_queue": response_queue,
            }
        )
        while True:
            try:
                return response_queue.get(timeout=1)
            except queue.Empty:
                if not _is_state_sync_session_active():
                    return False, "Desktop state-sync session became unavailable before PAM start approval completed"

    try:
        request = _make_start_tunnel_approval_request(
            kdbc,
            action=action or _PAM_TUNNEL_START_ACTION,
            resource_handle=resource_handle,
            resource_title=resource_title,
            purpose=purpose,
            local_host=local_host,
            local_port=local_port,
        )
    except Exception as err:
        return False, _approval_exception_display_text(err)
    return _request_start_tunnel_approval_with_client(kdbc, request, params=params)


def _complete_owner_stop(command, ok, message):
    response_queue = command.get("response_queue")
    if response_queue is None:
        return
    try:
        response_queue.put_nowait((ok, message))
    except queue.Full:
        pass


def _request_metadata(request, name):
    value = getattr(request, name, None)
    if value is not None:
        return value
    kwargs = getattr(request, "kwargs", None)
    if isinstance(kwargs, dict):
        return kwargs.get(name)
    return None


def _request_owner_stop_with_session(session, kdbc, projection, reason):
    if not hasattr(session, "request_owner_stop") or not hasattr(kdbc, "RequestPamControlStopRequest"):
        return None

    try:
        request = _make_owner_stop_request(kdbc, projection, reason)
        logging.info(
            "Requesting Vault-owned PAM stop through coordinator: control_id=%s "
            "pam_session_id=%s tunnel_id=%s resource_handle=%s "
            "publisher_instance_id=%s vault_grant_id_present=%s reason=%s",
            getattr(request, "control_id", ""),
            getattr(request, "pam_session_id", ""),
            getattr(request, "tunnel_id", ""),
            getattr(request, "resource_handle", ""),
            _request_metadata(request, "publisher_instance_id"),
            bool(_request_metadata(request, "vault_grant_id")),
            getattr(request, "reason", ""),
        )
        result = session.request_owner_stop(request)
        if result is None:
            return False, (
                "Vault-owned stop request did not return an owner result "
                f"(control_id={getattr(request, 'control_id', '')})"
            )
        if _owner_stop_result_failed(result):
            message = _owner_stop_result_message(result) or "Vault-owned stop request failed"
            return False, f"Vault-owned stop request failed: {message}"
        if not _owner_stop_result_terminal(result):
            message = _owner_stop_result_message(result)
            details = f": {message}" if message else ""
            return False, (
                "Vault-owned stop request returned an unknown owner result"
                f"{details} (control_id={getattr(request, 'control_id', '')})"
            )
        _mark_external_projection_owner_stop_requested(
            projection,
            getattr(request, "control_id", ""),
            getattr(request, "reason", "") or reason or "user_stop",
        )
        return True, f"owner_stop_pending control_id={getattr(request, 'control_id', '')}"
    except Exception as err:
        return False, f"Vault-owned stop request failed: {err}"


def _drain_owner_stop_queue(session, kdbc):
    while True:
        try:
            command = _OWNER_STOP_QUEUE.get_nowait()
        except queue.Empty:
            return
        try:
            result = _request_owner_stop_with_session(
                session,
                kdbc,
                command.get("projection") or {},
                command.get("reason") or "user_stop",
            )
            if result is None:
                result = (False, "Desktop bridge PamCoordinator owner-stop API is unavailable")
            ok, message = result
        except Exception as err:
            ok, message = False, f"Vault-owned stop request failed: {err}"
        _complete_owner_stop(command, ok, message)


def _drain_action_approval_queue(session, kdbc):
    while True:
        try:
            command = _ACTION_APPROVAL_QUEUE.get_nowait()
        except queue.Empty:
            return
        try:
            ok, message = _request_start_tunnel_approval_with_session(session, kdbc, command)
            _complete_action_approval(command, ok, message)
        except Exception as err:
            _complete_action_approval(command, False, f"Desktop approval request failed: {err}")


def request_owner_stop(projection, reason="user_stop"):
    if not projection:
        return False, "No Vault-owned external projection matched the stop request"
    if projection.get("external_owner") != "vault_desktop":
        return False, "Projection is not owned by Vault/Desktop"

    kdbc = _kdbc()
    if not kdbc or not hasattr(kdbc, "RequestPamControlStopRequest"):
        return False, "Desktop bridge client does not support Vault-owned stop requests"
    if not _coordinator_supports_leaf_workflow(kdbc):
        return False, "Desktop bridge PamCoordinator owner-stop API is unavailable"

    if not _is_state_sync_session_active():
        return False, (
            "Desktop state-sync session is not active for Vault-owned stop; "
            "run with --via-desktop and refresh PAM tunnel list before retrying"
        )

    response_queue = queue.Queue(maxsize=1)
    _OWNER_STOP_QUEUE.put(
        {
            "projection": dict(projection),
            "reason": reason or "user_stop",
            "response_queue": response_queue,
        }
    )
    while True:
        try:
            return response_queue.get(timeout=1)
        except queue.Empty:
            if not _is_state_sync_session_active():
                return False, "Desktop state-sync session became unavailable before Vault-owned stop completed"


def build_event_request(
    *,
    event_type,
    state,
    pam_session_id,
    tunnel_id,
    resource_handle,
    local_host=None,
    local_port=None,
    error=None,
    vault_grant_id=None,
    publisher_id=None,
):
    kdbc = _kdbc()
    if not kdbc:
        return None

    now_ms = int(time.time() * 1000)
    extra_kwargs = {
        "sent_at_unix_ms": now_ms,
        "observed_at_unix_ms": now_ms,
        "vault_grant_id": vault_grant_id,
        "caller": _make_state_caller(kdbc),
        "local_endpoint": _make_local_endpoint(kdbc, local_host, local_port),
        "error": _make_safe_error(kdbc, error),
    }
    extra_kwargs.update(_vault_account_binding_kwargs(kdbc))
    return kdbc.PublishPamStateEventRequest(
        event_type,
        _next_sequence(),
        publisher_id or _PUBLISHER_INSTANCE_ID,
        str(pam_session_id),
        str(tunnel_id),
        str(resource_handle),
        _make_bridge_peer(kdbc),
        state,
        **extra_kwargs,
    )


def _publish_with_client(kdbc, event_kwargs):
    request = build_event_request(**event_kwargs)
    if request is None:
        return False
    kdbc.BridgeClient().publish_pam_state_event(_make_config(kdbc), request)
    return True


def _queue_or_publish(event_kwargs):
    if not _DESKTOP_BRIDGE_ACCOUNT_ALLOWED:
        return False
    kdbc = _kdbc()
    if not kdbc:
        return False

    _track_heartbeat_candidate(event_kwargs)
    if _ensure_worker_started(kdbc):
        _EVENT_QUEUE.put(event_kwargs)
        return True

    try:
        return _publish_with_client(kdbc, event_kwargs)
    except Exception as err:
        logging.debug(
            "Failed to publish PAM state event type=%s session=%s tunnel=%s: %s",
            event_kwargs.get("event_type"),
            event_kwargs.get("pam_session_id"),
            event_kwargs.get("tunnel_id"),
            err,
        )
        return False


def _ensure_worker_started(kdbc=None):
    global _WORKER_THREAD
    kdbc = kdbc or _kdbc()
    if not kdbc or not _supports_persistent_session(kdbc):
        return False

    with _WORKER_LOCK:
        if _WORKER_THREAD and _WORKER_THREAD.is_alive():
            return True
        _WORKER_STOP.clear()
        _WORKER_THREAD = threading.Thread(
            target=_state_sync_worker,
            name="KDBC-PAM-StateSync",
            daemon=True,
        )
        _WORKER_THREAD.start()
        return True


def _drain_publish_queue(session):
    while True:
        try:
            event_kwargs = _EVENT_QUEUE.get_nowait()
        except queue.Empty:
            return
        try:
            request = build_event_request(**event_kwargs)
            if request is not None:
                session.publish_pam_state_event(request)
        except Exception as err:
            logging.debug(
                "Failed to publish queued PAM state event type=%s session=%s tunnel=%s: %s",
                event_kwargs.get("event_type"),
                event_kwargs.get("pam_session_id"),
                event_kwargs.get("tunnel_id"),
                err,
            )


def _heartbeat_key(event_kwargs):
    return (
        event_kwargs.get("pam_session_id") or "",
        event_kwargs.get("tunnel_id") or "",
        event_kwargs.get("resource_handle") or "",
    )


def _track_heartbeat_candidate(event_kwargs):
    event_type = event_kwargs.get("event_type")
    state = event_kwargs.get("state")
    key = _heartbeat_key(event_kwargs)
    if not any(key):
        return

    with _HEARTBEAT_LOCK:
        if event_type == "pam_session_started" or (
            event_type == "pam_session_heartbeat" and state == "active"
        ):
            heartbeat_kwargs = dict(event_kwargs)
            heartbeat_kwargs["event_type"] = "pam_session_heartbeat"
            heartbeat_kwargs["state"] = "active"
            heartbeat_kwargs["error"] = None
            _ACTIVE_HEARTBEATS[key] = heartbeat_kwargs
            _LAST_HEARTBEAT_AT.setdefault(key, time.monotonic())
        elif state in {"stopping", "stopped", "error"} or event_type in {
            "pam_session_state_changed",
            "pam_session_error",
        }:
            _ACTIVE_HEARTBEATS.pop(key, None)
            _LAST_HEARTBEAT_AT.pop(key, None)


def _publish_periodic_heartbeats(session):
    now = time.monotonic()
    due = []
    with _HEARTBEAT_LOCK:
        for key, event_kwargs in list(_ACTIVE_HEARTBEATS.items()):
            last_sent = _LAST_HEARTBEAT_AT.get(key, 0)
            if now - last_sent >= _HEARTBEAT_INTERVAL_SECONDS:
                due.append((key, dict(event_kwargs)))
                _LAST_HEARTBEAT_AT[key] = now

    for key, event_kwargs in due:
        try:
            request = build_event_request(**event_kwargs)
            if request is not None:
                session.publish_pam_state_event(request)
        except Exception as err:
            logging.debug(
                "Failed to publish periodic PAM heartbeat session=%s tunnel=%s: %s",
                event_kwargs.get("pam_session_id"),
                event_kwargs.get("tunnel_id"),
                err,
            )
            with _HEARTBEAT_LOCK:
                _LAST_HEARTBEAT_AT.pop(key, None)


def _handle_logout_notice(notice):
    reason = _notice_value(notice, "reason", "vault_logout") or "vault_logout"
    pam_session_id = _notice_value(notice, "pam_session_id", "")
    tunnel_id = _notice_value(notice, "tunnel_id", "")
    resource_handle = _notice_value(notice, "resource_handle", "")
    removed_projections = _clear_external_projections_for_logout_notice(notice)
    try:
        from .tunnel_lifecycle import handle_desktop_logout_notice
        stopped, failed = handle_desktop_logout_notice(_WORKER_PARAMS, notice)
    except Exception as err:
        stopped, failed = 0, 1
        logging.debug("Desktop PAM logout callback cleanup failed: %s", err)

    logging.info(
        "Desktop PAM logout notice handled: reason=%s pam_session_id=%s tunnel_id=%s "
        "resource_handle=%s local_stopped=%s local_failed=%s projections_removed=%s",
        reason,
        pam_session_id,
        tunnel_id,
        resource_handle,
        stopped,
        failed,
        removed_projections,
    )


class _VaultTerminalNotice:
    reason = "vault_desktop_disconnected"
    pam_session_id = ""
    tunnel_id = ""
    resource_handle = ""


def _clear_terminal_via_desktop_session(reason):
    params = _WORKER_PARAMS
    if params is None or getattr(params, "via_desktop_login", False) is not True:
        return False
    clear_session = getattr(params, "clear_session", None)
    if not callable(clear_session):
        return False
    try:
        clear_session()
        setattr(params, "via_desktop_session_terminated", True)
        logging.warning("Vault Desktop disconnected; cleared Keeper via-desktop session: %s", reason)
        return True
    except Exception as err:
        logging.debug("Unable to clear Keeper via-desktop session after Desktop disconnect: %s", err)
    return False


def _handle_vault_terminal_disconnect(err):
    try:
        from .tunnel_lifecycle import handle_desktop_logout_notice
        stopped, failed = handle_desktop_logout_notice(_WORKER_PARAMS, _VaultTerminalNotice())
    except Exception as cleanup_err:
        stopped, failed = 0, 1
        logging.debug("Desktop PAM terminal disconnect cleanup failed: %s", cleanup_err)
    _clear_local_state_sync_buffers()
    session_cleared = _clear_terminal_via_desktop_session("vault_desktop_disconnected")

    logging.warning(
        "Vault Desktop disconnected; Desktop PAM state-sync is terminal: %s "
        "(local_stopped=%s local_failed=%s session_cleared=%s)",
        err,
        stopped,
        failed,
        session_cleared,
    )


def _register_logout_callback(session):
    try:
        session.set_logout_callback(_handle_logout_notice)
    except Exception as err:
        logging.debug("Unable to register KDBC PAM logout callback: %s", err)


def _handle_control(session, kdbc, control):
    handler = _CONTROL_HANDLER
    if handler is None:
        error = {
            "code": "commander_control_handler_missing",
            "kind": "internal_error",
            "message": "Commander PAM control handler is not registered",
        }
        session.fail_pam_control(_make_fail_request(kdbc, control, error))
        return

    try:
        result = handler(control)
        ok = result
        message = None
        if isinstance(result, tuple):
            ok = result[0]
            if len(result) > 1:
                message = result[1]
        if ok:
            session.ack_pam_control(_make_ack_request(kdbc, control))
        else:
            error = {
                "code": "commander_stop_failed",
                "kind": "internal_error",
                "message": message or "Commander could not stop the requested PAM session",
            }
            session.fail_pam_control(_make_fail_request(kdbc, control, error))
    except Exception as err:
        error = {
            "code": "commander_stop_exception",
            "kind": "internal_error",
            "message": str(err),
        }
        try:
            session.fail_pam_control(_make_fail_request(kdbc, control, error))
        except Exception as fail_err:
            logging.debug("Failed to send PAM control failure response: %s", fail_err)


def _unwrap_frame(frame):
    for attr in ("state_event", "control_stop_requested", "control"):
        value = getattr(frame, attr, None)
        if value is not None:
            return value
    return frame


def _is_state_event(frame):
    return bool(
        _message_value(frame, "event_type", None)
        and (
            _message_value(frame, "publisher_instance_id", None)
            or _message_value(frame, "pam_session_id", None)
            or _message_value(frame, "tunnel_id", None)
            or _message_value(frame, "resource_handle", None)
        )
    )


def _handle_frame(session, kdbc, frame):
    frame = _unwrap_frame(frame)
    if frame is None:
        return
    if _is_state_event(frame):
        projection = _upsert_external_projection(frame)
        if projection:
            logging.debug(
                "Projected Vault-owned PAM session state=%s session=%s tunnel=%s resource=%s",
                projection.get("state"),
                projection.get("pam_session_id"),
                projection.get("tunnel_id"),
                projection.get("resource_handle"),
            )
        return
    _handle_control(session, kdbc, frame)


def _state_sync_worker():
    global _STATE_SYNC_SESSION, _STATE_SYNC_SESSION_ACTIVE
    kdbc = _kdbc()
    if not kdbc:
        return
    coordinator_cls = _coordinator_class(kdbc)
    if coordinator_cls is None:
        logging.debug("KDBC PamCoordinator is unavailable; state-sync worker not started")
        return

    session = None
    while not _WORKER_STOP.is_set():
        try:
            if session is None:
                session = coordinator_cls(_make_config(kdbc))
                _register_logout_callback(session)
                session.start_state_sync()
            with _WORKER_LOCK:
                _STATE_SYNC_SESSION = session
                _STATE_SYNC_SESSION_ACTIVE = True
            try:
                from .tunnel_lifecycle import reconcile_local_tunnel_liveness
                pruned = reconcile_local_tunnel_liveness(_WORKER_PARAMS)
                if pruned:
                    logging.info("Pruned %d stale local PAM tunnel(s) after Desktop state-sync reconnect", pruned)
            except Exception as err:
                logging.debug("Unable to reconcile local PAM tunnel liveness after reconnect: %s", err)
            while not _WORKER_STOP.is_set():
                try:
                    _drain_publish_queue(session)
                    _drain_action_approval_queue(session, kdbc)
                    _drain_owner_stop_queue(session, kdbc)
                    _publish_periodic_heartbeats(session)
                    frame = session.receive_next_frame(timeout_ms=250)
                    _handle_frame(session, kdbc, frame)
                except Exception as err:
                    _handle_vault_terminal_disconnect(err)
                    _WORKER_STOP.set()
                    break
        except Exception as err:
            state = None
            try:
                state = session.state() if session is not None else None
            except Exception:
                state = None
            logging.warning(
                "Desktop PAM state-sync terminal%s: %s",
                f" (state={state})" if state else "",
                err,
            )
            _WORKER_STOP.set()
        finally:
            with _WORKER_LOCK:
                if _STATE_SYNC_SESSION is session:
                    _STATE_SYNC_SESSION = None
                    _STATE_SYNC_SESSION_ACTIVE = False
            if session is not None and _WORKER_STOP.is_set():
                try:
                    session.clear_logout_callback()
                except Exception:
                    pass
                session = None


def register_control_handler(handler):
    global _CONTROL_HANDLER
    _CONTROL_HANDLER = handler


def _register_default_control_handler():
    try:
        from .port_forward import tunnel_helpers
        tunnel_helpers.register_pam_stop_control_handler()
    except Exception as err:
        logging.debug("Unable to register default PAM stop control handler: %s", err)


def start_state_sync_worker(params=None):
    global _WORKER_PARAMS
    if params is not None:
        allowed, message = desktop_bridge_account_gate(params)
        if not allowed:
            logging.warning(message)
            suspend_desktop_bridge_state(params, clear_binding=False)
            return False
        _WORKER_PARAMS = params
    elif not _DESKTOP_BRIDGE_ACCOUNT_ALLOWED:
        return False
    _register_default_control_handler()
    return _ensure_worker_started()


def _is_worker_running():
    with _WORKER_LOCK:
        return bool(_WORKER_THREAD and _WORKER_THREAD.is_alive())


def _is_state_sync_session_active():
    with _WORKER_LOCK:
        return bool(
            _WORKER_THREAD
            and _WORKER_THREAD.is_alive()
            and _STATE_SYNC_SESSION is not None
        )


def stop_state_sync_worker(timeout_seconds=1):
    global _WORKER_THREAD, _WORKER_PARAMS
    _WORKER_STOP.set()
    with _WORKER_LOCK:
        worker_thread = _WORKER_THREAD
    if (
        worker_thread
        and worker_thread.is_alive()
        and worker_thread is not threading.current_thread()
    ):
        worker_thread.join(timeout_seconds)
    with _WORKER_LOCK:
        if _WORKER_THREAD is worker_thread and worker_thread and not worker_thread.is_alive():
            _WORKER_THREAD = None
            _WORKER_PARAMS = None


def publish_pam_state_event(
    *,
    event_type,
    state,
    pam_session_id,
    tunnel_id,
    resource_handle,
    local_host=None,
    local_port=None,
    error=None,
    vault_grant_id=None,
):
    return _queue_or_publish(
        {
            "event_type": event_type,
            "state": state,
            "pam_session_id": pam_session_id,
            "tunnel_id": tunnel_id,
            "resource_handle": resource_handle,
            "local_host": local_host,
            "local_port": local_port,
            "error": error,
            "vault_grant_id": vault_grant_id,
        }
    )


def publish_tunnel_session_event(session, event_type, state, error=None):
    if not session:
        return False
    return publish_pam_state_event(
        event_type=event_type,
        state=state,
        pam_session_id=getattr(session, "conversation_id", None) or getattr(session, "tube_id", ""),
        tunnel_id=getattr(session, "tube_id", None) or getattr(session, "conversation_id", ""),
        resource_handle=getattr(session, "record_uid", None) or getattr(session, "record_title", "") or "unknown",
        local_host=getattr(session, "host", None),
        local_port=getattr(session, "port", None),
        error=error,
    )


def publish_started(session):
    published = publish_tunnel_session_event(session, "pam_session_started", "active")
    publish_tunnel_session_event(session, "pam_session_heartbeat", "active")
    return published


def publish_stopped(session):
    return publish_tunnel_session_event(session, "pam_session_state_changed", "stopped")


def publish_stopping(session):
    return publish_tunnel_session_event(session, "pam_session_state_changed", "stopping")


def publish_error(session, error):
    return publish_tunnel_session_event(session, "pam_session_error", "error", error=error)
