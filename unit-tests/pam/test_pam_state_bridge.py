import importlib
import builtins
import time
import sys
import threading
import types
from unittest import TestCase, mock


class _FakeBridgeClientConfig:
    def __init__(
        self,
        server=None,
        region=None,
        socket_override=None,
        timeout_millis=None,
        verification_policy=None,
        vault_account_binding=None,
    ):
        self.server = server
        self.region = region
        self.socket_override = socket_override
        self.timeout_millis = timeout_millis
        self.verification_policy = verification_policy
        self.vault_account_binding = vault_account_binding


class _FakeVaultAccountBinding:
    def __init__(self, vault_account_uid, username=None, email=None):
        self.vault_account_uid = vault_account_uid
        self.username = username
        self.email = email


class _FakePamBridgePeer:
    def __init__(self, peer_id, pid=None, path=None, bundle_id=None, signed=None, signing_subject=None, binary_hash=None):
        self.peer_id = peer_id


class _FakePamLocalEndpoint:
    def __init__(self, host, port):
        self.host = host
        self.port = port


class _FakePamStateCaller:
    def __init__(
        self,
        session_id=None,
        mcp_session_id=None,
        tool_call_id=None,
        caller_instance_id=None,
        display_name=None,
    ):
        self.session_id = session_id
        self.mcp_session_id = mcp_session_id
        self.tool_call_id = tool_call_id
        self.caller_instance_id = caller_instance_id
        self.display_name = display_name


class _FakePamControlCaller:
    def __init__(
        self,
        session_id=None,
        mcp_session_id=None,
        tool_call_id=None,
        caller_instance_id=None,
        display_name=None,
    ):
        self.session_id = session_id
        self.mcp_session_id = mcp_session_id
        self.tool_call_id = tool_call_id
        self.caller_instance_id = caller_instance_id
        self.display_name = display_name


class _FakeClientIdentity:
    def __init__(self, name, version, kind, ka_client_version=None):
        self.name = name
        self.version = version
        self.kind = kind
        self.ka_client_version = ka_client_version


class _FakePamSafeError:
    def __init__(self, code, kind, message):
        self.code = code
        self.kind = kind
        self.message = message


class _FakePublishPamStateEventRequest:
    def __init__(
        self,
        event_type,
        sequence,
        publisher_instance_id,
        pam_session_id,
        tunnel_id,
        resource_handle,
        bridge_peer,
        state,
        **kwargs
    ):
        self.event_type = event_type
        self.sequence = sequence
        self.publisher_instance_id = publisher_instance_id
        self.pam_session_id = pam_session_id
        self.tunnel_id = tunnel_id
        self.resource_handle = resource_handle
        self.bridge_peer = bridge_peer
        self.state = state
        self.kwargs = kwargs


class _FakeAckPamControlRequest:
    def __init__(
        self,
        control_id,
        pam_session_id,
        tunnel_id,
        resource_handle,
        bridge_peer,
        result,
        **kwargs
    ):
        self.control_id = control_id
        self.pam_session_id = pam_session_id
        self.tunnel_id = tunnel_id
        self.resource_handle = resource_handle
        self.bridge_peer = bridge_peer
        self.result = result
        self.kwargs = kwargs


class _FakeFailPamControlRequest:
    def __init__(
        self,
        control_id,
        pam_session_id,
        tunnel_id,
        resource_handle,
        bridge_peer,
        error,
        **kwargs
    ):
        self.control_id = control_id
        self.pam_session_id = pam_session_id
        self.tunnel_id = tunnel_id
        self.resource_handle = resource_handle
        self.bridge_peer = bridge_peer
        self.error = error
        self.kwargs = kwargs


class _FakeRequestPamControlStopRequest:
    def __init__(
        self,
        control_id,
        pam_session_id,
        tunnel_id,
        resource_handle,
        reason,
        **kwargs
    ):
        self.control_id = control_id
        self.pam_session_id = pam_session_id
        self.tunnel_id = tunnel_id
        self.resource_handle = resource_handle
        self.reason = reason
        caller = kwargs.get("caller")
        if caller is not None and not isinstance(caller, _FakePamControlCaller):
            raise TypeError("caller must be PamControlCaller")
        self.kwargs = kwargs


class _FakePAMActionApprovalRequest:
    def __init__(self, request_id, action, resource_handle, **kwargs):
        self.request_id = request_id
        self.action = action
        self.resource_handle = resource_handle
        caller = kwargs.get("caller")
        if caller is not None and not isinstance(caller, _FakePamControlCaller):
            raise TypeError("caller must be PamControlCaller")
        self.kwargs = kwargs


class _FakePAMActionApprovalDecision:
    def __init__(self, decision, reason=None, message=None):
        self.decision = decision
        self.reason = reason
        self.message = message


class _FakeBridgeClient:
    module = None

    def publish_pam_state_event(self, config, request):
        self.module.calls.append((config, request))

    def request_pam_action_approval(self, config, request):
        self.module.approval_calls.append((config, request))
        if self.module.approval_error is not None:
            raise self.module.approval_error
        return self.module.approval_decision


class _FakeAliveThread:
    def is_alive(self):
        return True

    def join(self, timeout=None):
        return None


class _FakePamCoordinator:
    module = None

    def __init__(self, config):
        self.config = config
        self.started = False
        self.snapshot_waits = []
        sequence = getattr(self.module, "coordinator_frames", [])
        index = len(self.module.coordinators)
        self.frames = list(sequence[index] if index < len(sequence) else [])
        self.published = []
        self.acks = []
        self.fails = []
        self.approval_requests = []
        self.owner_stop_requests = []
        self.closed = False
        self.approval_decision = _FakePAMActionApprovalDecision("allow")
        self.approval_error = None
        self.owner_stop_result = getattr(self.module, "owner_stop_result", None)
        self.owner_stop_error = None
        self.owner_thread_id = None
        self.reauth_count = 0
        self.logout_callback = None
        self.clear_logout_callback_count = 0
        self.module.coordinators.append(self)

    def start_state_sync(self):
        self.started = True
        self.owner_thread_id = threading.get_ident()

    def state(self):
        return "authenticated"

    def reauth(self):
        self.reauth_count += 1
        errors = getattr(self.module, "reauth_errors", [])
        if errors:
            raise errors.pop(0)
        self.started = True
        self.owner_thread_id = threading.get_ident()

    def set_logout_callback(self, callback):
        self.logout_callback = callback

    def clear_logout_callback(self):
        self.clear_logout_callback_count += 1
        self.logout_callback = None

    def receive_next_frame(self, timeout_ms=5000):
        if self.frames:
            frame = self.frames.pop(0)
            if isinstance(frame, BaseException):
                raise frame
            return frame
        time.sleep(0.01)
        return None

    def publish_pam_state_event(self, request):
        self.published.append(request)

    def ack_pam_control(self, request):
        self.acks.append(request)

    def fail_pam_control(self, request):
        self.fails.append(request)

    def wait_initial_snapshot(self, timeout_ms=10000):
        self.snapshot_waits.append(timeout_ms)

    def known_projections(self):
        return []

    def request_owner_stop(self, request, timeout_ms=15000):
        self.owner_stop_requests.append((request, timeout_ms))
        if self.owner_stop_error is not None:
            raise self.owner_stop_error
        return self.owner_stop_result

    def request_pam_action_approval(self, request):
        if self.owner_thread_id is not None:
            current_thread_id = threading.get_ident()
            if current_thread_id != self.owner_thread_id:
                raise RuntimeError("request_pam_action_approval called from wrong thread")
        self.approval_requests.append(request)
        if self.approval_error is not None:
            raise self.approval_error
        return self.approval_decision

    def vault_account_binding(self):
        return getattr(self.module, "coordinator_account_binding", None)

    def close(self):
        self.closed = True


class PamStateBridgeTest(TestCase):
    def setUp(self):
        self.fake_kdbc = types.ModuleType("keeper_desktop_bridge_client")
        self.fake_kdbc.BridgeClientConfig = _FakeBridgeClientConfig
        self.fake_kdbc.VaultAccountBinding = _FakeVaultAccountBinding
        self.fake_kdbc.PamBridgePeer = _FakePamBridgePeer
        self.fake_kdbc.PamLocalEndpoint = _FakePamLocalEndpoint
        self.fake_kdbc.PamStateCaller = _FakePamStateCaller
        self.fake_kdbc.PamControlCaller = _FakePamControlCaller
        self.fake_kdbc.ClientIdentity = _FakeClientIdentity
        self.fake_kdbc.PamSafeError = _FakePamSafeError
        self.fake_kdbc.PublishPamStateEventRequest = _FakePublishPamStateEventRequest
        self.fake_kdbc.RequestPamControlStopRequest = _FakeRequestPamControlStopRequest
        self.fake_kdbc.PAMActionApprovalRequest = _FakePAMActionApprovalRequest
        self.fake_kdbc.PAM_ACTION_TUNNEL_START = "pam_tunnel_start"
        self.fake_kdbc.PAM_ACTION_LAUNCH = "pam_launch"
        self.fake_kdbc.PAM_APPROVAL_REASON_DUPLICATE_ACTIVE_SESSION = "duplicate_active_session"
        self.fake_kdbc.calls = []
        self.fake_kdbc.coordinators = []
        self.fake_kdbc.approval_calls = []
        self.fake_kdbc.approval_decision = _FakePAMActionApprovalDecision("allow")
        self.fake_kdbc.approval_error = None
        self.fake_kdbc.owner_stop_result = None
        self.fake_kdbc.coordinator_account_binding = None
        _FakeBridgeClient.module = self.fake_kdbc
        _FakePamCoordinator.module = self.fake_kdbc
        self.fake_kdbc.BridgeClient = _FakeBridgeClient
        sys.modules["keeper_desktop_bridge_client"] = self.fake_kdbc

        import keepercommander.commands.tunnel.pam_state_bridge as pam_state_bridge
        self.pam_state_bridge = importlib.reload(pam_state_bridge)

    def tearDown(self):
        self.pam_state_bridge.stop_state_sync_worker()
        self.pam_state_bridge.clear_external_projections()
        sys.modules.pop("keeper_desktop_bridge_client", None)
        importlib.reload(self.pam_state_bridge)

    def _start_worker_with_coordinator(self, owner_stop_result=None):
        self.fake_kdbc.AckPamControlRequest = _FakeAckPamControlRequest
        self.fake_kdbc.FailPamControlRequest = _FakeFailPamControlRequest
        self.fake_kdbc.PamCoordinator = _FakePamCoordinator
        self.fake_kdbc.owner_stop_result = owner_stop_result
        self.pam_state_bridge = importlib.reload(self.pam_state_bridge)
        self.pam_state_bridge.start_state_sync_worker()

        deadline = time.time() + 1.0
        while time.time() < deadline and len(self.fake_kdbc.coordinators) < 1:
            time.sleep(0.01)

        self.assertEqual(1, len(self.fake_kdbc.coordinators))
        self._wait_for_active_state_sync_session()
        return self.fake_kdbc.coordinators[0]

    def _wait_for_active_state_sync_session(self):
        deadline = time.time() + 1.0
        while time.time() < deadline and not self.pam_state_bridge._is_state_sync_session_active():
            time.sleep(0.01)
        self.assertTrue(self.pam_state_bridge._is_state_sync_session_active())

    def test_publish_uses_leaf_socket_env_and_core_fields(self):
        with mock.patch.dict(
            "os.environ",
            {
                "KEEPER_BRIDGE_LEAF_SOCKET": "/tmp/ai-402-bridge-leaf.sock",
                "KDBC_VERIFICATION_POLICY": "log_only",
            },
            clear=False,
        ):
            published = self.pam_state_bridge.publish_pam_state_event(
                event_type="pam_session_started",
                state="active",
                pam_session_id="conversation-1",
                tunnel_id="tube-1",
                resource_handle="record-1",
                local_host="127.0.0.1",
                local_port=3306,
            )

        self.assertTrue(published)
        self.assertEqual(1, len(self.fake_kdbc.calls))
        config, request = self.fake_kdbc.calls[0]
        self.assertEqual("/tmp/ai-402-bridge-leaf.sock", config.socket_override)
        self.assertEqual("log_only", config.verification_policy)
        self.assertEqual("pam_session_started", request.event_type)
        self.assertEqual("active", request.state)
        self.assertEqual("conversation-1", request.pam_session_id)
        self.assertEqual("tube-1", request.tunnel_id)
        self.assertEqual("record-1", request.resource_handle)
        self.assertNotIn("commander_context", request.kwargs)
        self.assertEqual("Commander", request.kwargs["caller"].display_name)
        self.assertTrue(request.kwargs["caller"].caller_instance_id.startswith("commander:"))
        self.assertEqual("127.0.0.1", request.kwargs["local_endpoint"].host)
        self.assertEqual(3306, request.kwargs["local_endpoint"].port)

    def test_publish_attaches_retained_vault_account_binding_to_event_body(self):
        from keepercommander import utils as keeper_utils
        from keepercommander.params import KeeperParams

        params = KeeperParams()
        params.via_desktop_login = True
        params.account_uid_bytes = b"\x05" * 16
        account_uid = keeper_utils.base64_url_encode(params.account_uid_bytes)
        ok, message = self.pam_state_bridge.set_desktop_account_binding(
            params,
            {
                "vault_account_uid": account_uid,
                "username": "Vault User",
                "email": "vault@example.com",
            },
        )
        self.assertTrue(ok, message)

        published = self.pam_state_bridge.publish_pam_state_event(
            event_type="pam_session_started",
            state="active",
            pam_session_id="conversation-1",
            tunnel_id="tube-1",
            resource_handle="record-1",
        )

        self.assertTrue(published)
        config, request = self.fake_kdbc.calls[0]
        self.assertEqual(account_uid, config.vault_account_binding.vault_account_uid)
        binding = request.kwargs["vault_account_binding"]
        self.assertEqual(account_uid, binding.vault_account_uid)
        self.assertEqual("Vault User", binding.username)
        self.assertEqual("vault@example.com", binding.email)

    def test_state_sync_session_publish_attaches_retained_vault_account_binding(self):
        from keepercommander import utils as keeper_utils
        from keepercommander.params import KeeperParams

        self.fake_kdbc.AckPamControlRequest = _FakeAckPamControlRequest
        self.fake_kdbc.FailPamControlRequest = _FakeFailPamControlRequest
        self.fake_kdbc.PamCoordinator = _FakePamCoordinator
        self.pam_state_bridge = importlib.reload(self.pam_state_bridge)

        params = KeeperParams()
        params.via_desktop_login = True
        params.account_uid_bytes = b"\x05" * 16
        account_uid = keeper_utils.base64_url_encode(params.account_uid_bytes)
        ok, message = self.pam_state_bridge.set_desktop_account_binding(
            params,
            {
                "vault_account_uid": account_uid,
                "username": "Vault User",
                "email": "vault@example.com",
            },
        )
        self.assertTrue(ok, message)
        self.assertTrue(self.pam_state_bridge.start_state_sync_worker(params))
        self._wait_for_active_state_sync_session()

        published = self.pam_state_bridge.publish_pam_state_event(
            event_type="pam_session_started",
            state="active",
            pam_session_id="conversation-1",
            tunnel_id="tube-1",
            resource_handle="record-1",
        )

        self.assertTrue(published)
        session = self.fake_kdbc.coordinators[0]
        deadline = time.time() + 1.0
        while time.time() < deadline and not session.published:
            time.sleep(0.01)
        self.assertEqual(account_uid, session.config.vault_account_binding.vault_account_uid)
        binding = session.published[0].kwargs["vault_account_binding"]
        self.assertEqual(account_uid, binding.vault_account_uid)
        self.assertEqual("Vault User", binding.username)
        self.assertEqual("vault@example.com", binding.email)

    def test_publish_returns_false_when_kdbc_unavailable(self):
        sys.modules.pop("keeper_desktop_bridge_client", None)
        real_import = builtins.__import__

        def unavailable_import(name, *args, **kwargs):
            if name == "keeper_desktop_bridge_client":
                raise ImportError("missing test module")
            return real_import(name, *args, **kwargs)

        with mock.patch("builtins.__import__", side_effect=unavailable_import):
            import keepercommander.commands.tunnel.pam_state_bridge as pam_state_bridge
            pam_state_bridge = importlib.reload(pam_state_bridge)
            published = pam_state_bridge.publish_pam_state_event(
                event_type="pam_session_started",
                state="active",
                pam_session_id="conversation-1",
                tunnel_id="tube-1",
                resource_handle="record-1",
            )

        self.assertFalse(published)

    def test_start_tunnel_approval_builds_safe_commander_request(self):
        approved, message = self.pam_state_bridge.request_start_tunnel_approval(
            resource_handle="record-1",
            resource_title="Database",
            purpose="demo",
            local_host="127.0.0.1",
            local_port=49152,
        )

        self.assertTrue(approved)
        self.assertEqual("allow", message)
        self.assertEqual(1, len(self.fake_kdbc.approval_calls))
        config, request = self.fake_kdbc.approval_calls[0]
        self.assertIsInstance(config, _FakeBridgeClientConfig)
        self.assertIsNone(config.timeout_millis)
        self.assertEqual("pam_tunnel_start", request.action)
        self.assertEqual("record-1", request.resource_handle)
        self.assertEqual(1, request.kwargs["contract_version"])
        self.assertEqual("Database", request.kwargs["resource_title"])
        self.assertEqual("Database", request.kwargs["display_name"])
        self.assertEqual("demo", request.kwargs["purpose"])
        self.assertTrue(request.kwargs["publisher_instance_id"].startswith("commander:"))
        self.assertEqual("Commander", request.kwargs["caller"].display_name)
        self.assertIsInstance(request.kwargs["caller"], _FakePamControlCaller)
        self.assertEqual("127.0.0.1", request.kwargs["local_endpoint"].host)
        self.assertEqual(49152, request.kwargs["local_endpoint"].port)
        identity = request.kwargs["client_identity"]
        self.assertEqual("Keeper Commander", identity.name)
        self.assertEqual("commander", identity.kind)
        self.assertTrue(identity.version)
        self.assertTrue(identity.ka_client_version.startswith("c"))
        self.assertNotIn("bridge_peer", request.kwargs)
        self.assertNotIn("router_tokens", request.kwargs)
        self.assertNotIn("trafficEncryptionSeed", request.kwargs)

    def test_desktop_account_binding_mirror_uses_vault_account_uid(self):
        from keepercommander import utils as keeper_utils
        from keepercommander.params import KeeperParams

        params = KeeperParams()
        params.via_desktop_login = True
        params.account_uid_bytes = b"\x01" * 16
        account_uid = keeper_utils.base64_url_encode(params.account_uid_bytes)

        ok, message = self.pam_state_bridge.set_desktop_account_binding(
            params,
            {
                "vault_account_uid": account_uid,
                "username": "Commander User",
                "email": "commander@example.com",
            },
        )

        self.assertTrue(ok)
        self.assertIsNone(message)
        self.assertEqual(account_uid, params.desktop_account_uid)
        self.assertEqual("commander@example.com", params.desktop_user)
        self.assertEqual("Commander User", params.desktop_account_username)

    def test_start_tunnel_approval_attaches_retained_vault_account_binding(self):
        from keepercommander import utils as keeper_utils
        from keepercommander.params import KeeperParams

        params = KeeperParams()
        params.via_desktop_login = True
        params.account_uid_bytes = b"\x01" * 16
        account_uid = keeper_utils.base64_url_encode(params.account_uid_bytes)
        ok, message = self.pam_state_bridge.set_desktop_account_binding(
            params,
            {
                "vault_account_uid": account_uid,
                "username": "Commander User",
                "email": "commander@example.com",
            },
        )
        self.assertTrue(ok)
        self.assertIsNone(message)

        approved, message = self.pam_state_bridge.request_start_tunnel_approval(
            params=params,
            resource_handle="record-1",
        )

        self.assertTrue(approved)
        self.assertEqual("allow", message)
        config, request = self.fake_kdbc.approval_calls[0]
        binding = config.vault_account_binding
        self.assertIsInstance(binding, _FakeVaultAccountBinding)
        self.assertEqual(account_uid, binding.vault_account_uid)
        self.assertEqual("Commander User", binding.username)
        self.assertEqual("commander@example.com", binding.email)
        binding = request.kwargs["vault_account_binding"]
        self.assertIsInstance(binding, _FakeVaultAccountBinding)
        self.assertEqual(account_uid, binding.vault_account_uid)
        self.assertEqual("Commander User", binding.username)
        self.assertEqual("commander@example.com", binding.email)

    def test_start_tunnel_approval_defaults_dev_via_desktop_to_log_only(self):
        from keepercommander import utils as keeper_utils
        from keepercommander.params import KeeperParams

        params = KeeperParams(server="dev.keepersecurity.com")
        params.via_desktop_login = True
        params.account_uid_bytes = b"\x01" * 16
        account_uid = keeper_utils.base64_url_encode(params.account_uid_bytes)
        ok, message = self.pam_state_bridge.set_desktop_account_binding(
            params,
            {"vault_account_uid": account_uid},
        )
        self.assertTrue(ok)
        self.assertIsNone(message)

        with mock.patch.dict("os.environ", {}, clear=True):
            approved, message = self.pam_state_bridge.request_start_tunnel_approval(
                params=params,
                resource_handle="record-1",
            )

        self.assertTrue(approved)
        self.assertEqual("allow", message)
        config, _ = self.fake_kdbc.approval_calls[0]
        self.assertEqual("log_only", config.verification_policy)

    def test_start_tunnel_approval_keeps_production_verification_policy_default(self):
        from keepercommander import utils as keeper_utils
        from keepercommander.params import KeeperParams

        params = KeeperParams(server="keepersecurity.com")
        params.via_desktop_login = True
        params.account_uid_bytes = b"\x01" * 16
        account_uid = keeper_utils.base64_url_encode(params.account_uid_bytes)
        ok, message = self.pam_state_bridge.set_desktop_account_binding(
            params,
            {"vault_account_uid": account_uid},
        )
        self.assertTrue(ok)
        self.assertIsNone(message)

        with mock.patch.dict("os.environ", {}, clear=True):
            approved, message = self.pam_state_bridge.request_start_tunnel_approval(
                params=params,
                resource_handle="record-1",
            )

        self.assertTrue(approved)
        self.assertEqual("allow", message)
        config, _ = self.fake_kdbc.approval_calls[0]
        self.assertIsNone(config.verification_policy)

    def test_desktop_account_binding_canonicalizes_base64_uid_strings(self):
        import base64
        from keepercommander import utils as keeper_utils
        from keepercommander.params import KeeperParams

        params = KeeperParams()
        params.via_desktop_login = True
        params.account_uid_bytes = b"\x01" * 16
        padded_uid = base64.urlsafe_b64encode(params.account_uid_bytes).decode("ascii")

        ok, message = self.pam_state_bridge.set_desktop_account_binding(
            params,
            {"vault_account_uid": padded_uid},
        )

        self.assertTrue(ok)
        self.assertIsNone(message)
        self.assertEqual(keeper_utils.base64_url_encode(params.account_uid_bytes), params.desktop_account_uid)

    def test_desktop_account_binding_mismatch_suspends_bridge_state(self):
        from keepercommander import utils as keeper_utils
        from keepercommander.params import KeeperParams

        params = KeeperParams()
        params.via_desktop_login = True
        params.account_uid_bytes = b"\x01" * 16

        ok, message = self.pam_state_bridge.set_desktop_account_binding(
            params,
            {"vault_account_uid": keeper_utils.base64_url_encode(b"\x02" * 16)},
        )

        self.assertFalse(ok)
        self.assertEqual(self.pam_state_bridge.DESKTOP_ACCOUNT_MISMATCH_MESSAGE, message)
        allowed, gate_message = self.pam_state_bridge.desktop_bridge_account_gate(params)
        self.assertFalse(allowed)
        self.assertEqual(self.pam_state_bridge.DESKTOP_ACCOUNT_MISMATCH_MESSAGE, gate_message)
        diagnostic = self.pam_state_bridge.desktop_account_binding_mismatch_diagnostic(params)
        self.assertIn(self.pam_state_bridge.DESKTOP_ACCOUNT_MISMATCH_MESSAGE, diagnostic)
        self.assertIn("desktop_uid=len=", diagnostic)
        self.assertIn("commander_uid=len=", diagnostic)

    def test_state_sync_worker_requires_matching_desktop_account_binding(self):
        from keepercommander import utils as keeper_utils
        from keepercommander.params import KeeperParams

        self.fake_kdbc.AckPamControlRequest = _FakeAckPamControlRequest
        self.fake_kdbc.FailPamControlRequest = _FakeFailPamControlRequest
        self.fake_kdbc.PamCoordinator = _FakePamCoordinator
        self.pam_state_bridge = importlib.reload(self.pam_state_bridge)
        params = KeeperParams()
        params.via_desktop_login = True
        params.account_uid_bytes = b"\x01" * 16
        params.desktop_account_uid = keeper_utils.base64_url_encode(b"\x02" * 16)

        started = self.pam_state_bridge.start_state_sync_worker(params)

        self.assertFalse(started)
        self.assertEqual([], self.fake_kdbc.coordinators)

    def test_start_tunnel_approval_requires_matching_desktop_account_binding(self):
        from keepercommander import utils as keeper_utils
        from keepercommander.params import KeeperParams

        params = KeeperParams()
        params.via_desktop_login = True
        params.account_uid_bytes = b"\x01" * 16
        params.desktop_account_uid = keeper_utils.base64_url_encode(b"\x02" * 16)

        approved, message = self.pam_state_bridge.request_start_tunnel_approval(
            params=params,
            resource_handle="record-1",
        )

        self.assertFalse(approved)
        self.assertEqual(self.pam_state_bridge.DESKTOP_ACCOUNT_MISMATCH_MESSAGE, message)
        self.assertEqual(0, len(self.fake_kdbc.approval_calls))

    def test_start_tunnel_approval_uses_timeout_env_override(self):
        with mock.patch.dict("os.environ", {"KDBC_PAM_ACTION_APPROVAL_TIMEOUT_MS": "7000"}):
            approved, message = self.pam_state_bridge.request_start_tunnel_approval(
                resource_handle="record-1",
            )

        self.assertTrue(approved)
        self.assertEqual("allow", message)
        config, _request = self.fake_kdbc.approval_calls[0]
        self.assertEqual(7000, config.timeout_millis)

    def test_start_tunnel_approval_uses_requested_action(self):
        approved, message = self.pam_state_bridge.request_start_tunnel_approval(
            action="pam_launch",
            resource_handle="record-1",
        )

        self.assertTrue(approved)
        self.assertEqual("allow", message)
        _config, request = self.fake_kdbc.approval_calls[0]
        self.assertEqual("pam_launch", request.action)
        self.assertEqual("record-1", request.resource_handle)

    def test_start_tunnel_approval_denies_fail_closed(self):
        self.fake_kdbc.approval_decision = _FakePAMActionApprovalDecision("deny")

        approved, message = self.pam_state_bridge.request_start_tunnel_approval(
            resource_handle="record-1"
        )

        self.assertFalse(approved)
        self.assertEqual("Desktop approval denied", message)
        self.assertEqual(1, len(self.fake_kdbc.approval_calls))

    def test_start_tunnel_approval_duplicate_tunnel_has_friendly_message(self):
        self.fake_kdbc.approval_decision = _FakePAMActionApprovalDecision(
            "deny",
            reason="duplicate_active_session",
        )

        approved, message = self.pam_state_bridge.request_start_tunnel_approval(
            resource_handle="record-1"
        )

        self.assertFalse(approved)
        self.assertTrue(self.pam_state_bridge.is_duplicate_active_approval_message(message))
        self.assertIn("PAM tunnel is already active", self.pam_state_bridge.approval_message_display_text(message))
        self.assertIn("record-1", message)

    def test_launch_approval_duplicate_session_has_friendly_message(self):
        self.fake_kdbc.approval_decision = _FakePAMActionApprovalDecision(
            "deny",
            reason="duplicate_active_session",
        )

        approved, message = self.pam_state_bridge.request_start_tunnel_approval(
            action="pam_launch",
            resource_handle="record-1",
        )

        self.assertFalse(approved)
        self.assertTrue(self.pam_state_bridge.is_duplicate_active_approval_message(message))
        self.assertIn("PAM launch session is already active", self.pam_state_bridge.approval_message_display_text(message))
        self.assertIn("record-1", message)

    def test_launch_approval_duplicate_session_detects_message_reason(self):
        self.fake_kdbc.approval_decision = _FakePAMActionApprovalDecision(
            "deny",
            message="duplicate_active_session",
        )

        approved, message = self.pam_state_bridge.request_start_tunnel_approval(
            action="pam_launch",
            resource_handle="record-1",
        )

        self.assertFalse(approved)
        self.assertTrue(self.pam_state_bridge.is_duplicate_active_approval_message(message))
        self.assertIn("PAM launch session is already active", self.pam_state_bridge.approval_message_display_text(message))

    def test_start_tunnel_approval_reports_missing_api(self):
        self.fake_kdbc.PAMActionApprovalRequest = None

        approved, message = self.pam_state_bridge.request_start_tunnel_approval(
            resource_handle="record-1"
        )

        self.assertFalse(approved)
        self.assertIn("pre-action approval API is unavailable", message)

    def test_start_tunnel_approval_timeout_fails_closed(self):
        self.fake_kdbc.approval_error = TimeoutError("approval timed out")

        approved, message = self.pam_state_bridge.request_start_tunnel_approval(
            resource_handle="record-1"
        )

        self.assertFalse(approved)
        self.assertIn("approval timed out", message)

    def test_start_tunnel_approval_hides_binding_validator_error(self):
        self.fake_kdbc.approval_error = Exception(
            'protocol_error: pam_state vault_account_binding is required'
        )

        approved, message = self.pam_state_bridge.request_start_tunnel_approval(
            resource_handle="record-1"
        )

        self.assertFalse(approved)
        self.assertEqual(
            self.pam_state_bridge.DESKTOP_ACCOUNT_BINDING_UNAVAILABLE_MESSAGE,
            message,
        )

    def test_start_tunnel_approval_uses_active_state_sync_session(self):
        self.fake_kdbc.AckPamControlRequest = _FakeAckPamControlRequest
        self.fake_kdbc.FailPamControlRequest = _FakeFailPamControlRequest
        self.fake_kdbc.PamCoordinator = _FakePamCoordinator
        self.pam_state_bridge = importlib.reload(self.pam_state_bridge)
        self.pam_state_bridge.start_state_sync_worker()

        deadline = time.time() + 1.0
        while time.time() < deadline and len(self.fake_kdbc.coordinators) < 1:
            time.sleep(0.01)

        self.assertEqual(1, len(self.fake_kdbc.coordinators))
        self._wait_for_active_state_sync_session()
        first_session = self.fake_kdbc.coordinators[0]

        approved, message = self.pam_state_bridge.request_start_tunnel_approval(
            resource_handle="record-1"
        )

        self.assertTrue(approved)
        self.assertEqual("allow", message)
        self.assertFalse(first_session.closed)
        self.assertEqual(1, len(self.fake_kdbc.coordinators))
        self.assertEqual(0, len(self.fake_kdbc.approval_calls))
        self.assertEqual(1, len(first_session.approval_requests))
        request = first_session.approval_requests[0]
        self.assertEqual("pam_tunnel_start", request.action)
        self.assertEqual("record-1", request.resource_handle)
        self.assertIsInstance(request.kwargs["caller"], _FakePamControlCaller)

    def test_active_state_sync_action_approval_attaches_retained_vault_account_binding(self):
        from keepercommander import utils as keeper_utils
        from keepercommander.params import KeeperParams

        self.fake_kdbc.AckPamControlRequest = _FakeAckPamControlRequest
        self.fake_kdbc.FailPamControlRequest = _FakeFailPamControlRequest
        self.fake_kdbc.PamCoordinator = _FakePamCoordinator
        self.pam_state_bridge = importlib.reload(self.pam_state_bridge)

        params = KeeperParams()
        params.via_desktop_login = True
        params.account_uid_bytes = b"\x05" * 16
        account_uid = keeper_utils.base64_url_encode(params.account_uid_bytes)
        ok, message = self.pam_state_bridge.set_desktop_account_binding(
            params,
            {
                "vault_account_uid": account_uid,
                "username": "Vault User",
                "email": "vault@example.com",
            },
        )
        self.assertTrue(ok, message)
        self.assertTrue(self.pam_state_bridge.start_state_sync_worker(params))
        self._wait_for_active_state_sync_session()
        first_session = self.fake_kdbc.coordinators[0]

        approved, message = self.pam_state_bridge.request_start_tunnel_approval(
            resource_handle="record-1"
        )

        self.assertTrue(approved)
        self.assertEqual("allow", message)
        self.assertEqual(1, len(first_session.approval_requests))
        binding = first_session.approval_requests[0].kwargs["vault_account_binding"]
        self.assertIsInstance(binding, _FakeVaultAccountBinding)
        self.assertEqual(account_uid, binding.vault_account_uid)
        self.assertEqual("Vault User", binding.username)
        self.assertEqual("vault@example.com", binding.email)

    def test_register_control_handler_does_not_start_worker(self):
        self.fake_kdbc.AckPamControlRequest = _FakeAckPamControlRequest
        self.fake_kdbc.FailPamControlRequest = _FakeFailPamControlRequest
        self.fake_kdbc.PamCoordinator = _FakePamCoordinator
        self.pam_state_bridge = importlib.reload(self.pam_state_bridge)

        self.pam_state_bridge.register_control_handler(lambda _control: True)
        time.sleep(0.05)

        self.assertEqual([], self.fake_kdbc.coordinators)

    def test_session_helper_maps_existing_tunnel_ids(self):
        session = types.SimpleNamespace(
            conversation_id="conversation-1",
            tube_id="tube-1",
            record_uid="record-1",
            record_title="Example",
            host="127.0.0.1",
            port=5432,
        )

        self.assertTrue(self.pam_state_bridge.publish_started(session))
        request = self.fake_kdbc.calls[0][1]
        self.assertEqual("conversation-1", request.pam_session_id)
        self.assertEqual("tube-1", request.tunnel_id)
        self.assertEqual("record-1", request.resource_handle)

    def test_receive_control_invokes_handler_and_acks_on_session(self):
        from keepercommander import utils as keeper_utils
        from keepercommander.params import KeeperParams

        bridge_peer = _FakePamBridgePeer("bridge")
        control = types.SimpleNamespace(
            control_id="control-1",
            pam_session_id="conversation-1",
            tunnel_id="tube-1",
            resource_handle="record-1",
            bridge_peer=bridge_peer,
            vault_grant_id=None,
            caller=None,
        )
        self.fake_kdbc.AckPamControlRequest = _FakeAckPamControlRequest
        self.fake_kdbc.FailPamControlRequest = _FakeFailPamControlRequest
        self.fake_kdbc.PamCoordinator = _FakePamCoordinator
        self.fake_kdbc.coordinator_frames = [[control]]
        self.pam_state_bridge = importlib.reload(self.pam_state_bridge)
        params = KeeperParams()
        params.via_desktop_login = True
        params.account_uid_bytes = b"\x05" * 16
        account_uid = keeper_utils.base64_url_encode(params.account_uid_bytes)
        ok, message = self.pam_state_bridge.set_desktop_account_binding(
            params,
            {
                "vault_account_uid": account_uid,
                "username": "Vault User",
                "email": "vault@example.com",
            },
        )
        self.assertTrue(ok, message)

        handled = []
        self.pam_state_bridge.register_control_handler(lambda received: handled.append(received) or True)
        self.pam_state_bridge.publish_pam_state_event(
            event_type="pam_session_started",
            state="active",
            pam_session_id="conversation-1",
            tunnel_id="tube-1",
            resource_handle="record-1",
        )

        deadline = time.time() + 1.0
        while time.time() < deadline and (
            not self.fake_kdbc.coordinators or not self.fake_kdbc.coordinators[0].acks
        ):
            time.sleep(0.01)

        state_sync_session = self.fake_kdbc.coordinators[0]
        self.assertEqual([control], handled)
        self.assertEqual(1, len(state_sync_session.acks))
        self.assertEqual("control-1", state_sync_session.acks[0].control_id)
        self.assertEqual("stopped", state_sync_session.acks[0].result)
        self.assertEqual("conversation-1", state_sync_session.acks[0].pam_session_id)
        binding = state_sync_session.acks[0].kwargs["vault_account_binding"]
        self.assertIsInstance(binding, _FakeVaultAccountBinding)
        self.assertEqual(account_uid, binding.vault_account_uid)
        self.assertEqual("Vault User", binding.username)
        self.assertEqual("vault@example.com", binding.email)

    def test_receive_state_frame_projects_vault_owned_session(self):
        state_event = types.SimpleNamespace(
            event_type="pam_session_started",
            sequence=3,
            publisher_instance_id="keeper-vault-desktop:pid:abc",
            pam_session_id="vault-conversation-1",
            tunnel_id="vault-tube-1",
            resource_handle="record-1",
            bridge_peer=_FakePamBridgePeer("vault"),
            state="active",
            local_endpoint=_FakePamLocalEndpoint("127.0.0.1", 49152),
            vault_grant_id="grant-1",
        )
        self.fake_kdbc.AckPamControlRequest = _FakeAckPamControlRequest
        self.fake_kdbc.FailPamControlRequest = _FakeFailPamControlRequest
        self.fake_kdbc.PamCoordinator = _FakePamCoordinator
        self.fake_kdbc.coordinator_frames = [[state_event]]
        self.pam_state_bridge = importlib.reload(self.pam_state_bridge)
        self.pam_state_bridge.register_control_handler(lambda _control: True)
        self.pam_state_bridge.start_state_sync_worker()

        deadline = time.time() + 1.0
        projection = None
        while time.time() < deadline and projection is None:
            projection = self.pam_state_bridge.find_external_projection_for_resource("record-1")
            time.sleep(0.01)

        self.assertIsNotNone(projection)
        self.assertEqual("vault_desktop", projection["external_owner"])
        self.assertEqual("keeper-vault-desktop:pid:abc", projection["publisher_instance_id"])
        self.assertEqual("vault-conversation-1", projection["pam_session_id"])
        self.assertEqual("vault-tube-1", projection["tunnel_id"])
        self.assertEqual("record-1", projection["resource_handle"])
        self.assertEqual("active", projection["state"])
        self.assertEqual({"host": "127.0.0.1", "port": 49152}, projection["local_endpoint"])

    def test_receive_heartbeat_snapshot_without_publisher_projects_vault_owned_session(self):
        state_event = {
            "event_type": "pam_session_heartbeat",
            "sequence": 3,
            "pam_session_id": "vault-pam-session:record-1:1",
            "tunnel_id": "vault-port-forward:record-1:1",
            "resource_handle": "record-1",
        }

        self.pam_state_bridge._handle_frame(None, self.fake_kdbc, state_event)

        projection = self.pam_state_bridge.find_external_projection_for_resource("record-1")
        self.assertIsNotNone(projection)
        self.assertEqual("vault_desktop", projection["external_owner"])
        self.assertEqual("vault_desktop", projection["publisher_instance_id"])
        self.assertEqual("vault-pam-session:record-1:1", projection["pam_session_id"])
        self.assertEqual("vault-port-forward:record-1:1", projection["tunnel_id"])
        self.assertEqual("record-1", projection["resource_handle"])
        self.assertEqual("pam_session_heartbeat", projection["event_type"])
        self.assertEqual("active", projection["state"])

    def test_state_sync_worker_treats_stream_error_as_terminal_logout(self):
        from keepercommander import utils as keeper_utils
        from keepercommander.params import KeeperParams

        self.fake_kdbc.AckPamControlRequest = _FakeAckPamControlRequest
        self.fake_kdbc.FailPamControlRequest = _FakeFailPamControlRequest
        self.fake_kdbc.PamCoordinator = _FakePamCoordinator
        self.fake_kdbc.coordinator_frames = [[RuntimeError("bad inbound snapshot")]]
        self.pam_state_bridge = importlib.reload(self.pam_state_bridge)
        params = KeeperParams()
        params.via_desktop_login = True
        params.user = "vault@example.com"
        params.session_token = "session-token"
        params.session_token_bytes = b"session-token"
        params.account_uid_bytes = b"\x03" * 16
        account_uid = keeper_utils.base64_url_encode(params.account_uid_bytes)
        ok, message = self.pam_state_bridge.set_desktop_account_binding(
            params,
            {
                "vault_account_uid": account_uid,
                "username": "Vault User",
                "email": "vault@example.com",
            },
        )
        self.assertTrue(ok, message)
        self.pam_state_bridge._ACTIVE_HEARTBEATS[("old-session", "old-tube", "record-1")] = {
            "event_type": "pam_session_heartbeat",
            "state": "active",
            "pam_session_id": "old-session",
            "tunnel_id": "old-tube",
            "resource_handle": "record-1",
        }
        self.pam_state_bridge._LAST_HEARTBEAT_AT[("old-session", "old-tube", "record-1")] = 0
        with mock.patch(
            "keepercommander.commands.tunnel.tunnel_lifecycle.handle_desktop_logout_notice",
            return_value=(2, 0),
        ) as handler:
            self.pam_state_bridge.start_state_sync_worker(params)
            deadline = time.time() + 2.0
            while time.time() < deadline and self.pam_state_bridge._is_worker_running():
                time.sleep(0.01)

        self.pam_state_bridge.stop_state_sync_worker()

        self.assertEqual(1, len(self.fake_kdbc.coordinators))
        self.assertEqual(0, self.fake_kdbc.coordinators[0].reauth_count)
        handler.assert_called_once()
        notice = handler.call_args.args[1]
        self.assertEqual("vault_desktop_disconnected", notice.reason)
        self.assertIsNone(params.session_token)
        self.assertIsNone(params.session_token_bytes)
        self.assertFalse(params.via_desktop_login)
        self.assertEqual("", params.user)
        self.assertFalse(self.pam_state_bridge._ACTIVE_HEARTBEATS)
        self.assertFalse(self.pam_state_bridge._LAST_HEARTBEAT_AT)
        self.assertIsNone(self.pam_state_bridge._STATE_SYNC_SESSION)
        self.assertFalse(self.pam_state_bridge._STATE_SYNC_SESSION_ACTIVE)

    def test_start_approval_does_not_queue_while_worker_is_reauthing(self):
        self.pam_state_bridge._WORKER_THREAD = _FakeAliveThread()
        self.pam_state_bridge._STATE_SYNC_SESSION = None
        self.pam_state_bridge._STATE_SYNC_SESSION_ACTIVE = False

        approved, message = self.pam_state_bridge.request_start_tunnel_approval(
            action="pam_tunnel_start",
            resource_handle="record-1",
            resource_title="Record 1",
        )

        self.assertTrue(approved)
        self.assertEqual("allow", message)
        self.assertEqual(1, len(self.fake_kdbc.approval_calls))
        self.assertTrue(self.pam_state_bridge._ACTION_APPROVAL_QUEUE.empty())

    def test_owner_stop_does_not_queue_while_worker_is_reauthing(self):
        self.fake_kdbc.AckPamControlRequest = _FakeAckPamControlRequest
        self.fake_kdbc.FailPamControlRequest = _FakeFailPamControlRequest
        self.fake_kdbc.PamCoordinator = _FakePamCoordinator
        self.pam_state_bridge = importlib.reload(self.pam_state_bridge)
        self.pam_state_bridge._WORKER_THREAD = _FakeAliveThread()
        self.pam_state_bridge._STATE_SYNC_SESSION = None
        self.pam_state_bridge._STATE_SYNC_SESSION_ACTIVE = False
        projection = {
            "external_owner": "vault_desktop",
            "publisher_instance_id": "keeper-vault-desktop:pid:abc",
            "pam_session_id": "vault-conversation-1",
            "tunnel_id": "vault-tube-1",
            "resource_handle": "record-1",
            "vault_grant_id": "grant-1",
        }

        requested, message = self.pam_state_bridge.request_owner_stop(projection, reason="user_stop")

        self.assertFalse(requested)
        self.assertIn("state-sync session is not active", message)
        self.assertTrue(self.pam_state_bridge._OWNER_STOP_QUEUE.empty())

    def test_logout_callback_clears_projection_and_local_state(self):
        projection = {
            "external_owner": "vault_desktop",
            "publisher_instance_id": "keeper-vault-desktop:pid:abc",
            "pam_session_id": "vault-conversation-1",
            "tunnel_id": "vault-tube-1",
            "resource_handle": "record-1",
            "state": "active",
            "last_seen": time.time(),
        }
        self.pam_state_bridge._EXTERNAL_PROJECTIONS[(
            projection["publisher_instance_id"],
            projection["pam_session_id"],
            projection["tunnel_id"],
        )] = projection
        notice = types.SimpleNamespace(
            reason="vault_logout",
            pam_session_id="vault-conversation-1",
            tunnel_id="vault-tube-1",
            resource_handle="record-1",
        )

        with mock.patch(
            "keepercommander.commands.tunnel.tunnel_lifecycle.handle_desktop_logout_notice",
            return_value=(1, 0),
        ) as handler:
            self.pam_state_bridge._handle_logout_notice(notice)

        handler.assert_called_once()
        self.assertIsNone(self.pam_state_bridge.find_external_projection("record-1"))

    def test_receive_state_frame_projects_ssh_agent_fields_in_memory(self):
        state_event = types.SimpleNamespace(
            event_type="pam_session_started",
            sequence=3,
            publisher_instance_id="keeper-vault-desktop:pid:abc",
            pam_session_id="vault-conversation-1",
            tunnel_id="vault-tube-1",
            resource_handle="record-1",
            bridge_peer=_FakePamBridgePeer("vault"),
            state="active",
            authn_hint="desktop_ssh_agent",
            ssh_agent_available=True,
            ssh_agent_endpoint="/tmp/keeper-agent.sock",
            ssh_agent_endpoint_kind="unix_socket",
            ssh_agent_scope="desktop_session",
        )

        projection = self.pam_state_bridge._upsert_external_projection(state_event)

        self.assertIsNotNone(projection)
        self.assertEqual("desktop_ssh_agent", projection["authn_hint"])
        self.assertTrue(projection["ssh_agent_available"])
        self.assertEqual("/tmp/keeper-agent.sock", projection["ssh_agent_endpoint"])
        self.assertEqual("unix_socket", projection["ssh_agent_endpoint_kind"])
        self.assertEqual("desktop_session", projection["ssh_agent_scope"])

    def test_terminal_state_removes_external_projection(self):
        active = types.SimpleNamespace(
            event_type="pam_session_started",
            sequence=1,
            publisher_instance_id="keeper-vault-desktop:pid:abc",
            pam_session_id="vault-conversation-1",
            tunnel_id="vault-tube-1",
            resource_handle="record-1",
            bridge_peer=_FakePamBridgePeer("vault"),
            state="active",
        )
        stopped = types.SimpleNamespace(
            event_type="pam_session_state_changed",
            sequence=2,
            publisher_instance_id="keeper-vault-desktop:pid:abc",
            pam_session_id="vault-conversation-1",
            tunnel_id="vault-tube-1",
            resource_handle="record-1",
            bridge_peer=_FakePamBridgePeer("vault"),
            state="stopped",
        )

        self.pam_state_bridge._upsert_external_projection(active)
        self.assertIsNotNone(self.pam_state_bridge.find_external_projection_for_resource("record-1"))
        self.pam_state_bridge._upsert_external_projection(stopped)
        self.assertIsNone(self.pam_state_bridge.find_external_projection_for_resource("record-1"))

    def test_external_projection_lookup_prefers_newest_matching_route(self):
        older = types.SimpleNamespace(
            event_type="pam_session_started",
            sequence=1,
            publisher_instance_id="keeper-vault-desktop:pid:abc",
            pam_session_id="vault-conversation-old",
            tunnel_id="vault-tube-old",
            resource_handle="record-1",
            bridge_peer=_FakePamBridgePeer("vault"),
            state="active",
        )
        newer = types.SimpleNamespace(
            event_type="pam_session_started",
            sequence=3,
            publisher_instance_id="keeper-vault-desktop:pid:abc",
            pam_session_id="vault-conversation-new",
            tunnel_id="vault-tube-new",
            resource_handle="record-1",
            bridge_peer=_FakePamBridgePeer("vault"),
            state="active",
        )

        self.pam_state_bridge._upsert_external_projection(older)
        time.sleep(0.01)
        self.pam_state_bridge._upsert_external_projection(newer)

        by_resource = self.pam_state_bridge.find_external_projection_for_resource("record-1")
        by_stop_identifier = self.pam_state_bridge.find_external_projection("record-1")

        self.assertEqual("vault-conversation-new", by_resource["pam_session_id"])
        self.assertEqual("vault-tube-new", by_stop_identifier["tunnel_id"])

    def test_request_owner_stop_requires_pam_coordinator(self):
        self.fake_kdbc.AckPamControlRequest = _FakeAckPamControlRequest
        self.fake_kdbc.FailPamControlRequest = _FakeFailPamControlRequest
        self.pam_state_bridge = importlib.reload(self.pam_state_bridge)
        self.pam_state_bridge.start_state_sync_worker()

        projection = {
            "external_owner": "vault_desktop",
            "publisher_instance_id": "keeper-vault-desktop:pid:abc",
            "pam_session_id": "vault-conversation-1",
            "tunnel_id": "vault-tube-1",
            "resource_handle": "record-1",
            "vault_grant_id": "grant-1",
        }
        self.pam_state_bridge._upsert_external_projection(_FakePublishPamStateEventRequest(
            "pam_session_state_changed",
            1,
            "keeper-vault-desktop:pid:abc",
            "vault-conversation-1",
            "vault-tube-1",
            "record-1",
            None,
            "active",
            vault_grant_id="grant-1",
        ))
        requested, message = self.pam_state_bridge.request_owner_stop(projection, reason="user_stop")

        self.assertFalse(requested)
        self.assertIn("PamCoordinator owner-stop API is unavailable", message)
        self.assertIsNone(self.pam_state_bridge._STATE_SYNC_SESSION)

    def test_request_owner_stop_prefers_pam_coordinator(self):
        from keepercommander import utils as keeper_utils
        from keepercommander.params import KeeperParams

        coordinator = self._start_worker_with_coordinator("stopped")
        projection = {
            "external_owner": "vault_desktop",
            "publisher_instance_id": "keeper-vault-desktop:pid:abc",
            "pam_session_id": "vault-conversation-1",
            "tunnel_id": "vault-tube-1",
            "resource_handle": "record-1",
            "vault_grant_id": "grant-1",
        }
        self.pam_state_bridge._upsert_external_projection(_FakePublishPamStateEventRequest(
            "pam_session_state_changed",
            1,
            "keeper-vault-desktop:pid:abc",
            "vault-conversation-1",
            "vault-tube-1",
            "record-1",
            None,
            "active",
            vault_grant_id="grant-1",
        ))
        params = KeeperParams()
        params.via_desktop_login = True
        params.account_uid_bytes = b"\x05" * 16
        account_uid = keeper_utils.base64_url_encode(params.account_uid_bytes)
        ok, message = self.pam_state_bridge.set_desktop_account_binding(
            params,
            {
                "vault_account_uid": account_uid,
                "username": "Vault User",
                "email": "vault@example.com",
            },
        )
        self.assertTrue(ok, message)

        requested, message = self.pam_state_bridge.request_owner_stop(projection, reason="user_stop")

        self.assertTrue(requested)
        self.assertIn("owner_stop_pending control_id=", message)
        self.assertEqual(1, len(self.fake_kdbc.coordinators))
        self.assertTrue(coordinator.started)
        self.assertEqual([], coordinator.snapshot_waits)
        self.assertFalse(coordinator.closed)
        self.assertEqual(1, len(coordinator.owner_stop_requests))
        request, timeout_ms = coordinator.owner_stop_requests[0]
        self.assertEqual(15000, timeout_ms)
        self.assertEqual("vault-conversation-1", request.pam_session_id)
        self.assertEqual("vault-tube-1", request.tunnel_id)
        self.assertEqual("record-1", request.resource_handle)
        self.assertEqual("user_stop", request.reason)
        self.assertEqual("grant-1", request.kwargs["vault_grant_id"])
        binding = request.kwargs["vault_account_binding"]
        self.assertIsInstance(binding, _FakeVaultAccountBinding)
        self.assertEqual(account_uid, binding.vault_account_uid)
        self.assertEqual("Vault User", binding.username)
        self.assertEqual("vault@example.com", binding.email)
        pending_projection = self.pam_state_bridge.find_external_projection("record-1")
        self.assertIsNotNone(pending_projection)
        self.assertEqual("stopping", pending_projection["state"])
        self.assertTrue(pending_projection["owner_stop_pending"])
        self.assertEqual(request.control_id, pending_projection["owner_stop_control_id"])

    def test_request_owner_stop_reports_no_terminal_result(self):
        coordinator = self._start_worker_with_coordinator(None)
        projection = {
            "external_owner": "vault_desktop",
            "publisher_instance_id": "keeper-vault-desktop:pid:abc",
            "pam_session_id": "vault-conversation-1",
            "tunnel_id": "vault-tube-1",
            "resource_handle": "record-1",
        }
        self.pam_state_bridge._upsert_external_projection(_FakePublishPamStateEventRequest(
            "pam_session_state_changed",
            1,
            "keeper-vault-desktop:pid:abc",
            "vault-conversation-1",
            "vault-tube-1",
            "record-1",
            None,
            "active",
        ))

        requested, message = self.pam_state_bridge.request_owner_stop(projection, reason="user_stop")

        self.assertFalse(requested)
        self.assertIn("did not return an owner result", message)
        self.assertEqual(1, len(self.fake_kdbc.coordinators))
        self.assertEqual(1, len(coordinator.owner_stop_requests))
        pending_projection = self.pam_state_bridge.find_external_projection("record-1")
        self.assertIsNotNone(pending_projection)
        self.assertEqual("active", pending_projection["state"])
        self.assertNotIn("owner_stop_pending", pending_projection)

    def test_request_owner_stop_reports_typed_transport_failure(self):
        self._start_worker_with_coordinator("failed:transport_error")
        projection = {
            "external_owner": "vault_desktop",
            "publisher_instance_id": "keeper-vault-desktop:pid:abc",
            "pam_session_id": "vault-conversation-1",
            "tunnel_id": "vault-tube-1",
            "resource_handle": "record-1",
        }

        requested, message = self.pam_state_bridge.request_owner_stop(projection, reason="user_stop")

        self.assertFalse(requested)
        self.assertIn("transport_error", message)
        self.assertEqual(1, len(self.fake_kdbc.coordinators[0].owner_stop_requests))

    def test_request_owner_stop_reports_timeout(self):
        self._start_worker_with_coordinator("timeout")
        projection = {
            "external_owner": "vault_desktop",
            "publisher_instance_id": "keeper-vault-desktop:pid:abc",
            "pam_session_id": "vault-conversation-1",
            "tunnel_id": "vault-tube-1",
            "resource_handle": "record-1",
        }

        requested, message = self.pam_state_bridge.request_owner_stop(projection, reason="user_stop")

        self.assertFalse(requested)
        self.assertIn("Timed out", message)
        self.assertEqual(1, len(self.fake_kdbc.coordinators[0].owner_stop_requests))

    def test_request_owner_stop_reports_unavailable_without_session(self):
        projection = {
            "external_owner": "vault_desktop",
            "pam_session_id": "vault-conversation-1",
            "tunnel_id": "vault-tube-1",
            "resource_handle": "record-1",
        }

        requested, message = self.pam_state_bridge.request_owner_stop(projection)

        self.assertFalse(requested)
        self.assertIn("PamCoordinator owner-stop API is unavailable", message)
