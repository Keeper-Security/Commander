import unittest
import threading
import time
import types
from unittest import mock

from keepercommander.error import CommandError

import datetime
import socket
import string
from cryptography import x509
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec

from keepercommander.commands.tunnel.port_forward.tunnel_helpers import (
    CloseConnectionReasons,
    TunnelSignalHandler,
    _handle_pam_stop_control,
    find_open_port,
    generate_random_bytes,
    register_tunnel_session,
    unregister_tunnel_session,
)
import keepercommander.commands.tunnel_and_connections as tunnel_and_connections
from keepercommander.commands.tunnel_and_connections import PAMTunnelListCommand, PAMTunnelStartCommand, PAMTunnelStopCommand

def generate_self_signed_cert(private_key):
    # Generate a self-signed certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(
            # Our certificate will be valid for 10 days
            datetime.datetime.utcnow() + datetime.timedelta(days=10)
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')

    return cert_pem


def new_private_key():
    # Generate an EC private key
    private_key = ec.generate_private_key(
        ec.SECP256R1(),  # Using P-256 curve
        backend=default_backend()
    )
    # Serialize to PEM format
    private_key_str = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    return private_key, private_key_str


class TestFindOpenPort(unittest.TestCase):
    def mock_bind(self, address):
        # Mock the behavior of socket.socket.bind
        port = address[1]
        if port in self.in_use_ports:
            raise OSError("Address already in use")
        else:
            print(f"Port {port} bound successfully.")

    def test_preferred_port(self):
        # Test that the function returns the preferred port if it's available
        preferred_port = 50000
        open_port = find_open_port([], preferred_port=preferred_port)
        self.assertEqual(open_port, preferred_port)

    def test_preferred_port_unavailable(self):
        # Mock the bind method to simulate that port 80 is in use
        with mock.patch('socket.socket.bind', side_effect=OSError("Address already in use")):
            preferred_port = 80
            with self.assertRaises(CommandError):
                open_port = find_open_port([], preferred_port=preferred_port)

    def test_range(self):
        # Test that the function returns a port within the specified range
        start_port = 50000
        end_port = 50010
        open_port = find_open_port([], start_port=start_port, end_port=end_port)
        self.assertTrue(start_port <= open_port <= end_port)

    def test_no_available_ports(self):
        # Setup
        self.in_use_ports = set(range(50000, 50011))  # All these ports are in use

        # Patch
        with mock.patch.object(socket.socket, 'bind', side_effect=self.mock_bind):
            # Test
            open_port = find_open_port([], start_port=50000, end_port=50010)
            self.assertIsNone(open_port)

    def test_invalid_range(self):
        # Test that the function returns None if the range is invalid
        open_port = find_open_port([], start_port=50010, end_port=50000)
        self.assertIsNone(open_port)

    def test_socket_exception(self):
        # Test that the function handles exceptions other than OSError gracefully
        with mock.patch('socket.socket.bind', side_effect=Exception("Test exception")):
            open_port = find_open_port([], start_port=49152, end_port=49153, host='localhost')
            self.assertIsNone(open_port)

    def test_tried_ports(self):
        # Setup
        self.in_use_ports = {50000, 50001}  # These ports are in use

        # Patch
        with mock.patch.object(socket.socket, 'bind', side_effect=self.mock_bind):
            # Test
            open_port = find_open_port([50000, 50001], start_port=50000, end_port=50002)
            self.assertEqual(open_port, 50002)


class TestGenerateRandomBytes(unittest.TestCase):

    def test_default_length(self):
        # Test that the default length of the returned bytes is 32
        random_bytes = generate_random_bytes()
        self.assertEqual(len(random_bytes), 32, f'Length 32 failed found {len(random_bytes)} in '
                                                f'{random_bytes}')

    def test_custom_length(self):
        # Test custom lengths
        for length in [1, 10, 20, 50, 100]:
            random_bytes = generate_random_bytes(length)
            self.assertEqual(len(random_bytes), length, f'Length {length} failed found {len(random_bytes)} in '
                                                        f'{random_bytes}')

    def test_content(self):
        # Test that the returned bytes only contain printable characters
        for length in [1, 10, 20, 50, 100]:
            random_bytes = generate_random_bytes(length)
            self.assertTrue(all(byte in string.printable.encode('utf-8') for byte in random_bytes))

    def test_zero_length(self):
        # Test that a zero length returns an empty bytes object
        random_bytes = generate_random_bytes(0)
        self.assertEqual(random_bytes, b'')

    def test_negative_length(self):
        # Test that a negative length raises a ValueError
        with self.assertRaises(ValueError):
            generate_random_bytes(-1)

    def test_type(self):
        # Test that the return type is bytes
        random_bytes = generate_random_bytes()
        self.assertIsInstance(random_bytes, bytes)

    def test_uniqueness(self):
        # Test that multiple calls return different values
        random_bytes1 = generate_random_bytes()
        random_bytes2 = generate_random_bytes()
        self.assertNotEqual(random_bytes1, random_bytes2)


class TestPamStopControl(unittest.TestCase):
    def tearDown(self):
        unregister_tunnel_session("tube-foreground")

    def test_stop_control_closes_tunnel_and_wakes_foreground(self):
        test_case = self

        class FakeRegistry:
            def __init__(self, signal_handler):
                self.closed = []
                self.signal_handler = signal_handler

            def close_tube(self, tube_id, reason=None):
                test_case.assertFalse(
                    getattr(self.signal_handler, "tube_close_initiated", False),
                    "remote stop must issue close_tube before marking the close as already initiated",
                )
                self.closed.append((tube_id, reason))

        signal_handler = types.SimpleNamespace(tube_close_initiated=False)
        registry = FakeRegistry(signal_handler)
        signal_handler.tube_registry = registry
        foreground_shutdown = threading.Event()
        external_shutdown = threading.Event()
        session = types.SimpleNamespace(
            tube_id="tube-foreground",
            conversation_id="conversation-foreground",
            record_uid="record-foreground",
            record_title="Foreground",
            signal_handler=signal_handler,
            foreground_shutdown_event=foreground_shutdown,
            external_shutdown_event=external_shutdown,
        )
        control = types.SimpleNamespace(
            tunnel_id="tube-foreground",
            pam_session_id="conversation-foreground",
            resource_handle="record-foreground",
        )

        register_tunnel_session("tube-foreground", session)
        with mock.patch(
            "keepercommander.commands.tunnel.port_forward.tunnel_helpers.pam_state_bridge"
        ) as pam_state_bridge:
            stopped, message = _handle_pam_stop_control(control)

        self.assertTrue(stopped)
        self.assertEqual("fallback_close_executed", message)
        self.assertEqual([("tube-foreground", CloseConnectionReasons.Normal)], registry.closed)
        self.assertTrue(getattr(session, "shutdown_initiated", False))
        self.assertTrue(getattr(session.signal_handler, "shutdown_initiated", False))
        self.assertTrue(getattr(session.signal_handler, "tube_close_initiated", False))
        pam_state_bridge.publish_stopping.assert_called_once_with(session)
        pam_state_bridge.publish_stopped.assert_called_once_with(session)
        self.assertTrue(foreground_shutdown.is_set())
        self.assertTrue(external_shutdown.is_set())

    def test_stop_control_matches_by_resource_handle(self):
        class FakeRegistry:
            def __init__(self):
                self.closed = []

            def close_tube(self, tube_id, reason=None):
                self.closed.append((tube_id, reason))

        registry = FakeRegistry()
        session = types.SimpleNamespace(
            tube_id="tube-by-resource",
            conversation_id="conversation-by-resource",
            record_uid="record-by-resource",
            record_title="By Resource",
            signal_handler=types.SimpleNamespace(tube_registry=registry, tube_close_initiated=False),
        )
        control = types.SimpleNamespace(
            tunnel_id="vault-tunnel-id-not-local-tube",
            pam_session_id="vault-session-id-not-local-conversation",
            resource_handle="record-by-resource",
        )

        register_tunnel_session("tube-by-resource", session)
        try:
            with mock.patch(
                "keepercommander.commands.tunnel.port_forward.tunnel_helpers.pam_state_bridge"
            ):
                stopped, message = _handle_pam_stop_control(control)
        finally:
            unregister_tunnel_session("tube-by-resource")

        self.assertTrue(stopped)
        self.assertEqual("fallback_close_executed", message)
        self.assertEqual([("tube-by-resource", CloseConnectionReasons.Normal)], registry.closed)

    def test_stop_control_missing_session_is_already_stopped(self):
        control = types.SimpleNamespace(
            tunnel_id="tube-gone",
            pam_session_id="conversation-gone",
            resource_handle="record-gone",
        )

        with mock.patch(
            "keepercommander.commands.tunnel.port_forward.tunnel_helpers.pam_state_bridge"
        ) as pam_state_bridge, mock.patch(
            "keepercommander.commands.tunnel_registry.list_registered_tunnels",
            return_value=[],
        ):
            stopped, message = _handle_pam_stop_control(control)

        self.assertTrue(stopped)
        self.assertEqual("already_stopped", message)
        pam_state_bridge.publish_stopping.assert_not_called()
        pam_state_bridge.publish_error.assert_not_called()

    def test_stop_control_missing_session_stops_matching_registry_tunnel(self):
        control = types.SimpleNamespace(
            tunnel_id="tube-file-registry",
            pam_session_id="conversation-file-registry",
            resource_handle="record-file-registry",
        )
        entry = {
            "pid": 12345,
            "tube_id": "tube-file-registry",
            "record_uid": "record-file-registry",
            "record_title": "File Registry",
            "mode": "interactive",
            "pid_started_at": "pid-start-1",
        }

        with mock.patch(
            "keepercommander.commands.tunnel.port_forward.tunnel_helpers.pam_state_bridge"
        ) as pam_state_bridge, mock.patch(
            "keepercommander.commands.tunnel_registry.list_registered_tunnels",
            return_value=[entry],
        ) as list_registered_tunnels, mock.patch(
            "keepercommander.commands.tunnel_registry.is_pid_alive",
            side_effect=[True, False],
        ) as is_pid_alive, mock.patch(
            "keepercommander.commands.tunnel_registry.stop_tunnel_process",
            return_value=True,
        ) as stop_tunnel_process, mock.patch(
            "keepercommander.commands.tunnel_registry.registry_entry_exists",
            return_value=True,
        ), mock.patch(
            "keepercommander.commands.tunnel_registry.unregister_tunnel",
        ) as unregister_tunnel:
            stopped, message = _handle_pam_stop_control(control)

        self.assertTrue(stopped)
        self.assertEqual("registry_stop_signal_sent", message)
        list_registered_tunnels.assert_called_once_with(clean_stale=False)
        self.assertEqual([mock.call(12345, "pid-start-1"), mock.call(12345, "pid-start-1")], is_pid_alive.call_args_list)
        stop_tunnel_process.assert_called_once_with(12345, "pid-start-1")
        unregister_tunnel.assert_called_once_with(12345)
        pam_state_bridge.publish_stopping.assert_not_called()
        pam_state_bridge.publish_error.assert_not_called()

    def test_stop_control_missing_session_matches_registry_by_pam_session_id(self):
        control = types.SimpleNamespace(
            tunnel_id="vault-tunnel-not-local",
            pam_session_id="conversation-file-registry",
            resource_handle="unknown",
        )
        entry = {
            "pid": 12345,
            "tube_id": "tube-file-registry",
            "pam_session_id": "conversation-file-registry",
            "conversation_id": "conversation-file-registry",
            "record_uid": "record-file-registry",
            "record_title": "File Registry",
            "mode": "interactive",
            "pid_started_at": "pid-start-1",
        }

        with mock.patch(
            "keepercommander.commands.tunnel.port_forward.tunnel_helpers.pam_state_bridge"
        ) as pam_state_bridge, mock.patch(
            "keepercommander.commands.tunnel_registry.list_registered_tunnels",
            return_value=[entry],
        ), mock.patch(
            "keepercommander.commands.tunnel_registry.is_pid_alive",
            side_effect=[True, False],
        ), mock.patch(
            "keepercommander.commands.tunnel_registry.stop_tunnel_process",
            return_value=True,
        ) as stop_tunnel_process, mock.patch(
            "keepercommander.commands.tunnel_registry.registry_entry_exists",
            return_value=True,
        ), mock.patch(
            "keepercommander.commands.tunnel_registry.unregister_tunnel",
        ) as unregister_tunnel:
            stopped, message = _handle_pam_stop_control(control)

        self.assertTrue(stopped)
        self.assertEqual("registry_stop_signal_sent", message)
        stop_tunnel_process.assert_called_once_with(12345, "pid-start-1")
        unregister_tunnel.assert_called_once_with(12345)
        pam_state_bridge.publish_stopping.assert_not_called()
        pam_state_bridge.publish_error.assert_not_called()

    def test_stop_control_succeeds_when_interactive_sibling_removes_registry_entry(self):
        control = types.SimpleNamespace(
            tunnel_id="tube-file-registry",
            pam_session_id="conversation-file-registry",
            resource_handle="record-file-registry",
        )
        entry = {
            "pid": 12345,
            "tube_id": "tube-file-registry",
            "record_uid": "record-file-registry",
            "record_title": "File Registry",
            "mode": "interactive",
            "pid_started_at": "pid-start-1",
        }

        with mock.patch(
            "keepercommander.commands.tunnel.port_forward.tunnel_helpers.pam_state_bridge"
        ) as pam_state_bridge, mock.patch(
            "keepercommander.commands.tunnel_registry.list_registered_tunnels",
            return_value=[entry],
        ), mock.patch(
            "keepercommander.commands.tunnel_registry.is_pid_alive",
            return_value=True,
        ) as is_pid_alive, mock.patch(
            "keepercommander.commands.tunnel_registry.stop_tunnel_process",
            return_value=True,
        ) as stop_tunnel_process, mock.patch(
            "keepercommander.commands.tunnel_registry.registry_entry_exists",
            return_value=False,
        ) as registry_entry_exists, mock.patch(
            "keepercommander.commands.tunnel_registry.unregister_tunnel",
        ) as unregister_tunnel:
            stopped, message = _handle_pam_stop_control(control)

        self.assertTrue(stopped)
        self.assertEqual("registry_stop_signal_sent", message)
        is_pid_alive.assert_called_once_with(12345, "pid-start-1")
        stop_tunnel_process.assert_called_once_with(12345, "pid-start-1")
        registry_entry_exists.assert_called_once_with(12345, "pid-start-1")
        unregister_tunnel.assert_not_called()
        pam_state_bridge.publish_stopping.assert_not_called()
        pam_state_bridge.publish_error.assert_not_called()

    def test_stop_control_missing_session_returns_failed_when_registry_signal_fails(self):
        control = types.SimpleNamespace(
            tunnel_id="tube-file-registry",
            pam_session_id="conversation-file-registry",
            resource_handle="record-file-registry",
        )
        entry = {
            "pid": 12345,
            "tube_id": "tube-file-registry",
            "record_uid": "record-file-registry",
            "record_title": "File Registry",
            "mode": "interactive",
            "pid_started_at": "pid-start-1",
        }

        with mock.patch(
            "keepercommander.commands.tunnel.port_forward.tunnel_helpers.pam_state_bridge"
        ) as pam_state_bridge, mock.patch(
            "keepercommander.commands.tunnel_registry.list_registered_tunnels",
            return_value=[entry],
        ), mock.patch(
            "keepercommander.commands.tunnel_registry.is_pid_alive",
            return_value=True,
        ) as is_pid_alive, mock.patch(
            "keepercommander.commands.tunnel_registry.stop_tunnel_process",
            return_value=False,
        ) as stop_tunnel_process, mock.patch(
            "keepercommander.commands.tunnel_registry.unregister_tunnel",
        ) as unregister_tunnel:
            stopped, message = _handle_pam_stop_control(control)

        self.assertFalse(stopped)
        self.assertIn("failed to signal", message)
        self.assertEqual([mock.call(12345, "pid-start-1"), mock.call(12345, "pid-start-1")], is_pid_alive.call_args_list)
        stop_tunnel_process.assert_called_once_with(12345, "pid-start-1")
        unregister_tunnel.assert_not_called()
        pam_state_bridge.publish_stopping.assert_not_called()
        pam_state_bridge.publish_error.assert_not_called()

    def test_stop_control_close_failure_returns_failed_result(self):
        class FakeRegistry:
            def close_tube(self, tube_id, reason=None):
                raise RuntimeError("close failed")

        session = types.SimpleNamespace(
            tube_id="tube-foreground",
            conversation_id="conversation-foreground",
            record_uid="record-foreground",
            record_title="Foreground",
            signal_handler=types.SimpleNamespace(tube_registry=FakeRegistry(), tube_close_initiated=False),
        )
        control = types.SimpleNamespace(
            tunnel_id="tube-foreground",
            pam_session_id="conversation-foreground",
            resource_handle="record-foreground",
        )

        register_tunnel_session("tube-foreground", session)
        with mock.patch(
            "keepercommander.commands.tunnel.port_forward.tunnel_helpers.pam_state_bridge"
        ) as pam_state_bridge:
            stopped, message = _handle_pam_stop_control(control)

        self.assertFalse(stopped)
        self.assertIn("close failed", message)
        pam_state_bridge.publish_stopping.assert_called_once_with(session)
        pam_state_bridge.publish_error.assert_called_once()
        pam_state_bridge.publish_stopped.assert_not_called()
        self.assertFalse(getattr(session.signal_handler, "tube_close_initiated", False))

    def test_stop_control_unobserved_close_returns_failed_result(self):
        class FakeRegistry:
            def __init__(self):
                self.closed = []

            def close_tube(self, tube_id, reason=None):
                self.closed.append((tube_id, reason))

            def get_connection_state(self, tube_id):
                return "connected"

        registry = FakeRegistry()
        session = types.SimpleNamespace(
            tube_id="tube-foreground",
            conversation_id="conversation-foreground",
            record_uid="record-foreground",
            record_title="Foreground",
            signal_handler=types.SimpleNamespace(tube_registry=registry, tube_close_initiated=False),
        )
        control = types.SimpleNamespace(
            tunnel_id="tube-foreground",
            pam_session_id="conversation-foreground",
            resource_handle="record-foreground",
        )

        register_tunnel_session("tube-foreground", session)
        with mock.patch(
            "keepercommander.commands.tunnel.port_forward.tunnel_helpers.pam_state_bridge"
        ) as pam_state_bridge, mock.patch(
            "keepercommander.commands.tunnel.port_forward.tunnel_helpers._wait_for_tube_closed",
            return_value=False,
        ) as wait_for_tube_closed:
            stopped, message = _handle_pam_stop_control(control)

        self.assertFalse(stopped)
        self.assertIn("did not report closed", message)
        self.assertEqual([("tube-foreground", CloseConnectionReasons.Normal)], registry.closed)
        wait_for_tube_closed.assert_called_once_with(registry, "tube-foreground")
        pam_state_bridge.publish_stopping.assert_called_once_with(session)
        pam_state_bridge.publish_error.assert_called_once()
        pam_state_bridge.publish_stopped.assert_not_called()
        self.assertTrue(getattr(session.signal_handler, "tube_close_initiated", False))

    def test_stop_control_signals_external_shutdown_before_close(self):
        external_shutdown = mock.Mock()

        class FakeRegistry:
            def __init__(self):
                self.closed = []

            def close_tube(self, tube_id, reason=None):
                external_shutdown.set.assert_called_once_with()
                self.closed.append((tube_id, reason))

        registry = FakeRegistry()
        session = types.SimpleNamespace(
            tube_id="tube-foreground",
            conversation_id="conversation-foreground",
            record_uid="record-foreground",
            record_title="Foreground",
            external_shutdown_event=external_shutdown,
            signal_handler=types.SimpleNamespace(tube_registry=registry, tube_close_initiated=False),
        )
        control = types.SimpleNamespace(
            tunnel_id="tube-foreground",
            pam_session_id="conversation-foreground",
            resource_handle="record-foreground",
        )

        register_tunnel_session("tube-foreground", session)
        with mock.patch(
            "keepercommander.commands.tunnel.port_forward.tunnel_helpers.pam_state_bridge"
        ), mock.patch(
            "keepercommander.commands.tunnel.port_forward.tunnel_helpers._wait_for_tube_closed",
            return_value=True,
        ):
            stopped, message = _handle_pam_stop_control(control)

        self.assertTrue(stopped)
        self.assertEqual("fallback_close_executed", message)
        self.assertEqual([("tube-foreground", CloseConnectionReasons.Normal)], registry.closed)
        external_shutdown.set.assert_called()

    def test_late_ice_restart_offer_is_ignored_after_shutdown(self):
        handler = TunnelSignalHandler(
            params=mock.Mock(),
            record_uid="record-foreground",
            gateway_uid="gateway-foreground",
            symmetric_key=b"key",
            base64_nonce="nonce",
            conversation_id="conversation-foreground",
            tube_registry=mock.Mock(),
            tube_id="tube-foreground",
        )
        handler.shutdown_initiated = True
        handler._send_restart_offer = mock.Mock()

        handler._signal_from_rust_inner({
            "kind": "ice_restart_offer",
            "tube_id": "tube-foreground",
            "data": "not-base64",
        })

        handler._send_restart_offer.assert_not_called()


class TestPamTunnelListExternalProjection(unittest.TestCase):
    def test_list_shows_vault_owned_external_projection(self):
        projection = {
            "external_owner": "vault_desktop",
            "publisher_instance_id": "keeper-vault-desktop:pid:abc",
            "pam_session_id": "vault-conversation-1",
            "tunnel_id": "vault-tube-1",
            "resource_handle": "record-1",
            "state": "active",
            "local_endpoint": {"host": "127.0.0.1", "port": 49152},
        }
        rows = []

        with mock.patch(
            "keepercommander.commands.tunnel_and_connections.get_or_create_tube_registry",
            return_value=None,
        ), mock.patch(
            "keepercommander.commands.tunnel_and_connections.iter_visible_registry_tunnels",
            return_value=[],
        ), mock.patch(
            "keepercommander.commands.tunnel_and_connections.pam_state_bridge.wait_for_external_projections",
            return_value=[projection],
        ), mock.patch(
            "keepercommander.commands.tunnel_and_connections.pam_state_bridge.start_state_sync_worker",
        ), mock.patch(
            "keepercommander.commands.tunnel_and_connections.dump_report_data",
            side_effect=lambda table, *_args, **_kwargs: rows.extend(table),
        ):
            PAMTunnelListCommand().execute(types.SimpleNamespace())

        self.assertEqual(1, len(rows))
        self.assertEqual("record-1", rows[0][0])
        self.assertIn("Vault-owned", rows[0][1])
        self.assertIn("127.0.0.1:49152", rows[0][2])
        self.assertEqual("vault-tube-1", rows[0][3])
        self.assertEqual("vault-conversation-1", rows[0][4])
        self.assertIn("Vault-owned external: active", rows[0][5])

    def test_list_uses_snapshot_wait_for_external_projection(self):
        projection = {
            "external_owner": "vault_desktop",
            "publisher_instance_id": "keeper-vault-desktop:pid:abc",
            "pam_session_id": "vault-conversation-1",
            "tunnel_id": "vault-tube-1",
            "resource_handle": "record-1",
            "state": "active",
        }
        rows = []

        with mock.patch(
            "keepercommander.commands.tunnel_and_connections.get_or_create_tube_registry",
            return_value=None,
        ), mock.patch(
            "keepercommander.commands.tunnel_and_connections.iter_visible_registry_tunnels",
            return_value=[],
        ), mock.patch(
            "keepercommander.commands.tunnel_and_connections.pam_state_bridge.wait_for_external_projections",
            return_value=[projection],
        ) as wait_for_external_projections, mock.patch(
            "keepercommander.commands.tunnel_and_connections.pam_state_bridge.start_state_sync_worker",
        ) as start_state_sync_worker, mock.patch(
            "keepercommander.commands.tunnel_and_connections.dump_report_data",
            side_effect=lambda table, *_args, **_kwargs: rows.extend(table),
        ):
            PAMTunnelListCommand().execute(types.SimpleNamespace(via_desktop_login=True))

        start_state_sync_worker.assert_called_once_with(mock.ANY)
        wait_for_external_projections.assert_called_once_with(timeout_seconds=0.25)
        self.assertEqual(1, len(rows))
        self.assertEqual("record-1", rows[0][0])

    def test_list_shows_vault_projection_when_record_not_in_local_cache(self):
        projection = {
            "external_owner": "vault_desktop",
            "publisher_instance_id": "keeper-vault-desktop:pid:abc",
            "pam_session_id": "vault-conversation-1",
            "tunnel_id": "vault-tube-1",
            "resource_handle": "record-missing-locally",
            "state": "active",
            "owning_account_uid": "vault-account-1",
        }
        rows = []

        with mock.patch(
            "keepercommander.commands.tunnel_and_connections.get_or_create_tube_registry",
            return_value=None,
        ), mock.patch(
            "keepercommander.commands.tunnel_and_connections.iter_visible_registry_tunnels",
            return_value=[],
        ), mock.patch(
            "keepercommander.commands.tunnel_and_connections.pam_state_bridge.wait_for_external_projections",
            return_value=[projection],
        ), mock.patch(
            "keepercommander.commands.tunnel_and_connections.pam_state_bridge.start_state_sync_worker",
        ), mock.patch(
            "keepercommander.commands.tunnel_and_connections.dump_report_data",
            side_effect=lambda table, *_args, **_kwargs: rows.extend(table),
        ):
            PAMTunnelListCommand().execute(types.SimpleNamespace(records={}))

        self.assertEqual(1, len(rows))
        self.assertEqual("record-missing-locally", rows[0][0])
        self.assertEqual("vault-tube-1", rows[0][3])

    def test_list_shows_owner_stop_pending_external_projection(self):
        projection = {
            "external_owner": "vault_desktop",
            "publisher_instance_id": "keeper-vault-desktop:pid:abc",
            "pam_session_id": "vault-conversation-1",
            "tunnel_id": "vault-tube-1",
            "resource_handle": "record-1",
            "state": "stopping",
            "owner_stop_pending": True,
            "owner_stop_control_id": "control-1",
        }
        rows = []

        with mock.patch(
            "keepercommander.commands.tunnel_and_connections.get_or_create_tube_registry",
            return_value=None,
        ), mock.patch(
            "keepercommander.commands.tunnel_and_connections.iter_visible_registry_tunnels",
            return_value=[],
        ), mock.patch(
            "keepercommander.commands.tunnel_and_connections.pam_state_bridge.wait_for_external_projections",
            return_value=[projection],
        ), mock.patch(
            "keepercommander.commands.tunnel_and_connections.pam_state_bridge.start_state_sync_worker",
        ), mock.patch(
            "keepercommander.commands.tunnel_and_connections.dump_report_data",
            side_effect=lambda table, *_args, **_kwargs: rows.extend(table),
        ):
            PAMTunnelListCommand().execute(types.SimpleNamespace(via_desktop_login=True))

        self.assertEqual(1, len(rows))
        self.assertIn("Vault-owned external: stopping (owner stop pending)", rows[0][5])

    def test_list_shows_ssh_agent_guidance_only_with_explicit_hint(self):
        projection = {
            "external_owner": "vault_desktop",
            "publisher_instance_id": "keeper-vault-desktop:pid:abc",
            "pam_session_id": "vault-conversation-1",
            "tunnel_id": "vault-tube-1",
            "resource_handle": "record-1",
            "state": "active",
            "authn_hint": "desktop_ssh_agent",
            "ssh_agent_available": True,
            "ssh_agent_endpoint": "/tmp/keeper agent.sock",
            "ssh_agent_endpoint_kind": "unix_socket",
            "ssh_agent_scope": "desktop_session",
        }
        rows = []
        printed = []

        with mock.patch(
            "keepercommander.commands.tunnel_and_connections.get_or_create_tube_registry",
            return_value=None,
        ), mock.patch(
            "keepercommander.commands.tunnel_and_connections.iter_visible_registry_tunnels",
            return_value=[],
        ), mock.patch(
            "keepercommander.commands.tunnel_and_connections.pam_state_bridge.wait_for_external_projections",
            return_value=[projection],
        ), mock.patch(
            "keepercommander.commands.tunnel_and_connections.pam_state_bridge.start_state_sync_worker",
        ), mock.patch(
            "keepercommander.commands.tunnel_and_connections.dump_report_data",
            side_effect=lambda table, *_args, **_kwargs: rows.extend(table),
        ), mock.patch("builtins.print", side_effect=lambda text="": printed.append(text)):
            PAMTunnelListCommand().execute(types.SimpleNamespace(via_desktop_login=True))

        self.assertEqual(1, len(rows))
        joined = "\n".join(str(x) for x in printed)
        self.assertIn("Keeper Desktop SSH Agent", joined)
        self.assertIn("export SSH_AUTH_SOCK='/tmp/keeper agent.sock'", joined)

    def test_list_does_not_show_ssh_agent_guidance_without_hint(self):
        projection = {
            "external_owner": "vault_desktop",
            "publisher_instance_id": "keeper-vault-desktop:pid:abc",
            "pam_session_id": "vault-conversation-1",
            "tunnel_id": "vault-tube-1",
            "resource_handle": "record-1",
            "state": "active",
            "ssh_agent_endpoint": "/tmp/keeper-agent.sock",
            "ssh_agent_available": True,
        }
        rows = []
        printed = []

        with mock.patch(
            "keepercommander.commands.tunnel_and_connections.get_or_create_tube_registry",
            return_value=None,
        ), mock.patch(
            "keepercommander.commands.tunnel_and_connections.iter_visible_registry_tunnels",
            return_value=[],
        ), mock.patch(
            "keepercommander.commands.tunnel_and_connections.pam_state_bridge.wait_for_external_projections",
            return_value=[projection],
        ), mock.patch(
            "keepercommander.commands.tunnel_and_connections.pam_state_bridge.start_state_sync_worker",
        ), mock.patch(
            "keepercommander.commands.tunnel_and_connections.dump_report_data",
            side_effect=lambda table, *_args, **_kwargs: rows.extend(table),
        ), mock.patch("builtins.print", side_effect=lambda text="": printed.append(text)):
            PAMTunnelListCommand().execute(types.SimpleNamespace(via_desktop_login=True))

        self.assertEqual(1, len(rows))
        self.assertNotIn("keeper-agent.sock", "\n".join(str(x) for x in printed))


class TestPamTunnelStartPreActionApproval(unittest.TestCase):
    class FakeField:
        def __init__(self, value):
            self.value = value

        def get_default_value(self, *_args, **_kwargs):
            return self.value

    class FakeTypedRecord:
        record_type = "pamMachine"
        title = "Demo Machine"

        def get_typed_field(self, field_name, *_args, **_kwargs):
            if field_name == "pamSettings":
                return TestPamTunnelStartPreActionApproval.FakeField(
                    {
                        "allowSupplyHost": False,
                        "portForward": {"port": 22},
                        "connection": {},
                    }
                )
            if field_name == "pamHostname":
                return TestPamTunnelStartPreActionApproval.FakeField(
                    {"hostName": "demo.internal", "port": 22}
                )
            if field_name == "trafficEncryptionSeed":
                return TestPamTunnelStartPreActionApproval.FakeField("AQIDBAUGBwgJCgsMDQ4PEA==")
            return None

    def _patch_start_dependencies(self, external_projection=None):
        patches = [
            mock.patch(
                "keepercommander.commands.tunnel_and_connections.get_or_create_tube_registry",
                return_value=object(),
            ),
            mock.patch(
                "keepercommander.commands.tunnel_and_connections.find_open_port",
                return_value=49152,
            ),
            mock.patch("keepercommander.commands.tunnel_and_connections.api.sync_down"),
            mock.patch.object(
                __import__(
                    "keepercommander.commands.tunnel_and_connections",
                    fromlist=["vault"],
                ).vault,
                "TypedRecord",
                self.FakeTypedRecord,
            ),
            mock.patch(
                "keepercommander.commands.tunnel_and_connections.vault.KeeperRecord.load",
                return_value=self.FakeTypedRecord(),
            ),
            mock.patch(
                "keepercommander.commands.workflow.helpers.is_pam_action_allowed_by_enforcement",
                return_value=True,
            ),
            mock.patch(
                "keepercommander.commands.workflow.helpers.is_pam_config_action_allowed_for_record",
                return_value=True,
            ),
            mock.patch(
                "keepercommander.commands.workflow.check_workflow_for_launch",
                return_value=types.SimpleNamespace(
                    allowed=True,
                    two_factor_value=None,
                    expires_on_ms=0,
                ),
            ),
            mock.patch(
                "keepercommander.commands.tunnel_and_connections.pam_state_bridge.find_external_projection_for_resource",
                return_value=external_projection,
            ),
            mock.patch(
                "keepercommander.commands.tunnel_and_connections.get_gateway_uid_from_record",
                return_value="gateway-1",
            ),
            mock.patch(
                "keepercommander.commands.tunnel_and_connections.start_rust_tunnel",
                return_value={"success": False},
            ),
        ]
        return patches

    def test_via_desktop_denied_start_approval_prevents_tunnel_open(self):
        patches = self._patch_start_dependencies()
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7], patches[8], patches[9], patches[10] as start_rust_tunnel, mock.patch(
            "keepercommander.commands.tunnel_and_connections.pam_state_bridge.request_start_tunnel_approval",
            return_value=(False, "Desktop approval denied"),
        ) as request_start_tunnel_approval:
            with self.assertRaises(CommandError) as context:
                PAMTunnelStartCommand().execute(
                    types.SimpleNamespace(via_desktop_login=True, batch_mode=False),
                    uid="record-1",
                )

        self.assertIn("Desktop approval denied", str(context.exception))
        request_start_tunnel_approval.assert_called_once()
        approval_kwargs = request_start_tunnel_approval.call_args.kwargs
        self.assertEqual("record-1", approval_kwargs["resource_handle"])
        self.assertEqual("Demo Machine", approval_kwargs["resource_title"])
        self.assertEqual("Open PAM tunnel", approval_kwargs["purpose"])
        self.assertEqual("127.0.0.1", approval_kwargs["local_host"])
        self.assertEqual(49152, approval_kwargs["local_port"])
        start_rust_tunnel.assert_not_called()

    def test_via_desktop_allowed_start_approval_opens_tunnel(self):
        patches = self._patch_start_dependencies()
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7], patches[8], patches[9], patches[10] as start_rust_tunnel, mock.patch(
            "keepercommander.commands.tunnel_and_connections.pam_state_bridge.request_start_tunnel_approval",
            return_value=(True, "allow"),
        ) as request_start_tunnel_approval, mock.patch("builtins.print") as print_mock:
            PAMTunnelStartCommand().execute(
                types.SimpleNamespace(via_desktop_login=True, batch_mode=False),
                uid="record-1",
            )

        request_start_tunnel_approval.assert_called_once()
        start_rust_tunnel.assert_called_once()
        self.assertTrue(
            any("Vault approval received. Establishing tunnel" in str(call) for call in print_mock.call_args_list)
        )

    def test_default_interactive_start_registers_tunnel_for_list(self):
        patches = self._patch_start_dependencies()
        tube_registry = mock.Mock()
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7], patches[8], patches[9], patches[10] as start_rust_tunnel, mock.patch(
            "keepercommander.commands.tunnel_and_connections.pam_state_bridge.request_start_tunnel_approval",
            return_value=(True, "allow"),
        ), mock.patch(
            "keepercommander.commands.tunnel_and_connections.register_tunnel"
        ) as register_tunnel:
            start_rust_tunnel.return_value = {
                "success": True,
                "tube_id": "tube-1",
                "tube_registry": tube_registry,
            }

            PAMTunnelStartCommand().execute(
                types.SimpleNamespace(via_desktop_login=True, batch_mode=False),
                uid="record-1",
            )

        register_tunnel.assert_called_once()
        register_args = register_tunnel.call_args.args
        register_kwargs = register_tunnel.call_args.kwargs
        self.assertEqual("record-1", register_args[1])
        self.assertEqual("tube-1", register_args[2])
        self.assertIsNone(register_args[3])
        self.assertEqual(49152, register_args[4])
        self.assertEqual("demo.internal", register_args[5])
        self.assertEqual(22, register_args[6])
        self.assertEqual("interactive", register_kwargs["mode"])
        self.assertEqual("Demo Machine", register_kwargs["record_title"])
        tube_registry.close_tube.assert_not_called()

    def test_default_interactive_start_sigterm_closes_tunnel_without_exiting_shell(self):
        tunnel_and_connections._INTERACTIVE_SIGNAL_INSTALLED = False
        tunnel_and_connections._INTERACTIVE_PREVIOUS_SIGTERM = None
        tunnel_and_connections._INTERACTIVE_TUNNELS_BY_ID.clear()
        tunnel_and_connections._INTERACTIVE_SIGNAL_EVENT.clear()
        patches = self._patch_start_dependencies()
        tube_registry = mock.Mock()
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7], patches[8], patches[9], patches[10] as start_rust_tunnel, mock.patch(
            "keepercommander.commands.tunnel_and_connections.pam_state_bridge.request_start_tunnel_approval",
            return_value=(True, "allow"),
        ), mock.patch(
            "keepercommander.commands.tunnel_and_connections.register_tunnel"
        ), mock.patch(
            "keepercommander.commands.tunnel_and_connections.unregister_tunnel"
        ) as unregister_tunnel, mock.patch(
            "keepercommander.commands.tunnel_and_connections.unregister_tunnel_session"
        ) as unregister_tunnel_session, mock.patch(
            "keepercommander.commands.tunnel_and_connections.signal.signal"
        ) as signal_mock:
            start_rust_tunnel.return_value = {
                "success": True,
                "tube_id": "tube-1",
                "tube_registry": tube_registry,
            }

            PAMTunnelStartCommand().execute(
                types.SimpleNamespace(via_desktop_login=True, batch_mode=False),
                uid="record-1",
            )

            handler = signal_mock.call_args_list[0].args[1]
            handler(15, None)
            deadline = time.time() + 1.0
            while time.time() < deadline and not tube_registry.close_tube.called:
                time.sleep(0.01)

        tube_registry.close_tube.assert_called_once_with("tube-1", reason=CloseConnectionReasons.Normal)
        unregister_tunnel.assert_called_once_with()
        unregister_tunnel_session.assert_called_once_with("tube-1")
        self.assertFalse(tunnel_and_connections._INTERACTIVE_SIGNAL_INSTALLED)
        self.assertFalse(tunnel_and_connections._INTERACTIVE_TUNNELS_BY_ID)

    def test_interactive_sigterm_handler_drains_multiple_tunnels(self):
        tunnel_and_connections._INTERACTIVE_SIGNAL_INSTALLED = False
        tunnel_and_connections._INTERACTIVE_PREVIOUS_SIGTERM = None
        tunnel_and_connections._INTERACTIVE_TUNNELS_BY_ID.clear()
        tunnel_and_connections._INTERACTIVE_SIGNAL_EVENT.clear()
        registry_one = mock.Mock()
        registry_two = mock.Mock()

        with mock.patch(
            "keepercommander.commands.tunnel_and_connections.unregister_tunnel"
        ) as unregister_tunnel, mock.patch(
            "keepercommander.commands.tunnel_and_connections.unregister_tunnel_session"
        ) as unregister_tunnel_session, mock.patch(
            "keepercommander.commands.tunnel_and_connections.signal.signal"
        ) as signal_mock:
            handler_one = tunnel_and_connections._install_interactive_tunnel_signal_handler(
                "record-1",
                "tube-1",
                registry_one,
            )
            handler_two = tunnel_and_connections._install_interactive_tunnel_signal_handler(
                "record-2",
                "tube-2",
                registry_two,
            )

            self.assertIs(handler_one, handler_two)
            self.assertEqual(1, signal_mock.call_count)
            handler_one(15, None)
            deadline = time.time() + 1.0
            while time.time() < deadline and (
                not registry_one.close_tube.called or not registry_two.close_tube.called
            ):
                time.sleep(0.01)

        registry_one.close_tube.assert_called_once_with("tube-1", reason=CloseConnectionReasons.Normal)
        registry_two.close_tube.assert_called_once_with("tube-2", reason=CloseConnectionReasons.Normal)
        unregister_tunnel.assert_called_once_with()
        unregister_tunnel_session.assert_has_calls([mock.call("tube-1"), mock.call("tube-2")], any_order=True)
        self.assertFalse(tunnel_and_connections._INTERACTIVE_SIGNAL_INSTALLED)
        self.assertFalse(tunnel_and_connections._INTERACTIVE_TUNNELS_BY_ID)
        self.assertGreaterEqual(signal_mock.call_count, 2)

    def test_via_desktop_keyboard_interrupt_during_tunnel_start_cancels_cleanly(self):
        patches = self._patch_start_dependencies()
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7], patches[8], patches[9], patches[10] as start_rust_tunnel, mock.patch(
            "keepercommander.commands.tunnel_and_connections.pam_state_bridge.request_start_tunnel_approval",
            return_value=(True, "allow"),
        ), mock.patch("builtins.print") as print_mock:
            start_rust_tunnel.side_effect = KeyboardInterrupt()
            PAMTunnelStartCommand().execute(
                types.SimpleNamespace(via_desktop_login=True, batch_mode=False),
                uid="record-1",
            )

        start_rust_tunnel.assert_called_once()
        self.assertTrue(
            any("Tunnel start canceled" in str(call) for call in print_mock.call_args_list)
        )

    def test_via_desktop_external_projection_still_requests_vault_approval(self):
        patches = self._patch_start_dependencies(
            external_projection={
                "external_owner": "vault_desktop",
                "resource_handle": "record-1",
                "tunnel_id": "vault-tube-1",
                "state": "active",
            }
        )
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7], patches[8], patches[9], patches[10] as start_rust_tunnel, mock.patch(
            "keepercommander.commands.tunnel_and_connections.pam_state_bridge.request_start_tunnel_approval",
            return_value=(True, "allow"),
        ) as request_start_tunnel_approval:
            PAMTunnelStartCommand().execute(
                types.SimpleNamespace(via_desktop_login=True, batch_mode=False),
                uid="record-1",
            )

        request_start_tunnel_approval.assert_called_once()
        start_rust_tunnel.assert_called_once()

    def test_via_desktop_duplicate_tunnel_denial_is_user_friendly(self):
        patches = self._patch_start_dependencies()
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7], patches[8], patches[9], patches[10] as start_rust_tunnel, mock.patch(
            "keepercommander.commands.tunnel_and_connections.pam_state_bridge.request_start_tunnel_approval",
            return_value=(
                False,
                "duplicate_active_session: A PAM tunnel is already active for record record-1.",
            ),
        ):
            with self.assertRaises(CommandError) as context:
                PAMTunnelStartCommand().execute(
                    types.SimpleNamespace(via_desktop_login=True, batch_mode=False),
                    uid="record-1",
                )

        self.assertEqual("", context.exception.command)
        self.assertIn("PAM tunnel is already active", context.exception.message)
        self.assertNotIn("Desktop approval denied", context.exception.message)
        start_rust_tunnel.assert_not_called()

    def test_non_desktop_start_does_not_request_pre_action_approval(self):
        patches = self._patch_start_dependencies()
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7], patches[8], patches[9], patches[10] as start_rust_tunnel, mock.patch(
            "keepercommander.commands.tunnel_and_connections.pam_state_bridge.request_start_tunnel_approval"
        ) as request_start_tunnel_approval:
            PAMTunnelStartCommand().execute(
                types.SimpleNamespace(via_desktop_login=False, batch_mode=False),
                uid="record-1",
            )

        request_start_tunnel_approval.assert_not_called()
        start_rust_tunnel.assert_called_once()

    def test_non_desktop_external_projection_keeps_local_duplicate_guard(self):
        patches = self._patch_start_dependencies(
            external_projection={
                "external_owner": "vault_desktop",
                "resource_handle": "record-1",
                "tunnel_id": "vault-tube-1",
                "state": "active",
            }
        )
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7], patches[8], patches[9], patches[10] as start_rust_tunnel, mock.patch(
            "keepercommander.commands.tunnel_and_connections.pam_state_bridge.request_start_tunnel_approval"
        ) as request_start_tunnel_approval, mock.patch("builtins.print") as print_mock:
            PAMTunnelStartCommand().execute(
                types.SimpleNamespace(via_desktop_login=False, batch_mode=False),
                uid="record-1",
            )

        request_start_tunnel_approval.assert_not_called()
        start_rust_tunnel.assert_not_called()
        self.assertTrue(
            any("Vault-owned tunnel is already active" in str(call) for call in print_mock.call_args_list)
        )


class TestPamTunnelStopExternalProjection(unittest.TestCase):
    class EmptyRegistry:
        def find_tubes(self, uid):
            return []

        def tube_found(self, uid):
            return False

        def tube_id_from_connection_id(self, uid):
            return None

    def test_stop_external_projection_requests_owner_stop(self):
        projection = {
            "external_owner": "vault_desktop",
            "publisher_instance_id": "keeper-vault-desktop:pid:abc",
            "pam_session_id": "vault-conversation-1",
            "tunnel_id": "vault-tube-1",
            "resource_handle": "record-1",
            "state": "active",
        }

        with mock.patch(
            "keepercommander.commands.tunnel_and_connections.pam_state_bridge.find_external_projection",
            return_value=projection,
        ) as find_external_projection, mock.patch(
            "keepercommander.commands.tunnel_and_connections.pam_state_bridge.request_owner_stop",
            return_value=(True, "owner_stop_requested"),
        ) as request_owner_stop, mock.patch(
            "keepercommander.commands.tunnel_and_connections.get_or_create_tube_registry",
            return_value=self.EmptyRegistry(),
        ):
            PAMTunnelStopCommand().execute(types.SimpleNamespace(), uid="record-1")

        find_external_projection.assert_called_once_with("record-1")
        request_owner_stop.assert_called_once_with(projection)

    def test_stop_external_projection_reports_owner_unavailable(self):
        projection = {
            "external_owner": "vault_desktop",
            "publisher_instance_id": "keeper-vault-desktop:pid:abc",
            "pam_session_id": "vault-conversation-1",
            "tunnel_id": "vault-tube-1",
            "resource_handle": "record-1",
            "state": "active",
        }

        with mock.patch(
            "keepercommander.commands.tunnel_and_connections.pam_state_bridge.find_external_projection",
            return_value=projection,
        ), mock.patch(
            "keepercommander.commands.tunnel_and_connections.pam_state_bridge.request_owner_stop",
            return_value=(False, "Vault-owned tunnel owner route is unavailable"),
        ), mock.patch(
            "keepercommander.commands.tunnel_and_connections.get_or_create_tube_registry",
            return_value=self.EmptyRegistry(),
        ):
            with self.assertRaises(CommandError) as context:
                PAMTunnelStopCommand().execute(types.SimpleNamespace(), uid="record-1")

        self.assertIn("owner route is unavailable", str(context.exception))

    def test_stop_by_record_prefers_local_tube_over_external_projection(self):
        projection = {
            "external_owner": "vault_desktop",
            "publisher_instance_id": "keeper-vault-desktop:pid:abc",
            "pam_session_id": "vault-conversation-1",
            "tunnel_id": "vault-tube-1",
            "resource_handle": "record-1",
            "state": "active",
        }

        class FakeRegistry:
            def __init__(self):
                self.closed = []

            def find_tubes(self, uid):
                return ["local-tube"] if uid == "record-1" else []

            def tube_found(self, uid):
                return False

            def tube_id_from_connection_id(self, uid):
                return None

            def close_tube(self, tube_id, reason=None):
                self.closed.append((tube_id, reason))

        registry = FakeRegistry()
        session = types.SimpleNamespace(tube_id="local-tube")

        with mock.patch(
            "keepercommander.commands.tunnel_and_connections.pam_state_bridge.find_external_projection",
            return_value=projection,
        ), mock.patch(
            "keepercommander.commands.tunnel_and_connections.pam_state_bridge.request_owner_stop",
        ) as request_owner_stop, mock.patch(
            "keepercommander.commands.tunnel_and_connections.get_or_create_tube_registry",
            return_value=registry,
        ), mock.patch(
            "keepercommander.commands.tunnel_and_connections.get_tunnel_session",
            return_value=session,
        ), mock.patch(
            "keepercommander.commands.tunnel_and_connections.pam_state_bridge.publish_stopping",
        ), mock.patch(
            "keepercommander.commands.tunnel_and_connections.pam_state_bridge.publish_stopped",
        ):
            PAMTunnelStopCommand().execute(types.SimpleNamespace(), uid="record-1")

        request_owner_stop.assert_not_called()
        self.assertEqual([("local-tube", CloseConnectionReasons.Normal)], registry.closed)

    def test_stop_commander_owned_tunnel_keeps_local_close_path(self):
        class FakeRegistry:
            def __init__(self):
                self.closed = []

            def find_tubes(self, uid):
                return ["local-tube"] if uid == "local-tube" else []

            def tube_found(self, uid):
                return uid == "local-tube"

            def close_tube(self, tube_id, reason=None):
                self.closed.append((tube_id, reason))

        registry = FakeRegistry()
        session = types.SimpleNamespace(tube_id="local-tube")

        with mock.patch(
            "keepercommander.commands.tunnel_and_connections.pam_state_bridge.find_external_projection",
            return_value=None,
        ), mock.patch(
            "keepercommander.commands.tunnel_and_connections.pam_state_bridge.request_owner_stop",
        ) as request_owner_stop, mock.patch(
            "keepercommander.commands.tunnel_and_connections.get_or_create_tube_registry",
            return_value=registry,
        ), mock.patch(
            "keepercommander.commands.tunnel_and_connections.get_tunnel_session",
            return_value=session,
        ), mock.patch(
            "keepercommander.commands.tunnel_and_connections.pam_state_bridge.publish_stopping",
        ) as publish_stopping, mock.patch(
            "keepercommander.commands.tunnel_and_connections.pam_state_bridge.publish_stopped",
        ) as publish_stopped:
            PAMTunnelStopCommand().execute(types.SimpleNamespace(), uid="local-tube")

        request_owner_stop.assert_not_called()
        self.assertEqual([("local-tube", CloseConnectionReasons.Normal)], registry.closed)
        publish_stopping.assert_called_once_with(session)
        publish_stopped.assert_not_called()
