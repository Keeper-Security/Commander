"""Regression tests for ssh option injection in the SSH key rotation plugin."""

import unittest
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from keepercommander import vault
from keepercommander.plugins.sshkey import sshkey


def _private_key_pem():
    pk = ed25519.Ed25519PrivateKey.generate()
    return pk.private_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption()).decode()


def _record(login, hosts=('example.com',)):
    rec = vault.PasswordRecord()
    rec.login = login
    rec.custom.append(vault.CustomField.new_field('cmdr:private_key', _private_key_pem()))
    for h in hosts:
        rec.custom.append(vault.CustomField.new_field('cmdr:host', h))
    return rec


class _FakeChild:
    def __init__(self, out=b''):
        self.out = out

    def communicate(self, timeout=None):
        return self.out, b''

    def poll(self):
        return 0


class TestSshKeyRotationArgv(unittest.TestCase):
    def _rotate(self, record):
        with mock.patch.object(sshkey.subprocess, 'Popen', side_effect=lambda *a, **k: _FakeChild()) as popen:
            result = sshkey.rotate(record, 'new-pass')
        return result, popen

    def test_double_dash_precedes_target(self):
        result, popen = self._rotate(_record('root'))
        self.assertTrue(result)
        self.assertEqual(popen.call_count, 2)
        for call in popen.call_args_list:
            argv = call.args[0]
            idx = argv.index('root@example.com')
            self.assertEqual(argv[idx - 1], '--')

    def test_leading_dash_login_never_reaches_popen(self):
        for login in ('-oProxyCommand=touch /tmp/pwn #', '-oProxyCommand=x', '-v'):
            result, popen = self._rotate(_record(login))
            self.assertFalse(result)
            popen.assert_not_called()

    def test_whitespace_and_control_login_rejected(self):
        for login in ('root\n', 'a b', 'a\tb', 'a\x00b'):
            result, popen = self._rotate(_record(login))
            self.assertFalse(result, repr(login))
            popen.assert_not_called()

    def test_leading_dash_host_never_reaches_popen(self):
        result, popen = self._rotate(_record('root', hosts=('-oProxyCommand=x',)))
        self.assertFalse(result)
        popen.assert_not_called()

    def test_non_ascii_port_rejected(self):
        for port in ('²', '٢٢'):
            result, popen = self._rotate(_record('root', hosts=('example.com:' + port,)))
            self.assertFalse(result)
            popen.assert_not_called()

    def test_ipv6_literal_rejected(self):
        result, popen = self._rotate(_record('root', hosts=('fe80::1',)))
        self.assertFalse(result)
        popen.assert_not_called()

    def test_unusual_logins_still_allowed(self):
        for login in ('user+ssh@example.com', 'backup$', 'jörg'):
            result, popen = self._rotate(_record(login))
            self.assertTrue(result, login)
            argv = popen.call_args_list[0].args[0]
            self.assertEqual(argv[argv.index('--') + 1], login + '@example.com')

    def test_unusual_login_without_hosts_rotates(self):
        result, popen = self._rotate(_record('svc account', hosts=()))
        self.assertTrue(result)
        popen.assert_not_called()


if __name__ == '__main__':
    unittest.main()
