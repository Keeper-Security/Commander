import os
import stat
import tempfile
from types import SimpleNamespace
from unittest import TestCase, mock

from keepercommander import utils


class TestPathLinkDetection(TestCase):
    def test_detects_link_in_parent_component(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            link_dir = os.path.join(tmp_dir, 'linked-dir')
            file_path = os.path.join(link_dir, 'config.json')

            def fake_lstat(path):
                mode = stat.S_IFLNK if path == link_dir else stat.S_IFDIR
                return SimpleNamespace(st_mode=mode)

            with mock.patch('keepercommander.utils.os.lstat', side_effect=fake_lstat):
                self.assertTrue(utils._path_has_link_component(file_path))


class TestWindowsIcaclsPrincipal(TestCase):
    def test_userdomain_and_username(self):
        with mock.patch.dict(os.environ, {'USERNAME': 'ivan', 'USERDOMAIN': 'IVAN'}, clear=False):
            self.assertEqual(utils._windows_icacls_principal(), 'IVAN\\ivan')

    def test_domain_user(self):
        with mock.patch.dict(os.environ, {'USERNAME': 'jdoe', 'USERDOMAIN': 'CORP'}, clear=False):
            self.assertEqual(utils._windows_icacls_principal(), 'CORP\\jdoe')

    def test_falls_back_to_computername(self):
        env = os.environ.copy()
        env.pop('USERDOMAIN', None)
        with mock.patch.dict(os.environ, env, clear=True):
            os.environ['USERNAME'] = 'bob'
            os.environ['COMPUTERNAME'] = 'MYPC'
            self.assertEqual(utils._windows_icacls_principal(), 'MYPC\\bob')

    def test_already_qualified_username(self):
        with mock.patch.dict(os.environ, {'USERNAME': 'CORP\\jdoe', 'USERDOMAIN': 'CORP'}, clear=False):
            self.assertEqual(utils._windows_icacls_principal(), 'CORP\\jdoe')

    def test_falls_back_to_getlogin(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with mock.patch('os.getlogin', return_value='localuser'):
                with mock.patch.dict(os.environ, {'COMPUTERNAME': 'MYPC'}, clear=False):
                    self.assertEqual(utils._windows_icacls_principal(), 'MYPC\\localuser')


class TestSetFilePermissionsWindows(TestCase):
    def _grant_principal(self, mock_run):
        for call in mock_run.call_args_list:
            args = call.args[0]
            if '/grant' in args:
                return args[args.index('/grant') + 1]
        self.fail('icacls /grant was not called')

    @mock.patch('subprocess.run')
    @mock.patch('platform.system', return_value='Windows')
    @mock.patch('os.path.islink', return_value=False)
    def test_grant_uses_qualified_principal_when_names_collide(self, _islink, _system, mock_run):
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            path = os.path.realpath(tmp.name)
        try:
            with mock.patch.dict(os.environ, {'USERNAME': 'ivan', 'USERDOMAIN': 'IVAN'}, clear=False):
                utils.set_file_permissions(path)
            self.assertEqual(self._grant_principal(mock_run), 'IVAN\\ivan:RW')
        finally:
            os.unlink(path)

    @mock.patch('subprocess.run')
    @mock.patch('platform.system', return_value='Windows')
    @mock.patch('os.path.islink', return_value=False)
    def test_grant_uses_domain_principal(self, _islink, _system, mock_run):
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            path = os.path.realpath(tmp.name)
        try:
            with mock.patch.dict(os.environ, {'USERNAME': 'jdoe', 'USERDOMAIN': 'CORP'}, clear=False):
                utils.set_file_permissions(path)
            self.assertEqual(self._grant_principal(mock_run), 'CORP\\jdoe:RW')
        finally:
            os.unlink(path)

    @mock.patch('subprocess.run')
    @mock.patch('platform.system', return_value='Windows')
    @mock.patch('os.path.realpath', return_value=r'C:\Users\LongName\Temp\file.json')
    @mock.patch(
        'keepercommander.utils.os.lstat',
        return_value=SimpleNamespace(st_mode=stat.S_IFREG),
    )
    def test_canonical_path_alias_does_not_skip_permissions(
            self, _lstat, _realpath, _system, mock_run):
        """Windows short-path canonicalization must not skip ACL hardening."""
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            path = os.path.abspath(tmp.name)
        try:
            with mock.patch.dict(
                    os.environ, {'USERNAME': 'jdoe', 'USERDOMAIN': 'CORP'}, clear=False):
                utils.set_file_permissions(path)
            self.assertTrue(any(
                '/inheritance:r' in call.args[0]
                for call in mock_run.call_args_list
            ))
        finally:
            os.unlink(path)
