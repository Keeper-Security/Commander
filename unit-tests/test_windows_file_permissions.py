import os
import tempfile
from unittest import TestCase, mock

from keepercommander import utils


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
            path = tmp.name
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
            path = tmp.name
        try:
            with mock.patch.dict(os.environ, {'USERNAME': 'jdoe', 'USERDOMAIN': 'CORP'}, clear=False):
                utils.set_file_permissions(path)
            self.assertEqual(self._grant_principal(mock_run), 'CORP\\jdoe:RW')
        finally:
            os.unlink(path)
