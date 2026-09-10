import unittest
from unittest import mock

from keepercommander.service.util.process_util import (
    spawn_detached_process, CREATE_NO_WINDOW, DETACHED_PROCESS, CREATE_NEW_PROCESS_GROUP
)


class TestSpawnDetachedProcess(unittest.TestCase):
    """These force sys.platform to 'darwin' to exercise the POSIX branch regardless of
    the machine actually running the tests. os.setpgrp doesn't exist on a real Windows
    os module, so it needs create=True wherever that branch is forced on Windows CI."""

    def test_default_mode_truncates_log_file(self):
        with mock.patch('builtins.open', mock.mock_open()) as mock_open, \
             mock.patch('keepercommander.service.util.process_util.subprocess.Popen'), \
             mock.patch('keepercommander.service.util.process_util.os.setpgrp', create=True), \
             mock.patch('keepercommander.service.util.process_util.sys.platform', 'darwin'):
            spawn_detached_process(['cmd'], '/tmp/test.log')
            mock_open.assert_called_once_with('/tmp/test.log', 'w')

    def test_append_mode_preserves_log_history(self):
        with mock.patch('builtins.open', mock.mock_open()) as mock_open, \
             mock.patch('keepercommander.service.util.process_util.subprocess.Popen'), \
             mock.patch('keepercommander.service.util.process_util.os.setpgrp', create=True), \
             mock.patch('keepercommander.service.util.process_util.sys.platform', 'darwin'):
            spawn_detached_process(['cmd'], '/tmp/test.log', append=True)
            mock_open.assert_called_once_with('/tmp/test.log', 'a')

    def test_windows_uses_hidden_detached_creation_flags(self):
        with mock.patch('builtins.open', mock.mock_open()), \
             mock.patch('keepercommander.service.util.process_util.subprocess.Popen') as mock_popen, \
             mock.patch('keepercommander.service.util.process_util.sys.platform', 'win32'):
            spawn_detached_process(['cmd'], '/tmp/test.log', cwd='/work', env={'A': '1'})

            _, kwargs = mock_popen.call_args
            self.assertEqual(
                kwargs['creationflags'],
                DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW
            )
            self.assertEqual(kwargs['cwd'], '/work')
            self.assertEqual(kwargs['env'], {'A': '1'})
            self.assertNotIn('preexec_fn', kwargs)

    def test_posix_uses_new_process_group_via_preexec(self):
        with mock.patch('builtins.open', mock.mock_open()), \
             mock.patch('keepercommander.service.util.process_util.subprocess.Popen') as mock_popen, \
             mock.patch('keepercommander.service.util.process_util.sys.platform', 'darwin'), \
             mock.patch('keepercommander.service.util.process_util.os.setpgrp', create=True):
            spawn_detached_process(['cmd'], '/tmp/test.log')

            _, kwargs = mock_popen.call_args
            self.assertNotIn('creationflags', kwargs)
            self.assertIn('preexec_fn', kwargs)

    def test_returns_the_popen_object(self):
        with mock.patch('builtins.open', mock.mock_open()), \
             mock.patch('keepercommander.service.util.process_util.subprocess.Popen') as mock_popen, \
             mock.patch('keepercommander.service.util.process_util.os.setpgrp', create=True), \
             mock.patch('keepercommander.service.util.process_util.sys.platform', 'darwin'):
            mock_process = mock.Mock()
            mock_popen.return_value = mock_process

            result = spawn_detached_process(['cmd'], '/tmp/test.log')
            self.assertIs(result, mock_process)


if __name__ == '__main__':
    unittest.main()
