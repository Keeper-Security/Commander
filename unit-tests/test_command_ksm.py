"""Unit tests for secrets-manager (KSM) CLI commands."""
import unittest
from unittest.mock import MagicMock, patch

from keepercommander.commands.ksm import KSMCommand


class TestKSMTokenAdd(unittest.TestCase):
    """secrets-manager token add <app-uid> → calls add_client."""

    def _make_params(self, record_uid='test-app-uid'):
        params = MagicMock()
        params.record_cache = {}
        return params

    @patch('keepercommander.commands.ksm.KSMCommand.add_client')
    def test_token_add_calls_add_client(self, mock_add_client):
        mock_add_client.return_value = [{'oneTimeToken': 'US:abc123', 'deviceToken': 'dt1'}]
        params = self._make_params()
        cmd = KSMCommand()
        result = cmd.execute(params, command=['token', 'add', 'MyApp'],
                             count=1, unlockIp=False, firstAccessExpiresIn=None,
                             accessExpireInMin=None, name=None, config_init=None,
                             returnTokens=False, format='table')
        mock_add_client.assert_called_once()
        call_args = mock_add_client.call_args
        assert call_args[0][1] == 'MyApp', f"Expected 'MyApp', got {call_args[0][1]}"

    @patch('keepercommander.commands.ksm.KSMCommand.add_client')
    def test_token_add_return_tokens(self, mock_add_client):
        mock_add_client.return_value = [{'oneTimeToken': 'US:tok1'}, {'oneTimeToken': 'US:tok2'}]
        params = self._make_params()
        cmd = KSMCommand()
        result = cmd.execute(params, command=['token', 'add', 'MyApp'],
                             count=2, unlockIp=False, firstAccessExpiresIn=None,
                             accessExpireInMin=None, name=None, config_init=None,
                             returnTokens=True, format='table')
        assert result == 'US:tok1, US:tok2', f"Expected 'US:tok1, US:tok2', got {result!r}"

    def test_token_add_missing_app_prints_help(self):
        params = self._make_params()
        cmd = KSMCommand()
        # Should print help and return None without calling add_client
        with patch('keepercommander.commands.ksm.KSMCommand.add_client') as mock_ac:
            result = cmd.execute(params, command=['token', 'add'],
                                 count=1, unlockIp=False, firstAccessExpiresIn=None,
                                 accessExpireInMin=None, name=None, config_init=None,
                                 returnTokens=False, format='table')
            mock_ac.assert_not_called()
            assert result is None, f"Expected None, got {result!r}"


if __name__ == '__main__':
    unittest.main()
