import unittest
from unittest import mock

from keepercommander.service.config.tailscale_config import TailscaleConfigurator


def _base_config_data():
    return {
        "tailscale": "y",
        "port": 8080,
        "tailscale_auth_key": "tskey-auth-xxx",
        "tailscale_advertise_tags": "",
        "run_mode": "foreground",
        "tailscale_public_url": "",
    }


class TestVerifyFunnelActive(unittest.TestCase):
    def test_returns_true_immediately_when_already_active(self):
        with mock.patch('keepercommander.service.config.tailscale_config.get_tailscale_funnel_status', return_value=True) as mock_status:
            self.assertTrue(TailscaleConfigurator._verify_funnel_active(8080, max_retries=3, retry_delay=0))
            mock_status.assert_called_once_with(8080)

    def test_retries_before_succeeding(self):
        """A slower daemon-side registration can take a beat after `--bg` returns -
        the check must retry rather than declaring failure on the first miss."""
        with mock.patch('keepercommander.service.config.tailscale_config.get_tailscale_funnel_status',
                         side_effect=[False, False, True]) as mock_status, \
             mock.patch('time.sleep'):
            self.assertTrue(TailscaleConfigurator._verify_funnel_active(8080, max_retries=3, retry_delay=0))
            self.assertEqual(mock_status.call_count, 3)

    def test_returns_false_after_exhausting_retries(self):
        with mock.patch('keepercommander.service.config.tailscale_config.get_tailscale_funnel_status', return_value=False), \
             mock.patch('time.sleep'):
            self.assertFalse(TailscaleConfigurator._verify_funnel_active(8080, max_retries=3, retry_delay=0))


class TestConfigureTailscaleVerification(unittest.TestCase):
    """configure_tailscale's Funnel-active verification and rollback, added after a
    live approval-pending case showed `tailscale funnel --bg` can exit 0 without the
    target ever actually going live."""

    def _patch_happy_path_prereqs(self):
        return [
            mock.patch('keepercommander.service.config.tailscale_config.reset_tailscale_log'),
            mock.patch.object(TailscaleConfigurator, '_ensure_ready'),
            mock.patch.object(TailscaleConfigurator, '_validate_tailscale_config'),
            mock.patch('keepercommander.service.config.tailscale_config.tailscale_up'),
            mock.patch('keepercommander.service.config.tailscale_config.start_tailscale_funnel'),
        ]

    def test_rolls_back_and_raises_when_funnel_never_becomes_active(self):
        config_data = _base_config_data()
        patches = self._patch_happy_path_prereqs()
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
             mock.patch.object(TailscaleConfigurator, '_verify_funnel_active', return_value=False), \
             mock.patch('keepercommander.service.config.tailscale_config.stop_tailscale_funnel') as mock_stop, \
             mock.patch('keepercommander.service.config.tailscale_config.get_tailscale_funnel_url') as mock_get_url:
            with self.assertRaises(Exception):
                TailscaleConfigurator.configure_tailscale(config_data, mock.Mock())

            mock_stop.assert_called_once_with(config_data["port"])
            # Must fail before ever asking for the public URL - there isn't a live one.
            mock_get_url.assert_not_called()

    def test_rollback_failure_does_not_mask_the_original_error(self):
        """stop_tailscale_funnel itself failing during rollback must not swallow or
        replace the original 'Funnel never became active' error."""
        config_data = _base_config_data()
        patches = self._patch_happy_path_prereqs()
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
             mock.patch.object(TailscaleConfigurator, '_verify_funnel_active', return_value=False), \
             mock.patch('keepercommander.service.config.tailscale_config.stop_tailscale_funnel',
                         side_effect=Exception("reset failed too")):
            with self.assertRaisesRegex(Exception, "did not become active"):
                TailscaleConfigurator.configure_tailscale(config_data, mock.Mock())

    def test_succeeds_and_fetches_url_when_funnel_is_verified_active(self):
        config_data = _base_config_data()
        patches = self._patch_happy_path_prereqs()
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
             mock.patch.object(TailscaleConfigurator, '_verify_funnel_active', return_value=True), \
             mock.patch('keepercommander.service.config.tailscale_config.get_tailscale_funnel_url',
                         return_value='https://node.example.ts.net') as mock_get_url:
            result = TailscaleConfigurator.configure_tailscale(config_data, mock.Mock())

            self.assertIsNone(result)
            mock_get_url.assert_called_once_with(config_data["port"])
            self.assertEqual(config_data["tailscale_public_url"], 'https://node.example.ts.net')


if __name__ == '__main__':
    unittest.main()
