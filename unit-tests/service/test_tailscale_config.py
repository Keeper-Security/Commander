import unittest
from unittest import mock

from keepercommander.service.config.tailscale_config import TailscaleConfigurator
from keepercommander.service.util.tunneling import TailscaleAccessDeniedError
from keepercommander.service.util.exceptions import ValidationError


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


class TestAuthenticate(unittest.TestCase):
    """The one-time Tailscale operator-grant fallback for tailscale_up failing
    with TailscaleAccessDeniedError - common on a fresh Linux install where the
    control socket is root-owned by default."""

    def test_retries_and_succeeds_after_operator_granted(self):
        config_data = _base_config_data()
        service_config = mock.Mock()
        service_config._get_yes_no_input.return_value = 'y'

        with mock.patch('keepercommander.service.config.tailscale_config.tailscale_up',
                         side_effect=[TailscaleAccessDeniedError("denied"), None]) as mock_up, \
             mock.patch('keepercommander.service.config.tailscale_config.set_tailscale_operator') as mock_set_op:
            TailscaleConfigurator._authenticate(config_data, service_config)

            self.assertEqual(mock_up.call_count, 2)
            mock_set_op.assert_called_once()

    def test_declining_raises_validation_error_without_granting(self):
        config_data = _base_config_data()
        service_config = mock.Mock()
        service_config._get_yes_no_input.return_value = 'n'

        with mock.patch('keepercommander.service.config.tailscale_config.tailscale_up',
                         side_effect=TailscaleAccessDeniedError("denied")), \
             mock.patch('keepercommander.service.config.tailscale_config.set_tailscale_operator') as mock_set_op:
            with self.assertRaises(ValidationError):
                TailscaleConfigurator._authenticate(config_data, service_config)
            mock_set_op.assert_not_called()

    def test_second_failure_after_operator_grant_propagates(self):
        """If granting operator rights doesn't actually fix it, the retry's
        failure must propagate rather than being silently swallowed or retried forever."""
        config_data = _base_config_data()
        service_config = mock.Mock()
        service_config._get_yes_no_input.return_value = 'y'

        with mock.patch('keepercommander.service.config.tailscale_config.tailscale_up',
                         side_effect=[TailscaleAccessDeniedError("denied"), Exception("still failing")]), \
             mock.patch('keepercommander.service.config.tailscale_config.set_tailscale_operator'):
            with self.assertRaisesRegex(Exception, "still failing"):
                TailscaleConfigurator._authenticate(config_data, service_config)

    def test_non_access_denied_failure_is_not_caught_here(self):
        config_data = _base_config_data()
        service_config = mock.Mock()

        with mock.patch('keepercommander.service.config.tailscale_config.tailscale_up',
                         side_effect=Exception("some other failure")):
            with self.assertRaisesRegex(Exception, "some other failure"):
                TailscaleConfigurator._authenticate(config_data, service_config)
            service_config._get_yes_no_input.assert_not_called()


if __name__ == '__main__':
    unittest.main()
