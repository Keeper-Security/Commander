#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
# Contact: commander@keepersecurity.com
#

from unittest import TestCase, mock

from keepercommander.service.docker.compose_builder import DockerComposeBuilder


def _base_config(**overrides):
    config = {
        'port': 8900,
        'commands': 'tree,ls',
        'queue_enabled': True,
        'ngrok_enabled': False,
        'ngrok_auth_token': '',
        'ngrok_custom_domain': '',
        'cloudflare_enabled': False,
        'cloudflare_tunnel_token': '',
        'cloudflare_custom_domain': '',
        'tailscale_enabled': False,
        'tailscale_auth_key': '',
        'tailscale_advertise_tags': '',
    }
    config.update(overrides)
    return config


def _build(config, commander_service_name='commander'):
    setup_result = mock.Mock(record_uid='rec-uid-123', b64_config='b64==')
    builder = DockerComposeBuilder(setup_result, config, commander_service_name=commander_service_name)
    return builder.build_dict()


def _command_for(config):
    return _build(config)['services']['commander']['command']


class TestNgrokCloudflareRegression(TestCase):
    """Adding the Tailscale sidecar must not change existing Ngrok/Cloudflare
    flag generation or the commander service's ports/network_mode."""

    def test_no_tunnel_enabled_produces_no_tunnel_flags(self):
        command = _command_for(_base_config())
        for flag in ('-ng', '-cf', '-ts', '-cd', '-cfd', '-tst'):
            self.assertNotIn(flag, command)

    def test_ngrok_enabled_produces_ng_and_cd_flags_unchanged(self):
        result = _build(_base_config(
            ngrok_enabled=True, ngrok_auth_token='ngrok-tok', ngrok_custom_domain='mydomain'
        ))
        command = result['services']['commander']['command']
        self.assertIn('-ng ngrok-tok', command)
        self.assertIn('-cd mydomain', command)
        self.assertNotIn('-cf', command)
        self.assertNotIn('-ts', command)
        # Ngrok/Cloudflare use the container's own published port, not the sidecar.
        self.assertIn('ports', result['services']['commander'])
        self.assertNotIn('network_mode', result['services']['commander'])
        self.assertNotIn('tailscale', result['services'])

    def test_cloudflare_enabled_produces_cf_and_cfd_flags_unchanged(self):
        result = _build(_base_config(
            cloudflare_enabled=True, cloudflare_tunnel_token='cf-tok', cloudflare_custom_domain='cf.example.com'
        ))
        command = result['services']['commander']['command']
        self.assertIn('-cf cf-tok', command)
        self.assertIn('-cfd cf.example.com', command)
        self.assertNotIn('-ng', command)
        self.assertNotIn('-ts', command)
        self.assertIn('ports', result['services']['commander'])
        self.assertNotIn('network_mode', result['services']['commander'])
        self.assertNotIn('tailscale', result['services'])


class TestTailscaleSidecar(TestCase):
    """Tailscale runs as a sidecar (official tailscale/tailscale image), not a
    service-create flag -- Docker deployments are headless and can't answer the
    install/daemon-start prompts -ts would otherwise trigger inside the container."""

    def test_tailscale_enabled_adds_sidecar_and_funnel_init_services(self):
        result = _build(_base_config(
            tailscale_enabled=True, tailscale_auth_key='tskey-auth-xxx',
            tailscale_advertise_tags='tag:commander-service'
        ), commander_service_name='commander-slack')
        services = result['services']

        self.assertIn('tailscale', services)
        self.assertEqual(services['tailscale']['image'], 'tailscale/tailscale:latest')
        self.assertEqual(services['tailscale']['hostname'], 'commander-slack')
        self.assertEqual(services['tailscale']['environment']['TS_AUTHKEY'], 'tskey-auth-xxx')
        self.assertIn('--advertise-tags=tag:commander-service', services['tailscale']['environment']['TS_EXTRA_ARGS'])
        self.assertIn('--force-reauth', services['tailscale']['environment']['TS_EXTRA_ARGS'])

        # Funnel is enabled via a post_start hook inside the sidecar's own
        # container -- a separate container sharing only the network namespace
        # can't reach tailscaled's control socket (verified empirically).
        post_start_cmd = services['tailscale']['post_start'][0]['command']
        self.assertEqual(post_start_cmd[:2], ['sh', '-c'])
        self.assertIn('tailscale funnel --bg --https=443 localhost:8900', post_start_cmd[2])

    def test_tailscale_enabled_without_tags_omits_advertise_tags_arg(self):
        result = _build(_base_config(tailscale_enabled=True, tailscale_auth_key='tskey-auth-xxx'))
        extra_args = result['services']['tailscale']['environment']['TS_EXTRA_ARGS']
        self.assertNotIn('--advertise-tags', extra_args)
        self.assertIn('--force-reauth', extra_args)

    def test_tailscale_enabled_reconfigures_commander_service_networking(self):
        result = _build(_base_config(tailscale_enabled=True, tailscale_auth_key='tskey-auth-xxx'))
        commander = result['services']['commander']

        self.assertNotIn('ports', commander)
        self.assertEqual(commander['network_mode'], 'service:tailscale')
        self.assertEqual(commander['depends_on']['tailscale'], {'condition': 'service_healthy'})
        # Tailscale is not passed as a service-create flag.
        for flag in ('-ts', '-tst'):
            self.assertNotIn(flag, commander['command'])

    def test_tailscale_enabled_declares_persistent_state_volume(self):
        result = _build(_base_config(tailscale_enabled=True, tailscale_auth_key='tskey-auth-xxx'))
        self.assertIn('tailscale-state', result.get('volumes', {}))
        self.assertIn('tailscale-state:/var/lib/tailscale', result['services']['tailscale']['volumes'])

    def test_tailscale_enabled_but_no_auth_key_adds_no_sidecar(self):
        """Mirrors ngrok/cloudflare's own guard - enabled alone isn't enough
        without the actual credential."""
        result = _build(_base_config(tailscale_enabled=True, tailscale_auth_key=''))
        self.assertNotIn('tailscale', result['services'])
        self.assertNotIn('volumes', result)
        self.assertIn('ports', result['services']['commander'])

    def test_no_tailscale_produces_no_volumes_key(self):
        result = _build(_base_config())
        self.assertNotIn('volumes', result)


if __name__ == '__main__':
    import unittest
    unittest.main()
