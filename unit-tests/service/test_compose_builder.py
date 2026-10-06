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

import json
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


def _build(config, commander_service_name='commander', commander_container_name='keeper-service'):
    setup_result = mock.Mock(record_uid='rec-uid-123', b64_config='b64==')
    builder = DockerComposeBuilder(
        setup_result, config,
        commander_service_name=commander_service_name,
        commander_container_name=commander_container_name,
    )
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
        # No --force-reauth: it would re-validate the key every boot, breaking
        # single-use keys from boot 2 and expired ones permanently.
        self.assertNotIn('--force-reauth', services['tailscale']['environment']['TS_EXTRA_ARGS'])

        # Declared, not executed: containerboot applies TS_SERVE_CONFIG itself. The only
        # hook is print-only (logs the URL) and never touches Funnel config.
        self.assertEqual(services['tailscale']['environment']['TS_SERVE_CONFIG'],
                         '/etc/tailscale/serve.json')
        self.assertNotIn('tailscale funnel', services['tailscale']['post_start'][0]['command'][2])

    def test_tailscale_container_name_matches_commander_naming_convention(self):
        """Without an explicit container_name, Compose falls back to
        <project>-tailscale-1 (unpredictable/inconsistent). Derive a real name
        matching the existing keeper-service[-<integration>] convention instead."""
        result = _build(
            _base_config(tailscale_enabled=True, tailscale_auth_key='tskey-auth-xxx'),
            commander_service_name='commander-slack',
            commander_container_name='keeper-service-slack',
        )
        self.assertEqual(result['services']['tailscale']['container_name'], 'keeper-tailscale-slack')

    def test_tailscale_container_name_default_no_integration_suffix(self):
        result = _build(_base_config(tailscale_enabled=True, tailscale_auth_key='tskey-auth-xxx'))
        self.assertEqual(result['services']['tailscale']['container_name'], 'keeper-tailscale')

    def test_tailscale_enabled_without_tags_still_states_advertise_tags_explicitly(self):
        """`--advertise-tags` must always be explicit (empty if unused), never omitted -
        `tailscale up` requires every non-default setting restated on each call or it
        errors out, and omitting the flag doesn't clear a tag left by a prior run on
        the same node/volume (e.g. switching from an OAuth key to a plain key)."""
        result = _build(_base_config(tailscale_enabled=True, tailscale_auth_key='tskey-auth-xxx'))
        extra_args = result['services']['tailscale']['environment']['TS_EXTRA_ARGS']
        self.assertIn('--advertise-tags=', extra_args)
        self.assertNotIn('--advertise-tags=tag', extra_args)
        self.assertNotIn('--force-reauth', extra_args)

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

    def test_no_tailscale_produces_no_volumes_or_configs_key(self):
        result = _build(_base_config())
        self.assertNotIn('volumes', result)
        self.assertNotIn('configs', result)

    def _serve_config(self):
        """Serve config as the container reads it - Compose turns `$$` into `$`."""
        result = _build(_base_config(tailscale_enabled=True, tailscale_auth_key='tskey-auth-xxx'))
        raw = result['configs']['tailscale-serve-config']['content']
        return json.loads(raw.replace('$$', '$'))

    def test_funnel_declared_via_serve_config_not_by_the_hook(self):
        """Funnel config must come from TS_SERVE_CONFIG, never the hook: the hostname can
        land after `tailscale up` returns, which once stranded Funnel on a dead name."""
        sidecar = _build(_base_config(tailscale_enabled=True, tailscale_auth_key='tskey-auth-xxx'))[
            'services']['tailscale']
        self.assertEqual(sidecar['environment']['TS_SERVE_CONFIG'], '/etc/tailscale/serve.json')
        self.assertEqual(sidecar['configs'],
                         [{'source': 'tailscale-serve-config', 'target': '/etc/tailscale/serve.json'}])

    def test_url_hook_is_print_only_and_cannot_configure_funnel(self):
        hook = _build(_base_config(tailscale_enabled=True, tailscale_auth_key='tskey-auth-xxx'))[
            'services']['tailscale']['post_start'][0]['command'][2]
        self.assertIn('Tailscale Funnel URL: https://', hook)
        self.assertIn('/proc/1/fd/1', hook)      # else the line never reaches docker logs
        self.assertNotIn('tailscale funnel', hook)
        self.assertNotIn('funnel reset', hook)

    def test_url_hook_finishes_well_inside_compose_up(self):
        """Compose SIGKILLs a hook still running when `up` completes and tears the
        project down (reproduced in Docker), so the wait must stay short - verified that
        an ~8s cap prints on a normal start and exits cleanly when the hostname never
        appears, leaving both containers running either way."""
        hook = _build(_base_config(tailscale_enabled=True, tailscale_auth_key='tskey-auth-xxx'))[
            'services']['tailscale']['post_start'][0]['command'][2]
        self.assertIn('-lt 8', hook)
        self.assertIn('sleep 1;', hook)
        self.assertTrue(hook.rstrip().endswith('exit 0'))
        self.assertIn('h=$$(', hook)              # Compose-escaped
        self.assertNotIn('h=$(', hook)

    def test_serve_config_uses_cert_domain_placeholder_escaped_for_compose(self):
        """Bare ${TS_CERT_DOMAIN} would be interpolated away by Compose, handing
        containerboot an empty hostname."""
        raw = _build(_base_config(tailscale_enabled=True, tailscale_auth_key='tskey-auth-xxx'))[
            'configs']['tailscale-serve-config']['content']
        self.assertIn('$${TS_CERT_DOMAIN}:443', raw)
        self.assertNotIn('${TS_CERT_DOMAIN}', raw.replace('$${TS_CERT_DOMAIN}', ''))

    def test_serve_config_declares_funnel_for_the_commander_port(self):
        cfg = self._serve_config()
        host_port = '${TS_CERT_DOMAIN}:443'
        self.assertEqual(cfg['TCP'], {'443': {'HTTPS': True}})
        self.assertEqual(cfg['Web'][host_port]['Handlers']['/']['Proxy'], 'http://localhost:8900')
        # AllowFunnel is what makes this public Funnel, not tailnet-only Serve
        self.assertTrue(cfg['AllowFunnel'][host_port])

    def test_sidecar_healthcheck_stays_a_plain_liveness_probe(self):
        """Gating it on extra state once wedged the sidecar permanently unhealthy."""
        sidecar = _build(_base_config(tailscale_enabled=True, tailscale_auth_key='tskey-auth-xxx'))[
            'services']['tailscale']
        self.assertEqual(sidecar['healthcheck']['test'], ['CMD', 'tailscale', 'status'])

    def test_sidecar_healthcheck_tolerates_a_slow_first_login(self):
        """A key-type switch burns `tailscale up`'s 60s timeout plus a tailscaled
        restart; without start_period those failures could mark the sidecar unhealthy
        and abort commander's depends_on wait."""
        hc = _build(_base_config(tailscale_enabled=True, tailscale_auth_key='tskey-auth-xxx'))[
            'services']['tailscale']['healthcheck']
        self.assertEqual(hc['start_period'], '120s')

    def test_sidecar_gets_network_alias_for_commander_service_name(self):
        """network_mode: service:tailscale means commander isn't a named member of
        the compose network on its own - hostname: on the sidecar doesn't register
        a DNS alias either, so a sibling integration container resolving e.g.
        commander-slack:<port> would fail without this."""
        result = _build(
            _base_config(tailscale_enabled=True, tailscale_auth_key='tskey-auth-xxx'),
            commander_service_name='commander-slack',
        )
        aliases = result['services']['tailscale']['networks']['default']['aliases']
        self.assertIn('commander-slack', aliases)

    def test_sidecar_publishes_the_host_port_commander_lost(self):
        """commander's own 127.0.0.1:<port>:<port> binding is popped when Tailscale
        is enabled (it no longer has its own network identity) - printer.py's
        unconditional 'curl http://localhost:<port>/health' guidance only keeps
        working if something still publishes that port, so the sidecar does."""
        result = _build(_base_config(tailscale_enabled=True, tailscale_auth_key='tskey-auth-xxx'))
        self.assertIn('127.0.0.1:8900:8900', result['services']['tailscale']['ports'])

    def test_integration_service_combined_with_tailscale(self):
        """No existing test combined an integration service with Tailscale enabled -
        this is the exact scenario Blocker 2 was found in: the sidecar's network
        alias must be present so a sibling integration container can still resolve
        the commander service by its original name."""
        setup_result = mock.Mock(record_uid='rec-uid-123', b64_config='b64==')
        builder = DockerComposeBuilder(
            setup_result,
            _base_config(tailscale_enabled=True, tailscale_auth_key='tskey-auth-xxx'),
            commander_service_name='commander-slack',
            commander_container_name='keeper-service-slack',
        )
        builder.add_integration_service(
            'slack-app', 'keeper-slack-app', 'keeper/slack-app:latest', 'rec-uid-123', 'SLACK_RECORD_UID',
        )
        result = builder.build_dict()

        self.assertIn('tailscale', result['services'])
        self.assertIn('slack-app', result['services'])
        aliases = result['services']['tailscale']['networks']['default']['aliases']
        self.assertIn('commander-slack', aliases)
        # The integration service's own depends_on/networking is untouched by Tailscale.
        self.assertEqual(
            result['services']['slack-app']['depends_on'], {'commander-slack': {'condition': 'service_healthy'}}
        )


if __name__ == '__main__':
    import unittest
    unittest.main()
