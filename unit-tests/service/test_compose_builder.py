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

import copy
import json
import os
import shutil
import stat
import subprocess
import tempfile
import time
import unittest
import uuid
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
        # hook is print-only (logs the URL, and reads - never mutates - Funnel status).
        self.assertEqual(services['tailscale']['environment']['TS_SERVE_CONFIG'],
                         '/etc/tailscale/serve.json')
        hook_cmd = services['tailscale']['post_start'][0]['command'][2]
        self.assertNotIn('funnel --bg', hook_cmd)
        self.assertNotIn('funnel reset', hook_cmd)
        self.assertNotIn('--https=', hook_cmd)

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

    def _hook(self):
        return _build(_base_config(tailscale_enabled=True, tailscale_auth_key='tskey-auth-xxx'))[
            'services']['tailscale']['post_start'][0]['command'][2]

    def _run_hook(self, allow_funnel_json_body, dns_name='commander-sailpoint-5.taildb15b0.ts.net'):
        """Runs the real generated hook under a stub `tailscale`. `allow_funnel_json_body`
        is either one JSON string (every poll returns it) or a list consumed one-per-poll,
        repeating the last entry once exhausted - lets a test simulate AllowFunnel turning
        true only after a few retries. Returns stdout written to /proc/1/fd/1's stand-in."""
        import os
        import stat
        import subprocess
        import tempfile

        bodies = allow_funnel_json_body if isinstance(allow_funnel_json_body, list) \
            else [allow_funnel_json_body]

        with tempfile.TemporaryDirectory() as bin_dir, tempfile.TemporaryDirectory() as work_dir:
            sink = os.path.join(work_dir, 'sink.txt')
            counter = os.path.join(work_dir, 'n')
            stub_path = os.path.join(bin_dir, 'tailscale')
            bodies_sh = ' '.join(f"'{b}'" for b in bodies)
            with open(stub_path, 'w') as f:
                f.write(
                    "#!/bin/sh\n"
                    "if [ \"$1\" = status ] && [ \"$2\" = \"--json\" ]; then\n"
                    f"  echo '{{\"Self\":{{\"DNSName\":\"{dns_name}.\"}}}}'; exit 0\n"
                    "fi\n"
                    "if [ \"$1\" = funnel ] && [ \"$2\" = status ] && [ \"$3\" = \"--json\" ]; then\n"
                    f"  N=$(cat '{counter}' 2>/dev/null || echo 0); echo $((N+1)) > '{counter}'\n"
                    f"  i=0; for b in {bodies_sh}; do [ \"$i\" -ge \"$N\" ] && break; i=$((i+1)); done\n"
                    "  echo \"$b\"; exit 0\n"
                    "fi\n"
                    "exit 0\n"
                )
            os.chmod(stub_path, os.stat(stub_path).st_mode | stat.S_IEXEC)

            script = self._hook().replace('$$', '$').replace('/proc/1/fd/1', sink)
            env = dict(os.environ, PATH=f"{bin_dir}:{os.environ.get('PATH', '')}")
            subprocess.run(['sh', '-c', script], env=env, timeout=15)

            if not os.path.exists(sink):
                return ''
            with open(sink) as f:
                return f.read()

    def test_url_hook_is_print_only_and_cannot_mutate_funnel(self):
        """Only a read is allowed - TS_SERVE_CONFIG stays the sole source of truth."""
        hook = self._hook()
        self.assertIn('Tailscale Funnel URL: https://', hook)
        self.assertIn('/proc/1/fd/1', hook)      # else the line never reaches docker logs
        self.assertIn('tailscale funnel status', hook)
        self.assertNotIn('funnel --bg', hook)
        self.assertNotIn('funnel reset', hook)
        self.assertNotIn('--https=', hook)

    def test_url_hook_finishes_well_inside_compose_up(self):
        """A hook still running when `up` completes gets SIGKILLed and tears the
        project down - the ~8s cap and clean exit avoid that."""
        hook = self._hook()
        self.assertIn('-lt 8', hook)
        self.assertIn('sleep 1;', hook)
        self.assertTrue(hook.rstrip().endswith('exit 0'))
        self.assertIn('h=$$(', hook)              # Compose-escaped
        self.assertNotIn('h=$(', hook)

    def test_url_hook_prints_url_only_when_funnel_is_actually_live(self):
        """A hostname alone isn't enough - must match tunneling.py's AllowFunnel check."""
        out = self._run_hook(
            '{"AllowFunnel":{"commander-sailpoint-5.taildb15b0.ts.net:443": true}}')
        self.assertIn('Tailscale Funnel URL: https://commander-sailpoint-5.taildb15b0.ts.net', out)

    def test_url_hook_tolerates_compact_json_with_no_space_after_colon(self):
        """Go's JSON encoders don't always add a space after ':' - match must not depend on it."""
        out = self._run_hook(
            '{"AllowFunnel":{"commander-sailpoint-5.taildb15b0.ts.net:443":true}}')
        self.assertIn('Tailscale Funnel URL: https://', out)

    def test_url_hook_falls_back_to_diagnostic_when_allow_funnel_missing(self):
        out = self._run_hook('{"AllowFunnel":{}}')
        self.assertNotIn('Tailscale Funnel URL:', out)
        self.assertIn('Funnel is not active', out)
        self.assertIn('tailscale funnel status', out)

    def test_url_hook_falls_back_to_diagnostic_when_allow_funnel_is_false(self):
        """AllowFunnel must be true, not just present - a plain `serve` has a Proxy entry too."""
        out = self._run_hook(
            '{"AllowFunnel":{"commander-sailpoint-5.taildb15b0.ts.net:443": false}}')
        self.assertNotIn('Tailscale Funnel URL:', out)
        self.assertIn('Funnel is not active', out)

    def test_url_hook_does_not_match_a_different_hosts_allow_funnel_entry(self):
        out = self._run_hook(
            '{"AllowFunnel":{"some-other-host.taildb15b0.ts.net:443": true}}')
        self.assertNotIn('Tailscale Funnel URL:', out)
        self.assertIn('Funnel is not active', out)

    def test_url_hook_retries_allow_funnel_check_before_falling_back(self):
        """Regression: TS_SERVE_CONFIG + the ACME fetch behind it can take 30s+ even
        though the hostname lands in ~2s. The hook used to check AllowFunnel once and
        give up; it must keep polling instead."""
        out = self._run_hook([
            '{"AllowFunnel":{}}',
            '{"AllowFunnel":{}}',
            '{"AllowFunnel":{"commander-sailpoint-5.taildb15b0.ts.net:443": true}}',
        ])
        self.assertIn('Tailscale Funnel URL: https://', out)
        self.assertNotIn('Funnel is not active', out)

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


DOCKER_SIGNIN_REQUIRED_MARKER = "Sign in to continue using Docker Desktop"


def _docker_compose_available():
    """True only if containers can actually run, not just that the `docker` binary
    or `docker info`/`compose version` succeed - confirmed experimentally that a
    Docker Desktop instance requiring org sign-in still returns exit 0 for those two,
    while `docker ps` (and any real container operation) fails identically to `up`."""
    if shutil.which('docker') is None:
        return False
    try:
        result = subprocess.run(['docker', 'ps'], capture_output=True, text=True, timeout=10)
        return result.returncode == 0
    except Exception:
        return False


@unittest.skipUnless(
    _docker_compose_available(),
    "requires a running Docker Engine with the Compose v2 plugin")
class TestTailscaleSidecarDockerSmoke(TestCase):
    """A real `docker compose up`, not mocks - covers the PR review's concern that the
    sidecar path (TS_SERVE_CONFIG, Compose lifecycle, hostname timing) could break on
    a slow first login. Only `tailscale`/`commander` images are swapped for a stub
    (busybox + fake `tailscale` CLI); post_start/healthcheck/networks/configs are
    exactly what production generates."""

    def _write_stub_tailscale(self, bin_dir, dns_delay_s):
        """`tailscale status` only exits 0 once dns_delay_s has elapsed, matching real
        containerboot - a stub that always exits 0 would hide a real slow-login case."""
        script = f"""#!/bin/sh
STATE_FILE=/tmp/.smoke_start_time
[ -f "$STATE_FILE" ] || date +%s > "$STATE_FILE"
ELAPSED=$(($(date +%s) - $(cat "$STATE_FILE")))

if [ "$1" = "status" ] && [ "$2" = "--json" ]; then
    if [ "$ELAPSED" -ge {dns_delay_s} ]; then
        echo '{{"Self":{{"DNSName":"smoketest-host.ts.net."}}}}'
    else
        echo '{{"Self":{{}}}}'
    fi
    exit 0
fi

if [ "$1" = "funnel" ] && [ "$2" = "status" ] && [ "$3" = "--json" ]; then
    if [ "$ELAPSED" -ge {dns_delay_s} ]; then
        echo '{{"AllowFunnel":{{"smoketest-host.ts.net:443": true}}}}'
    else
        echo '{{"AllowFunnel":{{}}}}'
    fi
    exit 0
fi

if [ "$1" = "status" ]; then
    [ "$ELAPSED" -ge {dns_delay_s} ] && exit 0 || exit 1
fi
exit 0
"""
        stub_path = os.path.join(bin_dir, 'tailscale')
        with open(stub_path, 'w') as f:
            f.write(script)
        os.chmod(stub_path, os.stat(stub_path).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    def _patched_compose_dict(self, bin_dir):
        """Real DockerComposeBuilder output, Tailscale enabled - only image/entrypoint
        swapped for the tailscale/commander services. post_start, healthcheck,
        networks, and configs are untouched, since those are what's under test."""
        config = {
            'port': 18900,
            'commands': 'ls',
            'tailscale_enabled': True,
            'tailscale_auth_key': 'tskey-auth-smoketest-not-real',
        }

        class _FakeSetupResult:
            b64_config = 'ZmFrZS1rc20tY29uZmln'
            record_uid = 'smoke-test-record-uid'

        compose = DockerComposeBuilder(_FakeSetupResult(), config).build_dict()
        compose = copy.deepcopy(compose)

        ts = compose['services']['tailscale']
        ts['image'] = 'busybox:stable'
        ts['healthcheck']['interval'] = '2s'
        ts['healthcheck']['retries'] = 90
        ts.setdefault('volumes', []).append(f'{bin_dir}:/usr/local/bin:ro')
        ts['entrypoint'] = ['sh', '-c']
        ts['command'] = ['tail -f /dev/null']

        cmd = compose['services']['commander']
        cmd['image'] = 'busybox:stable'
        cmd.pop('healthcheck', None)
        cmd.pop('command', None)
        cmd['entrypoint'] = ['sh', '-c']
        cmd['command'] = ['tail -f /dev/null']

        return compose

    def test_sidecar_survives_a_slow_first_login_without_tearing_down(self):
        """A slow login (e.g. a key-type switch burning `tailscale up`'s 60s timeout)
        must not SIGKILL the hook and tear the project down. Login forced to land at
        15s, past the hook's own ~8s bound, to test Compose's lifecycle, not the hook."""
        import yaml

        DNS_DELAY_S = 15
        project = f"ts-smoke-{uuid.uuid4().hex[:8]}"
        work_dir = tempfile.mkdtemp(prefix='tailscale_smoke_')
        bin_dir = os.path.join(work_dir, 'bin')
        os.makedirs(bin_dir)
        compose_path = os.path.join(work_dir, 'docker-compose.yml')

        try:
            self._write_stub_tailscale(bin_dir, DNS_DELAY_S)
            with open(compose_path, 'w') as f:
                yaml.dump(self._patched_compose_dict(bin_dir), f,
                          default_flow_style=False, sort_keys=False)

            up = subprocess.run(
                ['docker', 'compose', '-p', project, '-f', compose_path, 'up', '-d'],
                capture_output=True, text=True, timeout=60)
            if DOCKER_SIGNIN_REQUIRED_MARKER in up.stderr:
                self.skipTest("Docker Desktop requires sign-in in this environment "
                              "(flipped after the module-level availability check)")
            self.assertEqual(up.returncode, 0, f"`compose up` failed: {up.stderr}")

            # Past the hook's ~8s bound and the forced 15s login, before asserting.
            time.sleep(DNS_DELAY_S + 10)

            logs = subprocess.run(
                ['docker', 'compose', '-p', project, '-f', compose_path,
                 'logs', '--no-log-prefix', 'tailscale'],
                capture_output=True, text=True, timeout=30).stdout

            ps = subprocess.run(
                ['docker', 'compose', '-p', project, '-f', compose_path,
                 'ps', '-a', '--format', '{{.Service}}:{{.State}}'],
                capture_output=True, text=True, timeout=30).stdout

            self.assertNotIn('137', logs, f"hook was SIGKILLed - logs:\n{logs}")
            self.assertIn('tailscale', ps, f"project was torn down - `ps`: {ps}")
            self.assertIn('commander', ps, f"project was torn down - `ps`: {ps}")
            self.assertNotIn('exited', ps.lower(), f"a service exited unexpectedly:\n{ps}")
            # DNS_DELAY_S (15s) exceeds the hook's ~8s bound, so it exhausts and prints
            # nothing - expected. Retry behavior itself is covered faster by
            # test_url_hook_retries_allow_funnel_check_before_falling_back above.
            self.assertNotIn('Tailscale Funnel URL: https://', logs,
                             f"hook should not have had time to see the hostname at all:\n{logs}")
        finally:
            subprocess.run(['docker', 'compose', '-p', project, '-f', compose_path, 'down', '-v'],
                          capture_output=True, timeout=30)
            shutil.rmtree(work_dir, ignore_errors=True)


if __name__ == '__main__':
    unittest.main()
