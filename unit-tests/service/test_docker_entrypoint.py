import base64
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


class TestDockerEntrypointFederatedLogin(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.keeper_dir = self.root / '.keeper'
        self.keeper_dir.mkdir()
        self.bin_dir = self.root / 'bin'
        self.bin_dir.mkdir()
        self.call_log = self.root / 'calls.log'
        self._write_command_stubs()

        repo_root = Path(__file__).resolve().parents[2]
        entrypoint = (repo_root / 'docker-entrypoint.sh').read_text()
        entrypoint = entrypoint.replace(
            'readonly KEEPER_DIR="/home/commander/.keeper"',
            'readonly KEEPER_DIR="${TEST_KEEPER_DIR}"',
        )
        self.entrypoint = self.root / 'docker-entrypoint.sh'
        self.entrypoint.write_text(entrypoint)
        self.entrypoint.chmod(0o755)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _write_command_stubs(self):
        python_stub = self.bin_dir / 'python3'
        python_stub.write_text(
            """#!/bin/bash
printf '%s|fed=%s|token=%s\\n' "$*" "${KEEPER_FEDERATED_CONFIG:-}" \\
    "${KEEPER_OIDC_TOKEN_FILE:-}" >> "${ENTRYPOINT_CALL_LOG}"

if [[ "$1" == "docker_ksm_utility.py" ]]; then
    command="$2"
    shift 2
    case "${command}" in
        download-attachment)
            file_name=""
            output_file=""
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    --file-name) file_name="$2"; shift 2 ;;
                    --output-file) output_file="$2"; shift 2 ;;
                    *) shift ;;
                esac
            done
            if [[ "${file_name}" == "federated-config.json" ]]; then
                printf '%s\\n' '{"authType":"oauth","hostname":"keepersecurity.com","clientId":"demo","dataKey":"ZGF0YQ=="}' > "${output_file}"
            else
                printf '%s\\n' 'header.payload.signature' > "${output_file}"
            fi
            ;;
        download)
            output_file=""
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    --config-file) output_file="$2"; shift 2 ;;
                    *) shift ;;
                esac
            done
            printf '%s\\n' '{"user":"demo@example.com"}' > "${output_file}"
            ;;
    esac
elif [[ "$1" == "keeper.py" && " $* " == *" service-status "* ]]; then
    printf '%s\\n' 'No service status'
fi
"""
        )
        python_stub.chmod(0o755)

        for command in ('sleep', 'pkill'):
            stub = self.bin_dir / command
            stub.write_text('#!/bin/bash\nexit 0\n')
            stub.chmod(0o755)

    def _run_entrypoint(self, *args, **extra_env):
        env = os.environ.copy()
        env.update({
            'PATH': f'{self.bin_dir}{os.pathsep}{env.get("PATH", "")}',
            'TEST_KEEPER_DIR': str(self.keeper_dir),
            'ENTRYPOINT_CALL_LOG': str(self.call_log),
            'KEEPER_KEEP_ALIVE': 'false',
        })
        env.update(extra_env)
        return subprocess.run(
            ['bash', str(self.entrypoint), *args],
            env=env,
            text=True,
            capture_output=True,
            timeout=10,
        )

    def _calls(self):
        return self.call_log.read_text().splitlines() if self.call_log.exists() else []

    def test_existing_config_takes_precedence_over_oidc_environment(self):
        config = self.keeper_dir / 'config.json'
        config.write_text('{"user":"local@example.com"}')
        result = self._run_entrypoint(
            '--ksm-token', 'bootstrap-token',
            '--record', 'record-uid',
            'service-create', '-p', '8900',
            KEEPER_FEDERATED_CONFIG='/external/federated-config.json',
        )

        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        keeper_calls = [call for call in self._calls() if call.startswith('keeper.py ')]
        self.assertTrue(any(f'--config {config}' in call for call in keeper_calls))
        self.assertTrue(any('service-create -p 8900' in call for call in keeper_calls))
        self.assertTrue(all('fed=|token=' in call for call in keeper_calls))
        self.assertFalse(any('download-attachment' in call for call in self._calls()))

    def test_direct_federated_environment_does_not_require_ksm_bootstrap(self):
        config = self.root / 'mounted-federated-config.json'
        token = self.root / 'mounted-token.jwt'
        config.write_text('{"authType":"oauth"}')
        token.write_text('header.payload.signature')
        result = self._run_entrypoint(
            'service-create', '-p', '8900',
            KEEPER_FEDERATED_CONFIG=str(config),
            KEEPER_OIDC_TOKEN_FILE=str(token),
        )

        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        keeper_calls = [call for call in self._calls() if call.startswith('keeper.py ')]
        self.assertTrue(any('service-create -p 8900' in call and '--config' not in call
                            for call in keeper_calls))
        self.assertTrue(all('fed=|token=' not in call for call in keeper_calls))
        self.assertFalse(any('download-attachment' in call for call in self._calls()))

    def test_inline_federated_config_and_projected_token_need_no_ksm(self):
        config = base64.b64encode(
            json.dumps({
                'authType': 'oauth',
                'hostname': 'keepersecurity.com',
                'clientId': 'demo',
                'dataKey': 'ZGF0YQ==',
            }).encode()
        ).decode()
        token = self.root / 'projected-token.jwt'
        token.write_text('header.payload.signature')
        result = self._run_entrypoint(
            'service-create', '-p', '8900',
            KEEPER_FEDERATED_CONFIG=config,
            KEEPER_OIDC_TOKEN_FILE=str(token),
        )

        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        keeper_calls = [call for call in self._calls() if call.startswith('keeper.py ')]
        self.assertTrue(any('service-create -p 8900' in call and '--config' not in call
                            for call in keeper_calls))
        self.assertFalse(any('download-attachment' in call for call in self._calls()))

    def test_managed_oidc_downloads_only_federated_attachments(self):
        managed_config = self.keeper_dir / 'federated-config.json'
        managed_token = self.keeper_dir / 'oidc-token.jwt'
        result = self._run_entrypoint(
            '--ksm-token', 'bootstrap-token',
            '--record', 'record-uid',
            'service-create', '-p', '8900',
            KEEPER_FEDERATED_CONFIG=str(managed_config),
            KEEPER_OIDC_TOKEN_FILE=str(managed_token),
        )

        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        calls = self._calls()
        downloads = [call for call in calls if 'download-attachment' in call]
        self.assertEqual(len(downloads), 2)
        self.assertTrue(any('federated-config.json' in call for call in downloads))
        self.assertTrue(any('oidc-token.jwt' in call for call in downloads))
        self.assertFalse(any(
            'docker_ksm_utility.py download|' in call for call in calls
        ))
        keeper_calls = [call for call in calls if call.startswith('keeper.py ')]
        self.assertTrue(any('service-create -p 8900' in call for call in keeper_calls))
        self.assertTrue(managed_config.is_file())
        self.assertTrue(managed_token.is_file())
        self.assertFalse(any(self.keeper_dir.glob('oidc-runtime-config.*')))


if __name__ == '__main__':
    unittest.main()
