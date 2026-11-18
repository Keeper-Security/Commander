"""docker-entrypoint.sh must keep its own diagnostics off stdout.

Scripts do `docker run ... get --format password <uid>` and capture stdout, so
stdout has to carry only what the wrapped Commander command printed.
"""
import os
import shutil
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

ENTRYPOINT = Path(__file__).resolve().parent.parent / 'docker-entrypoint.sh'
SECRET = 'correct-horse-battery-staple'


@unittest.skipUnless(shutil.which('bash'), 'bash is required')
class TestDockerEntrypointStdout(unittest.TestCase):

    def _run(self, with_config):
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            keeper_dir = tmp_path / 'keeper'
            keeper_dir.mkdir()
            if with_config:
                (keeper_dir / 'config.json').write_text('{}')

            # The script hard-codes /home/commander/.keeper; point it at a temp dir.
            script = tmp_path / 'docker-entrypoint.sh'
            text = ENTRYPOINT.read_text().replace('/home/commander/.keeper', str(keeper_dir))
            script.write_text(text)

            # Stand-in for `python3 keeper.py ...`: a shell function, loaded through
            # BASH_ENV, that prints only the "secret".
            stub = tmp_path / 'stub.sh'
            stub.write_text('python3() { echo %s; }\n' % SECRET)

            env = {k: v for k, v in os.environ.items() if not k.startswith('BASH_FUNC_')}
            env['BASH_ENV'] = str(stub)
            env.pop('KEEPER_KEEP_ALIVE', None)
            return subprocess.run(
                ['bash', str(script), 'get', '--format', 'password', 'UID123'],
                cwd=tmp, env=env, capture_output=True, text=True, timeout=60)

    def test_config_auth_stdout_has_only_command_output(self):
        result = self._run(with_config=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, SECRET + '\n')

    def test_config_auth_logs_still_reach_stderr(self):
        result = self._run(with_config=True)
        self.assertIn('Config file found', result.stderr)
        self.assertIn('Cleanup completed', result.stderr)

    def test_no_auth_fallback_stdout_has_only_command_output(self):
        result = self._run(with_config=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, SECRET + '\n')
