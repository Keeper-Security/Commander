import hashlib
import io
import json
import os
import shutil
import sys
import tarfile
import tempfile
import zipfile
from unittest import TestCase, mock

from keepercommander import updater, versioning


def make_archive(path, version='9.9.9', extra=None):
    """tar.gz with the layout produced by the build: keeper-commander/keeper-commander"""
    with tarfile.open(path, 'w:gz') as tf:
        data = ('#!/bin/sh\necho {0}\n'.format(version)).encode()
        ti = tarfile.TarInfo('keeper-commander/keeper-commander')
        ti.size = len(data)
        ti.mode = 0o755
        tf.addfile(ti, io.BytesIO(data))
        for ti, payload in (extra or []):
            tf.addfile(ti, io.BytesIO(payload) if payload is not None else None)


def sha256_of(path):
    with open(path, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()


class FakeResponse(object):
    def __init__(self, content=b'', url='https://example.com/a', status=200, text=None):
        self.content = content
        self.url = url
        self.status_code = status
        self.text = text if text is not None else content.decode(errors='replace')

    def raise_for_status(self):
        if self.status_code >= 400:
            import requests
            raise requests.HTTPError(str(self.status_code))

    def iter_content(self, chunk_size=0):
        yield self.content

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class TempDirTestCase(TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)


class TestMeta(TestCase):
    def test_parse_meta(self):
        text = ('keeper-commander.version=17.2.0\n'
                'keeper-commander.url.linux_x86_64=https://h/a.tar.gz\n'
                'keeper-commander.sha256.linux_x86_64=abc\n'
                'something.else=1\n\n')
        meta = updater.parse_meta(text)
        self.assertEqual(meta['version'], '17.2.0')
        self.assertEqual(meta['url.linux_x86_64'], 'https://h/a.tar.gz')
        self.assertNotIn('something.else', meta)

    def test_fetch_meta_rejects_http(self):
        with self.assertRaises(updater.UpdateError):
            updater.fetch_meta('http://example.com/keeper-commander.meta')

    def test_fetch_meta_rejects_html(self):
        with mock.patch('requests.get', return_value=FakeResponse(b'<!DOCTYPE html><html>404</html>')):
            with self.assertRaises(updater.UpdateError):
                updater.fetch_meta('https://example.com/keeper-commander.meta')

    def test_fetch_meta_rejects_bad_version(self):
        with mock.patch('requests.get', return_value=FakeResponse(b'keeper-commander.version=1.0/../../x\n')):
            with self.assertRaises(updater.UpdateError):
                updater.fetch_meta('https://example.com/keeper-commander.meta')

    def test_is_newer(self):
        self.assertTrue(updater.is_newer('99.0.0', '1.0.0'))
        self.assertFalse(updater.is_newer('1.0.0', '1.0.0'))
        self.assertFalse(updater.is_newer('0.9', '1.0.0'))


class TestDownload(TempDirTestCase):
    def test_ok(self):
        data = b'hello archive'
        dest = os.path.join(self.tmp, 'a')
        with mock.patch('requests.get', return_value=FakeResponse(data)):
            updater.download_and_verify('https://example.com/a', hashlib.sha256(data).hexdigest().upper(), dest)
        with open(dest, 'rb') as f:
            self.assertEqual(f.read(), data)

    def test_checksum_mismatch(self):
        with mock.patch('requests.get', return_value=FakeResponse(b'hello')):
            with self.assertRaises(updater.UpdateError) as ctx:
                updater.download_and_verify('https://example.com/a', '0' * 64, os.path.join(self.tmp, 'a'))
        self.assertIn('checksum mismatch', str(ctx.exception))

    def test_html_page(self):
        data = b'<html><body>Not found</body></html>'
        with mock.patch('requests.get', return_value=FakeResponse(data)):
            with self.assertRaises(updater.UpdateError) as ctx:
                updater.download_and_verify('https://example.com/a', hashlib.sha256(data).hexdigest(),
                                            os.path.join(self.tmp, 'a'))
        self.assertIn('HTML', str(ctx.exception))

    def test_http_url_refused(self):
        with self.assertRaises(updater.UpdateError):
            updater.download_and_verify('http://example.com/a', '0' * 64, os.path.join(self.tmp, 'a'))

    def test_redirect_to_http_refused(self):
        with mock.patch('requests.get', return_value=FakeResponse(b'x', url='http://evil.example/a')):
            with self.assertRaises(updater.UpdateError):
                updater.download_and_verify('https://example.com/a', '0' * 64, os.path.join(self.tmp, 'a'))


class TestExtract(TempDirTestCase):
    def test_extract_ok(self):
        archive = os.path.join(self.tmp, 'a.tar.gz')
        make_archive(archive)
        dest = os.path.join(self.tmp, 'out')
        updater.extract_archive(archive, dest)
        self.assertTrue(os.path.isfile(os.path.join(dest, 'keeper-commander', 'keeper-commander')))

    def test_path_traversal_rejected(self):
        archive = os.path.join(self.tmp, 'a.tar.gz')
        ti = tarfile.TarInfo('../escaped.txt')
        ti.size = 1
        make_archive(archive, extra=[(ti, b'x')])
        with self.assertRaises(updater.UpdateError):
            updater.extract_archive(archive, os.path.join(self.tmp, 'out'))
        self.assertFalse(os.path.exists(os.path.join(self.tmp, 'escaped.txt')))

    def test_absolute_path_rejected(self):
        archive = os.path.join(self.tmp, 'a.tar.gz')
        ti = tarfile.TarInfo(os.path.join(self.tmp, 'abs.txt'))
        ti.size = 1
        make_archive(archive, extra=[(ti, b'x')])
        with self.assertRaises(updater.UpdateError):
            updater.extract_archive(archive, os.path.join(self.tmp, 'out'))
        self.assertFalse(os.path.exists(os.path.join(self.tmp, 'abs.txt')))

    def test_symlink_escape_rejected(self):
        archive = os.path.join(self.tmp, 'a.tar.gz')
        ti = tarfile.TarInfo('keeper-commander/link')
        ti.type = tarfile.SYMTYPE
        ti.linkname = '../../../etc'
        make_archive(archive, extra=[(ti, None)])
        with self.assertRaises(updater.UpdateError):
            updater.extract_archive(archive, os.path.join(self.tmp, 'out'))

    def test_special_files_rejected(self):
        archive = os.path.join(self.tmp, 'a.tar.gz')
        ti = tarfile.TarInfo('keeper-commander/fifo')
        ti.type = tarfile.FIFOTYPE
        make_archive(archive, extra=[(ti, None)])
        with self.assertRaises(updater.UpdateError):
            updater.extract_archive(archive, os.path.join(self.tmp, 'out'))

    def test_setuid_bit_dropped(self):
        archive = os.path.join(self.tmp, 'a.tar.gz')
        ti = tarfile.TarInfo('keeper-commander/suid')
        ti.size = 1
        ti.mode = 0o4755
        make_archive(archive, extra=[(ti, b'x')])
        dest = os.path.join(self.tmp, 'out')
        updater.extract_archive(archive, dest)
        mode = os.stat(os.path.join(dest, 'keeper-commander', 'suid')).st_mode
        self.assertEqual(mode & 0o7000, 0)

    def test_zip_traversal_rejected(self):
        archive = os.path.join(self.tmp, 'a.zip')
        with zipfile.ZipFile(archive, 'w') as zf:
            zf.writestr('keeper-commander\\..\\..\\escaped.txt', 'x')
        with self.assertRaises(updater.UpdateError):
            updater.extract_archive(archive, os.path.join(self.tmp, 'out'))

    def test_zip_backslash_entries_extract(self):
        archive = os.path.join(self.tmp, 'a.zip')
        with zipfile.ZipFile(archive, 'w') as zf:
            zf.writestr('keeper-commander/keeper-commander.exe', 'x')
        dest = os.path.join(self.tmp, 'out')
        updater.extract_archive(archive, dest)
        self.assertTrue(os.path.isfile(os.path.join(dest, 'keeper-commander', 'keeper-commander.exe')))


@mock.patch('keepercommander.updater.os.name', 'posix')
class TestActivate(TempDirTestCase):
    def stage(self, name, version):
        staged = os.path.join(self.tmp, name)
        os.makedirs(os.path.join(staged, 'keeper-commander'))
        with open(os.path.join(staged, 'keeper-commander', 'keeper-commander'), 'w') as f:
            f.write(version)
        return staged

    def test_activate_switches_current_and_prunes(self):
        if os.name == 'nt':
            self.skipTest('posix only')
        prefix = os.path.join(self.tmp, 'prefix')
        os.makedirs(prefix)
        # three versions installed one after another; "running" is the first one
        running_exe = os.path.join(prefix, '1.0.0', 'keeper-commander', 'keeper-commander')
        for v in ('1.0.0', '1.1.0', '1.2.0'):
            updater.activate_version(prefix, v, self.stage('stage-' + v, v))
        self.assertEqual(os.readlink(os.path.join(prefix, 'current')),
                         os.path.join(prefix, '1.2.0', 'keeper-commander'))
        self.assertEqual(updater._version_of_current(prefix), '1.2.0')
        # 1.0.0 was pruned (not running here); the new and the previous version remain
        self.assertEqual(sorted(d for d in os.listdir(prefix) if d != 'current'), ['1.1.0', '1.2.0'])
        self.assertFalse(os.path.exists(running_exe))

    def test_running_version_is_kept(self):
        prefix = os.path.join(self.tmp, 'prefix')
        os.makedirs(prefix)
        for v in ('1.0.0', '1.1.0'):
            updater.activate_version(prefix, v, self.stage('stage-' + v, v))
        running = os.path.join(prefix, '1.0.0', 'keeper-commander', 'keeper-commander')
        with mock.patch.object(sys, 'executable', running):
            updater.activate_version(prefix, '1.2.0', self.stage('stage-1.2.0', '1.2.0'))
        self.assertEqual(sorted(d for d in os.listdir(prefix) if d != 'current'), ['1.0.0', '1.1.0', '1.2.0'])

    def test_bad_layout_rejected(self):
        prefix = os.path.join(self.tmp, 'prefix')
        os.makedirs(prefix)
        staged = os.path.join(self.tmp, 'bad')
        os.makedirs(staged)
        with self.assertRaises(updater.UpdateError):
            updater.activate_version(prefix, '1.0.0', staged)

    def test_bad_version_rejected(self):
        with self.assertRaises(updater.UpdateError):
            updater.activate_version(self.tmp, '../x', self.stage('s', 'x'))


class TestPerformUpdate(TempDirTestCase):
    def setUp(self):
        super(TestPerformUpdate, self).setUp()
        self.prefix = os.path.join(self.tmp, 'prefix')
        os.makedirs(self.prefix)
        self.archive = os.path.join(self.tmp, 'new.tar.gz')
        make_archive(self.archive, '99.0.0')
        self.info = {'method': 'script', 'version': '1.0.0', 'platform': 'linux_x86_64',
                     'meta_url': 'https://example.com/keeper-commander.meta', 'prefix': self.prefix}
        self.meta = {'version': '99.0.0', 'url.linux_x86_64': 'https://example.com/new.tar.gz',
                     'sha256.linux_x86_64': sha256_of(self.archive)}

    def fake_download(self, url, sha256, dest, proxies=None, timeout=60):
        shutil.copy(self.archive, dest)
        if sha256_of(dest) != sha256:
            raise updater.UpdateError('checksum mismatch')

    def test_update_installs_and_writes_marker(self):
        if os.name == 'nt':
            self.skipTest('posix only')
        out = []
        with mock.patch.object(updater, 'download_and_verify', self.fake_download):
            self.assertEqual(updater.perform_update(self.info, meta=self.meta, out=out.append), '99.0.0')
        self.assertTrue(os.path.isfile(os.path.join(self.prefix, 'current', 'keeper-commander')))
        with open(os.path.join(self.prefix, 'install.json')) as f:
            marker = json.load(f)
        self.assertEqual(marker['version'], '99.0.0')
        self.assertEqual(marker['platform'], 'linux_x86_64')
        self.assertNotIn('prefix', marker)
        self.assertTrue(any('Verified SHA-256' in line for line in out))
        # no leftovers of the working folder
        self.assertEqual([d for d in os.listdir(self.prefix) if d.startswith('.update-')], [])

    def test_already_current(self):
        self.meta['version'] = '0.0.1'
        with mock.patch.object(updater, 'download_and_verify') as dl:
            self.assertIsNone(updater.perform_update(self.info, meta=self.meta, out=lambda x: None))
        dl.assert_not_called()

    def test_missing_checksum_refused(self):
        del self.meta['sha256.linux_x86_64']
        with self.assertRaises(updater.UpdateError):
            updater.perform_update(self.info, meta=self.meta, out=lambda x: None)

    def test_missing_platform_refused(self):
        self.info['platform'] = 'linux_arm64'
        with self.assertRaises(updater.UpdateError):
            updater.perform_update(self.info, meta=self.meta, out=lambda x: None)

    def test_failed_checksum_leaves_install_untouched(self):
        self.meta['sha256.linux_x86_64'] = '0' * 64
        with mock.patch.object(updater, 'download_and_verify', self.fake_download):
            with self.assertRaises(updater.UpdateError):
                updater.perform_update(self.info, meta=self.meta, out=lambda x: None)
        self.assertEqual(os.listdir(self.prefix), [])


class TestPrompt(TempDirTestCase):
    def setUp(self):
        super(TestPrompt, self).setUp()
        self.info = {'method': 'script', 'platform': 'linux_x86_64', 'prefix': self.tmp}
        self.params = mock.Mock(batch_mode=False, service_mode=False)
        self.newer = {'is_up_to_date': False, 'current_github_version': '99.0.0'}
        patches = [
            mock.patch.object(updater, 'get_install_info', return_value=self.info),
            mock.patch('sys.stdin.isatty', return_value=True),
            mock.patch('sys.stdout.isatty', return_value=True),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.perform = mock.patch.object(updater, 'perform_update', return_value='99.0.0').start()
        self.addCleanup(mock.patch.stopall)

    def test_asks_once_per_version(self):
        with mock.patch('builtins.input', return_value='n') as inp:
            updater.prompt_for_update_on_exit(self.params, self.newer)
            updater.prompt_for_update_on_exit(self.params, self.newer)
        self.assertEqual(inp.call_count, 1)
        self.perform.assert_not_called()
        # a newer version asks again
        with mock.patch('builtins.input', return_value='n') as inp:
            updater.prompt_for_update_on_exit(self.params, {'is_up_to_date': False, 'current_github_version': '100.0.0'})
        self.assertEqual(inp.call_count, 1)

    def test_yes_updates(self):
        with mock.patch('builtins.input', return_value='y'):
            updater.prompt_for_update_on_exit(self.params, self.newer)
        self.perform.assert_called_once()

    def test_no_prompt_when_up_to_date_or_unknown(self):
        with mock.patch('builtins.input') as inp:
            updater.prompt_for_update_on_exit(self.params, {'is_up_to_date': None, 'current_github_version': None})
            updater.prompt_for_update_on_exit(self.params, {'is_up_to_date': True, 'current_github_version': '1.0'})
        inp.assert_not_called()

    def test_no_prompt_in_batch_service_or_env(self):
        with mock.patch('builtins.input') as inp:
            updater.prompt_for_update_on_exit(mock.Mock(batch_mode=True, service_mode=False), self.newer)
            updater.prompt_for_update_on_exit(mock.Mock(batch_mode=False, service_mode=True), self.newer)
            with mock.patch.dict(os.environ, {updater.NO_PROMPT_ENV: '1'}):
                updater.prompt_for_update_on_exit(self.params, self.newer)
        inp.assert_not_called()

    def test_no_prompt_without_tty(self):
        with mock.patch('sys.stdin.isatty', return_value=False), mock.patch('builtins.input') as inp:
            updater.prompt_for_update_on_exit(self.params, self.newer)
        inp.assert_not_called()

    def test_no_prompt_for_other_install_methods(self):
        with mock.patch.object(updater, 'get_install_info', return_value=None), mock.patch('builtins.input') as inp:
            updater.prompt_for_update_on_exit(self.params, self.newer)
        inp.assert_not_called()

    def test_eof_does_not_raise(self):
        with mock.patch('builtins.input', side_effect=EOFError):
            updater.prompt_for_update_on_exit(self.params, self.newer)


class TestDetect(TempDirTestCase):
    def test_script_install_detected_from_marker(self):
        prefix = os.path.join(self.tmp, 'kc')
        exe_dir = os.path.join(prefix, '1.0.0', 'keeper-commander')
        os.makedirs(exe_dir)
        exe = os.path.join(exe_dir, 'keeper-commander')
        open(exe, 'w').close()
        with open(os.path.join(prefix, 'install.json'), 'w') as f:
            json.dump({'method': 'script', 'platform': 'linux_x86_64'}, f)
        with mock.patch.object(updater, 'is_binary_app', return_value=True), mock.patch.object(sys, 'executable', exe):
            info = updater.get_install_info()
            self.assertEqual(os.path.realpath(info['prefix']), os.path.realpath(prefix))
            self.assertEqual(updater.detect_install_method(), updater.METHOD_SCRIPT)

    def test_binary_without_marker(self):
        exe = os.path.join(self.tmp, 'bin', 'keeper-commander')
        os.makedirs(os.path.dirname(exe))
        open(exe, 'w').close()
        with mock.patch.object(updater, 'is_binary_app', return_value=True), mock.patch.object(sys, 'executable', exe), \
                mock.patch('os.path.exists', side_effect=lambda p: False if p == '/.dockerenv' else os.path.lexists(p)):
            self.assertEqual(updater.detect_install_method(), updater.METHOD_BINARY)

    def test_pkg_and_brew_and_inno(self):
        def method(exe, **kw):
            with mock.patch.object(updater, 'is_binary_app', return_value=True), \
                    mock.patch.object(sys, 'executable', exe), \
                    mock.patch('os.path.exists', return_value=False), \
                    mock.patch('os.path.isfile', side_effect=kw.get('isfile', lambda p: False)):
                return updater.detect_install_method()
        self.assertEqual(method('/usr/local/keepercommandercli/bin/keeper-commander'), updater.METHOD_PKG)
        self.assertEqual(method('/opt/homebrew/Cellar/keepercommander/1/bin/x'), updater.METHOD_BREW)
        self.assertEqual(method('C:\\Program Files\\Keeper\\keeper-commander.exe',
                                isfile=lambda p: p.endswith('unins000.exe')), updater.METHOD_INSTALLER)

    def test_docker(self):
        with mock.patch.object(updater, 'is_binary_app', return_value=False), \
                mock.patch('os.path.exists', side_effect=lambda p: p == '/.dockerenv'):
            self.assertEqual(updater.detect_install_method(), updater.METHOD_DOCKER)

    def test_every_method_has_instructions(self):
        for method in (updater.METHOD_SCRIPT, updater.METHOD_PKG, updater.METHOD_INSTALLER, updater.METHOD_BREW,
                       updater.METHOD_PIPX, updater.METHOD_UV, updater.METHOD_PIP, updater.METHOD_DOCKER,
                       updater.METHOD_SOURCE, updater.METHOD_BINARY, updater.METHOD_UNKNOWN):
            self.assertTrue(updater.get_update_instructions(method))
            self.assertIn(method, updater.METHOD_NAMES)


class TestVersioningCache(TestCase):
    def test_welcome_caches_result(self):
        info = {'is_up_to_date': True, 'current_github_version': '1.0', 'new_version_download_url': ''}
        with mock.patch.object(versioning, 'is_up_to_date_version', return_value=info):
            versioning.welcome_print_version(mock.Mock())
        self.assertIs(versioning.last_version_info, info)
