#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#
"""Self-update for Commander installed with the install script (install.sh / install.ps1).

Layout created by the install scripts::

    <prefix>/install.json            marker written by the installer
    <prefix>/update-state.json       last version the user was asked about
    <prefix>/<version>/keeper-commander/...   one folder per installed version
    <prefix>/current                 symlink (macOS/Linux) or junction (Windows) to the active version

A new version is installed next to the running one and ``current`` is repointed, so the running process is never
modified. Other installation methods (pkg, installer, Homebrew, pip, ...) are only recognised so that the right
update instructions can be shown.
"""
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile

import requests

from . import __version__
from .versioning import is_binary_app, version_compare

INSTALL_MARKER = 'install.json'
STATE_FILE = 'update-state.json'
DEFAULT_META_URL = 'https://github.com/Keeper-Security/Commander/releases/latest/download/keeper-commander.meta'
META_PREFIX = 'keeper-commander.'
APP_DIR = 'keeper-commander'
VERSION_RE = re.compile(r'^[0-9A-Za-z._-]+$')
NO_PROMPT_ENV = 'KEEPER_NO_UPDATE_PROMPT'

METHOD_SCRIPT = 'script'
METHOD_PKG = 'pkg'
METHOD_INSTALLER = 'installer'
METHOD_BREW = 'brew'
METHOD_PIPX = 'pipx'
METHOD_UV = 'uv'
METHOD_PIP = 'pip'
METHOD_DOCKER = 'docker'
METHOD_SOURCE = 'source'
METHOD_BINARY = 'binary'
METHOD_UNKNOWN = 'unknown'

RELEASES_URL = 'https://github.com/Keeper-Security/Commander/releases'

UPDATE_INSTRUCTIONS = {
    METHOD_SCRIPT: "Run the 'update' command.",
    METHOD_PKG: 'Download the latest .pkg installer from ' + RELEASES_URL + ' and run it.',
    METHOD_INSTALLER: 'Download the latest installer from ' + RELEASES_URL +
                      ' and run it (or run: winget upgrade Keeper.Commander).',
    METHOD_BREW: 'Run: brew upgrade keepercommander',
    METHOD_PIPX: 'Run: pipx upgrade keepercommander',
    METHOD_UV: 'Run: uv tool upgrade keepercommander',
    METHOD_PIP: 'Run: pip install --upgrade keepercommander',
    METHOD_DOCKER: 'Pull the latest Commander image and recreate the container.',
    METHOD_SOURCE: 'Run: git pull (in your Commander checkout), then reinstall dependencies if they changed.',
    METHOD_BINARY: 'Download the latest version from ' + RELEASES_URL,
    METHOD_UNKNOWN: 'Download the latest version from ' + RELEASES_URL,
}

METHOD_NAMES = {
    METHOD_SCRIPT: 'install script',
    METHOD_PKG: 'macOS installer package',
    METHOD_INSTALLER: 'Windows installer',
    METHOD_BREW: 'Homebrew',
    METHOD_PIPX: 'pipx',
    METHOD_UV: 'uv tool',
    METHOD_PIP: 'pip',
    METHOD_DOCKER: 'Docker',
    METHOD_SOURCE: 'source checkout',
    METHOD_BINARY: 'standalone binary',
    METHOD_UNKNOWN: 'unknown',
}


class UpdateError(Exception):
    pass


# ---------------------------------------------------------------------------------------------------------------------
# Installation method detection
# ---------------------------------------------------------------------------------------------------------------------

def _norm(path):
    return path.replace('\\', '/').lower()


def get_install_info():  # type: () -> dict
    """Return the install marker (plus 'prefix') when Commander was installed by the install script, else None."""
    if not is_binary_app():
        return None
    try:
        exe = os.path.realpath(sys.executable)
        # <prefix>/<version>/keeper-commander/<exe>   (also true when launched through <prefix>/current)
        prefix = os.path.dirname(os.path.dirname(os.path.dirname(exe)))
        with open(os.path.join(prefix, INSTALL_MARKER), 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or data.get('method') != METHOD_SCRIPT:
        return None
    data['prefix'] = prefix
    return data


def detect_install_method():  # type: () -> str
    if get_install_info():
        return METHOD_SCRIPT

    if os.path.exists('/.dockerenv'):
        return METHOD_DOCKER

    if is_binary_app():
        exe = sys.executable
        path = _norm(exe)
        if path.startswith('/usr/local/keepercommandercli/'):
            return METHOD_PKG
        if os.path.isfile(os.path.join(os.path.dirname(exe), 'unins000.exe')):
            return METHOD_INSTALLER      # Inno Setup (also what winget installs)
        if '/cellar/' in path or '/homebrew/' in path:
            return METHOD_BREW
        return METHOD_BINARY

    pkg_dir = os.path.dirname(os.path.abspath(__file__))
    path = _norm(pkg_dir)
    if '/cellar/' in path or '/homebrew/' in path:
        return METHOD_BREW
    if '/pipx/venvs/' in path:
        return METHOD_PIPX
    if '/uv/tools/' in path:
        return METHOD_UV
    if os.path.isdir(os.path.join(os.path.dirname(pkg_dir), '.git')):
        return METHOD_SOURCE
    if 'site-packages' in path or 'dist-packages' in path:
        return METHOD_PIP
    return METHOD_UNKNOWN


def get_update_instructions(method=None):  # type: (str) -> str
    return UPDATE_INSTRUCTIONS.get(method or detect_install_method(), UPDATE_INSTRUCTIONS[METHOD_UNKNOWN])


# ---------------------------------------------------------------------------------------------------------------------
# Meta file
# ---------------------------------------------------------------------------------------------------------------------

def _looks_like_html(data):  # type: (bytes) -> bool
    head = data[:64].lower()
    return b'<!doctype' in head or b'<html' in head


def parse_meta(text):  # type: (str) -> dict
    meta = {}
    for line in text.splitlines():
        line = line.strip()
        if line.startswith(META_PREFIX) and '=' in line:
            key, value = line[len(META_PREFIX):].split('=', 1)
            meta[key.strip()] = value.strip()
    return meta


def _require_https(url):
    if not url.lower().startswith('https://'):
        raise UpdateError('refusing to use a non-HTTPS URL: {0}'.format(url))


def fetch_meta(meta_url, proxies=None, timeout=10):  # type: (str, dict, int) -> dict
    _require_https(meta_url)
    try:
        rs = requests.get(meta_url, proxies=proxies, timeout=timeout)
        rs.raise_for_status()
    except requests.RequestException as e:
        raise UpdateError('cannot download {0}: {1}'.format(meta_url, e))
    if _looks_like_html(rs.content):
        raise UpdateError('{0} returned an HTML page instead of the meta file'.format(meta_url))
    meta = parse_meta(rs.text)
    version = meta.get('version')
    if not version:
        raise UpdateError('cannot read the version from {0}'.format(meta_url))
    if not VERSION_RE.match(version):
        raise UpdateError('invalid version in meta file: {0}'.format(version))
    return meta


def is_newer(latest, current=__version__):  # type: (str, str) -> bool
    try:
        return version_compare(current, latest) < 0
    except (ValueError, TypeError):
        raise UpdateError('cannot compare versions {0} and {1}'.format(current, latest))


# ---------------------------------------------------------------------------------------------------------------------
# Download, verify, extract
# ---------------------------------------------------------------------------------------------------------------------

def download_and_verify(url, sha256, dest, proxies=None, timeout=60):  # type: (str, str, str, dict, int) -> None
    _require_https(url)
    digest = hashlib.sha256()
    first = None
    try:
        with requests.get(url, stream=True, proxies=proxies, timeout=timeout) as rs:
            rs.raise_for_status()
            _require_https(rs.url)       # redirects must stay on HTTPS
            with open(dest, 'wb') as f:
                for chunk in rs.iter_content(chunk_size=1024 * 256):
                    if not chunk:
                        continue
                    if first is None:
                        first = chunk
                    digest.update(chunk)
                    f.write(chunk)
    except requests.RequestException as e:
        raise UpdateError('download failed: {0} ({1})'.format(url, e))
    if first is None:
        raise UpdateError('download is empty: {0}'.format(url))
    if _looks_like_html(first):
        raise UpdateError('download is an HTML page, not an archive: {0}'.format(url))
    actual = digest.hexdigest()
    if actual.lower() != sha256.strip().lower():
        raise UpdateError('checksum mismatch (expected {0}, got {1})'.format(sha256, actual))


def _inside(root, path):
    return path == root or path.startswith(root + os.sep)


def extract_archive(archive, dest):  # type: (str, str) -> None
    """Extract a .tar.gz or .zip into dest, rejecting any entry that would land outside of it."""
    os.makedirs(dest, exist_ok=True)
    root = os.path.realpath(dest)
    if archive.lower().endswith('.zip'):
        with zipfile.ZipFile(archive) as zf:
            for name in zf.namelist():
                target = os.path.realpath(os.path.join(root, name.replace('\\', '/')))
                if not _inside(root, target):
                    raise UpdateError('archive contains an unsafe path: {0}'.format(name))
            zf.extractall(root)
        return

    with tarfile.open(archive, 'r:gz') as tf:
        members = tf.getmembers()
        for m in members:
            target = os.path.realpath(os.path.join(root, m.name))
            if not _inside(root, target):
                raise UpdateError('archive contains an unsafe path: {0}'.format(m.name))
            if m.isdev() or m.isfifo():
                raise UpdateError('archive contains a special file: {0}'.format(m.name))
            if m.issym():
                link = os.path.realpath(os.path.join(os.path.dirname(target), m.linkname))
                if not _inside(root, link):
                    raise UpdateError('archive contains an unsafe link: {0}'.format(m.name))
            elif m.islnk():
                link = os.path.realpath(os.path.join(root, m.linkname))
                if not _inside(root, link):
                    raise UpdateError('archive contains an unsafe link: {0}'.format(m.name))
            m.mode &= 0o777                       # no setuid / setgid / sticky bits
            if hasattr(os, 'getuid'):
                m.uid, m.gid = os.getuid(), os.getgid()   # never apply ownership recorded in the archive
        for m in members:
            tf.extract(m, root)


# ---------------------------------------------------------------------------------------------------------------------
# Activation
# ---------------------------------------------------------------------------------------------------------------------

def _exe_name():
    return 'keeper-commander.exe' if os.name == 'nt' else 'keeper-commander'


def _current_target(dest):
    """What <prefix>/current points to: the app folder on macOS/Linux (matches install.sh), the version folder on
    Windows (matches install.ps1, where PATH uses current\\keeper-commander)."""
    return dest if os.name == 'nt' else os.path.join(dest, APP_DIR)


def _version_of_current(prefix):
    current = os.path.join(prefix, 'current')
    if not os.path.lexists(current):
        return None
    target = os.path.realpath(current)
    if os.name != 'nt':
        target = os.path.dirname(target)
    return os.path.basename(target)


def _switch_current(prefix, dest):
    current = os.path.join(prefix, 'current')
    target = _current_target(dest)
    if os.name == 'nt':
        if os.path.lexists(current):
            os.rmdir(current)                    # removes the junction only, never its target
        rs = subprocess.run(['cmd', '/c', 'mklink', '/J', current, target],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if rs.returncode != 0:
            raise UpdateError('cannot create junction: {0}'.format(rs.stderr.decode(errors='replace').strip()))
    else:
        tmp = current + '.new'
        if os.path.lexists(tmp):
            os.remove(tmp)
        os.symlink(target, tmp)
        os.replace(tmp, current)                 # atomic


def _prune(prefix, keep):
    for name in os.listdir(prefix):
        path = os.path.join(prefix, name)
        if name in keep or name == 'current' or os.path.islink(path) or not os.path.isdir(path):
            continue
        if not VERSION_RE.match(name) or name.startswith('.'):
            continue
        try:
            shutil.rmtree(path)
        except OSError as e:                     # e.g. an older version still running on Windows
            logging.debug('Cannot remove old version %s: %s', name, e)


def _write_json(path, data):
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(data, f)
    os.replace(tmp, path)


def activate_version(prefix, version, staged):  # type: (str, str, str) -> str
    """Move the staged folder to <prefix>/<version> and make it the current one. Returns the version folder."""
    if not VERSION_RE.match(version):
        raise UpdateError('invalid version: {0}'.format(version))
    if not os.path.isfile(os.path.join(staged, APP_DIR, _exe_name())):
        raise UpdateError('unexpected archive layout')

    previous = _version_of_current(prefix)
    dest = os.path.join(prefix, version)
    if os.path.isdir(dest):
        shutil.rmtree(dest)
    os.rename(staged, dest)
    _switch_current(prefix, dest)

    keep = {version}
    if previous:
        keep.add(previous)
    try:
        keep.add(os.path.basename(os.path.dirname(os.path.dirname(os.path.realpath(sys.executable)))))
    except Exception:
        pass
    _prune(prefix, keep)
    return dest


# ---------------------------------------------------------------------------------------------------------------------
# Update flow
# ---------------------------------------------------------------------------------------------------------------------

def get_latest(info, proxies=None):  # type: (dict, dict) -> dict
    """Fetch the meta file for an install-script installation."""
    return fetch_meta(info.get('meta_url') or DEFAULT_META_URL, proxies=proxies)


def perform_update(info, meta=None, proxies=None, out=print):  # type: (dict, dict, dict, callable) -> str
    """Install the version published in the meta file. Returns the installed version, or None if already current."""
    prefix = info['prefix']
    meta = meta or get_latest(info, proxies)
    version = meta['version']
    if not is_newer(version):
        return None

    plat = info.get('platform')
    url = meta.get('url.{0}'.format(plat)) if plat else None
    sha256 = meta.get('sha256.{0}'.format(plat)) if plat else None
    if not url:
        raise UpdateError('no Keeper Commander build is published for {0}'.format(plat))
    if not sha256:
        raise UpdateError('no checksum is published for {0}; refusing to install'.format(plat))

    out('Installing Keeper Commander {0}...'.format(version))
    work = tempfile.mkdtemp(prefix='.update-', dir=prefix)
    try:
        archive = os.path.join(work, 'archive.zip' if url.lower().endswith('.zip') else 'archive.tar.gz')
        out('  Downloading keeper-commander {0}...'.format(version))
        download_and_verify(url, sha256, archive, proxies=proxies)
        out('  Verified SHA-256 checksum.')
        staged = os.path.join(work, 'staged')
        extract_archive(archive, staged)
        dest = activate_version(prefix, version, staged)
    finally:
        shutil.rmtree(work, ignore_errors=True)

    info = dict(info)
    info.pop('prefix', None)
    info['version'] = version
    _write_json(os.path.join(prefix, INSTALL_MARKER), info)
    out('Keeper Commander {0} installed to {1}'.format(version, dest))
    out('The new version starts the next time you run Commander.')
    return version


# ---------------------------------------------------------------------------------------------------------------------
# "Ask once per version" state and the exit prompt
# ---------------------------------------------------------------------------------------------------------------------

def load_state(prefix):  # type: (str) -> dict
    try:
        with open(os.path.join(prefix, STATE_FILE), 'r', encoding='utf-8') as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_state(prefix, state):  # type: (str, dict) -> None
    try:
        _write_json(os.path.join(prefix, STATE_FILE), state)
    except OSError as e:
        logging.debug('Cannot save update state: %s', e)


def prompt_for_update_on_exit(params, version_info=None):
    """Ask once per new version whether to update when the interactive shell closes. Never raises."""
    try:
        if getattr(params, 'batch_mode', False) or getattr(params, 'service_mode', False):
            return
        if os.environ.get(NO_PROMPT_ENV):
            return
        if not (sys.stdin.isatty() and sys.stdout.isatty()):
            return
        info = get_install_info()
        if not info:
            return
        if version_info is None:
            from . import versioning
            version_info = versioning.last_version_info
        if not version_info or version_info.get('is_up_to_date') is not False:
            return
        latest = version_info.get('current_github_version')
        if not latest:
            return

        prefix = info['prefix']
        state = load_state(prefix)
        if state.get('last_prompted') == latest:
            return
        state['last_prompted'] = latest          # recorded before asking: one prompt per version, whatever the answer
        save_state(prefix, state)

        print('')
        answer = input('Keeper Commander {0} is available (you have {1}). Update now? [y/N]: '
                       .format(latest, __version__)).strip().lower()
        if answer in ('y', 'yes'):
            proxies = getattr(getattr(params, 'rest_context', None), 'proxies', None)
            try:
                if perform_update(info, proxies=proxies) is None:
                    print('Keeper Commander is already up to date.')
            except UpdateError as e:
                print('Update failed: {0}'.format(e))
        else:
            print("Run 'update' any time to install it.")
    except (EOFError, KeyboardInterrupt):
        print('')
    except Exception as e:
        logging.debug('Update prompt failed: %s', e, exc_info=True)
