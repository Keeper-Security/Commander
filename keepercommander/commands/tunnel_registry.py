#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2023 Keeper Security Inc.
#

"""Cross-process file-based tunnel session registry.

Each foreground/background/run tunnel writes JSON metadata to
<tempdir>/keeper-tunnel-sessions/<pid>.json so ``pam tunnel list`` and
``pam tunnel stop`` can discover tunnels across Commander processes.

The registry lives under the system temp directory rather than ~/.keeper/
so it survives credential removal/replacement. Temp directories are
cleared on reboot, matching tunnel lifecycle (tunnels do not survive reboots).
"""

from __future__ import annotations

import json
import logging
import os
import platform
import signal
import tempfile
import time
from pathlib import Path

from ..error import CommandError

logger = logging.getLogger(__name__)

#: Parent poll allowance beyond the child's ``--timeout`` for ``--background`` (process startup).
PARENT_GRACE_SECONDS = 10

_registry_dir_initialized = False


def normalize_bind_host(host) -> str:
    """Normalize host for duplicate local bind detection (best-effort)."""
    if host is None:
        return ''
    h = str(host).strip().lower()
    if h == 'localhost':
        return '127.0.0.1'
    return h


def tunnel_registry_dir() -> Path:
    """Return (and create) the tunnel session registry directory."""
    global _registry_dir_initialized
    base = Path(tempfile.gettempdir()) / 'keeper-tunnel-sessions'
    existed = base.exists()
    base.mkdir(parents=True, exist_ok=True)
    if os.name != 'nt':
        try:
            os.chmod(base, 0o700)
        except OSError:
            pass
    if not _registry_dir_initialized:
        _registry_dir_initialized = True
        if existed:
            _clean_stale_registry_files(base)
    return base


def _clean_stale_registry_files(reg_dir: Path) -> None:
    """Remove dead or corrupt JSON entries under reg_dir."""
    try:
        for fname in os.listdir(reg_dir):
            if not fname.endswith('.json'):
                continue
            fpath = reg_dir / fname
            try:
                with open(fpath, encoding='utf-8') as f:
                    data = json.load(f)
                pid = data.get('pid')
                if pid and is_pid_alive(pid):
                    continue
                os.remove(fpath)
            except Exception as exc:
                logger.debug('Removing corrupt tunnel registry file %s: %s', fpath, exc)
                try:
                    os.remove(fpath)
                except OSError:
                    pass
    except OSError:
        pass


def register_tunnel(
    pid,
    record_uid,
    tube_id,
    host,
    port,
    target_host=None,
    target_port=None,
    mode='foreground',
    record_title=None,
):
    """Write a JSON file for an active tunnel so other processes can see it.

    Uses atomic write (temp file + rename) so readers never see partial data.
    Stale entries are cleaned before duplicate checks (Issue 6 / 7).
    """
    existing = list_registered_tunnels(clean_stale=True)
    nh = normalize_bind_host(host)
    try:
        p_int = int(port)
    except (TypeError, ValueError):
        p_int = port
    for entry in existing:
        if entry.get('pid') == pid:
            continue
        if normalize_bind_host(entry.get('host')) == nh and int(entry.get('port') or 0) == int(p_int):
            raise CommandError(
                'pam tunnel start',
                f'Port {port} on {host} is already in use by tunnel PID {entry.get("pid")} '
                f'(record {entry.get("record_uid")}). '
                f'Use "pam tunnel stop {entry.get("record_uid")}" first.',
            )

    reg_dir = tunnel_registry_dir()
    path = reg_dir / f'{pid}.json'
    data = {
        'pid': pid,
        'record_uid': record_uid,
        'tube_id': tube_id,
        'host': host,
        'port': port,
        'target_host': target_host,
        'target_port': target_port,
        'mode': mode,
        'record_title': record_title,
        'started': time.strftime('%Y-%m-%d %H:%M:%S'),
    }
    tmp_path = path.with_suffix('.json.tmp')
    try:
        with open(tmp_path, 'w', encoding='utf-8') as f:
            json.dump(data, f)
        os.replace(tmp_path, path)
    except Exception as exc:
        logger.debug('Could not write tunnel registry file %s: %s', path, exc)
        try:
            os.remove(tmp_path)
        except OSError:
            pass


def unregister_tunnel(pid=None):
    """Remove the registry file for a tunnel (defaults to current PID)."""
    pid = pid or os.getpid()
    path = tunnel_registry_dir() / f'{pid}.json'
    try:
        os.remove(path)
    except OSError:
        pass


def is_pid_alive(pid) -> bool:
    """Return True if a process with the given PID is still running."""
    if os.name == 'nt':
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(0x100000, False, pid)  # SYNCHRONIZE
        if handle:
            kernel32.CloseHandle(handle)
            return True
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def stop_tunnel_process(pid: int) -> bool:
    """Send termination to a tunnel process. Returns True if a signal was sent.

    On Unix, sends SIGTERM for graceful shutdown (target cleans registry/WebRTC).
    On Windows, SIGTERM maps to TerminateProcess; the registry row is removed
    here because the target cannot run cleanup handlers.
    """
    if not is_pid_alive(pid):
        return False
    try:
        if platform.system() == 'Windows':
            unregister_tunnel(pid)
        os.kill(pid, signal.SIGTERM)
        return True
    except (ProcessLookupError, PermissionError, OSError):
        return False


def list_registered_tunnels(clean_stale=True):
    """Read registry files. Optionally remove dead or corrupt entries.

    Returns a list of dicts for tunnels whose owning process is still alive.
    """
    reg_dir = tunnel_registry_dir()
    result = []
    try:
        fnames = os.listdir(reg_dir)
    except OSError:
        return result
    for fname in fnames:
        if not fname.endswith('.json'):
            continue
        fpath = reg_dir / fname
        try:
            with open(fpath, encoding='utf-8') as f:
                data = json.load(f)
            pid = data.get('pid')
            if pid and is_pid_alive(pid):
                result.append(data)
            elif clean_stale:
                os.remove(fpath)
        except Exception as exc:
            logger.debug('Removing corrupt tunnel registry file %s: %s', fpath, exc)
            if clean_stale:
                try:
                    os.remove(fpath)
                except OSError:
                    pass
    return result
