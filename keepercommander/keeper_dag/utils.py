import logging
import os
import platform
import stat
import subprocess


def value_to_boolean(value):
    value = str(value)
    if value.lower() in ['true', 'yes', 'on', '1']:
        return True
    elif value.lower() in ['false', 'no', 'off', '0']:
        return False
    else:
        return None


def kotlin_bytes(data: bytes):
    return [b if b < 128 else b - 256 for b in data]


def set_file_permissions(file_path):     # type: (str) -> None
    """
    Set secure file permissions (0o600 on POSIX, owner-RW-only via icacls on Windows)
    for files containing sensitive local state.

    Mirrors keepercommander.utils.set_file_permissions intentionally — keeper_dag is
    vendored as a self-contained sub-package and must not import upward from its
    parent. Keep these two functions in sync.
    """
    file_path = os.path.abspath(file_path)

    try:
        if os.path.islink(file_path):
            logging.warning(f'Skipping permission setting on symbolic link: {file_path}')
            return

        if platform.system() != 'Windows':
            file_stat = os.stat(file_path)
            if file_stat.st_uid != os.getuid():
                logging.warning(f'Skipping permission setting on file not owned by current user: {file_path}')
                return

            os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)
            logging.debug(f'Set secure permissions (600) for file: {file_path}')
        else:
            username = os.getlogin()
            subprocess.run(["icacls", file_path, "/inheritance:r"], check=True, capture_output=True)
            subprocess.run(["icacls", file_path, "/remove", "NT AUTHORITY\\SYSTEM", "BUILTIN\\Administrators"],
                           check=False, capture_output=True)
            subprocess.run(["icacls", file_path, "/grant", f"{username}:RW"], check=True, capture_output=True)
            logging.debug(f'Set secure permissions (owner RW only) for Windows file: {file_path}')
    except Exception:
        logging.warning(f'Failed to set file permissions for {file_path}')
