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
    Set secure file permissions (0o600 on POSIX, owner-Modify-only via icacls on
    Windows) for files containing sensitive local state -- currently the local
    DAG SQLite database.

    POSIX: `chmod 0o600` so only the owning user can read/write/delete.

    Windows: NTFS DACL hardening via icacls -- strip inheritance, remove
    `NT AUTHORITY\\SYSTEM` and `BUILTIN\\Administrators`, then grant the current
    user `:M` (Modify, which is Read + Write + Delete). `:M` is used rather
    than `:RW` because POSIX 0o600 lets the owner delete their own file, and a
    bare `:RW` grant on Windows would NOT include delete.
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
            subprocess.run(["icacls", file_path, "/grant", f"{username}:M"], check=True, capture_output=True)
            logging.debug(f'Set secure permissions (owner Modify only) for Windows file: {file_path}')
    except (OSError, subprocess.SubprocessError) as err:
        logging.warning(f'Failed to set file permissions for {file_path}: {err}')
