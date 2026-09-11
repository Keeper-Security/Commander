#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2024 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import subprocess
import sys

# Windows CreateProcess flags to run subprocesses fully detached and hidden
CREATE_NO_WINDOW = 0x08000000
DETACHED_PROCESS = 0x00000008
CREATE_NEW_PROCESS_GROUP = 0x00000200


def spawn_detached_process(cmd, log_file, cwd=None, env=None, append=False):
    """
    Start cmd as a fully detached background subprocess, hidden on Windows, with
    stdout/stderr redirected to log_file. Returns the Popen object.
    """
    mode = 'a' if append else 'w'
    with open(log_file, mode) as log_f:
        if sys.platform == "win32":
            return subprocess.Popen(
                cmd,
                creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW,
                stdout=log_f,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                cwd=cwd,
                env=env,
            )
        return subprocess.Popen(
            cmd,
            stdout=log_f,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            start_new_session=True,  # os.setsid() in the child - not thread-unsafe like preexec_fn
            cwd=cwd,
            env=env,
        )
