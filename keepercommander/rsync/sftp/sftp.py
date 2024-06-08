#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2022 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

"""Commander Plugin for SFTP
   Dependencies:
       pip install paramiko
"""

import logging
import stat

from typing import Optional

from paramiko.sftp_client import SFTPClient
from paramiko import Transport

from ...commands.base import RecordMixin
from .. import rsync

logging.getLogger("paramiko").setLevel(logging.WARNING)


class SFtpPlugin(rsync.RSyncPluginBase):
    def __init__(self):
        self._client = None      # type: Optional[SFTPClient]

    def connect(self, record):
        self.disconnect()

        host = RecordMixin.get_record_field(record, 'host')
        if host:
            host, _, port = host.partition(':')
        else:
            port = ''
        if not port:
            port = RecordMixin.get_record_field(record, 'port')
        if port:
            port = int(port)
        else:
            port = None
        if not host:
            raise ValueError(f'SFTP plugin: SFTP server (\"host\") is not set.')
        transport = Transport((host, port))

        logging.info('SFTP: connecting to %s', host)

        username = RecordMixin.get_record_field(record, 'login')
        if not username:
            raise ValueError(f'SFTP plugin: (\"login\") is not set.')
        password = RecordMixin.get_record_field(record, 'password')
        if not password:
            raise ValueError(f'SFTP plugin: (\"password\") is not set.')

        transport.connect(None, username, password)
        client = SFTPClient.from_transport(transport)
        self._client = client

    def disconnect(self):
        if self._client:
            self._client.close()
            self._client = None

    def get_entries(self, root_dir=None):
        if not self._client:
            raise Exception('Not connected')
        if root_dir:
            if not root_dir.endswith('/'):
                root_dir += '/'
        else:
            root_dir = '/'

        dirs = [root_dir or '/']
        pos = 0
        while pos < len(dirs):
            cwd = dirs[pos]
            if cwd.endswith('/'):
                cwd = cwd[0:-1]
            pos += 1
            for entry in self._client.listdir_attr(path=cwd):
                if entry.filename.startswith('.'):
                    continue
                name = f'{cwd}/{entry.filename}'
                if stat.S_ISDIR(entry.st_mode):
                    dirs.append(name)
                    pass
                elif stat.S_ISREG(entry.st_mode):
                    e = rsync.RSyncFileEntry(name[len(root_dir):])
                    e.size = entry.st_size
                    e.last_modified = int(entry.st_mtime)
                    e.full_path = name
                    yield e

    def get_entry_stream(self, entry):
        if not self._client:
            raise Exception('Not connected')
        return self._client.open(entry.full_path)
