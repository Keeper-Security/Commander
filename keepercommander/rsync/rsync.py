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

import abc
from typing import Iterable, BinaryIO, Optional

from .. import vault


class RSyncFileEntry:
    def __init__(self, path):
        self.path = path or ''
        self.size = 0
        self.last_modified = 0
        self.full_path = ''


class RSyncPluginBase(abc.ABC):
    @abc.abstractmethod
    def connect(self, record):    # type: (vault.KeeperRecord) -> None
        pass

    @abc.abstractmethod
    def disconnect(self):    # type: () -> None
        pass

    @abc.abstractmethod
    def get_entries(self, root_dir=None):        # type: (Optional[str]) -> Iterable[RSyncFileEntry]
        pass

    @abc.abstractmethod
    def get_entry_stream(self, entry):    # type: (RSyncFileEntry) -> BinaryIO
        pass
