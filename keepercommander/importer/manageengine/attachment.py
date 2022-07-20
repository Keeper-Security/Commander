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
import requests
from contextlib import contextmanager

from ..importer import Attachment


class ManageEngineAttachment(Attachment):
    def __init__(self, name, request_kwargs):
        Attachment.__init__(self)
        self.name = name

        attach_size = 0
        request_kwargs['stream'] = True
        with requests.get(**request_kwargs) as r:
            r.raw.decode_content = True
            for chunk in r.iter_content(chunk_size=10000):
                attach_size += len(chunk)

        self.size = attach_size
        self.request_kwargs = request_kwargs

    @contextmanager
    def open(self):
        response = requests.get(**self.request_kwargs)
        response.raw.decode_content = True
        yield response.raw
