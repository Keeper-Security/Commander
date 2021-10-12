from contextlib import contextmanager

from .decryption_reader import DecryptionReader


class LastpassAttachment:
    def __init__(self, id, parent, mimetype, storagekey, size, filename):
        self.file_id = id
        self.parent = parent
        self.mime = mimetype
        self.storagekey = storagekey
        self.size = size
        self.name = filename
        self.tmpfile = None
        self.key = None  # This lets the importer know to re-encrypt with a new Keeper key

    @contextmanager
    def open(self):
        with DecryptionReader.get_buffered_reader(self.tmpfile, self.parent.attach_key) as reader:
            yield reader

    @contextmanager
    def open_text(self):
        with DecryptionReader.get_text_reader(self.tmpfile, self.parent.attach_key, encoding='utf-8-sig') as reader:
            yield reader
