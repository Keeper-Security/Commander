from contextlib import contextmanager

from .decryption_reader import DecryptionReader


class Attachment:
    def __init__(self, id, parent, mimetype, storagekey, size, filename):
        self.id = id
        self.parent = parent
        self.mimetype = mimetype
        self.storagekey = storagekey
        self.size = size
        self.filename = filename
        self.tmpfile = None

    @contextmanager
    def open(self):
        with DecryptionReader.get_buffered_reader(self.tmpfile, self.parent.attach_key) as reader:
            yield reader

    @contextmanager
    def open_text(self):
        with DecryptionReader.get_text_reader(self.tmpfile, self.parent.attach_key, encoding='utf-8-sig') as reader:
            yield reader
