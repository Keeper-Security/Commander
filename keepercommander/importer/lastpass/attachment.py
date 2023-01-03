from contextlib import contextmanager

from .attachment_reader import LastpassAttachmentReader
from ..importer import Attachment


class LastpassAttachment(Attachment):
    def __init__(self, id, parent, mimetype, storagekey, lastpass_size, filename):
        super().__init__()
        self.file_id = id
        self.parent = parent
        self.mime = mimetype
        self.storagekey = storagekey
        self.lastpass_size = lastpass_size
        self.name = filename
        self.tmpfile = None
        self.size = None  # Decrypted size to pass to importer
        self.key = None  # This lets the importer know to re-encrypt with a new Keeper key

    @contextmanager
    def open(self):
        with LastpassAttachmentReader.get_buffered_reader(self) as reader:
            yield reader

    @contextmanager
    def open_text(self):
        with LastpassAttachmentReader.get_text_reader(self, encoding='utf-8-sig') as reader:
            yield reader
