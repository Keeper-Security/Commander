class Attachment:
    def __init__(self, id, parent, mimetype, storagekey, size, filename):
        self.id = id
        self.parent = parent
        self.mimetype = mimetype
        self.storagekey = storagekey
        self.size = size
        self.filename = filename
        self.tmpfile = None

    # TODO: Make methods for fetching and returning stream of attachment data
