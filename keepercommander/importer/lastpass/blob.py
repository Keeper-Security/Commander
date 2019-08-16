# coding: utf-8
class Blob(object):
    def __init__(self, bytes, key_iteration_count):
        self.bytes = bytes
        self.key_iteration_count = key_iteration_count

    def encryption_key(self, username, password):
        from . import fetcher
        return fetcher.make_key(username, password, self.key_iteration_count)

    def __eq__(self, other):
        return self.bytes == other.bytes and self.key_iteration_count == other.key_iteration_count
