# coding: utf-8
class Chunk(object):
    def __init__(self, id, payload):
        self.id = id
        self.payload = payload

    def __eq__(self, other):
        return self.id == other.id and self.payload == other.payload
