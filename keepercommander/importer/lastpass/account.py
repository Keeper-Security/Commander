# coding: utf-8
class Account(object):
    def __init__(self, id, name, username, password, url, group, notes=None):
        self.id = id
        self.name = name
        self.username = username
        self.password = password
        self.url = url
        self.group = group
        self.notes = notes
