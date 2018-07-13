#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2018 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import libkeepass

from ..importer import PathDelimiter, BaseImporter, Record, Folder


class KeepassImporter(BaseImporter):

    @staticmethod
    def get_folder(group):
        g = group
        name = ''
        while g.tag == 'Group':
            nm = g.find('Name')
            if nm is not None:
                n = nm.text.replace(PathDelimiter, PathDelimiter*2)
                if len(name) > 0:
                    name = PathDelimiter + name
                name = n + name
            g = g.getparent()
        return name

    def do_import(self, filename):
        password = input('...' + 'Password'.rjust(16) + ': ')

        with libkeepass.open(filename, password=password) as kdb:
            root = kdb.obj_root.find('Root/Group')
            if root is not None:
                groups = [root]
                pos = 0
                while pos < len(groups):
                    g = groups[pos]
                    groups.extend(g.findall('Group'))
                    pos = pos + 1

                for group in groups:
                    entries = group.findall('Entry')
                    if len(entries) > 0:
                        folder = KeepassImporter.get_folder(group)
                        for entry in entries:
                            record = Record()
                            fol = Folder()
                            fol.path = folder
                            record.folders = [fol]
                            # node = entry.find('UUID')
                            # if node is not None:
                            #     record.record_uid = base64.urlsafe_b64encode(base64.b64decode(node.text)).decode().rstrip('=')
                            for node in entry.findall('String'):
                                sn = node.find('Key')
                                if sn is None:
                                    continue
                                key = sn.text
                                sn = node.find('Value')
                                if sn is None:
                                    continue
                                value = sn.text
                                if key == 'Title':
                                    record.title = value
                                elif key == 'UserName':
                                    record.login = value
                                elif key == 'Password':
                                    record.password = value
                                elif key == 'URL':
                                    record.login_url = value
                                elif key == 'Notes':
                                    record.notes = value
                                else:
                                    record.custom_fields.append({'name': key, 'value': value})

                            yield record
