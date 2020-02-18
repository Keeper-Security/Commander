#  _  __  
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|            
#
# Keeper Commander 
# Contact: ops@keepersecurity.com
#
import datetime
import hashlib
import base64
import hmac

from urllib import parse

from .subfolder import get_folder_path, find_folders, BaseFolderNode
from .error import Error


def get_totp_code(url):
    # type: (str) -> (str, int) or None
    comp = parse.urlparse(url)
    if comp.scheme == 'otpauth':
        secret = None
        algorithm = 'SHA1'
        digits = 6
        period = 30
        for k, v in parse.parse_qsl(comp.query):
            if k == 'secret':
                secret = v
            elif k == 'algorithm':
                algorithm = v
            elif k == 'digits':
                digits = int(v)
            elif k == 'period':
                period = int(v)
        if secret:
            tm_base = int(datetime.datetime.now().timestamp())
            tm = tm_base / period
            alg = algorithm.lower()
            if alg in hashlib.__dict__:
                reminder = len(secret) % 8
                if reminder in {2, 4, 5, 7}:
                    padding = '=' * (8 - reminder)
                    secret += padding
                key = base64.b32decode(secret, casefold=True)
                msg = int(tm).to_bytes(8, byteorder='big')
                hash = hashlib.__dict__[alg]
                hm = hmac.new(key, msg=msg, digestmod=hash)
                digest = hm.digest()
                offset = digest[-1] & 0x0f
                base = bytearray(digest[offset:offset + 4])
                base[0] = base[0] & 0x7f
                code_int = int.from_bytes(base, byteorder='big')
                code = str(code_int % (10 ** digits))
                if len(code) < digits:
                    code = code.rjust(digits, '0')
                return code, period - (tm_base % period), period
            else:
                raise Error('Unsupported hash algorithm: {0}'.format(algorithm))


class Record:
    """Defines a user-friendly Keeper Record for display purposes"""

    def __init__(self, record_uid='', folder='', title='', login='', password='', login_url='', notes='',
                 custom_fields=None, revision=''):
        self.record_uid = record_uid
        self.folder = folder
        self.title = title
        self.login = login
        self.password = password
        self.login_url = login_url
        self.notes = notes
        self.custom_fields = custom_fields or []  # type: list
        self.attachments = None
        self.revision = revision
        self.unmasked_password = None
        self.totp = None

    def load(self, data, **kwargs):

        def xstr(s):
            return str(s or '')

        if 'folder' in data:
            self.folder = xstr(data['folder'])
        if 'title' in data:
            self.title = xstr(data['title'])
        if 'secret1' in data:
            self.login = xstr(data['secret1'])
        if 'secret2' in data:
            self.password = xstr(data['secret2'])
        if 'notes' in data:
            self.notes = xstr(data['notes'])
        if 'link' in data:
            self.login_url = xstr(data['link'])
        if 'custom' in data:
            self.custom_fields = data['custom']
        if 'revision' in kwargs:
            self.revision = kwargs['revision']
        if 'extra' in kwargs and kwargs['extra']:
            extra = kwargs['extra']
            self.attachments = extra.get('files')
            if 'fields' in extra:
                for field in extra['fields']:
                    if field['field_type'] == 'totp':
                        self.totp = field['data']

    def get(self, field):
        result = ''
        for c in self.custom_fields:
            if (c['name'] == field):
                result = c['value']
                break
        return result

    def set_field(self, name, value):
        found = False
        for field in self.custom_fields:
            if field['name'] == name:
                field['value'] = value
                found = True
                break
        if not found:
            self.custom_fields.append({'name': name, 'value': value})

    def remove_field(self, name):
        if self.custom_fields:
            idxs = [i for i, x in enumerate(self.custom_fields) if x['name'] == name]
            if len(idxs) == 1:
                return self.custom_fields.pop(idxs[0])

    def display(self, **kwargs):
        print('')
        print('{0:>20s}: {1:<20s}'.format('UID', self.record_uid))
        params = None
        if 'params' in kwargs:
            params = kwargs['params']
            folders = [get_folder_path(params, x) for x in find_folders(params, self.record_uid)]
            for i in range(len(folders)):
                print('{0:>21s} {1:<20s}'.format('Folder:' if i == 0 else '', folders[i]))

        if self.title: print('{0:>20s}: {1:<20s}'.format('Title', self.title))
        if self.login: print('{0:>20s}: {1:<20s}'.format('Login', self.login))
        if self.password: print('{0:>20s}: {1:<20s}'.format('Password', self.password))
        if self.login_url: print('{0:>20s}: {1:<20s}'.format('URL', self.login_url))
        # print('{0:>20s}: https://keepersecurity.com/vault#detail/{1}'.format('Link',self.record_uid))

        if len(self.custom_fields) > 0:
            for c in self.custom_fields:
                if not 'value' in c: c['value'] = ''
                if not 'name' in c: c['name'] = ''
                print('{0:>20s}: {1:<s}'.format(c['name'], c['value']))

        if self.notes:
            lines = self.notes.split('\n')
            for i in range(len(lines)):
                print('{0:>21s} {1}'.format('Notes:' if i == 0 else '', lines[i].strip()))

        if self.attachments:
            for i in range(len(self.attachments)):
                atta = self.attachments[i]
                size = atta.get('size') or 0
                scale = 'b'
                if size > 0:
                    if size > 1000:
                        size = size / 1024
                        scale = 'Kb'
                    if size > 1000:
                        size = size / 1024
                        scale = 'Mb'
                    if size > 1000:
                        size = size / 1024
                        scale = 'Gb'
                sz = '{0:.2f}'.format(size).rstrip('0').rstrip('.')
                print('{0:>21s} {1:<20s} {2:>6s}{3:<2s} {4:>6s}: {5}'.format('Attachments:' if i == 0 else '',
                                                                             atta.get('title') or atta.get('name'),
                                                                             sz, scale, 'ID',
                                                                             atta.get('id')))

        if self.totp:
            code, remain, _ = get_totp_code(self.totp)
            if code: print('{0:>20s}: {1:<20s} valid for {2} sec'.format('Two Factor Code', code, remain))

        if params is not None:
            if self.record_uid in params.record_cache:
                rec = params.record_cache[self.record_uid]
                if 'shares' in rec:
                    no = 0
                    if 'user_permissions' in rec['shares']:
                        perm = rec['shares']['user_permissions'].copy()
                        perm.sort(key=lambda r: (' 1' if r.get('owner') else ' 2' if r.get(
                            'editable') else ' 3' if r.get('sharable') else '') + r.get('username'))
                        for uo in perm:
                            flags = ''
                            if uo.get('owner'):
                                flags = 'Owner'
                            elif uo.get('awaiting_approval'):
                                flags = 'Awaiting Approval'
                            else:
                                if uo.get('editable'):
                                    flags = 'Edit'
                                if uo.get('sharable'):
                                    if flags:
                                        flags = flags + ', '
                                    flags = flags + 'Share'
                            if not flags:
                                flags = 'View'

                            print('{0:>21s} {1} ({2}) {3}'.format('Shared Users:' if no == 0 else '', uo['username'],
                                                                  flags,
                                                                  'self' if uo['username'] == params.user else ''))
                            no = no + 1
                    no = 0
                    if 'shared_folder_permissions' in rec['shares']:
                        for sfo in rec['shares']['shared_folder_permissions']:
                            flags = ''
                            if sfo.get('editable'):
                                flags = 'Edit'
                            if sfo.get('reshareable'):
                                if flags:
                                    flags = flags + ', '
                                flags = flags + 'Share'
                            if not flags:
                                flags = 'View'
                            sf_uid = sfo['shared_folder_uid']
                            for f_uid in find_folders(params, self.record_uid):
                                if f_uid in params.subfolder_cache:
                                    fol = params.folder_cache[f_uid]
                                    if fol.type in {BaseFolderNode.SharedFolderType,
                                                    BaseFolderNode.SharedFolderFolderType}:
                                        sfid = fol.uid if fol.type == BaseFolderNode.SharedFolderType else fol.shared_folder_uid
                                        if sf_uid == sfid:
                                            print('{0:>21s} {1:<20s}'.format('Shared Folders:' if no == 0 else '',
                                                                             fol.name))
                                            no = no + 1

        print('')

    def mask_password(self):
        if self.password != '******':
            self.unmasked_password = self.password
        self.password = '******'

    def to_string(self):
        target = self.record_uid + self.folder + self.title + \
                 self.login + self.password + self.notes + \
                 self.login_url + str(self.custom_fields)
        return target

    def to_lowerstring(self):
        return self.to_string().lower()

    def to_tab_delimited(self):

        def tabulate(*args):
            return '\t'.join(args)

        custom_fields = ''
        if self.custom_fields:
            for field in self.custom_fields:
                if ('name' in field) and ('value' in field):
                    custom_fields = '\t'.join([field['name'] + '\t' + \
                                               field['value'] for field in self.custom_fields])

        return tabulate(self.folder, self.title, self.login,
                        self.password, self.login_url, self.notes.replace('\n', '\\\\n'),
                        custom_fields)

    def to_dictionary(self):
        return {
            'uid': self.record_uid,
            'folder': self.folder,
            'title': self.title,
            'login': self.login,
            'password': self.password,
            'login_url': self.login_url,
            'notes': self.notes,
            'custom_fields': self.custom_fields,
        }
