# coding: utf-8
import json
import logging
import os
import shutil
from tempfile import mkdtemp

from . import fetcher
from . import parser
from .exceptions import InvalidResponseError
from .shared_folder import LastpassSharedFolder


TMPDIR_PREFIX = 'keepercommander_lastpass_import_'
DECRYPTED_SIZE_FILENAME = 'decrypted_file_sizes.json'


class Vault(object):
    @classmethod
    def open_remote(cls, username, password, multifactor_password=None, client_id=None, **kwargs):
        """Fetches a blob from the server and creates a vault"""
        session = fetcher.login(username, password, multifactor_password, client_id)
        blob = fetcher.fetch(session)
        encryption_key = blob.encryption_key(username, password)
        vault = cls(
            blob, encryption_key, session, tmpdir=kwargs.get('tmpdir'),
            shared_folder_details=kwargs.get('users_only') or False
        )

        fetcher.logout(session)
        return vault

    @classmethod
    def open_local(cls, blob_filename, username, password):
        """Creates a vault from a locally stored blob"""
        # TODO: read the blob here
        raise NotImplementedError()

    def __init__(self, blob, encryption_key, session, tmpdir=None, shared_folder_details=False, get_attachments=True):
        """This more of an internal method, use one of the static constructors instead"""
        chunks = parser.extract_chunks(blob)

        if not self.is_complete(chunks):
            raise InvalidResponseError('Blob is truncated')

        self.errors = set()
        self.shared_folders = []
        self.attachments = []
        self.accounts = self.parse_accounts(chunks, encryption_key)
        self.tmpdir = None

        if get_attachments:
            self.process_attachments(session, tmpdir)

        try:
            if self.shared_folders and shared_folder_details:
                for shared_folder in self.shared_folders:
                    members, teams, error = fetcher.fetch_shared_folder_members(session, shared_folder.id)
                    if error:
                        self.errors.add(error)
                        break
                    else:
                        shared_folder.members = members
                        shared_folder.teams = teams
        except:
            pass

    def is_complete(self, chunks):
        return len(chunks) > 0 and chunks[-1].id == b'ENDM' and chunks[-1].payload == b'OK'

    def parse_accounts(self, chunks, encryption_key):
        accounts = []

        key = encryption_key
        rsa_private_key = None
        shared_folder = None

        for i in chunks:
            if i.id == b'ACCT':
                account = parser.parse_ACCT(i, key, shared_folder)
                if account:
                    accounts.append(account)
            elif i.id == b'PRIK':
                rsa_private_key = parser.parse_PRIK(i, encryption_key)
            elif i.id == b'SHAR':
                # After SHAR chunk all the folliwing accounts are enrypted with a new key
                share = parser.parse_SHAR(i, encryption_key, rsa_private_key)
                key = share['encryption_key']
                shareid = share['id'].decode('utf-8')
                shared_folder = LastpassSharedFolder(shareid, share['name'].decode('utf-8'))
                self.shared_folders.append(shared_folder)
            elif i.id == b'ATTA':
                attachment = parser.parse_ATTA(i, accounts)
                if attachment:
                    self.attachments.append(attachment)

        return accounts

    def cleanup(self):
        """Cleanup should be performed when finished with encrypted attachment files"""
        if self.tmpdir:
            shutil.rmtree(self.tmpdir, ignore_errors=True)

    def process_attachments(self, session, tmpdir=None):
        skip_bad_attachments = []
        attach_cnt = len(self.attachments)
        if tmpdir is None:
            self.tmpdir = mkdtemp(prefix=TMPDIR_PREFIX)
        else:
            if not os.path.exists(tmpdir):
                os.makedirs(tmpdir)
            self.tmpdir = os.path.abspath(tmpdir)

        print(f'Processing {attach_cnt} LastPass attachments:')

        decrypted_size_file = os.path.join(self.tmpdir, DECRYPTED_SIZE_FILENAME)
        if os.path.exists(decrypted_size_file):
            with open(decrypted_size_file) as f:
                decrypted_file_sizes = json.loads(f.read())
        else:
            decrypted_file_sizes = {}
        update_decrypted_file_sizes = False

        for i, attachment in enumerate(self.attachments):
            tmp_filename = attachment.file_id
            attachment.tmpfile = os.path.join(self.tmpdir, tmp_filename)
            if os.path.isfile(attachment.tmpfile) and os.path.getsize(attachment.tmpfile) == attachment.lastpass_size:
                print(f'{i + 1}. Found {attachment.name}')
            else:
                attachment_stream = fetcher.stream_attachment(session, attachment)
                if attachment_stream:
                    try:
                        with attachment_stream as r:
                            with open(attachment.tmpfile, 'wb') as f:
                                print(f'{i + 1}. Downloading {attachment.name} ... ', end='', flush=True)
                                shutil.copyfileobj(r.raw, f)
                                print('Done')
                    except Exception as e:
                        logging.warning(f'Attachment {attachment.name} failed to download: {e}')
                        skip_bad_attachments.append(i)
                        continue

            if attachment.file_id in decrypted_file_sizes:
                attachment.size = decrypted_file_sizes[attachment.file_id]
            else:
                try:
                    with attachment.open() as atta:
                        with open(os.devnull, 'wb') as devnull:
                            shutil.copyfileobj(atta.raw, devnull)
                except Exception as e:
                    logging.warning(f'Attachment {attachment.name} is corrupted and failed to decrypt: {e}')
                    skip_bad_attachments.append(i)
                    continue

                update_decrypted_file_sizes = True
                decrypted_file_sizes[attachment.file_id] = attachment.size

        if skip_bad_attachments:
            for i in sorted(skip_bad_attachments, reverse=True):
                attachment = self.attachments[i]
                attachment.parent.attachments.remove(attachment)
                del self.attachments[i]

        if update_decrypted_file_sizes:
            with open(decrypted_size_file, 'w') as f:
                f.write(json.dumps(decrypted_file_sizes))
