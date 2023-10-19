# coding: utf-8
import json
import logging
import os
import shutil
import sys
from tempfile import mkdtemp
from typing import Optional

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
        session = fetcher.login(username, password, multifactor_password, client_id, **kwargs)
        blob = fetcher.fetch(session, **kwargs)
        encryption_key = blob.encryption_key(username, password)
        vault = cls(blob, encryption_key, session, **kwargs)

        fetcher.logout(session, **kwargs)
        return vault

    @classmethod
    def open_local(cls, blob_filename, username, password):
        """Creates a vault from a locally stored blob"""
        # TODO: read the blob here
        raise NotImplementedError()

    def __init__(self, blob, encryption_key, session, tmpdir=None, shared_folder_details=False, get_attachments=True,
                 **kwargs):
        """This more of an internal method, use one of the static constructors instead"""
        chunks = parser.extract_chunks(blob)

        if not self.is_complete(chunks):
            raise InvalidResponseError('Blob is truncated')

        self.errors = set()
        self.shared_folders = []
        self.attachments = []
        self.accounts = self.parse_accounts(chunks, encryption_key)
        self.tmpdir = None
        self.proxies = kwargs.get('proxies')
        self.certificate_check = kwargs.get('certificate_check')

        if 'filter_folder' in kwargs and kwargs['filter_folder']:
            folder_name = kwargs['filter_folder'].lower()
            shared_folder = next((x for x in self.shared_folders if x.name.lower() == folder_name), None)
            if isinstance(shared_folder, LastpassSharedFolder):
                self.shared_folders = [shared_folder]
                self.accounts = [x for x in self.accounts if x.shared_folder is shared_folder]
            else:
                self.shared_folders = []
                self.accounts = [x for x in self.accounts if not x.shared_folder and x.group and x.group.lower() == folder_name]
            account_ids = {x.id for x in self.accounts}
            self.attachments = [x for x in self.attachments if x.parent.id in account_ids]

        if get_attachments:
            self.process_attachments(session, tmpdir, proxies=self.proxies, certificate_check=self.certificate_check)

        try:
            if self.shared_folders and shared_folder_details:
                for shared_folder in self.shared_folders:
                    members, teams, error = fetcher.fetch_shared_folder_members(
                        session, shared_folder.id, proxies=self.proxies, certificate_check=self.certificate_check)
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
        rsa_private_key = None   # type: Optional[bytes]
        shared_folder = None
        last_account = None
        for i in chunks:
            if i.id == b'ACCT':
                try:
                    last_account = parser.parse_ACCT(i, key, shared_folder)
                except Exception as e:
                    logging.debug('Account parse error: %s', e)
                    last_account = None
                if last_account:
                    accounts.append(last_account)
            elif i.id == b'PRIK':
                rsa_private_key = parser.parse_PRIK(i, encryption_key)
            elif i.id == b'SHAR':
                # After SHAR chunk all the folliwing accounts are enrypted with a new key
                share = parser.parse_SHAR(i, encryption_key, rsa_private_key)
                key = share['encryption_key']
                shareid = share['id'].decode('utf-8')
                share_name = share['name'].decode('utf-8')
                share_name = share_name.strip()
                shared_folder = LastpassSharedFolder(shareid, share['name'].decode('utf-8'))
                self.shared_folders.append(shared_folder)
            elif i.id == b'ATTA':
                attachment = parser.parse_ATTA(i, accounts)
                if attachment:
                    self.attachments.append(attachment)
            elif i.id in (b'ACFL', b'ACOF'):
                if last_account:
                    try:
                        cf = parser.parse_ACFL(i, key)
                        if cf:
                            last_account.custom_fields.append(cf)
                    except Exception as e:
                        logging.debug('Error parsing custom field ID: %s: %s', i.id.decode(), e)
            else:
                pass

        return accounts

    def cleanup(self):
        """Cleanup should be performed when finished with encrypted attachment files"""
        if self.tmpdir:
            shutil.rmtree(self.tmpdir, ignore_errors=True)

    def process_attachments(self, session, tmpdir=None, **kwargs):
        skip_bad_attachments = []
        attach_cnt = len(self.attachments)
        if attach_cnt == 0:
            return

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
                attachment_stream = fetcher.stream_attachment(session, attachment, **kwargs)
                if attachment_stream:
                    try:
                        with attachment_stream as r:
                            with open(attachment.tmpfile, 'wb') as f:
                                print(f'{i + 1}. Downloading {attachment.name} ... ', file=sys.stderr, end='', flush=True)
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
