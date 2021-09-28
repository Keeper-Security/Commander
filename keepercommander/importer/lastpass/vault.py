# coding: utf-8
from . import fetcher
from . import parser
from .exceptions import InvalidResponseError
from .shared_folder import SharedFolder


class Vault(object):
    @classmethod
    def open_remote(cls, username, password, multifactor_password=None, client_id=None):
        """Fetches a blob from the server and creates a vault"""
        session = fetcher.login(username, password, multifactor_password, client_id)
        blob = fetcher.fetch(session)
        encryption_key = blob.encryption_key(username, password)
        return cls(blob, encryption_key, session)

    @classmethod
    def open_local(cls, blob_filename, username, password):
        """Creates a vault from a locally stored blob"""
        # TODO: read the blob here
        raise NotImplementedError()


    def __init__(self, blob, encryption_key, session):
        """This more of an internal method, use one of the static constructors instead"""
        chunks = parser.extract_chunks(blob)

        if not self.is_complete(chunks):
            raise InvalidResponseError('Blob is truncated')

        self.accounts = self.parse_accounts(chunks, encryption_key, session)

    def is_complete(self, chunks):
        return len(chunks) > 0 and chunks[-1].id == b'ENDM' and chunks[-1].payload == b'OK'

    def parse_accounts(self, chunks, encryption_key, session):
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
                shared_folder_members = fetcher.fetch_shared_folder_members(session, shareid)
                shared_folder = SharedFolder(shareid, share['name'].decode('utf-8'), shared_folder_members)

        fetcher.logout(session)
        return accounts
