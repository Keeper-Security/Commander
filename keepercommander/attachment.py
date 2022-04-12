#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Contact: ops@keepersecurity.com
#

import logging
import os
import shutil
from typing import BinaryIO, Iterator, Optional, List

import requests

from . import crypto, api, utils
from .params import KeeperParams
from .proto import record_pb2
from .vault import KeeperRecord, PasswordRecord, TypedRecord, FileRecord, AttachmentFile


def prepare_attachment_download(params, record_uid, attachment_name=None):
    # type: (KeeperParams, str, Optional[str]) -> Iterator['AttachmentDownloadRequest']
    record = KeeperRecord.load(params, record_uid)
    if not record:
        logging.warning('Record UID \"%s\" not found.', record_uid)

    if record.version in {3, 4}:
        rq = record_pb2.FilesGetRequest()
        rq.for_thumbnails = False
        if isinstance(record, FileRecord):
            rq.record_uids.append(utils.base64_url_decode(record.record_uid))
        elif isinstance(record, TypedRecord):
            typed_field = record.get_typed_field('fileRef')
            if typed_field and isinstance(typed_field.value, list):
                for file_uid in typed_field.value:
                    file_record = KeeperRecord.load(params, file_uid)
                    if isinstance(file_record, FileRecord):
                        if attachment_name:
                            if attachment_name != file_uid and file_record.title.lower() != attachment_name.lower() and \
                                    file_record.name.lower() != attachment_name.lower():
                                continue
                        rq.record_uids.append(utils.base64_url_decode(file_uid))

        if len(rq.record_uids) > 0:
            rs = api.communicate_rest(params, rq, 'vault/files_download', rs_type=record_pb2.FilesGetResponse)
            for file_status in rs.files:
                file_uid = utils.base64_url_encode(file_status.record_uid)
                if file_status.status == record_pb2.FG_SUCCESS:
                    file_record = KeeperRecord.load(params, file_uid)
                    if isinstance(file_record, FileRecord):
                        adr = AttachmentDownloadRequest()
                        adr.url = file_status.url
                        adr.success_status_code = file_status.success_status_code
                        adr.encryption_key = file_record.record_key
                        adr.title = file_record.title if file_record.title else file_record.name
                        adr.is_gcm_encrypted = file_status.fileKeyType == record_pb2.ENCRYPTED_BY_DATA_KEY_GCM
                        yield adr
                else:
                    logging.warning('Error requesting download URL for file \"%s\"', file_uid)
    elif record.version == 2:
        attachments = []   # type: List[AttachmentFile]
        if isinstance(record, PasswordRecord):
            for atta in (record.attachments or []):
                if attachment_name:
                    if attachment_name != atta.id and attachment_name.lower() != atta.title.lower() and \
                            attachment_name.lower() != atta.name.lower():
                        continue
                attachments.append(atta)
        if len(attachments) > 0:
            rq = {
                'command': 'request_download',
                'file_ids': [x.id for x in attachments],
            }
            api.resolve_record_access_path(params, record_uid, path=rq)
            rs = api.communicate(params, rq)

            if rs['result'] == 'success':
                for attachment, dl in zip(attachments, rs['downloads']):
                    if 'url' in dl:
                        adr = AttachmentDownloadRequest()
                        adr.title = attachment.title if attachment.title else attachment.name
                        adr.url = dl['url']
                        adr.encryption_key = utils.base64_url_decode(attachment.key)
                        adr.is_gcm_encrypted = False
                        yield adr


class AttachmentDownloadRequest:
    def __init__(self):
        self.url = ''
        self.encryption_key = b''
        self.title = ''
        self.is_gcm_encrypted = False
        self.success_status_code = 200

    def download_to_file(self, params, file_name):  # type: (KeeperParams, str) -> None
        logging.info('Downloading \'%s\'', os.path.abspath(file_name))
        with open(file_name, 'wb') as file_stream:
            self.download_to_stream(params, file_stream)

    def download_to_stream(self, params, output_stream):  # type: (KeeperParams, BinaryIO) -> int
        with requests.get(self.url, proxies=params.rest_context.proxies, stream=True) as rq_http:
            if self.success_status_code != rq_http.status_code:
                logging.warning('HTTP status code: %d', rq_http.status_code)
            crypter = crypto.StreamCrypter()
            crypter.is_gcm = self.is_gcm_encrypted
            crypter.key = self.encryption_key
            with crypter.set_stream(rq_http.raw, for_encrypt=False) as attachment:
                shutil.copyfileobj(attachment, output_stream, 10240)
            output_stream.flush()
            return crypter.bytes_read
