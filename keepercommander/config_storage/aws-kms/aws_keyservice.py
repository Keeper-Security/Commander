from typing import Optional, Tuple

import json
import logging
from urllib.parse import urlparse

import boto3
from botocore.exceptions import ClientError

from ..loader import SecureStorageBase, SecureStorageException
logging.getLogger('botocore').setLevel(logging.WARNING)


class KeyManagementService(SecureStorageBase):
    @staticmethod
    def get_endpoint(url):    # type: (str) -> Tuple[str, str]
        res = urlparse(url)
        if res.scheme != 'aws-kms':
            raise ValueError(f'Invalid URL scheme. "aws-kms" is expected.')

        secret_key = res.path
        if secret_key.startswith('/'):
            secret_key = secret_key[1:]
        region_name = res.netloc
        return region_name, secret_key

    def load_configuration(self, url, encrypted_data=None):    # type: (str, Optional[bytes]) -> dict
        region, secret_key = KeyManagementService.get_endpoint(url)
        try:
            session = boto3.session.Session()
            if encrypted_data:
                kms = session.client(service_name='kms', region_name=region)
                rs = kms.decrypt(KeyId=secret_key, CiphertextBlob=encrypted_data)
                decrypted_config = rs['Plaintext']     # type: bytes
                return json.loads(decrypted_config.decode())
            return {}
        except ClientError as e:
            raise SecureStorageException(str(e))

    def store_configuration(self, url, configuration):
        region, secret_key = KeyManagementService.get_endpoint(url)
        try:
            session = boto3.session.Session()
            if isinstance(configuration, dict):
                kms = session.client(service_name='kms', region_name=region)
                config_data = json.dumps(configuration).encode()
                rs = kms.encrypt(KeyId=secret_key, Plaintext=config_data)
                return rs['CiphertextBlob']     # type: bytes
            return {}
        except ClientError as e:
            raise SecureStorageException(str(e))


