
import json
import logging

from urllib.parse import urlparse

import boto3
from botocore.exceptions import ClientError

from ..loader import SecureStorageBase, SecureStorageException

logging.getLogger('botocore').setLevel(logging.WARNING)


class SecretsManagerStorage(SecureStorageBase):
    @staticmethod
    def get_endpoint(url):    # type: (str) -> Tuple[str, str]
        res = urlparse(url)
        if res.scheme != 'aws-sm':
            raise ValueError(f'Invalid URL scheme. "aws-sm" is expected.')

        secret_key = res.path
        if secret_key.startswith('/'):
            secret_key = secret_key[1:]
        region_name = res.netloc
        return region_name, secret_key

    def load_configuration(self, url, storage_value=None):
        region_name, secret_name = SecretsManagerStorage.get_endpoint(url)
        try:
            session = boto3.session.Session()
            client = session.client(service_name='secretsmanager', region_name=region_name)
            value = client.get_secret_value(SecretId=secret_name)
            if 'SecretString' in value:
                return json.loads(value['SecretString'])
            return {}
        except ClientError as e:
            raise SecureStorageException(str(e))

    def store_configuration(self, url, configuration):
        region_name, secret_name = SecretsManagerStorage.get_endpoint(url)
        try:
            session = boto3.session.Session()
            client = session.client(service_name='secretsmanager', region_name=region_name)

            value = json.dumps(configuration)
            client.put_secret_value(SecretId=secret_name, SecretString=value)
        except ClientError as e:
            raise SecureStorageException(str(e))
