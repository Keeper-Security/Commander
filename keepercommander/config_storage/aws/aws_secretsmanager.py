
import json
import logging

from urllib.parse import urlparse

import boto3
from botocore.exceptions import ClientError

from ..loader import SecureStorageBase, SecureStorageException

logging.getLogger('botocore').setLevel(logging.WARNING)


class SecretsManagerStorage(SecureStorageBase):
    def load_configuration(self, url):    # type: (str) -> dict
        res = urlparse(url)
        if res.scheme != 'aws':
            raise ValueError(f'Invalid URL scheme. "aws" is expected.')

        secret_name = res.path
        if secret_name.startswith('/'):
            secret_name = secret_name[1:]
        region_name = res.netloc

        try:
            session = boto3.session.Session()
            client = session.client(service_name='secretsmanager', region_name=region_name)
            value = client.get_secret_value(SecretId=secret_name)
            if 'SecretString' in value:
                return json.loads(value['SecretString'])
            return {}
        except ClientError as e:
            raise SecureStorageException(str(e))

    def store_configuration(self, url, configuration):  # type: (str, dict) -> None
        res = urlparse(url)
        if res.scheme != 'aws':
            raise ValueError(f'Invalid URL scheme. "aws" is expected.')

        secret_name = res.path
        if secret_name.startswith('/'):
            secret_name = secret_name[1:]
        region_name = res.netloc

        try:
            session = boto3.session.Session()
            client = session.client(service_name='secretsmanager', region_name=region_name)

            value = json.dumps(configuration)
            client.put_secret_value(SecretId=secret_name, SecretString=value)
        except ClientError as e:
            raise SecureStorageException(str(e))
