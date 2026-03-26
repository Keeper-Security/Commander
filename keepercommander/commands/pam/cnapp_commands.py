import argparse
import logging

from ..base import Command, GroupCommand
from .router_helper import _post_request_to_router
from ... import utils
from ...proto import cnapp_pb2


class CnappTestCommand(Command):
    parser = argparse.ArgumentParser(prog='pam cnapp test')
    parser.add_argument('-p', '--provider', required=True, help='CNAPP provider (e.g. WIZ)')
    parser.add_argument('--client-id', required=True, dest='client_id', help='OAuth2 client ID')
    parser.add_argument('--client-secret', required=True, dest='client_secret', help='OAuth2 client secret')
    parser.add_argument('--api-url', required=True, dest='api_url', help='API endpoint URL')
    parser.add_argument('--auth-url', required=True, dest='auth_url', help='OAuth2 auth URL')

    def get_parser(self):
        return CnappTestCommand.parser

    def execute(self, params, **kwargs):
        rq = cnapp_pb2.CnappTestCredentialsRequest()
        rq.provider = kwargs.get('provider', '')
        rq.clientId = kwargs.get('client_id', '')
        rq.clientSecret = kwargs.get('client_secret', '')
        rq.apiEndpointUrl = kwargs.get('api_url', '')
        rq.authUrl = kwargs.get('auth_url', '')

        rs = _post_request_to_router(params, 'cnapp/test-credentials',
                                     rq_proto=rq, rs_type=cnapp_pb2.CnappTestCredentialsResponse)
        if rs:
            if rs.valid:
                print(f'Credentials are valid: {rs.message}')
            else:
                print(f'Credentials are invalid: {rs.error} - {rs.message}')
        else:
            print('No response from router')


class CnappCreateCommand(Command):
    parser = argparse.ArgumentParser(prog='pam cnapp create')
    parser.add_argument('-p', '--provider', required=True, help='CNAPP provider (e.g. WIZ)')
    parser.add_argument('--client-id', required=True, dest='client_id', help='OAuth2 client ID')
    parser.add_argument('--client-secret', required=True, dest='client_secret', help='OAuth2 client secret')
    parser.add_argument('--api-url', required=True, dest='api_url', help='API endpoint URL')
    parser.add_argument('--auth-url', required=True, dest='auth_url', help='OAuth2 auth URL')
    parser.add_argument('-n', '--network-uid', required=True, dest='network_uid', help='Network UID (base64url)')
    parser.add_argument('--encryption-key-id', required=True, dest='encryption_key_id', help='Encryption record key ID (base64url)')
    parser.add_argument('-c', '--controller-uid', dest='controller_uid', default='', help='Controller UID (base64url)')
    parser.add_argument('-cc', '--cnapp-configuration-id', required=True, dest='cnapp_configuration_id', help='CNAPP Configuration ID string')

    def get_parser(self):
        return CnappCreateCommand.parser

    def execute(self, params, **kwargs):
        rq = cnapp_pb2.CnappConfigurationRequest()
        rq.networkUid = utils.base64_url_decode(kwargs.get('network_uid', ''))
        rq.provider = kwargs.get('provider', '')
        rq.clientId = kwargs.get('client_id', '')
        rq.clientSecret = kwargs.get('client_secret', '')
        rq.apiEndpointUrl = kwargs.get('api_url', '')
        rq.authUrl = kwargs.get('auth_url', '')
        rq.encryptionRecordKeyId = utils.base64_url_decode(kwargs.get('encryption_key_id', ''))
        controller_uid = kwargs.get('controller_uid', '')
        if controller_uid:
            rq.controllerUid = utils.base64_url_decode(controller_uid)
        rq.cnappConfigurationId = kwargs.get('cnapp_configuration_id', '')

        rs = _post_request_to_router(params, 'cnapp/configuration',
                                     rq_proto=rq, rs_type=cnapp_pb2.CnappConfigurationResponse)
        if rs:
            print(f'Configuration created:')
            print(f'  CNAPP Configuration ID:    {rs.cnappConfigurationId}')
            print(f'  Configuration URL:   {rs.configurationUrl}')
            print(f'  Configuration Token: {rs.configurationToken}')
        else:
            print('No response from router')


class CnappUpdateCommand(Command):
    parser = argparse.ArgumentParser(prog='pam cnapp update')
    parser.add_argument('-p', '--provider', required=True, help='CNAPP provider (e.g. WIZ)')
    parser.add_argument('-n', '--network-uid', required=True, dest='network_uid', help='Network UID (base64url)')
    parser.add_argument('--client-id', dest='client_id', default='', help='OAuth2 client ID')
    parser.add_argument('--client-secret', dest='client_secret', default='', help='OAuth2 client secret')
    parser.add_argument('--api-url', dest='api_url', default='', help='API endpoint URL')
    parser.add_argument('--auth-url', dest='auth_url', default='', help='OAuth2 auth URL')
    parser.add_argument('--encryption-key-id', dest='encryption_key_id', default='', help='Encryption record key ID (base64url)')
    parser.add_argument('-c', '--controller-uid', dest='controller_uid', default='', help='Controller UID (base64url)')
    parser.add_argument('-cc', '--cnapp-configuration-id', dest='cnapp_configuration_id', default='', help='CNAPP Configuration ID string')

    def get_parser(self):
        return CnappUpdateCommand.parser

    def execute(self, params, **kwargs):
        rq = cnapp_pb2.CnappConfigurationRequest()
        rq.networkUid = utils.base64_url_decode(kwargs.get('network_uid', ''))
        rq.provider = kwargs.get('provider', '')
        client_id = kwargs.get('client_id', '')
        if client_id:
            rq.clientId = client_id
        client_secret = kwargs.get('client_secret', '')
        if client_secret:
            rq.clientSecret = client_secret
        api_url = kwargs.get('api_url', '')
        if api_url:
            rq.apiEndpointUrl = api_url
        auth_url = kwargs.get('auth_url', '')
        if auth_url:
            rq.authUrl = auth_url
        encryption_key_id = kwargs.get('encryption_key_id', '')
        if encryption_key_id:
            rq.encryptionRecordKeyId = utils.base64_url_decode(encryption_key_id)
        controller_uid = kwargs.get('controller_uid', '')
        if controller_uid:
            rq.controllerUid = utils.base64_url_decode(controller_uid)
        cnapp_configuration_id = kwargs.get('cnapp_configuration_id', '')
        if cnapp_configuration_id:
            rq.cnappConfigurationId = cnapp_configuration_id

        rs = _post_request_to_router(params, 'cnapp/configuration/update',
                                     rq_proto=rq, rs_type=cnapp_pb2.CnappConfigurationResponse)
        if rs:
            print(f'Configuration updated:')
            print(f'  CNAPP Configuration ID:    {rs.cnappConfigurationId}')
            print(f'  Configuration URL:   {rs.configurationUrl}')
            print(f'  Configuration Token: {rs.configurationToken}')
        else:
            print('No response from router')


class CnappDeleteCommand(Command):
    parser = argparse.ArgumentParser(prog='pam cnapp delete')
    parser.add_argument('-n', '--network-uid', required=True, dest='network_uid', help='Network UID (base64url)')

    def get_parser(self):
        return CnappDeleteCommand.parser

    def execute(self, params, **kwargs):
        rq = cnapp_pb2.CnappDeleteConfigurationRequest()
        rq.networkUid = utils.base64_url_decode(kwargs.get('network_uid', ''))

        rs = _post_request_to_router(params, 'cnapp/configuration/delete', rq_proto=rq)
        print('CNAPP integration deleted successfully')


class CnappListCommand(Command):
    parser = argparse.ArgumentParser(prog='pam cnapp list')
    parser.add_argument('-n', '--network-uid', required=True, dest='network_uid', help='Network UID (base64url)')

    def get_parser(self):
        return CnappListCommand.parser

    def execute(self, params, **kwargs):
        rq = cnapp_pb2.CnappGetIntegrationRequest()
        rq.networkUid = utils.base64_url_decode(kwargs.get('network_uid', ''))

        rs = _post_request_to_router(params, 'cnapp/configuration/integration',
                                     rq_proto=rq, rs_type=cnapp_pb2.CnappGetIntegrationResponse)
        if rs:
            if not rs.integrations:
                print('No CNAPP integrations found for this network')
                return
            for i, item in enumerate(rs.integrations, 1):
                print(f'Integration {i}:')
                print(f'  Provider:           {item.provider}')
                print(f'  CNAPP Configuration ID:   {item.cnappConfigurationId}')
                print(f'  API URL:            {item.apiUrl}')
                print(f'  Auth URL:           {item.authUrl}')
                print(f'  Controller UID:     {item.controllerUid}')
                print(f'  Configuration URL:  {item.configurationUrl}')
                print(f'  Client ID:          {item.clientId}')
                if item.encryptionRecordKeyId:
                    print(f'  Encryption Key ID:  {utils.base64_url_encode(item.encryptionRecordKeyId)}')
                print()
        else:
            print('No response from router')


class CnappCommand(GroupCommand):

    def __init__(self):
        super(CnappCommand, self).__init__()
        self.register_command('test', CnappTestCommand(), 'Test CNAPP provider credentials', 't')
        self.register_command('create', CnappCreateCommand(), 'Create CNAPP integration', 'c')
        self.register_command('update', CnappUpdateCommand(), 'Update CNAPP integration', 'u')
        self.register_command('delete', CnappDeleteCommand(), 'Delete CNAPP integration', 'd')
        self.register_command('list', CnappListCommand(), 'List CNAPP integrations', 'l')
