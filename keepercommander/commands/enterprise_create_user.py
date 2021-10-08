#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2021 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import argparse
import logging
import re

from .. import api, crypto
from .base import RecordMixin, raise_parse_exception, suppress_exit
from .enterprise import EnterpriseCommand
from ..loginv3 import LoginV3API
from ..constants import EMAIL_PATTERN
from .. import utils
from ..record import Record
from ..params import KeeperParams
from ..proto import breachwatch_pb2 as breachwatch_proto
from ..proto import enterprise_pb2 as enterprise_proto


def register_commands(commands):
    commands['create-user'] = CreateEnterpriseUserCommand()


def register_command_info(_, command_info):
    command_info['create-user'] = 'Create Enterprise User'


register_parser = argparse.ArgumentParser(prog='create-user', description='Creates enterprise user')
register_parser.add_argument('--name', dest='name', action='store', help='user name')
register_parser.add_argument('--node', dest='node', action='store', help='node name or node ID')
register_parser.add_argument('--record', dest='record', action='store', help='record title or record UID to store the passwords')
register_parser.add_argument('email', action='append', help='email')
register_parser.error = raise_parse_exception
register_parser.exit = suppress_exit


class CreateEnterpriseUserCommand(EnterpriseCommand, RecordMixin):
    def get_parser(self):
        return register_parser

    def execute(self, params, **kwargs):
        node_name = kwargs.get('node')
        nodes = list(self.resolve_nodes(params, node_name))
        if len(nodes) == 0:
            logging.warning('Node \"%s\" is not found', node_name)
            return
        if len(nodes) > 1:
            logging.warning('More than one nodes \"%s\" are found', node_name)
            return

        enterprise_ec_public_key = None
        rs = api.communicate_rest(params, None, 'enterprise/get_enterprise_public_key', rs_type=breachwatch_proto.EnterprisePublicKeyResponse)
        if rs.enterpriseECCPublicKey:
            enterprise_ec_public_key = crypto.load_ec_public_key(rs.enterpriseECCPublicKey)

        node_id = nodes[0]['node_id']
        emails = kwargs.get('email', [])
        email_pattern = re.compile(EMAIL_PATTERN)

        added_accounts = {}
        for email in emails:
            match = email_pattern.match(email)
            if not match:
                logging.warning('"%s" appears not a valid email address. Skipping.', email)
                continue

            verification_code = ''
            try:
                verification_code = LoginV3API.provision_user_in_enterprise(params, email, node_id)
            except Exception as e:
                logging.error(e)
            if not verification_code:
                logging.warning('Failed to add account "%s" to enterprise. Skipping.', email)
                continue

            password = utils.generate_uid()
            try:
                LoginV3API.create_user(params, email, password, verification_code)
                added_accounts[email] = password

            except Exception as e:
                logging.error(e)
                logging.warning('Failed to create account "%s". Skipping.', email)

        if len(added_accounts) == 0:
            logging.info('No users created.')
            return

        record_name = kwargs.get('record') or 'Enterprise User Passwords'
        record_uid = next(self.resolve_records(params, record_name), None)
        if record_uid:
            record = api.get_record(params, record_uid)
        else:
            record = Record()
            record.title = record_name
        for name, value in added_accounts.items():
            record.set_field(name, value)

        try:
            if record.record_uid:
                api.update_record(params, record, silent=True)
            else:
                api.add_record(params, record, silent=True)
        except Exception as e:
            logging.info('Record store error: %s', e)

        param1 = KeeperParams()
        param1.server = params.server
        param1.device_token = params.device_token or params.config.get('device_token', '')
        param1.device_private_key = params.device_private_key or params.config.get('private_key', '')
        for email in added_accounts:
            param1.user = email
            param1.password = added_accounts[email]
            param1.data_key = b''
            try:
                api.login(param1)
                rq = enterprise_proto.EnterpriseUserDataKey()
                rq.userEncryptedDataKey = crypto.encrypt_ec(param1.data_key, enterprise_ec_public_key)
                api.communicate_rest(param1, rq, 'enterprise/set_enterprise_user_data_key')
            except Exception as e:
                logging.warning(e)
            try:
                rq = {
                    'command': 'set_master_password_expire',
                    'email': email
                }
                api.communicate(params, rq)
            except Exception as e:
                pass

"""
        if not displayname:
            raise CommandError('register', '\'name\' parameter is required for enterprise users')

        # Provision user to the logged-in admin's enterprise
        verification_code = LoginV3API().provision_user_in_enterprise(params, email, node, displayname)

        if verification_code:
            logging.info("User '%s' created and added to the enterprise" % email)

            # Create user (will send email to the user)
            info = LoginV3API().create_user(params, email, verification_code)
            print(info)

            # Refresh (sync-down) enterprise data only
            api.query_enterprise(params)
            if 'users' in params:
                pass




        email = kwargs['email'] if 'email' in kwargs else None

        if email:
            _, email = parseaddr(email)
        if not email:
            raise CommandError('register', 'A valid email address is expected.')

        rq = {
            'command': 'pre_register',
            'email': email
        }

        rs = api.run_command(params, rq)
        if rs['result_code'] != 'Failed_to_find_user':
            if rs['result'] == 'success':
                logging.warning('User \'%s\' already exists in Keeper', email)
            else:
                logging.error(rs['message'])
            # return
        else:
            password_rules = rs['password_rules']

        # check enterprise
        verification_code = None
        if params.enterprise:
            node_id = None
            if kwargs.get('node'):
                for node in params.enterprise['nodes']:
                    if kwargs['node'] in {str(node['node_id']), node['data'].get('displayname')}:
                        node_id = node['node_id']
                        break
                    elif not node.get('parent_id') and kwargs['node'] == params.enterprise['enterprise_name']:
                        node_id = node['node_id']
                        break
            if node_id is None:
                for node in params.enterprise['nodes']:
                    if not node.get('parent_id'):
                        node_id = node['node_id']
                        break
            data = {}
            name = kwargs.get('name')
            if name:
                data['displayname'] = name
            else:
                raise CommandError('register', '\'name\' parameter is required for enterprise users')

            rq = {
                'command': 'enterprise_user_add',
                'enterprise_user_id': EnterpriseCommand.get_enterprise_id(params),
                'enterprise_user_username': email,
                'encrypted_data': api.encrypt_aes(json.dumps(data).encode('utf-8'),
                                                  params.enterprise['unencrypted_tree_key']),
                'node_id': node_id,
                'suppress_email_invite': True
            }
            try:
                rs = api.communicate(params, rq)
                if rs['result'] == 'success':
                    verification_code = rs.get('verification_code')
                    # re-read password rules
                    rq = {
                        'command': 'pre_register',
                        'email': email
                    }
                    rs = api.run_command(params, rq)
                    if 'password_rules' in rs:
                        password_rules = rs['password_rules']
            except Exception as e:
                logging.warning(e["message"])

        password = kwargs['password'] if 'password' in kwargs else None
        generate = kwargs['generate'] if 'generate' in kwargs else None
        if generate:
            password = generator.generate(16)
        else:
            while not password:
                pwd = getpass.getpass(prompt='Password: ', stream=None)
                failed_rules = []
                if password_rules:
                    for r in password_rules:
                        m = re.match(r['pattern'], pwd)
                        if r['match']:
                            if m is None:
                                failed_rules.append(r['description'])
                        else:
                            if m is not None:
                                failed_rules.append(r['description'])
                if len(failed_rules) == 0:
                    password = pwd
                else:
                    logging.error(rs['password_rules_intro'])
                    for fr in failed_rules:
                        logging.error(fr)

        new_params = KeeperParams()
        new_params.server = params.server
        data_center = kwargs.get('data_center')
        if data_center:
            parts = list(urlsplit(new_params.server))
            host = parts[1]
            port = ''
            colon_pos = host.rfind(':')
            if colon_pos > 0:
                port = host[colon_pos:]
                host = host[:colon_pos]
            suffix = '.eu' if data_center == 'eu' else '.com'
            if not host.endswith(suffix):
                dot_pos = host.rfind('.')
                if dot_pos > 0:
                    host = host[:dot_pos] + suffix
            parts[1] = host + port
            new_params.server = urlunsplit(parts)

        data_key = os.urandom(32)
        iterations = self.get_iterations()
        auth_salt = os.urandom(16)
        enc_salt = os.urandom(16)
        backup_salt = os.urandom(16)

        private_key, public_key = loginv3.CommonHelperMethods.generate_rsa_key_pair()

        rq = {
            'command': 'register',
            'version': 1,
            'email': email,
            'auth_verifier': api.create_auth_verifier(password, auth_salt, iterations),
            'encryption_params': api.create_encryption_params(password, enc_salt, iterations, data_key),
            'encrypted_private_key': api.encrypt_aes(private_key, data_key),
            'public_key': base64.urlsafe_b64encode(public_key).decode().rstrip('='),
            'client_key': api.encrypt_aes(os.urandom(32), data_key)
        }
        if verification_code:
            rq['verification_code'] = verification_code

        rs = api.run_command(new_params, rq)
        if rs['result'] == 'success':
            logging.info("Created account: %s ", email)

            if kwargs.get('question'):
                if not kwargs.get('answer'):
                    print('...' + 'Security Question: '.rjust(24) + kwargs['question'])
                    kwargs['answer'] = input('...' + 'Security Answer: '.rjust(24))
                if kwargs.get('answer'):
                    try:
                        param1 = KeeperParams()
                        param1.server = new_params.server
                        param1.user = email
                        param1.password = password
                        param1.rest_context.device_id = params.rest_context.device_id
                        api.login(param1)
                        answer = kwargs['answer'].lower().replace(' ', '')
                        rq = {
                            'command': 'set_data_key_backup',
                            'version': 2,
                            'data_key_backup': api.create_encryption_params(answer, backup_salt, iterations, data_key),
                            'security_question': kwargs['question'],
                            'security_answer_salt': base64.urlsafe_b64encode(backup_salt).decode().rstrip('='),
                            'security_answer_iterations': iterations,
                            'security_answer_hash': base64.urlsafe_b64encode(
                                api.derive_key(answer, backup_salt, iterations)).decode().rstrip('=')
                        }
                        api.communicate(param1, rq)
                        logging.info('Master password backup is created.')
                    except Exception as e:
                        logging.error('Failed to create master password backup. %s', e)

            if params.enterprise:
                api.query_enterprise(params)
                file_name = kwargs.get('records')
                should_accept_share = False
                if file_name:
                    try:
                        push = EnterprisePushCommand()
                        push.execute(params, user=[email], file=file_name)
                        should_accept_share = True
                    except Exception as e:
                        logging.info('Error accepting shares: %s', e)

                # first accept shares from enterprise admin
                if should_accept_share:
                    try:
                        param1 = KeeperParams()
                        param1.server = new_params.server
                        param1.user = email
                        param1.password = password
                        param1.rest_context.device_id = params.rest_context.device_id
                        api.login(param1)
                        rq = {
                            'command': 'accept_share',
                            'from_email': params.user
                        }
                        api.communicate(param1, rq)
                    except Exception as e:
                        logging.info('Error accepting shares: %s', e)

                # last expire password
                if kwargs.get('expire'):
                    try:
                        rq = {
                            'command': 'set_master_password_expire',
                            'email': email
                        }
                        api.communicate(params, rq)
                    except Exception as e:
                        logging.info('Error expiring master password: %s', e)

            store = kwargs['store'] if 'store' in kwargs else None
            if store:
                if params.session_token:
                    try:
                        add_command = RecordAddCommand()
                        add_command.execute(params, title='Keeper credentials for {0}'.format(email), login=email,
                                            password=password, force=True)
                    except Exception:
                        store = False
                        logging.error('Failed to create record in Keeper')
                else:
                    store = False
            if generate and not store:
                logging.warning('Generated password: %s', password)

            if params.enterprise:
                api.query_enterprise(params)
        else:
            logging.error(rs['message'])


            store = kwargs['store'] if 'store' in kwargs else None
            if store:
                if params.session_token:
                    try:
                        add_command = RecordAddCommand()
                        add_command.execute(params, title='Keeper credentials for {0}'.format(email), login=email,
                                            password=password, force=True)
                    except Exception:
                        store = False
                        logging.error('Failed to create record in Keeper')
                else:
                    store = False
            if generate and not store:
                logging.warning('Generated password: %s', password)
"""
