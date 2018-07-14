#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2018 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import argparse
import getpass
import re
import os
import base64
from urllib.parse import urlsplit, urlunsplit

from Cryptodome.Cipher import AES
from Cryptodome.PublicKey import RSA
from Cryptodome.Util.asn1 import DerSequence
from Cryptodome.Math.Numbers import Integer

from .. import api, generator
from .record import RecordAddCommand
from email.utils import parseaddr
from ..params import KeeperParams

from .base import raise_parse_exception, suppress_exit, Command


def register_commands(commands, aliases, command_info):
    commands['create_user'] = RegisterCommand()
    aliases['cu'] = 'create_user'
    for p in [register_parser]:
        command_info[p.prog] = p.description


register_parser = argparse.ArgumentParser(prog='create_user', description='Create Keeper User')
register_parser.add_argument('--store-record', dest='store', action='store_true', help='store credentials into Keeper record (must be logged in)')
register_parser.add_argument('--generate', dest='generate', action='store_true', help='generate password')
register_parser.add_argument('--pass', dest='password', action='store', help='user password')
register_parser.add_argument('--data-center', dest='data_center', choices=['us', 'eu'], action='store', help='data center.')
#register_parser.add_argument('--skip-backup', dest='skip', action='store_true', help='skip data key backup')
#register_parser.add_argument('-q', '--question', dest='question', action='store', help='security question')
#register_parser.add_argument('-a', '--answer', dest='answer', action='store', help='security answer')
register_parser.add_argument('email', action='store', help='email')
register_parser.error = raise_parse_exception
register_parser.exit = suppress_exit


class RegisterCommand(Command):
    def is_authorised(self):
        return False

    def get_parser(self):
        return register_parser

    def execute(self, params, **kwargs):
        email = kwargs['email'] if 'email' in kwargs else None

        if email:
            _, email = parseaddr(email)
        if not email:
            print('A valid email address is expected.')
            return

        rq = {
            'command': 'pre_register',
            'email': email
        }

        rs = api.run_command(params, rq)
        if rs['result_code'] != 'Failed_to_find_user':
            if rs['result'] == 'success':
                print('User \'{0}\' already exists in Keeper'.format(email))
            else:
                print(rs['message'])
            return

        password = kwargs['password'] if 'password' in kwargs else None
        generate = kwargs['generate'] if 'generate' in kwargs else None
        if generate:
            password = generator.generate(16)
        else:
            while not password:
                pwd = getpass.getpass(prompt='Password: ', stream=None)
                failed_rules = []
                for r in rs['password_rules']:
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
                    print(rs['password_rules_intro'])
                    for fr in failed_rules:
                        print(fr)

        new_params = KeeperParams()
        new_params.server = params.server
        if 'data_center' in kwargs:
            data_center = kwargs['data_center']
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
            parts[1] = host+port
            new_params.server = urlunsplit(parts)

        iterations = 100000
        salt = os.urandom(16)
        auth_verifier = b''
        auth_verifier = auth_verifier + b'\x01' + iterations.to_bytes(3, 'big') + salt
        derived_key = api.derive_key(password, salt, iterations)
        auth_verifier = auth_verifier + derived_key

        encryption_params=b''
        salt = os.urandom(16)
        encryption_params = encryption_params + b'\x01' + iterations.to_bytes(3, 'big') + salt
        data_key = os.urandom(32)
        dk = data_key + data_key
        encryption_key = api.derive_key(password, salt, iterations)
        iv = os.urandom(16)
        cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
        encryption_params = encryption_params + iv + cipher.encrypt(dk)

        rsa_key = RSA.generate(2048)
        private_key = DerSequence([0,
                                   rsa_key.n,
                                   rsa_key.e,
                                   rsa_key.d,
                                   rsa_key.p,
                                   rsa_key.q,
                                   rsa_key.d % (rsa_key.p-1),
                                   rsa_key.d % (rsa_key.q-1),
                                   Integer(rsa_key.q).inverse(rsa_key.p)
                                   ]).encode()
        pub_key = rsa_key.publickey()
        public_key = DerSequence([pub_key.n,
                                  pub_key.e
                                  ]).encode()

        rq = {
            'command': 'register',
            'version': 1,
            'email': email,
            'auth_verifier': base64.urlsafe_b64encode(auth_verifier).rstrip(b'=').decode(),
            'encryption_params': base64.urlsafe_b64encode(encryption_params).rstrip(b'=').decode(),
            'encrypted_private_key': api.encrypt_aes(private_key, data_key),
            'public_key': base64.urlsafe_b64encode(public_key).rstrip(b'=').decode(),
            'security_answer_iterations': 1000,
            'security_answer_salt': base64.urlsafe_b64encode(salt).rstrip(b'=').decode(),
            'security_question': 'What is your favorite password manager application?',
            'security_answer_hash': api.auth_verifier('keeper', salt, 1000),
            'client_key': api.encrypt_aes(os.urandom(32), data_key)
        }

        rs = api.run_command(new_params, rq)
        if rs['result'] == 'success':
#                if not opts.skip:
#                    while len(opts.question or '') == 0:
#                        opts.question = input('... Security Question: ')
#                    while len(opts.answer or '') == 0:
#                        opts.answer =   input('...   Security Answer: ')

            store = kwargs['store'] if 'store' in kwargs else None
            if store:
                if params.session_token:
                    try:
                        add_command = RecordAddCommand()
                        add_command.execute(params, title='Keeper credentials for {0}'.format(email), login=email, password=password, force=True)
                    except Exception:
                        store = False
                        print('Failed to create record in Keeper')
                else:
                    store = False
            if generate and not store:
                print('Generated password: {0}'.format(password))
        else:
            print(rs['message'])
