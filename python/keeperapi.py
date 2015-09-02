import sys
import json
import requests

VERSION = '0.1'

def login(params):
    if params.debug:
        print('Login')

    validate()

def logout(params):
    if params.debug:
        print('Logout')

def ping(params):
    if params.debug:
        print('Ping')

def validate(params):
    if params.debug:
        print('Validating params')

    if not params.server:
        print('Error: server is not defined.')
        sys.exit()

    if not params.email:
        print('Error: email is not defined.')
        sys.exit()

    if not params.password:
        print('Error: password is not defined.')
        sys.exit()
