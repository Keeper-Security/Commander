# -*- coding: utf-8 -*-
#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2020 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import json
import logging

import requests
import msal     # pip install msal


def rotate(record, newpassword):
    """
    @type record: Record
    """

    user_id = record.login # The Azure user_id either as the object ID (GUID) or the user principal name (UPN) of the target user

    tenant_id = record.get("cmdr:azure_tenant_id")
    client_id = record.get("cmdr:azure_client_id")
    secret = record.get("cmdr:azure_secret")

    users_endpoint = 'https://graph.microsoft.com/v1.0/users'
    default_scope = 'https://graph.microsoft.com/.default'
    authority = 'https://login.microsoftonline.com/%s' % tenant_id

    try:

        # Create a preferably long-lived app instance which maintains a token cache.
        app = msal.ConfidentialClientApplication(
            client_id,
            authority=authority,
            client_credential=secret,
            # token_cache=...  # Default cache is in memory only.
            # To learn how to use SerializableTokenCache from
            #   https://msal-python.rtfd.io/en/latest/#msal.SerializableTokenCache
        )

        # Get access token
        result = app.acquire_token_silent(scopes=[default_scope], account=None)

        if not result:
            logging.debug("No suitable token exists in cache. Let's get a new one from AAD.")
            result = app.acquire_token_for_client(scopes=[default_scope])

        if "access_token" in result:
            access_token = result['access_token'] # JWT access token

            # 1. Getting all users from Azure Graph using the access token
            # all_users = requests.get(  # Use token to call downstream service
            #     users_endpoint,
            #     headers={'Authorization': 'Bearer ' + access_token}
            # ).json()
            #
            # 2. Getting only one user
            # usr = requests.get(
            #     '%s/%s' % (users_endpoint, user_id),
            #     headers={'Authorization': 'Bearer ' + access_token}
            # ).json()

            # 3. Updating user's password
            pwd_change_payload = {
                'passwordProfile': {
                    'password': newpassword,
                    'forceChangePasswordNextSignIn': False
                }
            }

            usr_pwd_update_resp = requests.patch(
                '%s/%s' % (users_endpoint, user_id),
                headers={
                    'Authorization': 'Bearer ' + access_token,
                    'Content-Type': 'application/json'
                },
                data=json.dumps(pwd_change_payload)
            )

            resp_status_code = usr_pwd_update_resp.status_code

            if resp_status_code == 204:
                logging.info("Password successfully changed in Azure")

                record.password = newpassword

                return True

            elif resp_status_code == 403:
                resp_data = usr_pwd_update_resp.json()

                if resp_data['error']['code'] == 'Authorization_RequestDenied':
                    logging.error("Status code: %d, message: %s" % (resp_status_code, resp_data['error']['message']))
                    logging.error("Insufficient privileges to perform the password reset")
                    logging.error('\tIf you have access to Azure with administrator permission then you can enable\n'
                          '\tpermission by navigating to Azure Portal -> Azure AD -> Roles and administrators ->\n'
                          '\t"Helpdesk Administrator" -> Click on "Add Assignments" > select the application with client\n'
                          '\tid "%s" > click on Add button.' % client_id)
                else:
                    logging.error("Unknown status code: %d, message: %s" % (resp_status_code, resp_data['error']['message']))
            else:
                logging.error("Unhandled status code: %d, message: %s" % (resp_status_code, usr_pwd_update_resp.json()['error']['message']))
        else:
            logging.error('Azure error: %s, description: %s' % (result['error'], result['error_description']))
    except Exception as ex:
        logging.error(ex)

    return False
