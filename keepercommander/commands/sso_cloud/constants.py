#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2024 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

from ...proto import ssocloud_pb2 as ssocloud

IDP_TYPE_CHOICES = [
    'generic', 'f5', 'google', 'okta', 'adfs', 'azure', 'onelogin', 'aws',
    'centrify', 'duo', 'ibm', 'jumpcloud', 'ping', 'pingone', 'rsa',
    'secureauth', 'thales', 'auth0', 'beyond', 'hypr', 'cas',
]

IDP_TYPE_NAMES = {
    ssocloud.XX_UNUSED: 'Unused',
    ssocloud.GENERIC: 'Generic',
    ssocloud.F5: 'F5',
    ssocloud.GOOGLE: 'Google Workspace',
    ssocloud.OKTA: 'Okta',
    ssocloud.ADFS: 'Microsoft ADFS',
    ssocloud.AZURE: 'Entra ID (Azure AD)',
    ssocloud.ONELOGIN: 'OneLogin',
    ssocloud.AWS: 'Amazon AWS',
    ssocloud.CENTRIFY: 'Centrify',
    ssocloud.DUO: 'Duo SSO',
    ssocloud.IBM: 'IBM',
    ssocloud.JUMPCLOUD: 'JumpCloud',
    ssocloud.PING: 'Ping Identity',
    ssocloud.PINGONE: 'PingOne',
    ssocloud.RSA: 'RSA SecurID Access',
    ssocloud.SECUREAUTH: 'SecureAuth',
    ssocloud.THALES: 'Thales',
    ssocloud.AUTH0: 'Auth0',
    ssocloud.BEYOND: 'BeyondTrust',
    ssocloud.HYPR: 'HYPR',
    ssocloud.PUREID: 'PureID',
    ssocloud.SDO: 'SDO',
    ssocloud.TRAIT: 'Trait',
    ssocloud.TRANSMIT: 'Transmit',
    ssocloud.TRUSONA: 'Trusona',
    ssocloud.VERIDIUM: 'Veridium',
    ssocloud.CAS: 'CAS',
}

IDP_TYPE_NAME_TO_ENUM = {
    'generic': ssocloud.GENERIC,
    'f5': ssocloud.F5,
    'google': ssocloud.GOOGLE,
    'okta': ssocloud.OKTA,
    'adfs': ssocloud.ADFS,
    'azure': ssocloud.AZURE,
    'onelogin': ssocloud.ONELOGIN,
    'aws': ssocloud.AWS,
    'centrify': ssocloud.CENTRIFY,
    'duo': ssocloud.DUO,
    'ibm': ssocloud.IBM,
    'jumpcloud': ssocloud.JUMPCLOUD,
    'ping': ssocloud.PING,
    'pingone': ssocloud.PINGONE,
    'rsa': ssocloud.RSA,
    'secureauth': ssocloud.SECUREAUTH,
    'thales': ssocloud.THALES,
    'auth0': ssocloud.AUTH0,
    'beyond': ssocloud.BEYOND,
    'hypr': ssocloud.HYPR,
    'cas': ssocloud.CAS,
}

IDP_ENUM_TO_KEY = {v: k for k, v in IDP_TYPE_NAME_TO_ENUM.items()}

SETTING_GROUPS = {
    'Service Provider': [
        'sso_sp_entity_id',
        'sso_sp_domain',
        'sso_sp_login_endpoint',
        'sso_sp_logout_endpoint',
        'sso_sp_acs_endpoint',
        'sso_sp_slo_endpoint',
    ],
    'Identity Provider': [
        'sso_idp_type_id',
        'sso_idp_entity_id',
        'sso_idp_sso_post_endpoint',
        'sso_idp_sso_redirect_endpoint',
        'sso_idp_slo_post_endpoint',
        'sso_idp_slo_redirect_endpoint',
        'sso_idp_initiated_login_endpoint',
        'sso_idp_passive_mode',
        'sso_idp_force_login_mode',
    ],
    'Attribute Mapping': [
        'sso_attribute_map_first_name',
        'sso_attribute_map_last_name',
        'sso_attribute_map_email',
        'sso_attribute_map_alias',
    ],
    'Options': [
        'sso_invite_new_users',
        'sso_login_method_preference',
        'sso_logout_method_preference',
        'sso_sign_messages',
    ],
    'Metadata & Certificates': [
        'sso_idp_metadata',
        'sso_idp_metadata_filename',
        'sso_idp_metadata_signing_key_description',
        'sso_idp_metadata_signing_key_is_expiring',
        'sso_signing_keypair',
        'sso_signing_keypair_filename',
        'sso_signing_keypair_description',
        'sso_signing_keypair_is_expiring',
    ],
}

AUTH0_SAML_JSON_TEMPLATE = """\
{{
  "audience": "{entity_id}",
  "mappings": {{
    "email": "Email",
    "given_name": "First",
    "family_name": "Last"
  }},
  "createUpnClaim": false,
  "passthroughClaimsWithNoMapping": false,
  "mapUnknownClaimsAsIs": false,
  "mapIdentities": false,
  "nameIdentifierFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
  "nameIdentifierProbes": [
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
  ]
}}"""

IDP_SETUP_GUIDANCE = {
    'auth0': {
        'portal_name': 'Auth0',
        'portal_url': 'https://manage.auth0.com',
        'steps': [
            ('idp',   'Go to Applications > Create Application > Regular Web App'),
            ('idp',   'Enable Addons > SAML2 WEB APP'),
            ('idp',   'In the Usage tab > Download IdP Metadata XML'),
            ('idp',   'In the Settings tab > paste the ACS Endpoint into "Application Callback URL":'),
            ('value', '{acs_endpoint}'),
            ('idp',   'Replace the Settings editor JSON with the below (Entity ID pre-filled in audience):'),
            ('json',  '{auth0_json}'),
            ('idp',   'Click "Debug" to verify, then Save'),
            ('cmd',   'sso-cloud upload "{name}" --file <downloaded-metadata.xml>'),
        ],
    },
    'azure': {
        'portal_name': 'Azure Entra ID',
        'portal_url': 'https://portal.azure.com',
        'steps': [
            ('cmd',   'sso-cloud download "{name}" --output sp-metadata.xml'),
            ('idp',   'In Azure portal, navigate to Microsoft Entra ID'),
            ('idp',   'Go to Enterprise Applications > New Application'),
            ('idp',   'Search "Keeper Password Manager" > Create'),
            ('idp',   'Go to Set up Single sign-on > SAML'),
            ('idp',   'Click "Upload metadata file" and upload sp-metadata.xml'),
            ('note',  'Azure auto-fills Entity ID and Reply URL from the metadata'),
            ('idp',   'Paste the IdP Initiated Login Endpoint into "Sign on URL":'),
            ('value', '{idp_login_endpoint}'),
            ('idp',   'Save the Basic SAML Configuration'),
            ('idp',   'Click on "No, I\'ll test later" when asked for the test SSO login'),
            ('idp',   'In Attributes & Claims card> Edit: delete the 4 extra Additional Claims'),
            ('note',  'Verify: NameID/Email = user.userprincipalname (or user.mail)'),
            ('idp',   'Reload page, under SAML Signing Certificate > Download "Federation Metadata XML"'),
            ('cmd',   'sso-cloud upload "{name}" --file <federation-metadata.xml> --force-authn'),
        ],
    },
    'okta': {
        'portal_name': 'Okta',
        'portal_url': 'https://login.okta.com',
        'steps': [
            ('idp',   'Go to Applications > Create App Integration > SAML 2.0'),
            ('idp',   'Paste the ACS Endpoint into "Single sign-on URL":'),
            ('value', '{acs_endpoint}'),
            ('idp',   'Paste the Entity ID into "Audience URI (SP Entity ID)":'),
            ('value', '{entity_id}'),
            ('idp',   'Set Name ID format to EmailAddress'),
            ('idp',   'Add attribute statements: Email, First, Last'),
            ('idp',   'Finish, then go to Sign On tab > Download IdP Metadata'),
            ('cmd',   'sso-cloud upload "{name}" --file <metadata.xml>'),
        ],
    },
    'google': {
        'portal_name': 'Google Workspace',
        'portal_url': 'https://admin.google.com',
        'steps': [
            ('idp',   'Go to Apps > Web and mobile apps > Add App > Add custom SAML app'),
            ('idp',   'Download IdP Metadata from the Google IdP Information step'),
            ('idp',   'Paste the ACS Endpoint into "ACS URL":'),
            ('value', '{acs_endpoint}'),
            ('idp',   'Paste the Entity ID into "Entity ID":'),
            ('value', '{entity_id}'),
            ('idp',   'Set Name ID format to EMAIL'),
            ('idp',   'Add attribute mappings for email, first name, last name'),
            ('cmd',   'sso-cloud upload "{name}" --file <google-idp-metadata.xml>'),
        ],
    },
    'jumpcloud': {
        'portal_name': 'JumpCloud',
        'portal_url': 'https://console.jumpcloud.com',
        'steps': [
            ('idp',   'Go to SSO Applications > Add New Application > Custom SAML App'),
            ('idp',   'Paste the ACS Endpoint into "ACS URL":'),
            ('value', '{acs_endpoint}'),
            ('idp',   'Paste the Entity ID into "SP Entity ID":'),
            ('value', '{entity_id}'),
            ('idp',   'Set SAMLSubject NameID to email'),
            ('idp',   'Add attribute mappings for email, first name, last name'),
            ('idp',   'Activate the application, then download IdP Metadata'),
            ('cmd',   'sso-cloud upload "{name}" --file <metadata.xml>'),
        ],
    },
}
