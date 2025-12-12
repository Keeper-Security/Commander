import abc
import datetime
import logging
from collections import namedtuple
from typing import Iterable, Union, Callable, Dict, List, Optional, Set, Any

import requests

from .. import utils
from ..error import CommandError
from .models import ScimGroup, ScimUser


class ICrmDataSource(abc.ABC):
    def __init__(self):
        self._load_errors = False     # type: bool
        self._debug_logger = ICrmDataSource.null_logger     # type: Callable[[str], None]

    @staticmethod
    def null_logger(message):
        pass

    @abc.abstractmethod
    def populate(self):        # type: () -> Iterable[Union[ScimGroup, ScimUser]]
        pass

    @property
    def load_errors(self):     # type: () -> bool
        return self._load_errors

    @property
    def debug_logger(self):    # type: () -> Callable[[str], None]
        return self._debug_logger

    @debug_logger.setter
    def debug_logger(self, value):    # type: (Callable[[str], None]) -> None
        if value is None:
            value = ICrmDataSource.null_logger
        self._debug_logger = value


class AdCrmDataSource(ICrmDataSource):
    def __init__(self, ad_url, ad_user, ad_password, scim_groups, use_netbios_domain=False):  # type: (str, str, str, Optional[List[str]], bool) -> None
        super().__init__()
        self.ad_url = ad_url
        self.ad_user = ad_user
        self.ad_password = ad_password
        self.scim_groups = scim_groups or []
        self.use_netbios_domain = use_netbios_domain
        self._domain_lookup = None  # type: Optional[Dict[str, str]]

    def _build_domain_lookup(self, connection) -> Dict[str, str]:
        """Build a mapping of DNS domain names to NetBIOS names.

        Returns:
            Dict mapping DNS names (e.g., 'test.local') to NetBIOS names (e.g., 'TEST')
        """
        try:
            import ldap3
        except ModuleNotFoundError:
            return {}

        domain_map: Dict[str, str] = {}

        if not connection.search('', '(class=*)', search_scope=ldap3.BASE, attributes=["*"]):
            return domain_map
        if len(connection.entries) == 0:
            return domain_map

        entry = connection.entries[0]
        entry_attributes = set(entry.entry_attributes)

        if 'configurationNamingContext' not in entry_attributes:
            return domain_map

        config_dn = entry.configurationNamingContext.value
        if not isinstance(config_dn, str):
            return domain_map

        # Search for all domains in the Partitions container
        search_base = f'CN=Partitions,{config_dn}'
        for attr_name in ('defaultNamingContext', 'rootDomainNamingContext'):
            if attr_name in entry_attributes:
                nc_dn = getattr(entry, attr_name).value
                if isinstance(nc_dn, str):
                    # Get DNS name from DN
                    parts = nc_dn.split(',')
                    dn_parts = [p[3:] for p in parts if p.lower().startswith('dc=')]
                    if dn_parts:
                        dns_name = '.'.join(dn_parts)

                        # Get NetBIOS name from partition
                        search_filter = f'(nCName={nc_dn})'
                        if connection.search(search_base, search_filter, search_scope=ldap3.SUBTREE,
                                           attributes=['nETBIOSName']):
                            for partition_entry in connection.entries:
                                if 'nETBIOSName' in partition_entry.entry_attributes:
                                    netbios_name = partition_entry.nETBIOSName.value
                                    if isinstance(netbios_name, str) and netbios_name:
                                        domain_map[dns_name] = netbios_name

        return domain_map

    def resolve_domains(self) -> List[str]:
        try:
            import ldap3
        except ModuleNotFoundError:
            raise CommandError('', 'LDAP3 client is not installed.\npip install ldap3')

        server = ldap3.Server(self.ad_url)
        with ldap3.Connection(server, user=self.ad_user, password=self.ad_password,
                              authentication=ldap3.SIMPLE if server.ssl else ldap3.NTLM) as connection:
            connection.bind()
            if not connection.search('', '(class=*)', search_scope=ldap3.BASE, attributes=["*"]):
                return []
            if len(connection.entries) == 0:
                return []
            entry = connection.entries[0]
            entry_attributes = set(entry.entry_attributes)

            domains: Set[str] = set()

            if self.use_netbios_domain:
                # Return NetBIOS domain names
                domain_map = self._build_domain_lookup(connection)
                domains.update(domain_map.values())

            # Return DNS domain names (or fallback if NetBIOS lookup failed)
            if not domains:
                for attr_name in ('rootDomainNamingContext', 'defaultNamingContext'):
                    if attr_name in entry_attributes:
                        dn = getattr(entry, attr_name).value
                        if isinstance(dn, str):
                            parts = dn.split(',')
                            dn_parts = [p[3:] for p in parts if p.lower().startswith('dc=')]
                            if dn_parts:
                                domains.add('.'.join(dn_parts))
                if not domains and 'namingContexts' in entry_attributes:
                    ncs = entry.namingContexts.values
                    if isinstance(ncs, list):
                        for dn in ncs:
                            if not isinstance(dn, str):
                                continue
                            parts = dn.split(',')
                            dn_parts = [p[3:] for p in parts if p.lower().startswith('dc=')]
                            if dn_parts:
                                domains.add('.'.join(dn_parts))
            return list(domains)

    def populate(self):
        try:
            import ldap3
            from ldap3.utils.conv import escape_filter_chars
        except ModuleNotFoundError:
            raise CommandError('', 'LDAP3 client is not installed.\npip install ldap3')

        server = ldap3.Server(self.ad_url)
        with ldap3.Connection(server, user=self.ad_user, password=self.ad_password,
                              authentication=ldap3.SIMPLE if server.ssl else ldap3.NTLM) as connection:
            connection.bind()
            if not connection.search('', '(class=*)', search_scope=ldap3.BASE, attributes=["*"]):
                raise CommandError('', 'Active Directory: cannot query Root DSE')
            if len(connection.entries) == 0:
                raise CommandError('', 'Active Directory: cannot query Root DSE')
            root_dn = ''
            entry = connection.entries[0]
            entry_attributes = set(entry.entry_attributes)
            if 'rootDomainNamingContext' in entry_attributes:
                root_dn = entry.rootDomainNamingContext.value
            if not root_dn and 'defaultNamingContext' in entry_attributes:
                root_dn = entry.defaultNamingContext.value
            if not root_dn and 'namingContexts' in entry_attributes:
                attrs = entry.namingContexts.values
                if isinstance(attrs, list) and len(attrs) > 0:
                    root_dn = attrs[0]

            # Build domain lookup (DNS -> NetBIOS) if needed
            if self.use_netbios_domain:
                self._domain_lookup = self._build_domain_lookup(connection)

            # Get default domain (DNS name)
            default_domain = ''
            if root_dn:
                parts = root_dn.split(',')
                dn_parts = []
                for p in parts:
                    if p.lower().startswith('dc='):
                        dn_parts.append(p[3:])
                if len(dn_parts) > 0:
                    default_domain = '.'.join(dn_parts)

            # Convert to NetBIOS if requested and mapping exists
            if self.use_netbios_domain and self._domain_lookup and default_domain in self._domain_lookup:
                default_domain = self._domain_lookup[default_domain]

            scim_groups = {}           # type: Dict[str, ScimGroup]
            if len(self.scim_groups) == 0:
                rs = connection.extend.standard.paged_search(
                    root_dn, '(objectClass=group)',
                    search_scope=ldap3.SUBTREE, paged_size=1000, generator=True,
                    attributes=['objectGUID', 'name'])
                for entry in rs:
                    if entry.get('type') != 'searchResEntry':
                        continue
                    attrs = entry.get('attributes') or {}
                    group_id = attrs.get('objectGUID')
                    group_name = attrs.get('name')
                    if group_id and group_name:
                        g = ScimGroup()
                        g.id = group_id
                        g.external_id = group_id
                        g.name = group_name
                        g.domain = default_domain
                        scim_groups[entry['dn']] = g
            else:
                for scim_group in self.scim_groups:
                    if scim_group.lower().startswith('cn='):
                        rs = connection.extend.standard.paged_search(
                            scim_group, f'(objectClass=group)',
                            search_scope=ldap3.BASE, attributes=['objectGUID', 'name'], generator=False)
                    else:
                        rs = connection.extend.standard.paged_search(
                            root_dn, f'(&(objectClass=group)(name={escape_filter_chars(scim_group)}))',
                            search_scope=ldap3.SUBTREE, attributes=['objectGUID', 'name'], generator=False)

                    group_entry = next((x for x in rs if x.get('type') == 'searchResEntry'), None)
                    if group_entry:
                        t = group_entry.get('type')
                        if t != 'searchResEntry':
                            continue
                        group_dn = group_entry['dn']
                        attrs = group_entry['attributes']
                        scim_group_obj = ScimGroup()
                        scim_group_obj.id = attrs.get('objectGUID')
                        scim_group_obj.external_id = attrs.get('objectGUID')
                        scim_group_obj.name = attrs.get('name')
                        scim_group_obj.domain = default_domain
                        scim_groups[group_dn] = scim_group_obj
                    else:
                        self.debug_logger(f'AD Group "{scim_group}" could not be resolved')
                        self._load_errors = True

            if len(scim_groups) == 0:
                if len(self.scim_groups) == 0:
                    self.debug_logger('No AD groups found')
                else:
                    raise Exception('No Active Directory groups could be resolved')

            scim_users = {}           # type: Dict[str, ScimUser]
            group_dns = None if len(self.scim_groups) == 0 else list(scim_groups.keys())
            now = datetime.datetime.now().timestamp()

            if group_dns is None:
                user_entries = connection.extend.standard.paged_search(
                    root_dn, '(objectClass=user)',
                    search_scope=ldap3.SUBTREE, paged_size=1000, generator=True,
                    attributes=['objectGUID', 'mail', 'userPrincipalName', 'sAMAccountName', 'givenName', 'accountExpires',
                                'sn', 'cn', 'memberOf'])
                for u in user_entries:
                    if u.get('type') != 'searchResEntry':
                        continue
                    attrs = u.get('attributes') or {}
                    user_id = attrs.get('objectGUID')
                    if not user_id:
                        continue
                    su = ScimUser()
                    su.id = user_id
                    su.external_id = user_id
                    login = ''
                    if 'sAMAccountName' in attrs:
                        login = attrs['sAMAccountName'] or ''
                    email = ''
                    if 'mail' in attrs:
                        email = attrs['mail']
                    if not email and 'userPrincipalName' in attrs:
                        email = attrs['userPrincipalName']
                    su.email = email
                    su.login = login
                    if 'userPrincipalName' in attrs and attrs['userPrincipalName']:
                        upn = attrs['userPrincipalName']
                        if isinstance(upn, str) and '@' in upn:
                            upn_domain = upn.split('@', 1)[1]
                            # Convert DNS domain to NetBIOS if requested
                            if self.use_netbios_domain and self._domain_lookup and upn_domain in self._domain_lookup:
                                su.domain = self._domain_lookup[upn_domain]
                            else:
                                su.domain = upn_domain
                    if not su.domain:
                        su.domain = default_domain
                    if 'cn' in attrs:
                        su.full_name = attrs['cn']
                    if 'givenName' in attrs:
                        su.first_name = attrs['givenName']
                    if 'sn' in attrs:
                        su.last_name = attrs['sn']
                    if 'accountExpires' in attrs:
                        ae = attrs['accountExpires']
                        if isinstance(ae, datetime.datetime):
                            su.active = ae.timestamp() > now
                    if 'memberOf' in attrs and isinstance(attrs['memberOf'], list):
                        su.groups.extend(attrs['memberOf'])
                    scim_users[user_id] = su
            else:
                for group_dn in group_dns:
                    group_users = connection.extend.standard.paged_search(
                        root_dn, f'(&(objectClass=user)(memberOf={escape_filter_chars(group_dn)}))',
                        search_scope=ldap3.SUBTREE, paged_size=1000, generator=True,
                        attributes=['objectGUID', 'mail', 'userPrincipalName', 'givenName', 'accountExpires',
                                'sn', 'cn', 'memberOf', 'sAMAccountName'])
                    for u in group_users:
                        t = u.get('type')
                        if t != 'searchResEntry':
                            continue

                        attrs = u.get('attributes') or {}
                        user_id = attrs.get('objectGUID')
                        if not user_id:
                            continue
                        su = scim_users.get(user_id)
                        if not su:
                            email = ''
                            login = ''
                            if 'sAMAccountName' in attrs:
                                login = attrs['sAMAccountName'] or ''
                            if 'mail' in attrs:
                                email = attrs['mail']
                            if not email and 'userPrincipalName' in attrs:
                                email = attrs['userPrincipalName']
                            su = ScimUser()
                            su.id = user_id
                            su.external_id = user_id
                            su.email = email
                            su.login = login
                            if 'userPrincipalName' in attrs and attrs['userPrincipalName']:
                                upn = attrs['userPrincipalName']
                                if isinstance(upn, str) and '@' in upn:
                                    upn_domain = upn.split('@', 1)[1]
                                    # Convert DNS domain to NetBIOS if requested
                                    if self.use_netbios_domain and self._domain_lookup and upn_domain in self._domain_lookup:
                                        su.domain = self._domain_lookup[upn_domain]
                                    else:
                                        su.domain = upn_domain
                            if not su.domain:
                                su.domain = default_domain
                            if 'cn' in attrs:
                                su.full_name = attrs['cn']
                            if 'givenName' in attrs:
                                su.first_name = attrs['givenName']
                            if 'sn' in attrs:
                                su.last_name = attrs['sn']
                            if 'accountExpires' in attrs:
                                ae = attrs['accountExpires']
                                if isinstance(ae, datetime.datetime):
                                    su.active = ae.timestamp() > now
                            scim_users[user_id] = su
                        su.groups.append(group_dn)

            yield from scim_groups.values()
            yield from scim_users.values()


class LocalCrmDataSource(ICrmDataSource):
    USER_FIELDS = ['id', 'external_id', 'login', 'email', 'domain', 'full_name', 'first_name', 'last_name', 'active', 'groups']
    GROUP_FIELDS = ['id', 'external_id', 'name', 'domain']

    def __init__(self, data):  # type: (Dict[str, Any]) -> None
        super().__init__()
        self.data = data

    def populate(self):      # type: () -> Iterable[Union[ScimGroup, ScimUser]]
        if not isinstance(self.data, dict):
            raise CommandError('', f'SCIM data are missing')

        if 'users' in self.data:
            for user in self.data['users']:
                if not isinstance(user, dict):
                    continue
                su = ScimUser()
                for key, value in user.items():
                    if hasattr(su, key):
                        setattr(su, key, value)
                    else:
                        user_fields = ','.join(self.USER_FIELDS)
                        raise CommandError('', f'SCIM user: unsupported field "{key}": {user_fields}')
                if not su.id or not su.email:
                    raise CommandError('', f'SCIM user: fields "id" and "email" are required')
                yield su

        if 'groups' in self.data:
            for group in self.data['groups']:
                if not isinstance(group, dict):
                    continue
                sg = ScimGroup()
                for key, value in group.items():
                    if hasattr(sg, key):
                        setattr(sg, key, value)
                    else:
                        group_fields = ','.join(self.GROUP_FIELDS)
                        raise CommandError('', f'SCIM group: unsupported field "{key}": {group_fields}')
                if not sg.id or not sg.name:
                    raise CommandError('', f'SCIM group: fields "id" and "name" are required')
                yield sg


class GoogleCrmDataSource(ICrmDataSource):
    def __init__(self, admin_account, credentials, scim_groups):  # type: (str, dict, List[str]) -> None
        super().__init__()
        self.admin_account = admin_account
        self.credentials = credentials
        self.scim_groups = scim_groups

    @staticmethod
    def parse_google_user(scim_user):   # type: (dict) -> Optional[ScimUser]
        if 'id' in scim_user and 'primaryEmail' in scim_user:
            u = ScimUser()
            u.id = scim_user['id']
            u.email = scim_user['primaryEmail']
            u.active = not (scim_user.get('suspended') is True)
            if 'name' in scim_user:
                scim_user_name = scim_user['name']
                if 'givenName' in scim_user_name:
                    u.first_name = scim_user['name']['givenName']
                if 'familyName' in scim_user_name:
                    u.last_name = scim_user['name']['familyName']
            if u.first_name or u.last_name:
                u.full_name = f'{(u.first_name or "")} {(u.last_name or "")}'.strip()
            return u

    @staticmethod
    def parse_google_group(scim_group):  # type: (dict) -> Optional[ScimGroup]
        if 'id' in scim_group and 'name' in scim_group:
            g = ScimGroup()
            g.id = scim_group.get('id')
            g.name = scim_group.get('name')
            return g

    def populate(self) -> Iterable[Union[ScimGroup, ScimUser]]:
        try:
            from google.oauth2 import service_account
            import googleapiclient.discovery
            logging.getLogger('googleapiclient.discovery_cache').setLevel(logging.ERROR)
        except ModuleNotFoundError:
            raise CommandError('', 'Google Cloud client is not installed.\npip install google-api-python-client')

        scopes = ['https://www.googleapis.com/auth/admin.directory.group.readonly',
                  'https://www.googleapis.com/auth/admin.directory.group.member.readonly',
                  'https://www.googleapis.com/auth/admin.directory.user.readonly']
        cred = service_account.Credentials.from_service_account_info(self.credentials, scopes=scopes).with_subject(self.admin_account)
        directory = googleapiclient.discovery.build('admin', 'directory_v1', credentials=cred, static_discovery=False)

        self.debug_logger('Resolving "SCIM Groups" content')
        scim_users = {}    # type: Dict[str, ScimUser]
        scim_groups = {}   # type: Dict[str, ScimGroup]

        if isinstance(self.scim_groups, list):
            for name in self.scim_groups:
                if utils.is_email(name):
                    rs = directory.groups().list(customer='my_customer', query=f'email={name}').execute()
                    groups = rs.get('groups')
                    if isinstance(groups, list) and len(groups) > 0:
                        for group in groups:
                            g = GoogleCrmDataSource.parse_google_group(group)
                            if isinstance(g, ScimGroup):
                                self.debug_logger(f'Found Google group "{g.name}" for email "{name}"')
                                scim_groups[g.id] = g
                    else:
                        rs = directory.users().list(customer='my_customer', query=f'email={name}').execute()
                        users = rs.get('users')
                        if isinstance(users, list) and len(users) > 0:
                            for user in users:
                                u = GoogleCrmDataSource.parse_google_user(user)
                                if isinstance(u, ScimUser):
                                    self.debug_logger(f'Found Google user for email "{name}"')
                                    scim_users[u.id] = u
                        else:
                            self.debug_logger(f'An email "{name}" could not be resolved as either Google User or Group')
                            self._load_errors = True
                else:
                    rs = directory.groups().list(customer='my_customer', query=f'name=\'{name}\'').execute()
                    groups = rs.get('groups')
                    if isinstance(groups, list) and len(groups) > 0:
                        for group in groups:
                            g = GoogleCrmDataSource.parse_google_group(group)
                            if isinstance(g, ScimGroup):
                                self.debug_logger(f'Found Google group "{g.name}" by name')
                                scim_groups[g.id] = g
                    else:
                        self.debug_logger(f'A name "{name}" could not be resolved to Google Group. Names are case sensitive')
                        self._load_errors = True
        if len(scim_groups) == 0 and len(scim_users) == 0:
            raise Exception('no Google Workspace groups could be resolved')

        self.debug_logger('Loading all users')
        user_lookup = {}   # type: Dict[str, ScimUser]
        user_request = directory.users().list(customer='my_customer')
        while user_request:
            user_response = user_request.execute()
            for user in user_response.get('users', []):
                u = GoogleCrmDataSource.parse_google_user(user)
                if isinstance(u, ScimUser):
                    user_lookup[u.id] = u
            user_request = directory.users().list_next(previous_request=user_request, previous_response=user_response)
        self.debug_logger(f'Total {len(user_lookup)} Google user(s) loaded')

        membership_cache = {}   # type: Dict[str, List[str]]
        for g_id, group in scim_groups.items():
            group_ids = [g_id]            # type: List[str]
            queued_ids = set(group_ids)   # type: Set[str]
            pos = 0
            while pos < len(group_ids):
                group_id = group_ids[pos]
                pos += 1
                if group_id not in membership_cache:
                    members_request = directory.members().list(groupKey=group_id)
                    members = []
                    while members_request:
                        try:
                            members_response = members_request.execute()
                            google_members = members_response.get('members')
                            if isinstance(google_members, list):
                                members.extend((x['id'] for x in google_members))
                            else:
                                break
                            members_request = directory.members().list_next(previous_request=members_request, previous_response=members_response)
                        except Exception as e:
                            self.debug_logger(f'Error loading members for group "{group_id}": {e}')
                            break
                    membership_cache[group_id] = members
                for member_id in membership_cache[group_id]:
                    if member_id in user_lookup:
                        u = user_lookup[member_id]
                        u.groups.append(group_id)
                        if u.id not in scim_users:
                            scim_users[u.id] = u
                    else:
                        if member_id not in queued_ids:
                            queued_ids.add(member_id)
                            group_ids.append(member_id)

        yield from scim_groups.values()
        yield from scim_users.values()


AZURE_ENDPOINT = namedtuple('AzureEndpoint', 'activeDirectory microsoftGraphResourceId')
AZURE_GLOBAL_CLOUD = 'AzureCloud'
AZURE_CLOUD_URLS = {
    AZURE_GLOBAL_CLOUD: AZURE_ENDPOINT('https://login.microsoftonline.com', 'https://graph.microsoft.com'),
    'AzureChinaCloud': AZURE_ENDPOINT('https://login.chinacloudapi.cn', 'https://microsoftgraph.chinacloudapi.cn'),
    'AzureUSGovernment': AZURE_ENDPOINT('https://login.microsoftonline.us', 'https://graph.microsoft.us'),
    'AzureGermanCloud': AZURE_ENDPOINT('https://login.microsoftonline.de', 'https://graph.microsoft.de'),
}


class AzureAdCrmDataSource(ICrmDataSource):
    def __init__(self, tenant_id, client_id, client_secret, azure_cloud=None):  # type: (str, str, str, Optional[str]) -> None
        super().__init__()
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.azure_cloud = azure_cloud or AZURE_GLOBAL_CLOUD

    def populate(self) -> Iterable[Union[ScimGroup, ScimUser]]:
        endpoints = self._resolve_cloud(self.azure_cloud)
        graph_base = endpoints.microsoftGraphResourceId
        token = self._get_token(endpoints)
        headers = {'Authorization': f'Bearer {token}'}

        groups = {}  # type: Dict[str, ScimGroup]
        for group in self._paged_get(f'{graph_base}/v1.0/groups?$select=id,displayName', headers):
            group_id = group.get('id')
            display_name = group.get('displayName')
            if not group_id or not display_name:
                continue
            sg = ScimGroup()
            sg.id = group_id
            sg.external_id = group_id
            sg.name = display_name
            groups[group_id] = sg

        users = {}  # type: Dict[str, ScimUser]
        for group_id in groups:
            for member in self._paged_get(
                    f'{graph_base}/v1.0/groups/{group_id}/members?$select=id,userPrincipalName,mail,displayName,givenName,surname,accountEnabled',
                    headers):
                if member.get('@odata.type') != '#microsoft.graph.user':
                    continue
                user_id = member.get('id')
                if not user_id:
                    continue
                if str(member.get('userType') or '').lower() == 'guest':
                    continue
                su = users.get(user_id)
                if not su:
                    su = ScimUser()
                    su.id = user_id
                    su.external_id = user_id
                    upn = member.get('userPrincipalName') or ''
                    if '#EXT#' in upn:
                        continue
                    su.email = member.get('mail') or upn or ''
                    if upn:
                        if '@' in upn:
                            su.login = upn.split('@', 1)[0]
                            su.domain = upn.split('@', 1)[1]
                        else:
                            su.login = upn
                    su.first_name = member.get('givenName') or ''
                    su.last_name = member.get('surname') or ''
                    display_name = member.get('displayName') or ''
                    su.full_name = display_name or f'{su.first_name} {su.last_name}'.strip()
                    su.active = member.get('accountEnabled') is True
                    users[user_id] = su
                su.groups.append(group_id)

        yield from groups.values()
        yield from users.values()

    def _get_token(self, endpoints) -> str:
        url = f'{endpoints.activeDirectory}/{self.tenant_id}/oauth2/v2.0/token'
        data = {
            'grant_type': 'client_credentials',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'scope': f'{endpoints.microsoftGraphResourceId}/.default'
        }
        rs = requests.post(url, data=data)
        if rs.status_code != 200:
            raise CommandError('', f'Azure AD token request failed: {rs.status_code}')
        token = rs.json().get('access_token')
        if not token:
            raise CommandError('', 'Azure AD token is missing in response')
        return token

    @staticmethod
    def _paged_get(url, headers):
        next_url = url
        while next_url:
            rs = requests.get(next_url, headers=headers)
            if rs.status_code != 200:
                raise CommandError('', f'Azure AD request failed: {rs.status_code}')
            body = rs.json()
            for item in body.get('value', []):
                yield item
            next_url = body.get('@odata.nextLink')

    @staticmethod
    def _resolve_cloud(azure_cloud):
        # normalize common aliases
        if isinstance(azure_cloud, str):
            ac = azure_cloud.lower()
            if 'china' in ac:
                azure_cloud = 'AzureChinaCloud'
            elif 'usgov' in ac or 'us_gov' in ac or 'government' in ac:
                azure_cloud = 'AzureUSGovernment'
            elif 'german' in ac or 'de' == ac:
                azure_cloud = 'AzureGermanCloud'
            elif 'global' in ac or 'azurecloud' == ac or ac == 'azure':
                azure_cloud = AZURE_GLOBAL_CLOUD

        if azure_cloud not in AZURE_CLOUD_URLS:
            azure_cloud = AZURE_GLOBAL_CLOUD
        return AZURE_CLOUD_URLS[azure_cloud]
