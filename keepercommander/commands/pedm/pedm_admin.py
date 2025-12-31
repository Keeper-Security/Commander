from __future__ import annotations

import argparse
import calendar
import copy
import datetime
import fnmatch
import getpass
import json
import logging
import os.path
import re
from urllib.parse import urlunparse
from typing import Any, List, Optional, Dict, Union, Tuple, Set, Pattern

import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from ... import crypto, constants, utils, api, vault
from ...params import KeeperParams
from ...pedm import admin_plugin, pedm_shared, admin_types, admin_storage
from ...proto import NotificationCenter_pb2, pedm_pb2
from .. import base
from ..helpers import report_utils, prompt_utils, whoami
from . import pedm_aram
from ...scim.data_sources import AdCrmDataSource, AzureAdCrmDataSource
from ...scim.models import ScimUser, ScimGroup


class PedmUtils:
    @staticmethod
    def resolve_single_agent(pedm: admin_plugin.PedmPlugin, agent_uid: Any) -> admin_types.PedmAgent:
        if not isinstance(agent_uid, str):
            raise base.CommandError(f'Invalid agent_name: {agent_uid}')

        agent = pedm.agents.get_entity(agent_uid)
        if agent:
            return agent
        raise base.CommandError(f'Agent UID \"{agent_uid}\" does not exist')

    @staticmethod
    def resolve_single_deployment(pedm: admin_plugin.PedmPlugin, deployment_name: Any) -> admin_types.PedmDeployment:
        if not isinstance(deployment_name, str):
            raise base.CommandError(f'Invalid deployment name: {deployment_name}')

        deployment = pedm.deployments.get_entity(deployment_name)
        if deployment:
            return deployment

        l_deployment_name = deployment_name.lower()
        deployments = [x for x in pedm.deployments.get_all_entities() if x.name.lower() == l_deployment_name]
        if len(deployments) == 0:
            raise base.CommandError(f'Deployment \"{deployment_name}\" does not exist')
        if len(deployments) >= 2:
            raise base.CommandError(f'Deployment \"{deployment_name}\" is not unique. Please use Deployment UID')

        return deployments[0]

    @staticmethod
    def resolve_existing_policies(pedm: admin_plugin.PedmPlugin, policy_names: Any) -> List[admin_types.PedmPolicy]:
        found_policies: Dict[str, admin_types.PedmPolicy] = {}
        p: Optional[admin_types.PedmPolicy]
        if isinstance(policy_names, list):
            for policy_name in policy_names:
                p = pedm.policies.get_entity(policy_name)
                if p is None:
                    raise base.CommandError(f'Policy name "{policy_name}" is not found')
                found_policies[p.policy_uid] = p
        if len(found_policies) == 0:
            raise base.CommandError('No policies were found')
        return list(found_policies.values())

    @staticmethod
    def resolve_single_policy(pedm: admin_plugin.PedmPlugin, policy_uid: Any) -> admin_types.PedmPolicy:
        if not isinstance(policy_uid, str):
            raise base.CommandError(f'Invalid policy UID: {policy_uid}')
        policy = pedm.policies.get_entity(policy_uid)

        if isinstance(policy, admin_types.PedmPolicy):
            return policy
        raise base.CommandError(f'Policy UID \"{policy_uid}\" does not exist')

    @staticmethod
    def resolve_single_approval(pedm: admin_plugin.PedmPlugin, approval_uid: Any) -> admin_types.PedmApproval:
        if not isinstance(approval_uid, str):
            raise base.CommandError(f'Invalid approval UID: {approval_uid}')
        approval = pedm.approvals.get_entity(approval_uid)

        if isinstance(approval, admin_types.PedmApproval):
            return approval
        raise base.CommandError(f'Approval UID \"{approval_uid}\" does not exist')

    @staticmethod
    def get_collection_name_lookup(
            pedm: admin_plugin.PedmPlugin
    ) -> Dict[str, Union[admin_types.PedmCollection, List[admin_types.PedmCollection]]]:
        collection_lookup: Dict[str, Union[admin_types.PedmCollection, List[admin_types.PedmCollection]]] = {}

        for collection in pedm.collections.get_all_entities():
            if not isinstance(collection.collection_data, dict):
                continue
            collection_name = collection.collection_data.get('Name')
            if not isinstance(collection_name, str) and not collection_name:
                continue
            collection_name = collection_name.lower()
            collection_lookup[collection_name] = collection
            c = collection_lookup.get(collection_name)
            if c is None:
                collection_lookup[collection_name] = collection
            elif isinstance(c, list):
                c.append(collection)
            elif isinstance(c, admin_types.PedmCollection):
                collection_lookup[collection_name] = [c, collection]
        return collection_lookup

    @staticmethod
    def get_orphan_resources(pedm: admin_plugin.PedmPlugin) -> List[str]:
        resource_types = {pedm_shared.CollectionType.OsBuild, pedm_shared.CollectionType.Application,
                          pedm_shared.CollectionType.UserAccount, pedm_shared.CollectionType.GroupAccount}
        collections = {x.collection_uid for x in pedm.storage.collections.get_all_entities() if x.collection_type in resource_types}
        links = {x.collection_uid for x in pedm.storage.collection_links.get_all_links() if x.link_type == pedm_pb2.CollectionLinkType.CLT_AGENT}
        return list(collections.difference(links))

    @staticmethod
    def resolve_existing_collections(
            pedm: admin_plugin.PedmPlugin,
            collection_names: Any,
            *,
            collection_type: Optional[int] = None,
            ignore_missing: bool = False,
    ) -> List[admin_types.PedmCollection]:

        found_collections: Dict[str, admin_types.PedmCollection] = {}
        if not isinstance(collection_names, list):
            collection_names = [collection_names]

        resolve_by_name = []
        for name in collection_names:
            if not isinstance(name, str) and not ignore_missing:
                raise base.CommandError(f'Invalid collection name: {name}')

            collection = pedm.collections.get_entity(name)
            if collection is None:
                resolve_by_name.append(name)
            else:
                found_collections[collection.collection_uid] = collection

        if len(resolve_by_name) > 0:
            collection_lookup = PedmUtils.get_collection_name_lookup(pedm)
            for name in resolve_by_name:
                c: Optional[admin_types.PedmCollection] = None
                cc = collection_lookup.get(name)
                if cc is None:
                    cc = collection_lookup.get(name.lower())
                if isinstance(cc, admin_types.PedmCollection):
                   c = cc
                elif isinstance(cc, list):
                    if len(cc) > 1 and isinstance(collection_type, int):
                        cc = [x for x in cc if x.collection_type == collection_type]
                    if len(cc) == 1:
                        c = cc[0]
                    else:
                        if not ignore_missing:
                            raise base.CommandError(f'Collection \"{name}\" is not unique. Please use Collection UID')
                if c is None:
                    if not ignore_missing:
                        raise base.CommandError(f'Collection "{name}" is not found')
                else:
                    found_collections[c.collection_uid] = c
        return list(found_collections.values())


class PedmCommand(base.GroupCommandNew):
    def __init__(self):
        super().__init__('Privilege Manager - PEDM')
        self.register_command_new(PedmSyncDownCommand(), 'sync-down')
        self.register_command_new(PedmDeploymentCommand(), 'deployment', 'd')
        self.register_command_new(PedmAgentCommand(), 'agent', 'a')
        self.register_command_new(PedmPolicyCommand(), 'policy', 'p')
        self.register_command_new(PedmCollectionCommand(), 'collection', 'c')
        self.register_command_new(PedmApprovalCommand(), 'approval')
        self.register_command_new(PedmScimCommand(), 'scim')
        self.register_command_new(pedm_aram.PedmReportCommand(), 'report')
        #self.register_command_new(PedmBICommand(), 'bi')

class PedmScimCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='scim', description='Sync PEDM user/group collections from AD or AzureAD')

        subparsers = parser.add_subparsers(title='Directory Type', dest='auth_type', required=True, help='Authentication method')
        record_parser = subparsers.add_parser('record', help='Connection parameters from Keeper record')
        record_parser.add_argument('record_uid', help='Keeper record UID')

        azure_parser = subparsers.add_parser('azure', help='Connect via Azure AD')
        azure_parser.add_argument('--tenant-id', dest='tenant_id', required=True)
        azure_parser.add_argument('--client-id', dest='client_id', required=True)
        azure_parser.add_argument('--client-secret', dest='client_secret')
        azure_parser.add_argument('--azure-cloud', dest='azure_cloud', choices=['US', 'GOV', 'CN', 'EU'],
                                  help='Azure cloud (AzureCloud, AzureChinaCloud, etc.)')

        ad_parser = subparsers.add_parser('ad', help='Connect via Active Directory')
        ad_parser.add_argument('--ad-url', dest='ad_url', required=True, help='AD LDAP URL (e.g., ldap(s)://<host>)')
        ad_parser.add_argument('--ad-user', dest='ad_user', required=True, help='AD bind user (DOMAIN\\username or DN)')
        ad_parser.add_argument('--ad-password', dest='ad_password', help='AD password')
        ad_parser.add_argument('--group', dest='groups', action='append', help='AD group name or DN (repeatable)')
        ad_parser.add_argument('--netbios-domain', dest='use_netbios_domain', action='store_true',
                              help='Use NetBIOS domain names (e.g., TEST) instead of DNS names (e.g., test.local)')

        for subparser in subparsers.choices.values():
            subparser.exit = base.suppress_exit
            subparser.error = base.raise_parse_exception

        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs):
        plugin = admin_plugin.get_pedm_plugin(context)

        source = (kwargs.get('auth_type') or '').lower()
        if source == 'record':
            config_record: vault.TypedRecord
            record_uid = kwargs.get('record_uid')

            if not record_uid:
                raise base.CommandError(f'Record UID parameter cannot be empty')
            if record_uid not in context.record_cache:
                raise base.CommandError(f'Record UID "{record_uid}" not found')
            r = vault.KeeperRecord.load(context, record_uid)
            if isinstance(r, vault.TypedRecord):
                config_record = r
            else:
                raise base.CommandError(f'Record UID "{record_uid}" is not a typed record')

            login: Optional[str] = None
            login_field = config_record.get_typed_field(field_type='login')
            if login_field:
                login = login_field.get_default_value(str)

            password: Optional[str] = None
            password_field = config_record.get_typed_field(field_type='password')
            if password_field:
                password = password_field.get_default_value(str)

            url: Optional[str] = None
            url_field = config_record.get_typed_field(field_type='url')
            if url_field:
                url = url_field.get_default_value(str)

            azure_tenant: Optional[str] = None
            custom_field = config_record.get_typed_field(field_type=None, label='Azure Tenant ID')
            if custom_field:
                azure_tenant = custom_field.get_default_value(str)

            if azure_tenant:
                source = 'azure'
                kwargs['tenant_id'] = azure_tenant
                client_id: Optional[str] = None
                custom_field = config_record.get_typed_field(field_type=None, label='Azure Client ID')
                if custom_field:
                    client_id = custom_field.get_default_value(str)
                if not client_id:
                    client_id = login
                if not client_id:
                    raise base.CommandError(f'Record "{config_record.title}" does not contain either "Azure Client ID" or "Login" value')
                kwargs['client_id'] = client_id
                client_secret: Optional[str] = None
                custom_field = config_record.get_typed_field(field_type=None, label='Azure Client Secret')
                if custom_field:
                    client_secret = custom_field.get_default_value(str)
                if not client_secret:
                    client_secret = password
                if not client_secret:
                    raise base.CommandError(f'Record "{config_record.title}" does not contain either "Azure Client Secret" or "Password" value')
                kwargs['client_secret'] = client_secret
            else:
                custom_field = config_record.get_typed_field(field_type=None, label='AD URL')
                if custom_field:
                    ad_url = custom_field.get_default_value(str)
                else:
                    ad_url = url
                if ad_url:
                    source = 'ad'
                    kwargs['ad_url'] = ad_url

                    ad_user: Optional[str] = None
                    custom_field = config_record.get_typed_field(field_type=None, label='AD User')
                    if custom_field:
                        ad_user = custom_field.get_default_value(str)
                    if not ad_user:
                        ad_user = login
                    if not ad_user:
                        raise base.CommandError(f'Record "{config_record.title}" does not contain either "AD User" or "Login" value')
                    kwargs['ad_user'] = ad_user

                    ad_password: Optional[str] = None
                    custom_field = config_record.get_typed_field(field_type=None, label='AD Password')
                    if custom_field:
                        ad_password = custom_field.get_default_value(str)
                    if not ad_password:
                        ad_password = password
                    if not ad_password:
                        raise base.CommandError(f'Record "{config_record.title}" does not contain either "AD Password" or "Password" value')
                    kwargs['ad_password'] = ad_password

                    custom_field = config_record.get_typed_field(field_type=None, label='SCIM Group')
                    if custom_field:
                        group_value = custom_field.get_default_value(str)
                        if isinstance(group_value, str):
                            groups = [x.strip() for x in group_value.split('\n')]
                            if groups:
                                kwargs['groups'] = groups

                    custom_field = config_record.get_typed_field(field_type=None, label='NetBIOS Domain')
                    if custom_field:
                        netbios_domain = custom_field.get_default_value(bool)
                        if netbios_domain is None:
                            custom_value = custom_field.get_default_value(str)
                            if custom_value:
                                try:
                                    netbios_domain = bool(custom_value)
                                except:
                                    pass
                        if netbios_domain is True:
                            kwargs['use_netbios_domain'] = netbios_domain

                else:
                    raise base.CommandError(f'Record "{config_record.title}" does not contain either "Azure Tenant ID" or "AD URL" value')

        if source == 'ad':
            ad_url = kwargs.get('ad_url')
            ad_user = kwargs.get('ad_user')
            ad_password = kwargs.get('ad_password')
            scim_groups = kwargs.get('groups')
            use_netbios_domain = kwargs.get('use_netbios_domain', False)
            if scim_groups and not isinstance(scim_groups, list):
                scim_groups = None

            if not ad_url or not ad_user:
                raise base.CommandError('AD source requires AD URL and AD User')
            try:
                if not ad_password:
                    ad_password = getpass.getpass(prompt=f'{ad_user} Password: ', stream=None)
                    if not ad_password:
                        raise base.CommandError('Cancelled')
                data_source = AdCrmDataSource(ad_url, ad_user, ad_password, scim_groups, use_netbios_domain)
                ad_domains = data_source.resolve_domains()
            except Exception as e:
                raise base.CommandError(f'Error connecting to Active Directory: {e}')
            account_type = 'AD'
            domain_name = ad_domains[0] if ad_domains else ''

        elif source == 'azure':
            tenant_id = kwargs.get('tenant_id')
            client_id = kwargs.get('client_id')
            client_secret = kwargs.get('client_secret')
            if not tenant_id or not client_id:
                raise base.CommandError('Azure source requires tenant-id and client-id')
            if not client_secret:
                client_secret = getpass.getpass(prompt=f'Azure Client Secret: ', stream=None)
            azure_cloud = kwargs.get('azure_cloud')
            if isinstance(azure_cloud, str):
                azure_cloud = azure_cloud.upper()
                if azure_cloud == 'CN':
                    azure_cloud = 'AzureChinaCloud'
                elif azure_cloud == 'GOV':
                    azure_cloud = 'AzureUSGovernment'
                elif azure_cloud == 'EU':
                    azure_cloud = 'AzureGermanCloud'
                else:
                    azure_cloud = None
            else:
                azure_cloud = None
            data_source = AzureAdCrmDataSource(tenant_id, client_id, client_secret, azure_cloud)
            account_type = 'Azure'
            domain_name = 'AzureAD'
        else:
            raise base.CommandError(f'Unsupported source: {source}')

        account_type_key = account_type.lower()
        domain_name_key = domain_name.lower()
        existing_users: Dict[tuple, admin_types.PedmCollection] = {}
        existing_groups: Dict[tuple, admin_types.PedmCollection] = {}
        for coll in plugin.collections.get_all_entities():
            if coll.collection_type == pedm_shared.CollectionType.UserAccount:
                acct_type = str(coll.collection_data.get('AccountType') or '').lower()
                if acct_type != account_type_key:
                    continue
                domain = str(coll.collection_data.get('Domainname') or '').lower()
                if domain != domain_name_key:
                    continue
                username = str(coll.collection_data.get('Username') or '').lower()
                if not username:
                    continue
                existing_users[(acct_type, domain, username)] = coll
            elif coll.collection_type == pedm_shared.CollectionType.GroupAccount:
                domain = str(coll.collection_data.get('Domainname') or '').lower()
                if domain != domain_name_key:
                    continue
                group_name = str(coll.collection_data.get('GroupName') or '').lower()
                if group_name:
                    existing_groups[(domain, group_name)] = coll
            else:
                continue

        add_map: Dict[str, admin_types.CollectionData] = {}
        update_map: Dict[str, admin_types.CollectionData] = {}

        def build_user(user: ScimUser) -> Optional[Tuple[admin_types.CollectionData, bool]]:
            user_login = user.login
            if not user_login:
                return None
            if source == 'azure':
                user_domain = domain_name
            else:
                user_domain = user.domain
                if not user_domain:
                    return None
                if user_login.endswith('$'):
                    return None
            key = (account_type_key, user_domain.lower(), user_login.lower())
            data = {
                'Domainname': user_domain,
                'Username': user_login,
                'AccountType': account_type,
            }
            if user.full_name:
                data['FullName'] = user.full_name
            if user.email:
                data['Email'] = user.email

            key_value = ''.join(key)
            collection_uid = pedm_shared.get_collection_uid(plugin.agent_key, int(pedm_shared.CollectionType.UserAccount), key_value)
            collection_json = json.dumps(data)
            existing = existing_users.get(key)
            if existing:
                if existing.collection_data != data:
                    cd = admin_types.CollectionData(collection_uid=collection_uid,
                                                    collection_type=int(pedm_shared.CollectionType.UserAccount),
                                                    collection_data=collection_json)
                    return cd, True
                return None
            cd = admin_types.CollectionData(collection_uid=collection_uid,
                                            collection_type=int(pedm_shared.CollectionType.UserAccount),
                                            collection_data=collection_json)
            return cd, False

        def build_group(group: ScimGroup) -> Optional[Tuple[admin_types.CollectionData, bool]]:
            if not group.name:
                return None
            group_domain = group.domain or domain_name
            data = {
                'GroupName': group.name,
                'Domainname': group_domain
            }

            key = (group_domain.lower(), group.name.lower())
            key_value = '\\'.join(key)
            collection_uid = pedm_shared.get_collection_uid(plugin.agent_key, int(pedm_shared.CollectionType.GroupAccount), key_value)
            collection_json = json.dumps(data)
            existing = existing_groups.get(key)
            if existing:
                if existing.collection_data != data:
                    cd = admin_types.CollectionData(collection_uid=collection_uid,
                                                    collection_type=int(pedm_shared.CollectionType.GroupAccount),
                                                    collection_data=collection_json)
                    return cd, True
                return None
            cd = admin_types.CollectionData(collection_uid=collection_uid,
                                            collection_type=int(pedm_shared.CollectionType.GroupAccount),
                                            collection_data=collection_json)
            return cd, False

        try:
            scim_records = list(data_source.populate())
        except Exception as e:
            raise base.CommandError(f'Error connecting to {account_type}: {e}')
        
        for element in scim_records:
            if isinstance(element, ScimUser):
                result = build_user(element)
                if isinstance(result, tuple):
                    cd, is_update = result
                    if is_update:
                        update_map[cd.collection_uid] = cd
                    else:
                        add_map[cd.collection_uid] = cd
            elif isinstance(element, ScimGroup):
                result = build_group(element)
                if isinstance(result, tuple):
                    cd, is_update = result
                    if is_update:
                        update_map[cd.collection_uid] = cd
                    else:
                        add_map[cd.collection_uid] = cd

        add_collections = list(add_map.values())
        update_collections = list(update_map.values())

        if len(add_collections) == 0 and len(update_collections) == 0:
            logging.info('No PEDM collections to add or update.')
            return

        status = plugin.modify_collections(add_collections=add_collections, update_collections=update_collections)
        logging.info('PEDM SCIM sync completed. Added: %d, Updated: %d', len(status.add), len(status.update))


class PedmSyncDownCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='sync-down', description='Sync down PEDM data from the backend')
        parser.add_argument('--reload', dest='reload', action='store_true', help='Perform full sync')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs):
        plugin = admin_plugin.get_pedm_plugin(context, skip_sync=True)
        plugin.sync_down(reload=kwargs.get('reload') is True)


class PedmDeploymentCommand(base.GroupCommandNew):
    def __init__(self):
        super().__init__('Manage PEDM deployments')
        self.register_command_new(PedmDeploymentListCommand(), 'list', 'l')
        self.register_command_new(PedmDeploymentAddCommand(), 'add', 'a')
        self.register_command_new(PedmDeploymentUpdateCommand(), 'edit')
        self.register_command_new(PedmDeploymentDeleteCommand(), 'delete')
        self.register_command_new(PedmDeploymentDownloadCommand(), 'download')
        self.default_verb = 'list'


class PedmDeploymentListCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='list', description='List PEDM deployments', parents=[base.report_output_parser])
        parser.add_argument('-v', '--verbose', dest='verbose', action='store_true',
                            help='print verbose information')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs):
        plugin = admin_plugin.get_pedm_plugin(context)

        verbose = kwargs.get('verbose') is True
        table: List[List[Any]] = []
        headers = ['deployment_uid', 'name', 'disabled', 'created', 'updated']
        if verbose:
            headers.append('agents')
        else:
            headers.append('agent_count')
        row: List[Any]
        for dep in plugin.deployments.get_all_entities():
            row = [dep.deployment_uid, dep.name, dep.disabled, dep.created, dep.updated]
            agents = [x.agent_uid for x in plugin.deployment_agents.get_links_for_subject(dep.deployment_uid)]
            if verbose:
                row.append(agents)
            else:
                row.append(len(agents))
            table.append(row)

        table.sort(key=lambda x: x[1])
        fmt = kwargs.get('format')
        if fmt != 'json':
            headers = [report_utils.field_to_title(x) for x in headers]
        return report_utils.dump_report_data(table, headers, fmt=fmt, filename=kwargs.get('output'))


class PedmDeploymentAddCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='add', description='Add PEDM deployments')
        parser.add_argument('-f', '--force', dest='force', action='store_true',
                            help='do not prompt for confirmation')
        # parser.add_argument('--spiffe-cert', dest='spiffe', action='store',
        #                     help='File containing SPIFFE server certificate')
        parser.add_argument('name', help='Deployment name')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs):
        enterprise_data = context.enterprise
        assert enterprise_data is not None
        plugin = admin_plugin.get_pedm_plugin(context)
        deployment_name = kwargs.get('name')
        if not deployment_name:
            raise base.CommandError('Deployment name is required')
        force =kwargs.get('force') is True
        if not force:
            l_name = deployment_name.lower()
            has_name = any((True for x in plugin.deployments.get_all_entities() if x.name.lower() == l_name))
            if has_name:
                raise base.CommandError(f'Deployment "{deployment_name}" already exists.')

        enterprise_keys = enterprise_data['keys']
        ec_public = enterprise_keys['ecc_public_key']
        ec_public_key = utils.base64_url_decode(ec_public)
        #ec_public_key = crypto.unload_ec_public_key(enterprise_data.enterprise_info.ec_public_key)
        agent_info = pedm_shared.DeploymentAgentInformation(hash_key=plugin.agent_key, peer_public_key=ec_public_key)
        spiffe_cert: Optional[bytes] = None
        spiffe = kwargs.get('spiffe')
        if isinstance(spiffe, str):
            spiffe = os.path.expanduser(spiffe)
            if not os.path.isfile(spiffe):
                raise base.CommandError(f'File "{spiffe}" does not exist')
            _, ext = os.path.splitext(spiffe)
            with open(spiffe, 'rb') as f:
                if ext in ('.cer', '.der'):
                    cert = x509.load_der_x509_certificate(f.read())
                elif ext == '.pem':
                    cert = x509.load_pem_x509_certificate(f.read())
                else:
                    cert = x509.load_pem_x509_certificate(f.read())
                spiffe_cert = cert.public_bytes(serialization.Encoding.DER)
        add_rq = admin_types.AddDeployment(name=deployment_name, spiffe_cert=spiffe_cert, agent_info=agent_info)
        rs = plugin.modify_deployments(add_deployments=[add_rq])
        if len(rs.remove) > 0:
            status = rs.remove[0]
            if isinstance(status, admin_types.EntityStatus) and not status.success:
                raise base.CommandError(f'Failed to add deployment "{status.entity_uid}": {status.message}')


class PedmDeploymentUpdateCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='update', description='Update PEDM deployment')
        parser.add_argument('--disable', dest='disable', action='store', choices=['on', 'off'],
                            help='do not prompt for confirmation')
        # parser.add_argument('--spiffe-cert', dest='spiffe', action='store',
        #                     help='File containing SPIFFE server certificate')
        parser.add_argument('--name',action='store', help='Deployment name')
        parser.add_argument('deployment', metavar='DEPLOYMENT', help='Deployment name or UID')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs):
        plugin = admin_plugin.get_pedm_plugin(context)
        deployment = PedmUtils.resolve_single_deployment(plugin, kwargs.get('deployment'))
        name = kwargs.get('name')
        disable_choice = kwargs.get('disable')
        disabled: Optional[bool] = None
        if disable_choice is not None:
            disabled = True if disable_choice == 'on' else False

        spiffe_cert: Optional[bytes] = None
        spiffe = kwargs.get('spiffe')
        if isinstance(spiffe, str):
            spiffe = os.path.expanduser(spiffe)
            if not os.path.isfile(spiffe):
                raise base.CommandError(f'File "{spiffe}" does not exist')
            _, ext = os.path.splitext(spiffe)
            with open(spiffe, 'rb') as f:
                if ext in ('.cer', '.der'):
                    cert = x509.load_der_x509_certificate(f.read())
                elif ext == '.pem':
                    cert = x509.load_pem_x509_certificate(f.read())
                else:
                    cert = x509.load_pem_x509_certificate(f.read())
                spiffe_cert = cert.public_bytes(serialization.Encoding.DER)

        update_rq = admin_types.UpdateDeployment(
            deployment_uid=deployment.deployment_uid, name=name, disabled=disabled, spiffe_cert=spiffe_cert)
        rs = plugin.modify_deployments(update_deployments=[update_rq])
        if len(rs.remove) > 0:
            status = rs.remove[0]
            if isinstance(status, admin_types.EntityStatus) and not status.success:
                raise base.CommandError(f'Failed to update policy "{status.entity_uid}": {status.message}')


class PedmDeploymentDeleteCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='delete', description='Delete PEDM deployment')
        parser.add_argument('-f', '--force', dest='force', action='store_true',
                            help='do not prompt for confirmation')
        parser.add_argument('deployment', metavar='DEPLOYMENT', nargs='+',
                            help='Deployment name or UID')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs):
        plugin = admin_plugin.get_pedm_plugin(context)
        deployment_names = kwargs.get('deployment')
        if isinstance(deployment_names, str):
            deployment_names = [deployment_names]
        if not isinstance(deployment_names, list):
            raise base.CommandError(f'deployment argument is empty')

        deployments: List[str] = []
        for deployment_name in deployment_names:
            try:
                deployment = PedmUtils.resolve_single_deployment(plugin, deployment_name)
                deployment_name = deployment.name
                deployment_uid = deployment.deployment_uid
            except Exception as e:
                d = plugin.storage.deployments.get_entity(deployment_name) if deployment_name else None
                if d:
                    deployment_uid = d.deployment_uid
                else:
                    raise e
            deployments.append(deployment_uid)

        if len(deployments) == 0:
            raise base.CommandError('No deployments found')

        force = kwargs.get('force') is True
        if not force:
            answer = prompt_utils.user_choice(f'Do you want to delete {len(deployments)} deployment(s)?', 'yN')
            if answer.lower() not in {'y', 'yes'}:
                return

        rs = plugin.modify_deployments(remove_deployments=deployments)
        for status in rs.remove:
            if isinstance(status, admin_types.EntityStatus) and not status.success:
                raise base.CommandError(f'Failed to delete deployment "{status.entity_uid}": {status.message}')


class PedmDeploymentDownloadCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='download', description='Download PEDM deployment package')
        grp = parser.add_mutually_exclusive_group()
        grp.add_argument('--file', dest='file', action='store', help='File name')
        grp.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='Verbose output')
        parser.add_argument('deployment', metavar='DEPLOYMENT', help='Deployment name or UID')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Optional[str]:
        plugin = admin_plugin.get_pedm_plugin(context)

        deployment = PedmUtils.resolve_single_deployment(plugin, kwargs.get('deployment'))
        host = next((host for host, server in constants.KEEPER_PUBLIC_HOSTS.items() if server == context.server), context.server)
        token = f'{host}:{deployment.deployment_uid}:{utils.base64_url_encode(deployment.private_key)}'
        filename = kwargs.get('file')
        if filename:
            with open(filename, 'wt') as f:
                f.write(token)
                return None

        if not kwargs.get('verbose'):
            return token

        path = ''
        windows = ''
        macos = ''
        linux = ''

        try:
            hostname = whoami.get_hostname(context.rest_context.server_base)
            for dc in constants.KEEPER_PUBLIC_HOSTS.values():
                if hostname.endswith(dc):
                    us = constants.KEEPER_PUBLIC_HOSTS['US']
                    hostname = hostname[:-len(us)] + us
                    break

            manifest_url = urlunparse(('https', hostname, '/pam/pedm/package-manifest.json', None, None, None))
            rs = requests.get(manifest_url)
            manifest = rs.json()
            core = manifest.get('Core')
            if isinstance(core, list) and len(core) > 0:
                latest = core[0]
                path = latest.get('Path')
                windows = latest.get('WindowsZip')
                macos = latest.get('MacOsZip')
                linux = latest.get('LinuxZip')
        except:
            pass

        table = [['', '']]
        if path:
            if windows:
                table.append(['Windows download URL', path + windows])
            if macos:
                table.append(['MacOS download URL', path + macos])
            if linux:
                table.append(['Linux download URL', path + linux])
            table.append(['', ''])
        table.append(['Deployment Token', token])
        base.dump_report_data(table, ['key', 'value'], no_header=True)
        return None


class PedmAgentCommand(base.GroupCommandNew):
    def __init__(self):
        super().__init__('Manage PEDM agents')
        self.register_command_new(PedmAgentListCommand(), 'list', 'l')
        self.register_command_new(PedmAgentEditCommand(), 'edit', 'e')
        self.register_command_new(PedmAgentDeleteCommand(), 'delete')
        self.register_command_new(PedmAgentCollectionCommand(), 'collection', 'c')
        self.default_verb = 'list'


class PedmAgentCollectionCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='list', parents=[base.report_output_parser],
                                         description='List PEDM agent resources')
        parser.add_argument('-v', '--verbose', dest='verbose', action='store_true',
                            help='print verbose information')
        parser.add_argument('--type', dest='type', action='store', type=int,
                            help='collection type filter')
        parser.add_argument('agent', help='Agent UID')

        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        plugin = admin_plugin.get_pedm_plugin(context)

        verbose = kwargs.get('verbose') is True
        collection_type: Optional[int] = kwargs.get('type')
        agent = PedmUtils.resolve_single_agent(plugin, kwargs.get('agent'))
        resource_uids = {x.collection_uid for x in plugin.storage.collection_links.get_links_for_object(agent.agent_uid)}
        collections = [plugin.collections.get_entity(x) or x for x in resource_uids]
        if isinstance(collection_type, int):
            collections = [x for x in collections if isinstance(x, admin_types.PedmCollection) and x.collection_type == collection_type]

        table: List[List[Any]] = []
        headers = ['collection_type']
        if verbose:
            headers.extend(['collection_uid', 'value'])
            for collection in collections:
                if isinstance(collection, admin_types.PedmCollection):
                    col_type_name = pedm_shared.collection_type_to_name(collection.collection_type)
                    col_type_name += f' ({col_type_name})'
                    collection_value = [f'{k}={v}' for k, v in collection.collection_data.items()]
                    row = [col_type_name, collection.collection_uid, collection_value]
                else:
                    row = ['', collection, '']
                table.append(row)
        else:
            headers.extend(['count'])
            r_map: Dict[int, int] = {}
            for collection in collections:
                if not isinstance(collection, admin_types.PedmCollection):
                    continue
                if collection.collection_type not in r_map:
                    r_map[collection.collection_type] = 0
                r_map[collection.collection_type] += 1
            for collection_type, cnt in r_map.items():
                col_type_name = pedm_shared.collection_type_to_name(collection_type)
                col_type_name += f' ({collection_type})'
                table.append([col_type_name, cnt])

        table.sort(key=lambda x: x[0])
        fmt = kwargs.get('format')
        if fmt != 'json':
            headers = [report_utils.field_to_title(x) for x in headers]
        return report_utils.dump_report_data(table, headers, fmt=fmt, filename=kwargs.get('output'))


class PedmAgentDeleteCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='update', description='Delete PEDM agents')
        parser.add_argument('--force', dest='force', action='store_true',
                            help='do not prompt for confirmation')
        parser.add_argument('agent', nargs='+', help='Agent UID(s)')

        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        plugin = admin_plugin.get_pedm_plugin(context)
        agents = kwargs['agent']
        if isinstance(agents, str):
            agents = [agents]
        agent_uid_list: List[str] = []
        if isinstance(agents, list):
            for agent_name in agents:
                agent = PedmUtils.resolve_single_agent(plugin, agent_name)
                agent_uid_list.append(agent.agent_uid)

        if len(agent_uid_list) == 0:
            return

        statuses = plugin.modify_agents( remove_agents=agent_uid_list)
        if isinstance(statuses.remove, list):
            for status in statuses.remove:
                if isinstance(status, admin_types.EntityStatus) and not status.success:
                    utils.get_logger().warning(f'Failed to remove agent "{status.entity_uid}": {status.message}')


class PedmAgentEditCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='update', description='Update PEDM agents')
        parser.add_argument('--enable', dest='enable', action='store', choices=['on', 'off'],
                                   help='Enables or disables agents')
        parser.add_argument('--deployment', dest='deployment', action='store',
                                   help='Moves agent to deployment')
        parser.add_argument('agent', nargs='+', help='Agent UID(s)')

        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        plugin = admin_plugin.get_pedm_plugin(context)

        deployment_uid = kwargs.get('deployment')
        if deployment_uid:
            deployment = plugin.deployments.get_entity(deployment_uid)
            if not deployment:
                raise base.CommandError(f'Deployment "{deployment_uid}" does not exist')
        else:
            deployment_uid = None

        disabled: Optional[bool] = None
        enable = kwargs.get('enable')
        if isinstance(enable, str):
            if enable.lower() == 'on':
                disabled = False
            elif enable.lower() == 'off':
                disabled = True
            else:
                raise base.CommandError(f'"enable" argument must be "on" or "off"')

        update_agents: List[admin_types.UpdateAgent] = []
        agents = kwargs['agent']
        if isinstance(agents, str):
            agents = [agents]
        if isinstance(agents, list):
            for a in agents:
                agent = plugin.agents.get_entity(a)
                if agent is None:
                    raise base.CommandError(f'Agent "{a}" does not exist')
                update_agents.append(admin_types.UpdateAgent(
                    agent_uid=agent.agent_uid,
                    deployment_uid=deployment_uid,
                    disabled=disabled,
                ))
        if len(update_agents) > 0:
            statuses = plugin.modify_agents(update_agents=update_agents)
            if isinstance(statuses.update, list):
                for status in statuses.update:
                    if isinstance(status, admin_types.EntityStatus) and not status.success:
                        utils.get_logger().warning(f'Failed to update agent "{status.entity_uid}": {status.message}')


class PedmAgentListCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='list', description='List PEDM agents',
                                         parents=[base.report_output_parser])
        parser.add_argument('-v', '--verbose', dest='verbose', action='store_true',
                            help='print verbose information')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        plugin = admin_plugin.get_pedm_plugin(context)

        verbose = kwargs.get('verbose') is True
        table = []
        headers = ['agent_uid', 'machine_name', 'deployment', 'disabled', 'created']
        active_agents: Set[str] = set()
        if verbose:
            headers.extend(('active', 'properties'))
            rq = pedm_pb2.PolicyAgentRequest()
            rq.summaryOnly = False
            rs = api.execute_router(context, "pedm/get_policy_agents", rq, rs_type=pedm_pb2.PolicyAgentResponse)
            assert rs is not None
            active_agents.update((utils.base64_url_encode(x) for x in rs.agentUid))

        for agent in plugin.agents.get_all_entities():
            deployment = plugin.deployments.get_entity(agent.deployment_uid)
            deployment_name = deployment.name if deployment else agent.deployment_uid
            time_created = datetime.datetime.fromtimestamp(int(agent.created // 1000)) if agent.created else None
            machine_name = ''
            if isinstance(agent.properties, dict):
                machine_name = agent.properties.get('MachineName') or ''
            row: List[Any] = [agent.agent_uid, machine_name, deployment_name, agent.disabled, time_created]
            if verbose:
                row.append(agent.agent_uid in active_agents)
                props: Optional[List[str]] = None
                if agent.properties:
                    props = [f'{k}={v}' for k, v in agent.properties.items()]
                    props.sort()
                row.append(props)

            table.append(row)

        table.sort(key=lambda x: x[2])
        fmt = kwargs.get('format')
        if fmt != 'json':
            headers = [report_utils.field_to_title(x) for x in headers]
        return report_utils.dump_report_data(table, headers, fmt=fmt, filename=kwargs.get('output'))


class PedmPolicyCommand(base.GroupCommandNew):
    def __init__(self):
        super().__init__('Manage PEDM policies')
        self.register_command_new(PedmPolicyListCommand(), 'list', 'l')
        self.register_command_new(PedmPolicyAddCommand(), 'add', 'a')
        self.register_command_new(PedmPolicyEditCommand(), 'edit', 'e')
        self.register_command_new(PedmPolicyViewCommand(), 'view', 'v')
        self.register_command_new(PedmPolicyAgentsCommand(), 'agents')
        self.register_command_new(PedmPolicyAssignCommand(), 'assign')
        self.register_command_new(PedmPolicyDeleteCommand(), 'delete')
        self.default_verb = 'list'


class PedmPolicyMixin:
    ALL_FILTERS: List[str] = ['USER', 'MACHINE', 'APP', 'TIME', 'DATE', 'DAY']
    ALL_CONTROLS: List[str] = ['ALLOW', 'DENY', 'NOTIFY', 'MFA', 'JUSTIFY', 'APPROVAL', 'AUDIT', 'RECORD']

    policy_filter = argparse.ArgumentParser(add_help=False)
    policy_filter.add_argument('--user-filter', dest='user_filter', action='append',
                        help='Policy user filter. User collection UID or *')
    policy_filter.add_argument('--machine-filter', dest='machine_filter', action='append',
                        help='Policy machine filter. Machine collection UID ')
    policy_filter.add_argument('--app-filter', dest='app_filter', action='append',
                        help='Policy application filter. Application collection UID')
    policy_filter.add_argument('--date-filter', dest='date_filter', action='append',
                        help='Policy date filter. Date range in ISO format. YYYY-MM-DD:YYYY-MM-DD')
    policy_filter.add_argument('--time-filter', dest='time_filter', action='append',
                        help='Policy time filter. Time. 24 hours format: HH:MM-HH:MM')
    policy_filter.add_argument('--day-filter', dest='day_filter', action='append',
                        help='Policy day filter. Day of Week')
    policy_filter.add_argument('--risk-level', dest='risk_level', type=int, help='Policy risk level')

    @staticmethod
    def resolve_collections(plugin: admin_plugin.PedmPlugin, col_types: List[int], col_values: List[str]) -> List[str]:
        result: List[str] = []
        if not col_values:
            return result

        collection_lookup: Dict[str, Union[str, List[str]]] = {}
        for c in plugin.collections.get_all_entities():
            if c.collection_type not in col_types: continue
            collection_lookup[c.collection_uid] = c.collection_uid
            if c.collection_type >= 100:
                collection_name: Optional[str] = c.collection_data.get('Name')
                if not collection_name:
                    continue
                collection_name = collection_name.lower()
                cv = collection_lookup.get(collection_name)
                if not cv:
                    cv = c.collection_uid
                elif isinstance(cv, str):
                    cv = [cv, c.collection_uid]
                elif isinstance(cv, list):
                    cv.append(c.collection_uid)
                else:
                    continue
                collection_lookup[collection_name] = cv

        for col_value in col_values:
            if col_value == '*':
                result.append(col_value)
            else:
                cv = collection_lookup[col_value]
                if not cv:
                    cv = collection_lookup[col_value.lower()]
                if not cv:
                    raise base.CommandError(f'collection value "{col_value}" cannot be resolved')
                if isinstance(cv, str):
                    result.append(cv)
                else:
                    raise base.CommandError(f'collection value "{col_value}" is not unique. Use collection UID')

        return result

    @staticmethod
    def to_time(v: str) -> Optional[str]:
        if not v:
            return None

        try:
            tc = [int(x) for x in v.split(':')]
            while len(tc) < 3:
                tc.append(0)
            if tc[0] >= 24:
                raise base.CommandError(f'time value "{v}" is not valid. Hours: 0 - 23')
            if tc[1] >= 60:
                raise base.CommandError(f'time value "{v}" is not valid. Minutes: 0 - 59')
            if tc[2] >= 60:
                raise base.CommandError(f'time value "{v}" is not valid. Seconds: 0 - 59')

            return ':'.join((f'{x:02d}' for x in tc))
        except Exception as e:
            raise base.CommandError(f'time value "{v}" is not valid.')

    @staticmethod
    def from_time(v: Any) -> Optional[str]:
        if not isinstance(v, str):
            return None
        try:
            tc = [int(x) for x in v.split(':')]
            tc = tc[:3]
            if tc[2] == 0:
                tc = tc[:2]
            return ':'.join((f'{x:02d}' for x in tc))
        except Exception:
            pass

    @staticmethod
    def parse_times(policy_times: Optional[List[Dict[str, Any]]]) -> Optional[List[str]]:
        if not isinstance(policy_times, list):
            return None

        result: List[str] = []
        for policy_time in policy_times:
            start_time = PedmPolicyMixin.from_time(policy_time.get('StartTime')) or ''
            end_time = PedmPolicyMixin.from_time(policy_time.get('EndTime')) or ''
            if start_time or end_time:
                result.append(f'{start_time}-{end_time}')
        return result

    @staticmethod
    def to_date(v: str) -> Optional[str]:
        if not v:
            return None
        try:
            date_value = datetime.datetime.fromisoformat(v).date()
            return date_value.isoformat()
        except Exception as e:
            raise base.CommandError(f'date value "{v}" is not valid.')

    @staticmethod
    def resolve_dates(d_values: List[str]) -> List[Dict[str, str]]:
        # { "StartDate": "2025-01-01",  "EndDate": "2025-01-25" }
        result: List[Dict[str, str]] = []
        if not d_values:
            return result
        for d_value in d_values:
            comp: List[Any] = d_value.split(':')
            if 1 <= len(comp) <= 2:
                dat: Dict[str, str] = {}
                comp = [PedmPolicyAddCommand.to_date(x) for x in comp]
                if comp[0]:
                    dat['StartDate'] = comp[0]
                if len(comp) == 2 and comp[1]:
                    dat['EndDate'] = comp[1]
                result.append(dat)
            else:
                raise base.CommandError(f'date range "{d_value}" is not valid.')

        return result

    @staticmethod
    def resolve_times(t_values: List[str]) -> List[Dict[str, str]]:
        #   { "StartTime" : "09:00:00", "EndTime" : "18:00:00" }
        result: List[Dict[str, str]] = []
        if not t_values:
            return result
        for t_value in t_values:
            comp: List[Any] = t_value.split('-')
            if 1 <= len(comp) <= 2:
                tim: Dict[str, str] = {}
                comp = [PedmPolicyAddCommand.to_time(x) for x in comp]
                if comp[0]:
                    tim['StartTime'] = comp[0]
                if len(comp) == 2 and comp[1]:
                    tim['EndTime'] = comp[1]
                result.append(tim)
            else:
                raise base.CommandError(f'time range "{t_value}" is not valid.')

        return result

    DAY_LOOKUP: Optional[Dict[str, int]] = None
    @staticmethod
    def get_day_lookup() -> Dict[str, int]:
        if PedmPolicyMixin.DAY_LOOKUP is None:
            PedmPolicyMixin.DAY_LOOKUP = {}
            for day_no, day_name in enumerate(calendar.day_name):
                day_no += 1
                if day_no > 6:
                    day_no -= 7
                PedmPolicyMixin.DAY_LOOKUP[day_name.lower()] = day_no
            for day_no, day_name in enumerate(calendar.day_abbr):
                day_no += 1
                if day_no > 6:
                    day_no -= 7
                PedmPolicyMixin.DAY_LOOKUP[day_name.lower()] = day_no
        return PedmPolicyMixin.DAY_LOOKUP

    @staticmethod
    def resolve_days(d_values: List[str]) -> List[int]:
        # integer in American convention
        result: List[int] = []
        if not d_values:
            return result

        day_lookup = PedmPolicyMixin.get_day_lookup()
        weekday: Optional[int]
        for d_value in d_values:
            if d_value.isnumeric():
                weekday = int(d_value)
                if 6 < weekday < 0:
                    weekday = None
            else:
                weekday = day_lookup.get(d_value.lower())
            if weekday is None:
                raise base.CommandError(f'day value "{d_value}" is not valid.')
            result.append(weekday)
        return result

    @staticmethod
    def get_policy_controls(policy_type_name: str, **kwargs) -> Optional[List[str]]:
        p_controls: Optional[Union[str, List[str]]] = kwargs.get('control')
        if not p_controls:
            return None

        allowed_controls: Set[str] = set()
        if policy_type_name == 'PrivilegeElevation':
            allowed_controls.update(('audit', 'notify', 'mfa', 'justify', 'approval'))
        elif policy_type_name == 'Access':
            allowed_controls.update(('audit', 'notify', 'allow', 'deny'))
        elif policy_type_name == 'CommandLine':
            allowed_controls.update(('audit', 'notify', 'allow', 'deny'))

        controls: List[str] = []
        if isinstance(p_controls, str):
            controls = [p_controls]

        wrong_controls = set(p_controls) - allowed_controls
        if len(wrong_controls) > 0:
            raise base.CommandError(f'"Control(s): {(", ".join(wrong_controls))}" are not valid for {policy_type_name} policy type')

        p_c = {x.upper() for x in p_controls}
        for c in PedmPolicyMixin.ALL_CONTROLS:
            if c in p_c:
                p_c.remove(c)
                controls.append(c)
        if len(p_c) > 0:
            raise base.CommandError(f'"control: {", ".join(p_c)}" is not supported')
        return controls

    @staticmethod
    def get_policy_filter(plugin: admin_plugin.PedmPlugin, **kwargs) -> Dict[str, Any]:
        policy_filter: Dict[str, Any] = {}
        for f in PedmPolicyMixin.ALL_FILTERS:
            arg_name = f'{f.lower()}_filter'
            p_filter: Any = kwargs.get(arg_name)
            if not p_filter: continue
            if isinstance(p_filter, str):
                p_filter = [p_filter]

            if f == 'USER':
                filter_name = 'UserCheck'
            elif f == 'MACHINE':
                filter_name = 'MachineCheck'
            elif f == 'APP':
                filter_name = 'ApplicationCheck'
            elif f == 'DATE':
                filter_name = 'DateCheck'
            elif f == 'TIME':
                filter_name = 'TimeCheck'
            elif f == 'DAY':
                filter_name = 'DayCheck'
            else:
                continue
            if '*' in p_filter:
                policy_filter[filter_name] = ['*']
            else:
                if f == 'USER':
                    policy_filter[filter_name] = PedmPolicyAddCommand.resolve_collections(plugin, [3, 6, 103], p_filter)
                elif f == 'MACHINE':
                    policy_filter[filter_name] = PedmPolicyAddCommand.resolve_collections(plugin, [1, 101], p_filter)
                elif f == 'APP':
                    policy_filter[filter_name] = PedmPolicyAddCommand.resolve_collections(plugin, [2, 102], p_filter)
                elif f == 'DATE':
                    policy_filter[filter_name] = PedmPolicyAddCommand.resolve_dates(p_filter)
                elif f == 'TIME':
                    policy_filter[filter_name] = PedmPolicyAddCommand.resolve_times(p_filter)
                elif f == 'DAY':
                    policy_filter[filter_name] = PedmPolicyAddCommand.resolve_days(p_filter)
        risk_level = kwargs.get('risk_level')
        if isinstance(risk_level, int):
            if risk_level < 0 or risk_level > 100:
                raise base.CommandError(f'risk level "{risk_level}" is not valid: 0-100')
            policy_filter['RiskLevel'] = risk_level
        return policy_filter


class PedmPolicyListCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='list', description='List PEDM policies',
                                         parents=[base.report_output_parser])
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        plugin = admin_plugin.get_pedm_plugin(context)
        table: List[List[Any]] = []
        all_agents = utils.base64_url_encode(plugin.all_agents)
        headers = ['policy_uid', 'policy_name', 'policy_type', 'status', 'controls', 'users', 'machines', 'applications', 'collections']
        for policy in plugin.policies.get_all_entities():
            data = policy.data or {}
            actions = data.get('Actions') or {}
            on_success = actions.get('OnSuccess') or {}
            controls = on_success.get('Controls') or ''

            collections = [x.collection_uid for x in plugin.storage.collection_links.get_links_for_object(policy.policy_uid)]
            collections = ['*' if x == all_agents else x for x in collections]
            collections.sort()

            status = data.get('Status')
            if policy.disabled:
                status = 'off'
            table.append([policy.policy_uid, data.get('PolicyName'), data.get('PolicyType'), status,
                          controls, data.get('UserCheck'), data.get('MachineCheck'), data.get('ApplicationCheck'),
                          collections])

        fmt = kwargs.get('format')
        if fmt != 'json':
            headers = [report_utils.field_to_title(x) for x in headers]
        return report_utils.dump_report_data(table, headers, fmt=fmt, filename=kwargs.get('output'), sort_by=1)


class PedmPolicyAddCommand(base.ArgparseCommand, PedmPolicyMixin):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='add', description='Add PEDM policy', parents=[PedmPolicyMixin.policy_filter])
        parser.add_argument('--policy-type', dest='policy_type', action='store', default='elevation',
                            choices=['elevation', 'file_access', 'command', 'least_privilege'],
                            help='Policy type')
        parser.add_argument('--policy-name', dest='policy_name', action='store',
                            help='Policy name')
        parser.add_argument('--control', dest='control', action='append',
                            choices=['allow', 'deny', 'audit', 'notify', 'mfa', 'justify', 'approval'],
                            help='Policy controls')
        parser.add_argument('--status', dest='status', action='store',
                            choices=['enforce', 'monitor', 'monitor_and_notify'],
                            help='Policy Status')
        parser.add_argument('--enable', dest='enable', action='store', choices=['on', 'off'],
                            help='Enables or disables policy')

        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        plugin = admin_plugin.get_pedm_plugin(context)

        p_type = kwargs.get('policy_type')
        if p_type == 'elevation':
            policy_type = 'PrivilegeElevation'
        elif p_type == 'file_access':
            policy_type = 'FileAccess'
        elif p_type == 'command':
            policy_type = 'CommandLine'
        elif p_type == 'least_privilege':
            policy_type = 'LeastPrivilege'
        else:
            raise base.CommandError(f'"policy-type: {p_type}" is not supported')

        policy_uid = utils.generate_uid()
        controls = PedmPolicyMixin.get_policy_controls(policy_type, **kwargs)

        policy_data: Dict[str, Any] = {
            'PolicyName': kwargs.get('policy_name') or '',
            'PolicyType': policy_type,
            'PolicyId': policy_uid,
            'Status': 'off',
            'Actions': {
                'OnSuccess': {'Controls': controls or []},
                'OnFailure': {'Command': ''}
            },
            "NotificationMessage": "A policy has been set to monitor mode.  When this policy is enabled, [mfa, justification, request] will be required to run this process as an administrator.",
            "NotificationRequiresAcknowledge": False,
            "RiskLevel": 50,
            'Operator': 'And',
            'Rules': [
                {
                    'RuleName': 'UserCheck',
                    'ErrorMessage': 'This user is not included in this policy',
                    'RuleExpressionType': 'BuiltInAction',
                    'Expression': 'CheckUser()'
                },
                {
                    'RuleName': 'MachineCheck',
                    'ErrorMessage': 'This Machine is not included in this policy',
                    'RuleExpressionType': 'BuiltInAction',
                    'Expression': 'CheckMachine()'
                },
                {
                    'RuleName': 'ApplicationCheck',
                    'ErrorMessage': 'This application is not included in this policy',
                    'RuleExpressionType': 'BuiltInAction',
                    'Expression': 'CheckFile(false)'
                },
                {
                    "RuleName": "DateCheck",
                    "ErrorMessage": "Current date is not covered by this policy",
                    "RuleExpressionType": "BuiltInAction",
                    "Expression": "CheckDate()"
                },
                {
                    'RuleName': 'TimeCheck',
                    'ErrorMessage': 'Current time is not covered by this policy',
                    'RuleExpressionType': 'BuiltInAction',
                    'Expression': 'CheckTime()'
                },
                {
                    'RuleName': 'DayCheck',
                    'ErrorMessage': 'Today is not included in this policy',
                    'RuleExpressionType': 'BuiltInAction',
                    'Expression': 'CheckDay()'
                }
            ]
        }
        policy_filter = PedmPolicyMixin.get_policy_filter(plugin, **kwargs)
        if policy_filter:
            policy_data.update(policy_filter)

        for filter_name in ('UserCheck', 'MachineCheck', 'ApplicationCheck', 'DateCheck', 'TimeCheck', 'DayCheck'):
            f = policy_filter.get(filter_name)
            if f is None:
                policy_filter[filter_name] = ['*']

        arg_status = kwargs.get('status')
        if isinstance(arg_status, str):
            policy_data['Status'] = arg_status
        else:
            policy_data['Status'] = 'enforce'

        disabled: bool = False
        arg_enable = kwargs.get('enable')
        if isinstance(arg_enable, str):
            disabled = True if arg_enable == 'off' else False

        policy_key = utils.generate_aes_key()
        add_policy = admin_types.PedmPolicy(
            policy_uid=policy_uid, policy_key=policy_key, data=policy_data, admin_data={}, disabled=disabled)
        rs = plugin.modify_policies(add_policies=[add_policy])
        if len(rs.remove) > 0:
            status = rs.remove[0]
            if isinstance(status, admin_types.EntityStatus) and not status.success:
                raise base.CommandError(f'Failed to add policy "{status.entity_uid}": {status.message}')


class PedmPolicyEditCommand(base.ArgparseCommand, PedmPolicyMixin):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='edit', description='Edit PEDM policy', parents=[PedmPolicyMixin.policy_filter])
        parser.add_argument('policy', help='Policy UID')
        parser.add_argument('--policy-name', dest='policy_name', action='store',
                            help='Policy name')
        parser.add_argument('--control', dest='control', action='append',
                            choices=['allow', 'deny', 'audit', 'notify', 'mfa', 'justify', 'approval'],
                            help='Policy controls')
        parser.add_argument('--status', dest='status', action='store',
                            choices=['enforce', 'monitor', 'monitor_and_notify'],
                            help='Policy Status')
        parser.add_argument('--enable', dest='enable', action='store', choices=['on', 'off'],
                            help='Enables or disables policy')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        plugin = admin_plugin.get_pedm_plugin(context)

        policy = PedmUtils.resolve_single_policy(plugin, kwargs.get('policy'))

        policy_data = copy.deepcopy(policy.data or {})
        policy_type = policy_data.get('PolicyType') or 'Unknown'
        controls = PedmPolicyMixin.get_policy_controls(policy_type, **kwargs)
        if isinstance(controls, list):
            actions = policy_data.get('Actions')
            if not isinstance(actions, dict):
                actions = {}
                policy_data['Actions'] = actions
            on_success = actions.get('OnSuccess')
            if not isinstance(on_success, dict):
                on_success = {}
            on_success['Controls'] = controls
            policy_data['OnSuccess'] = on_success

        policy_name = kwargs.get('policy_name')
        if policy_name:
            policy_data['PolicyName'] = policy_name
        policy_filter = PedmPolicyMixin.get_policy_filter(plugin, **kwargs)
        if policy_filter:
            policy_data.update(policy_filter)

        arg_status = kwargs.get('status')
        if isinstance(arg_status, str):
            policy_data['Status'] = arg_status

        disabled: Optional[bool] = None
        arg_enable = kwargs.get('enable')
        if isinstance(arg_enable, str):
            disabled = True if arg_enable == 'off' else False

        pu = admin_types.PedmUpdatePolicy(policy_uid=policy.policy_uid, data=policy_data, disabled=disabled)

        rs = plugin.modify_policies(update_policies=[pu])
        if len(rs.update) > 0:
            status = rs.update[0]
            if isinstance(status, admin_types.EntityStatus) and not status.success:
                raise base.CommandError(f'Failed to update policy "{status.entity_uid}": {status.message}')


class PedmPolicyViewCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='view', parents=[base.json_output_parser], description='View PEDM policy')
        parser.add_argument('policy', help='Policy UID or name')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        plugin = admin_plugin.get_pedm_plugin(context)

        policy = PedmUtils.resolve_single_policy(plugin, kwargs.get('policy'))

        body = json.dumps(policy.data, indent=4)
        filename = kwargs.get('output')
        if kwargs.get('format') == 'json' and filename:
            with open(filename, 'w') as f:
                f.write(body)
        else:
            return body


class PedmPolicyDeleteCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='delete', description='Delete PEDM policy')
        parser.add_argument('policy', type=str, nargs='+', help='Policy UID or name')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        plugin = admin_plugin.get_pedm_plugin(context)

        policies = PedmUtils.resolve_existing_policies(plugin, kwargs.get('policy'))
        to_delete = [x.policy_uid for x in policies]

        rs = plugin.modify_policies(remove_policies=to_delete)
        if len(rs.remove) > 0:
            status = rs.remove[0]
            if isinstance(status, admin_types.EntityStatus) and not status.success:
                raise base.CommandError(f'Failed to delete policy "{status.entity_uid}": {status.message}')


class PedmPolicyAgentsCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='agent', description='Show agents for policies')
        parser.add_argument('policy', type=str, nargs='+', help='Policy UID or name')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        plugin = admin_plugin.get_pedm_plugin(context)

        policy_args = kwargs.get('policy')
        if not isinstance(policy_args, list):
            policy_args = [policy_args]
        policies = PedmUtils.resolve_existing_policies(plugin, policy_args)
        if len(policies) == 0:
            policy_list = ', '.join(policy_args)
            raise base.CommandError(f'Policy "{policy_list}" not found')
        policy_uids = [utils.base64_url_decode(x.policy_uid) for x in policies]
        rq = pedm_pb2.PolicyAgentRequest()
        rq.policyUid.extend(policy_uids)
        rq.summaryOnly = False
        rs = api.execute_router(context, "pedm/get_policy_agents", rq, rs_type=pedm_pb2.PolicyAgentResponse)
        assert rs is not None

        table = []
        headers = ['key', 'uid', 'name', 'status']
        for p in policies:
            data = p.data or {}
            status = data.get('Status')
            if p.disabled:
                status = 'off'
            table.append(['Policy', p.policy_uid, data.get('PolicyName'), status])
        for a in rs.agentUid:
            agent_uid = utils.base64_url_encode(a)
            row = ['Agent', agent_uid]
            agent = plugin.agents.get_entity(agent_uid)
            machine_name = ''
            status = ''
            if agent:
                if isinstance(agent.properties, dict):
                    machine_name = agent.properties.get('MachineName') or ''
                status = 'off' if agent.disabled else 'on'
            row.append(machine_name)
            row.append(status)
            table.append(row)

        return report_utils.dump_report_data(table, headers, group_by=0)


class PedmPolicyAssignCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='assign', description='Assign collections to policy')
        parser.add_argument('-c', '--collection', action='append', help='Collection UID')
        parser.add_argument('policy', type=str, nargs='+', help='Policy UID or name')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        plugin = admin_plugin.get_pedm_plugin(context)

        policies = PedmUtils.resolve_existing_policies(plugin, kwargs.get('policy'))
        policy_uids = [utils.base64_url_decode(x.policy_uid) for x in policies]
        collections = kwargs.get('collection')
        collection_uids: List[bytes] = []
        if isinstance(collections, list):
            for c in collections:
                if c in ['*', 'all']:
                    collection_uids.append(plugin.all_agents)
                elif c:
                    collection_uid = utils.base64_url_decode(c)
                    if len(collection_uid) == 16:
                        collection_uids.append(collection_uid)
                    else:
                        utils.get_logger().info('Invalid collection UID: %s. Skipped', c)

        if len(policy_uids) == 0:
            raise base.CommandError('Nothing to do')

        statuses = plugin.assign_policy_collections(policy_uids, collection_uids)
        for status in statuses.add:
            if not status.success:
                raise base.CommandError(f'Failed to add to policy: {status.message}')
        for status in statuses.remove:
            if not status.success:
                raise base.CommandError(f'Failed to remove from policy: {status.message}')


class PedmCollectionCommand(base.GroupCommandNew):
    def __init__(self):
        super().__init__('Manage PEDM collections')
        self.register_command_new(PedmCollectionListCommand(), 'list', 'l')
        self.register_command_new(PedmCollectionViewCommand(), 'view', 'v')
        self.register_command_new(PedmCollectionAddCommand(), 'add', 'a')
        self.register_command_new(PedmCollectionUpdateCommand(), 'update', 'u')
        self.register_command_new(PedmCollectionDeleteCommand(), 'delete')
        self.register_command_new(PedmCollectionConnectCommand(), 'connect')
        self.register_command_new(PedmCollectionDisconnectCommand(), 'disconnect')
        self.register_command_new(PedmCollectionWipeOutCommand(), 'wipe-out')
        self.default_verb = 'list'


class PedmCollectionWipeOutCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='wipe-out', description='Wipe out PEDM collections')
        parser.add_argument('--type', dest='type', action='store', type=int,
                            help='collection type')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        plugin = admin_plugin.get_pedm_plugin(context)

        collection_type = kwargs.get('type')
        if isinstance(collection_type, int):
            collection_type = [collection_type]
        collections: List[str] = []
        for coll in plugin.storage.collections.get_all_entities():
            if collection_type and coll.collection_type not in collection_type:
                continue
            collections.append(coll.collection_uid)

        plugin.modify_collections(remove_collections=collections)


class PedmCollectionAddCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='add', description='Creates PEDM collections')
        parser.add_argument('--type', dest='type', action='store', type=int,
                            help='collection type')
        parser.add_argument('data', nargs='+', help='Field assignment key=value (repeatable)')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        plugin = admin_plugin.get_pedm_plugin(context)

        collection_type = kwargs.get('type')
        if not collection_type:
            raise base.CommandError('Collection type is required')

        extra_data: Dict[str, str] = {}
        for item in kwargs.get('data') or []:
            if '=' not in item:
                raise base.CommandError(f'Invalid data "{item}". Use key=value format.')
            k, v = item.split('=', 1)
            extra_data[k.strip()] = v.strip()

        required = pedm_shared.get_collection_required_fields(collection_type)
        if required is None:
            raise base.CommandError(f'Unknown collection type: {collection_type}')
        for field in required.all_fields:
            if field not in extra_data or not isinstance(extra_data[field], str) or not extra_data[field]:
                raise base.CommandError(f'Missing required field "{field}" for collection type {collection_type}')

        collection_data = json.dumps(extra_data)
        collection = admin_types.CollectionData(
            collection_uid='',
            collection_type=collection_type,
            collection_data=collection_data
        )

        status = plugin.modify_collections(add_collections=[collection])
        if len(status.add) > 0:
            for st in status.add:
                if isinstance(st, admin_types.EntityStatus) and not st.success:
                    raise base.CommandError(f'Failed to add collection "{st.entity_uid}": {st.message}')


class PedmCollectionUpdateCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='update', description='Update PEDM collection')
        parser.add_argument('--type', dest='type', action='store', type=int,
                            help='collection type (optional)')
        parser.add_argument('--name', dest='name', action='store', required=True,
                            help='Collection name')
        parser.add_argument('collection', help='Collection')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        plugin = admin_plugin.get_pedm_plugin(context)

        collection = kwargs.get('collection')
        collection_type = kwargs.get('type')
        collection_name = kwargs.get('name')
        if not collection_name:
            raise base.CommandError('Collection name is required')

        existing_collections = PedmUtils.resolve_existing_collections(plugin, collection, collection_type=collection_type)
        if len(existing_collections) > 0:
            if len(existing_collections) > 1:
                raise base.CommandError(f'Multiple collections found for collection "{collection}". Use Collection UID.')
            collections: admin_types.CollectionData
            coll = existing_collections[0]
            collection_info = coll.collection_data
            collection_info['Name'] = collection_name
            collection_data = admin_types.CollectionData(
                collection_uid=coll.collection_uid, collection_type=coll.collection_type,
                collection_data=json.dumps(collection_info))

            status = plugin.modify_collections(update_collections=[collection_data])
            if len(status.update) > 0:
                for st in status.update:
                    if isinstance(st, admin_types.EntityStatus) and not st.success:
                        raise base.CommandError(f'Failed to update collection "{st.entity_uid}": {st.message}')


class PedmCollectionDeleteCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='delete', description='Delete PEDM collections')
        parser.add_argument('-f', '--force', dest='force', action='store_true',
                            help='do not prompt for confirmation')
        parser.add_argument('collection', nargs='+', help='Collection or @orphan_resource')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        plugin = admin_plugin.get_pedm_plugin(context)

        collection = kwargs.get('collection')
        if not collection:
            raise base.CommandError('Collection is required')

        if isinstance(collection, str):
            collection = [collection]
        pseudo_collections = {x for x in collection if x in ('@orphan_resource')}
        collection = [x for x in collection if x not in pseudo_collections]
        force = kwargs.get('force') is True
        existing_collections = PedmUtils.resolve_existing_collections(plugin, collection, ignore_missing=True)
        unique_collections = set((x.collection_uid for x in existing_collections))
        if force:
            for collection_name in collection:
                if collection_name not in unique_collections:
                    try:
                        uid = utils.base64_url_decode(collection_name)
                        if len(uid) == 16:
                            unique_collections.add(collection_name)
                    except:
                        pass

        if '@orphan_resource' in pseudo_collections:
            unique_collections.update(PedmUtils.get_orphan_resources(plugin))

        if len(unique_collections) == 0:
            utils.get_logger().info('No collections found')
            return

        if not force:
            answer = prompt_utils.user_choice(f'Do you want to remove {len(unique_collections)} collection(s)?', 'yN', default='n')
            if answer.lower() not in ('y', 'yes'):
                return

        status = plugin.modify_collections(remove_collections=unique_collections)
        if len(status.remove) > 0:
            for st in status.remove:
                if isinstance(st, admin_types.EntityStatus) and not st.success:
                    raise base.CommandError(f'Failed to remove collection "{st.entity_uid}": {st.message}')


class PedmCollectionConnectCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='link', description='Link values to PEDM collection')
        parser.add_argument('--collection', '-c', dest='collection', action='store',
                            help='Parent collection UID or name')
        parser.add_argument('--link-type', dest='link_type', action='store', required=True,
                            choices=['agent', 'policy', 'collection'], help='collection type filter')
        parser.add_argument('links', nargs='+', help='Link UIDs or names')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        plugin = admin_plugin.get_pedm_plugin(context)

        col_name = kwargs.get('collection')
        collections = PedmUtils.resolve_existing_collections(plugin, [col_name])
        if len(collections) != 1:
            raise base.CommandError(f'Could not resolve a single collection: {col_name}')
        collection = collections[0]
        link_type = kwargs.get('link_type')
        link_names: Any = kwargs.get('links')
        links: List[str] = []
        collection_link_type: int
        if link_type == 'collection':
            coll_links = PedmUtils.resolve_existing_collections(plugin, link_names)
            links.extend((x.collection_uid for x in coll_links))
            collection_link_type = pedm_pb2.CLT_COLLECTION
        elif link_type == 'agent':
            for agent_name in link_names:
                agent = PedmUtils.resolve_single_agent(plugin, agent_name)
                links.append(agent.agent_uid)
            collection_link_type = pedm_pb2.CLT_AGENT
        elif link_type == 'policy':
            pol_links = PedmUtils.resolve_existing_policies(plugin, link_names)
            links.extend((x.policy_uid for x in pol_links))
            collection_link_type = pedm_pb2.CLT_POLICY
        else:
            raise base.CommandError(f'Unknown link type: {link_type}')

        to_add = [admin_types.CollectionLink(
            collection_uid=collection.collection_uid, link_uid=x, link_type=collection_link_type) for x in links]

        status = plugin.set_collection_links(set_links=to_add)
        if len(status.add) > 0:
            for st in status.add:
                if isinstance(st, admin_types.LinkStatus) and not st.success:
                    raise base.CommandError(f'Failed to set collection link "{st.object_uid}": {st.message}')


class PedmCollectionDisconnectCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='unlink', description='Unlink values from PEDM collections')
        parser.add_argument('--collection', '-c', dest='collection', action='store',
                            help='Parent collection UID or name')
        parser.add_argument('-f', '--force', dest='force', action='store_true',
                            help='do not prompt for confirmation')
        parser.add_argument('links', nargs='+', help='UIDs to unlink')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        plugin = admin_plugin.get_pedm_plugin(context)

        col_name = kwargs.get('collection')
        collections = PedmUtils.resolve_existing_collections(plugin, [col_name])
        if len(collections) != 1:
            raise base.CommandError(f'Could not resolve a single collection: {col_name}')
        collection = collections[0]

        existing_links= list(x for x in plugin.storage.collection_links.get_links_for_subject(collection.collection_uid))
        links: Any = kwargs.get('links')
        to_unlink: Set[str] = set(links)

        to_remove: List[admin_types.CollectionLink] = []
        for link in existing_links:
            link_uid = link.link_uid
            if link_uid in to_unlink:
                to_remove.append(admin_types.CollectionLink(
                    collection_uid=collection.collection_uid,
                    link_uid=link_uid,
                    link_type=link.link_type)     # type: ignore
                )
                to_unlink.remove(link_uid)

        if len(to_unlink) > 0:
            utils.get_logger().info(f'{len(to_unlink)} link(s) cannot be removed from collection: {col_name}')

        if len(to_remove) == 0:
            return

        force = kwargs.get('force') is True
        if not force:
            answer = prompt_utils.user_choice(
                f'Do you want to remove {len(to_remove)} link(s)?', 'yN', default='n')
            if answer.lower() not in ('y', 'yes'):
                return

        status = plugin.set_collection_links(unset_links=to_remove)
        if len(status.remove) > 0:
            for st in status.remove:
                if isinstance(st, admin_types.LinkStatus) and not st.success:
                    raise base.CommandError(f'Failed to unset collection link "{st.object_uid}": {st.message}')


class PedmCollectionListCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='list', description='List PEDM collections',
                                         parents=[base.report_output_parser])
        parser.add_argument('-v', '--verbose', dest='verbose', action='store_true',
                            help='print verbose information')
        parser.add_argument('--type', dest='type', action='store', type=int,
                            help='collection type filter')
        parser.add_argument('--pattern', dest='pattern', action='store',
                            help='collection search pattern')

        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        plugin = admin_plugin.get_pedm_plugin(context)

        table: List[List[Any]] = []
        row: List[Any]
        collection_type: Optional[int] = kwargs.get('type')
        verbose = kwargs.get('verbose') is True
        pattern = kwargs.get('pattern')

        if isinstance(collection_type, int):
            col_dict: Dict[str, List[admin_storage.PedmStorageCollectionLink]] = {}
            for col in plugin.collections.get_all_entities():
                if col.collection_type != collection_type:
                    continue
                col_dict[col.collection_uid] = list(plugin.storage.collection_links.get_links_for_subject(col.collection_uid))

            headers = ['collection_uid', 'value']
            if verbose:
                headers.extend(['link_info'])
            else:
                headers.extend(['link_count'])
            for (collection_uid, links) in col_dict.items():
                collection = plugin.collections.get_entity(collection_uid)
                if not collection:
                    continue
                cv = [f'{k}={v}' for k, v in collection.collection_data.items()]
                row = [collection_uid, cv]
                if verbose:
                    link_info = [f'{x.link_uid} ({pedm_shared.collection_link_type_to_name(x.link_type)})' for x in links]
                    row.append(link_info)
                else:
                    row.append(len(links))
                table.append(row)
        else:
            type_dict: Dict[int, List[admin_types.PedmCollection]] = {}
            for col in plugin.collections.get_all_entities():
                if col.collection_type not in type_dict:
                    type_dict[col.collection_type] = []
                type_dict[col.collection_type].append(col)

            headers = ['id', 'collection_type']
            if verbose:
                headers.extend(['collection_uid', 'value'])
            else:
                headers.extend(['value_count'])

            for (col_type, collections) in type_dict.items():
                col_type_name = pedm_shared.collection_type_to_name(col_type)
                if verbose:
                    for collection in collections:
                        cv = [f'{k}={v}' for k, v in collection.collection_data.items()]
                        table.append([col_type, col_type_name, collection.collection_uid, cv])
                else:
                    table.append([col_type, col_type_name, len(collections)])

        regex: Optional[Pattern[str]] = re.compile(fnmatch.translate(f'*{pattern}*'), re.IGNORECASE) if pattern else None
        if regex is not None:
            def any_match(row: Any) -> bool:
                if not row:
                    return False
                if not isinstance(row, list):
                    return False

                match = False
                for column in row:
                    column_values = []
                    if isinstance(column, list):
                        column_values.extend([x for x in column if isinstance(x, str)])
                    elif isinstance(column, str):
                        column_values.append(column)
                    match = any((True for x in column_values if regex.match(x)))
                    if match:
                        break
                return match

            table = [x for x in table if any_match(x)]

        table.sort(key=lambda x: x[0])
        fmt = kwargs.get('format')
        if fmt != 'json':
            headers = [report_utils.field_to_title(x) for x in headers]
        return report_utils.dump_report_data(table, headers, column_width=80, fmt=fmt, filename=kwargs.get('output'))


class PedmCollectionViewCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='view', description='Show PEDM collection details',
                                         parents=[base.report_output_parser])
        parser.add_argument('-v', '--verbose', dest='verbose', action='store_true',
                            help='print verbose information')
        parser.add_argument('--link', dest='link', action='append', help='Show link details')
        parser.add_argument('collection',  nargs='+', help='Collection UID')

        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        plugin = admin_plugin.get_pedm_plugin(context)

        collection_uid = kwargs.get('collection')
        if isinstance(collection_uid, str):
            collection_uid = [collection_uid]
        if not collection_uid:
            return

        collections: Dict[str, admin_types.PedmCollection] = {}

        for uid in collection_uid:
            coll = plugin.collections.get_entity(uid)
            if coll:
                collections[uid] = coll

        link_info: List[str] = []
        agent_link_data: Dict[Tuple[str, str], Dict[str, Any]] = {}
        link = kwargs.get('link')
        if isinstance(link, str):
            link = [link]
        if isinstance(link, list) and len(link) > 0:
            links: List[admin_types.CollectionLink] = []
            for c_uid in collection_uid:
                for l_uid in link:
                    cl = plugin.storage.collection_links.get_link(c_uid, l_uid)
                    if cl:
                        links.append(admin_types.CollectionLink(
                            collection_uid=c_uid, link_type=cl.link_type, link_uid=l_uid))
            if len(links) > 0:
                for cld in plugin.get_collection_links(links=links):
                    if not cld.link_data:
                        continue
                    collection_uid = cld.collection_link.collection_uid
                    link_uid = cld.collection_link.link_uid
                    try:
                        agent_data = json.loads(crypto.decrypt_aes_v2(cld.link_data, plugin.agent_key))
                        agent_link_data[(collection_uid, link_uid)] = agent_data
                    except:
                        pass
                link_info = list({x[1] for x in agent_link_data.keys()})

        verbose = kwargs.get('verbose') is True
        headers = ['collection_uid', 'collection_type', 'collection_value']
        if len(link_info) > 0:
            headers.extend((f'"{x}"' for x in link_info))
        else:
            if verbose:
                headers.append('link_uid')
            else:
                headers.append('link_count')
        table = []
        row: List[Any]
        for collection_uid, coll in collections.items():
            row = [collection_uid]
            if coll:
                collection_type = f'{pedm_shared.collection_type_to_name(coll.collection_type)} ({coll.collection_type})'
                row.append(collection_type)
                collection_value = [f'{k}={v}' for k, v in coll.collection_data.items()]
                row.append(collection_value)

                if len(link_info) > 0:
                    for link in link_info:
                        ld = agent_link_data[(coll.collection_uid, link)]
                        if ld:
                            row.append([f'{x[0]}={x[1]}' for x in ld.items()])
                        else:
                            row.append(None)
                else:
                    link_titles = list((f'{x.link_uid} ({pedm_shared.collection_link_type_to_name(x.link_type)})'
                                  for x in plugin.storage.collection_links.get_links_for_subject(collection_uid)))
                    if verbose:
                        row.append(link_titles)
                    else:
                        row.append(len(link_titles))
                table.append(row)

        table.sort(key=lambda x: x[0])
        fmt = kwargs.get('format')
        if fmt != 'json':
            headers = [report_utils.field_to_title(x) for x in headers]
        column_width = None if verbose else 50
        return report_utils.dump_report_data(table, headers, column_width=column_width, fmt=fmt, filename=kwargs.get('output'))


class PedmApprovalCommand(base.GroupCommandNew):
    def __init__(self):
        super().__init__('Manage PEDM approval requests and approvals')
        self.register_command_new(PedmApprovalListCommand(), 'list', 'l')
        self.register_command_new(PedmApprovalViewCommand(), 'view')
        self.register_command_new(PedmApprovalStatusCommand(), 'action', 'a')
        self.default_verb = 'list'


class PedmApprovalViewCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='view', parents=[base.json_output_parser], description='View PEDM approval')
        parser.add_argument('approval', help='Approval UID')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        plugin = admin_plugin.get_pedm_plugin(context)

        approval = PedmUtils.resolve_single_approval(plugin, kwargs.get('approval'))
        a_status = plugin.storage.approval_status.get_entity(approval.approval_uid)
        headers = ['approval_uid', 'approval_type', 'status', 'agent_uid', 'account_info', 'application_info', 'justification', 'expire_in', 'created']
        approval_type = pedm_shared.approval_type_to_name(approval.approval_type)
        approval_status = pedm_shared.approval_status_to_name(
            a_status.approval_status if a_status else NotificationCenter_pb2.NAS_UNSPECIFIED,
            approval.created,
            approval.expire_in
        )

        row = [approval.approval_uid, approval_type, approval_status, approval.agent_uid, approval.account_info,
               approval.application_info, approval.justification, approval.expire_in, approval.created]

        fmt = kwargs.get('format')
        if fmt == 'json':
            table = [row]
        else:
            headers = [report_utils.field_to_title(x) for x in headers]
            table = [[x[0], x[1]] for x in zip(headers, row)]
            headers = [report_utils.field_to_title(x) for x in ['property', 'value']]
        return report_utils.dump_report_data(table, headers, fmt=fmt, filename=kwargs.get('output'))

class PedmApprovalListCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='list', description='List PEDM approval requests',
                                         parents=[base.report_output_parser])
        parser.add_argument('--type', dest='type', action='store', choices=['approved', 'denied', 'pending', 'expired'],
                            help='approval type filter')

        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        plugin = admin_plugin.get_pedm_plugin(context)

        approval_type = kwargs.get('type')
        if isinstance(approval_type, str):
            approval_type = approval_type.lower()
        else:
            approval_type = None
        table: List[List[Any]] = []
        headers = ['approval_uid', 'approval_type', 'status', 'agent_uid', 'account_info', 'application_info', 'justification', 'expire_in', 'created']
        for approval in plugin.approvals.get_all_entities():
            approval_uid = approval.approval_uid
            a_status = plugin.storage.approval_status.get_entity(approval_uid)
            status = pedm_shared.approval_status_to_name(
                a_status.approval_status if a_status else NotificationCenter_pb2.NAS_UNSPECIFIED,
                approval.created,
                approval.expire_in
            )
            if approval_type and approval_type != status.lower():
                continue

            account_info = [y[:30] for y in (f'{k}={v}' for k, v in approval.account_info.items())]
            application_info = [y[:30] for y in (f'{k}={v}' for k, v in approval.application_info.items())]
            table.append([approval.approval_uid, pedm_shared.approval_type_to_name(approval.approval_type),
                          status, approval.agent_uid, account_info, application_info, approval.justification,
                          approval.expire_in, approval.created])

        table.sort(key=lambda x: x[8], reverse=True)
        fmt = kwargs.get('format')
        if fmt != 'json':
            headers = [report_utils.field_to_title(x) for x in headers]
        return report_utils.dump_report_data(table, headers, fmt=fmt, filename=kwargs.get('output'))


class PedmApprovalStatusCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='action', description='Modify PEDM approval requests')
        parser.add_argument('--approve', dest='approve', action='append',
                            help='Request UIDs for approval')
        parser.add_argument('--deny', dest='deny', action='append',
                            help='Request UIDs for denial')
        parser.add_argument('--remove', dest='remove', action='append',
                            help='Request UIDs for removal. UID, @approved, @denied, @expired, @pending')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> None:
        plugin = admin_plugin.get_pedm_plugin(context)

        logger = utils.get_logger()
        def verify_uid(uids: Any) -> Optional[List[bytes]]:
            if isinstance(uids, str):
                uids = [uids]
            if isinstance(uids, list):
                to_uid = []
                for uid in uids:
                    approve_uid = utils.base64_url_decode(uid)
                    if len(approve_uid) == 16:
                        to_uid.append(approve_uid)
                    else:
                        logger.warning(f'Invalid UID: {uid}')
                if len(to_uid) > 0:
                    return to_uid
            return None

        to_approve = verify_uid(kwargs.get('approve'))
        to_deny = verify_uid(kwargs.get('deny'))
        to_remove = kwargs.get('remove')
        expire_ts = int(datetime.datetime.now().timestamp() * 1000)
        if to_remove:
            if isinstance(to_remove, str):
                to_remove = [to_remove]
            to_remove_set: Set[bytes] = set()
            to_resolve = []
            for uid in to_remove:
                if uid == '@approved':
                    to_remove_set.update(
                        (utils.base64_url_decode(x.approval_uid) for x in plugin.storage.approval_status.get_all_entities() if x.approval_status == NotificationCenter_pb2.NAS_APPROVED))
                elif uid == '@denied':
                    to_remove_set.update(
                        (utils.base64_url_decode(x.approval_uid) for x in plugin.storage.approval_status.get_all_entities() if x.approval_status == NotificationCenter_pb2.NAS_DENIED))
                elif uid == '@pending':
                    to_remove_set.update(
                        (utils.base64_url_decode(x.approval_uid) for x in plugin.storage.approval_status.get_all_entities() if x.approval_status == NotificationCenter_pb2.NAS_UNSPECIFIED and x.modified >= expire_ts))
                elif uid == '@expired':
                    to_remove_set.update(
                        (utils.base64_url_decode(x.approval_uid) for x in plugin.storage.approval_status.get_all_entities() if x.approval_status == NotificationCenter_pb2.NAS_UNSPECIFIED and x.modified < expire_ts))
                else:
                    to_resolve.append(uid)
            if len(to_resolve) > 0:
                to_remove = verify_uid(to_resolve)
                if isinstance(to_remove, list):
                    to_remove_set.update(to_remove)
            to_remove = list(to_remove_set)

        if to_approve or to_deny or to_remove:
            status_rs = plugin.modify_approvals(to_approve=to_approve, to_deny=to_deny, to_remove=to_remove)
            if status_rs.add:
                for status in status_rs.add:
                    if not status.success:
                        if isinstance(status, admin_types.EntityStatus):
                            logger.warning(f'Failed to approved "{status.entity_uid}": {status.message}')
            if status_rs.update:
                for status in status_rs.update:
                    if not status.success:
                        if isinstance(status, admin_types.EntityStatus):
                            logger.warning(f'Failed to deny "{status.entity_uid}": {status.message}')
            if status_rs.remove:
                for status in status_rs.remove:
                    if not status.success:
                        if isinstance(status, admin_types.EntityStatus):
                            logger.warning(f'Failed to remove "{status.entity_uid}": {status.message}')
