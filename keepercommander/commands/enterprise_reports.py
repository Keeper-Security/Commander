import argparse
import datetime
import logging

from . import enterprise_common, register
from ..sox.sox_types import RecordPermissions
from ..error import Error
from ..display import bcolors
from . import base
from .. import constants
from ..commands.helpers.enterprise import is_addon_enabled


def register_commands(commands):
    commands['external-shares-report'] = ExternalSharesReportCommand()
    commands['license-consumption-report'] = LicenseConsumptionReportCommand()


def register_command_info(aliases, command_info):
    aliases['esr'] = 'external-shares-report'
    aliases['lcr'] = 'license-consumption-report'

    for p in [external_share_report_parser, license_consumption_report_parser]:
        command_info[p.prog] = p.description


def get_feature_enforcements_from_constants():
    """Get feature enforcement mappings from constants, categorizing them by feature type"""
    # Get all PAM-related enforcements from constants
    pam_enforcements = set()
    breachwatch_enforcements = set()
    secrets_manager_enforcements = set()
    
    for enforcement_tuple in constants._ENFORCEMENTS:
        enforcement_name = enforcement_tuple[0]  # First element is always the name
        enforcement_lower = enforcement_name.lower()
        
        if any(pam_keyword in enforcement_lower for pam_keyword in ['pam', 'rbi', 'kcm']):
            pam_enforcements.add(enforcement_lower)
        elif 'breach_watch' in enforcement_lower:
            breachwatch_enforcements.add(enforcement_lower)
        elif 'secrets_manager' in enforcement_lower:
            secrets_manager_enforcements.add(enforcement_lower)
    
    return {
        'pam': {
            'addon_name': 'privileged_access_manager',
            'enforcements': pam_enforcements
        },
        'secrets-manager': {
            'addon_name': 'secrets_manager',
            'enforcements': secrets_manager_enforcements
        },
        'connection-manager': {
            'addon_name': 'connection_manager',
            'enforcements': {'allow_view_kcm_recordings'}
        },
        'breachwatch': {
            'addon_name': 'enterprise_breach_watch',
            'enforcements': breachwatch_enforcements
        }
    }


ext_shares_report_desc = 'Run an external record sharing report'
external_share_report_parser = argparse.ArgumentParser(prog='external-shares-report', description=ext_shares_report_desc,
                                                       parents=[base.report_output_parser])
external_share_report_parser.add_argument('-a', '--action', action='store', choices=['remove', 'none'], default='none',
                                          help='action to perform on external shares, \'none\' if omitted')
external_share_report_parser.add_argument('-t', '--share-type', action='store', choices=['direct', 'shared-folder', 'all'],
                                          default='all', help='filter report by share type, \'all\' if omitted')
# external_share_report_parser.add_argument('-e', '--email', action='store', help='filter report by share-recipient email')
external_share_report_parser.add_argument('-f', '--force', action='store_true', help='apply action w/o confirmation')
external_share_report_parser.add_argument('-r', '--refresh-data', action='store_true', help='retrieve fresh data')

license_consumption_report_desc = 'Report of users consuming feature licenses based on policy'
license_consumption_report_parser = argparse.ArgumentParser(prog='license-consumption-report', description=license_consumption_report_desc,
                                                           parents=[base.report_output_parser])
license_consumption_report_parser.add_argument('--feature', dest='feature', action='store', 
                                               choices=['pam', 'secrets-manager', 'connection-manager', 'breachwatch', 'all'],
                                               default='pam',
                                               help='feature type to report on, or "all" for consolidated report (default: pam)')
license_consumption_report_parser.add_argument('--node', dest='node', action='store',
                                               help='filter users by node (node name or ID)')
license_consumption_report_parser.add_argument('--include-teams', dest='include_teams', action='store_true',
                                               help='include users from teams assigned to feature roles')
license_consumption_report_parser.add_argument('--details', dest='details', action='store_true',
                                               help='show detailed feature names instead of just counts')


class ExternalSharesReportCommand(enterprise_common.EnterpriseCommand):
    def __init__(self):
        super(ExternalSharesReportCommand, self).__init__()
        self.sox_data = None

    def get_sox_data(self, params, refresh_data):
        if not self.sox_data or refresh_data:
            from ..sox import get_compliance_data
            node_id = params.enterprise['nodes'][0].get('node_id', 0)
            enterprise_id = node_id >> 32
            now_ts = datetime.datetime.now().timestamp()
            self.sox_data = get_compliance_data(params, node_id, enterprise_id, True, now_ts, False, True)
        return self.sox_data

    def get_parser(self):
        return external_share_report_parser

    def execute(self, params, **kwargs):
        output = kwargs.get('output')
        output_fmt = kwargs.get('format', 'table')
        action = kwargs.get('action', 'none')
        force_action = kwargs.get('force')
        share_type = kwargs.get('share_type', 'all')
        refresh_data = kwargs.get('refresh_data')
        sd = self.get_sox_data(params, refresh_data)

        # Non-enterprise users
        external_users = {uid: user for uid, user in sd.get_users().items() if (user.user_uid >> 32) == 0}
        ext_uuids = set(external_users.keys())

        def get_direct_shares():
            records = sd.get_records()
            ext_recs = [r for r in records.values() if r.shared and ext_uuids.intersection(r.user_permissions.keys())]
            rec_shares = {r.record_uid: ext_uuids.intersection(r.user_permissions.keys()) for r in ext_recs}
            return rec_shares

        def get_sf_shares():
            folders = sd.get_shared_folders()
            ext_sfs = [sf for sf in folders.values() if ext_uuids.intersection(sf.users)]
            sf_shares = {sf.folder_uid: ext_uuids.intersection(sf.users) for sf in ext_sfs}
            return sf_shares

        def confirm_remove_shares():
            logging.info(bcolors.FAIL + bcolors.BOLD + '\nALERT!' + bcolors.ENDC)
            logging.info('You are about to delete the following shares:')
            generate_report('simple')
            answer = base.user_choice('\nDo you wish to proceed?', 'yn', 'n')
            if answer.lower() in {'y', 'yes'}:
                remove_shares()
            else:
                logging.info('Action aborted.')

        def remove_shares():
            if share_type in ('direct', 'all'):
                cmd = register.ShareRecordCommand()
                for rec_uid, user_uids in get_direct_shares().items():
                    emails = [external_users.get(user_uid).email for user_uid in user_uids]
                    try:
                        cmd.execute(params, email=emails, action='revoke', record=rec_uid)
                    except Error:
                        pass
            if share_type in ('shared-folder', 'all'):
                cmd = register.ShareFolderCommand()
                for sf_uid, user_uids in get_sf_shares().items():
                    emails = [external_users.get(user_uid).email for user_uid in user_uids]
                    try:
                        cmd.execute(params, user=emails, action='remove', folder=sf_uid)
                    except Error:
                        pass

        def apply_action():
            if action == 'remove':
                remove_shares() if force_action else confirm_remove_shares()

        def fill_rows(rows, shares, share_category):
            direct_shares = share_category.lower() == 'direct'
            for sf_or_rec_uid, targets in shares.items():
                if direct_shares:
                    rec = sd.get_records().get(sf_or_rec_uid)
                    name = (rec.data or {}).get('title')
                    perm_lookup = rec.user_permissions
                else:
                    # TODO : populate shared-folder 1) name and 2) permissions (from get_record_details endpoint in KA)
                    name = ''
                for target_id in targets:
                    target = external_users.get(target_id).email
                    perms = RecordPermissions.to_permissions_str(perm_lookup.get(target_id)) if direct_shares \
                        else ''
                    row = [sf_or_rec_uid, name, share_category, target, perms]
                    rows.append(row)
            return rows

        def generate_report(report_type='standard'):
            headers = ['uid', 'name', 'type', 'shared_to', 'permissions']
            rep_fmt = output_fmt if report_type == 'standard' else 'table'
            rep_out = output if report_type == 'standard' else None
            title = 'External Shares Report' if report_type == 'standard' else None
            if rep_fmt != 'json':
                headers = [base.field_to_title(field) for field in headers]
            table = []
            if share_type in ('direct', 'all'):
                table = fill_rows(table, get_direct_shares(), 'Direct')
            if share_type in ('shared-folder', 'all'):
                table = fill_rows(table, get_sf_shares(), 'Shared Folder')

            return base.dump_report_data(table, headers, title=title, fmt=rep_fmt, filename=rep_out)

        if action != 'none':
            apply_action()
        else:
            return generate_report()


class LicenseConsumptionReportCommand(enterprise_common.EnterpriseCommand):
    """Generate a report of users consuming feature licenses based on role enforcement policies."""

    def get_parser(self):
        return license_consumption_report_parser

    def execute(self, params, **kwargs):
        output = kwargs.get('output')
        output_fmt = kwargs.get('format', 'table')
        feature = kwargs.get('feature', 'pam')
        node_filter = kwargs.get('node')
        include_teams = kwargs.get('include_teams', False)
        show_details = kwargs.get('details', False)

        if not params.enterprise:
            raise Error('License consumption report requires enterprise data')

        # Get feature enforcements dynamically from constants
        feature_enforcements_map = get_feature_enforcements_from_constants()
        
        if feature == 'all':
            return self._generate_all_features_report(params, feature_enforcements_map, node_filter, include_teams, show_details, output_fmt, output)
        
        if feature not in feature_enforcements_map:
            raise Error(f'Unknown feature: {feature}. Available: {", ".join(list(feature_enforcements_map.keys()) + ["all"])}')

        feature_config = feature_enforcements_map[feature]
        feature_enforcements = feature_config['enforcements']
        addon_name = feature_config.get('addon_name')

        # Check if addon is enabled for this enterprise
        if addon_name and not is_addon_enabled(params, addon_name):
            logging.warning(f'{feature.upper()} addon is not enabled for this enterprise')

        # Get feature users using the refactored helper method
        feature_user_details = self._get_feature_users(params, feature_config, node_filter, include_teams)

        # Generate report data
        table = []
        headers = ['Username', 'Display Name', 'Node', 'Status', 'Direct Roles', 'Team Roles', f'{feature.upper()} Features']
        
        # Only add Feature Count column when not showing details (since it would be redundant)
        if not show_details:
            headers.append('Feature Count')
        
        if output_fmt == 'json':
            headers = ['username', 'display_name', 'node', 'status', 'direct_roles', 'team_roles', f'{feature}_features']
            if not show_details:
                headers.append('feature_count')

        for user_detail in sorted(feature_user_details.values(), key=lambda x: x['username'].lower()):
            node_path = self.get_node_path(params, user_detail['node_id']) if user_detail['node_id'] > 0 else ''
            
            direct_roles = ', '.join(user_detail['roles']) if user_detail['roles'] else ''
            team_roles = ', '.join(user_detail['teams']) if user_detail['teams'] else ''
            
            # Format feature enforcements based on details flag
            feature_count = len(user_detail['feature_enforcements'])
            if show_details:
                # Show detailed feature names (current behavior)
                feature_names = []
                for enforcement in sorted(user_detail['feature_enforcements']):
                    # Convert enforcement name to human readable
                    readable_name = enforcement.replace('allow_', '').replace('_', ' ').title()
                    # Special handling for some names
                    readable_name = readable_name.replace('Pam', 'PAM').replace('Rbi', 'RBI').replace('Kcm', 'KCM')
                    feature_names.append(readable_name)
                features_str = ', '.join(feature_names)
            else:
                # Show just the count (new default behavior)
                features_str = f'{feature_count} feature(s)'
            
            row = [
                user_detail['username'],
                user_detail['name'],
                node_path,
                user_detail['status'],
                direct_roles,
                team_roles, 
                features_str
            ]
            
            # Only add feature count when not showing details (to avoid redundancy)
            if not show_details:
                row.append(feature_count)
            table.append(row)

        # Add summary information
        total_feature_users = len(feature_user_details)
        title = f'{feature.upper()} License Consumption Report - {total_feature_users} Users Found'
        
        if node_filter:
            title += f' (Node: {node_filter})'
        
        if include_teams:
            title += ' (Including Team Assignments)'

        return base.dump_report_data(table, headers, title=title, fmt=output_fmt, filename=output)

    def _generate_all_features_report(self, params, feature_enforcements_map, node_filter, include_teams, show_details, output_fmt, output):
        """Generate a consolidated report showing license consumption across all features"""
        
        # Collect user data for all features
        all_users = {}  # user_id -> {user_info, feature_data}
        feature_types = [f for f in feature_enforcements_map.keys()]
        
        for feature_type in feature_types:
            feature_config = feature_enforcements_map[feature_type]
            addon_name = feature_config.get('addon_name')
            
            # Check if addon is enabled
            if addon_name and not is_addon_enabled(params, addon_name):
                logging.info(f'{feature_type.upper()} addon is not enabled - skipping')
                continue
                
            # Get users for this feature (reuse existing logic)
            feature_users = self._get_feature_users(params, feature_config, node_filter, include_teams)
            
            for user_id, user_detail in feature_users.items():
                if user_id not in all_users:
                    all_users[user_id] = {
                        'user_info': {
                            'user_id': user_detail['user_id'],
                            'username': user_detail['username'],
                            'name': user_detail['name'],
                            'node_id': user_detail['node_id'],
                            'status': user_detail['status'],
                            'roles': user_detail['roles'],
                            'teams': user_detail['teams']
                        },
                        'features': {}
                    }
                
                # Store feature-specific data
                all_users[user_id]['features'][feature_type] = {
                    'count': len(user_detail['feature_enforcements']),
                    'enforcements': user_detail['feature_enforcements'] if show_details else None
                }

        # Generate consolidated report
        headers = ['Username', 'Display Name', 'Node', 'Status', 'Direct Roles', 'Team Roles']
        
        # Add feature columns
        for feature_type in sorted(feature_types):
            feature_name = feature_type.replace('-', ' ').title()
            if show_details:
                headers.append(f'{feature_name} Features')
            # Only add count columns when not showing details (to avoid redundancy)
            if not show_details:
                headers.append(f'{feature_name} Count')
        
        # Add total column (always useful in consolidated view)
        headers.append('Total Features')
        
        if output_fmt == 'json':
            headers = [h.lower().replace(' ', '_') for h in headers]

        table = []
        for user_data in sorted(all_users.values(), key=lambda x: x['user_info']['username'].lower()):
            user_info = user_data['user_info']
            node_path = self.get_node_path(params, user_info['node_id']) if user_info['node_id'] > 0 else ''
            
            direct_roles = ', '.join(user_info['roles']) if user_info['roles'] else ''
            team_roles = ', '.join(user_info['teams']) if user_info['teams'] else ''
            
            row = [
                user_info['username'],
                user_info['name'],
                node_path,
                user_info['status'],
                direct_roles,
                team_roles
            ]
            
            total_features = 0
            for feature_type in sorted(feature_types):
                feature_data = user_data['features'].get(feature_type, {'count': 0, 'enforcements': set()})
                feature_count = feature_data['count']
                total_features += feature_count
                
                if show_details and feature_data['enforcements']:
                    # Show detailed feature names
                    feature_names = []
                    for enforcement in sorted(feature_data['enforcements']):
                        readable_name = enforcement.replace('allow_', '').replace('_', ' ').title()
                        readable_name = readable_name.replace('Pam', 'PAM').replace('Rbi', 'RBI').replace('Kcm', 'KCM')
                        feature_names.append(readable_name)
                    features_str = ', '.join(feature_names) if feature_names else ''
                    row.append(features_str)
                
                # Only add count columns when not showing details (to avoid redundancy) 
                if not show_details:
                    row.append(feature_count)
            
            row.append(total_features)
            
            # Only include users who have at least one feature
            if total_features > 0:
                table.append(row)

        # Generate title
        total_users = len(table)
        title = f'All Features License Consumption Report - {total_users} Users Found'
        
        if node_filter:
            title += f' (Node: {node_filter})'
        
        if include_teams:
            title += ' (Including Team Assignments)'

        return base.dump_report_data(table, headers, title=title, fmt=output_fmt, filename=output)
    
    def _get_feature_users(self, params, feature_config, node_filter, include_teams):
        """Extract the user collection logic for reuse in all-features report"""
        feature_enforcements = feature_config['enforcements']
        
        # Build lookup dictionaries
        users_by_id = {user['enterprise_user_id']: user for user in params.enterprise.get('users', [])}
        roles_by_id = {role['role_id']: role for role in params.enterprise.get('roles', [])}
        role_enforcements = {re['role_id']: re['enforcements'] for re in params.enterprise.get('role_enforcements', [])}
        
        # Filter by node if specified
        filtered_user_ids = set()
        if node_filter:
            target_node_id = None
            if node_filter.isdigit():
                target_node_id = int(node_filter)
            else:
                # Look up node by name
                for node in params.enterprise.get('nodes', []):
                    if node['data'].get('displayname', '').lower() == node_filter.lower():
                        target_node_id = node['node_id']
                        break
            
            if target_node_id is not None:
                # Get all users in this node and its descendants
                def get_descendant_nodes(node_id):
                    descendants = {node_id}
                    for node in params.enterprise.get('nodes', []):
                        if node.get('parent_id') == node_id:
                            descendants.update(get_descendant_nodes(node['node_id']))
                    return descendants
                
                target_nodes = get_descendant_nodes(target_node_id)
                filtered_user_ids = {user['enterprise_user_id'] for user in params.enterprise.get('users', [])
                                   if user.get('node_id') in target_nodes}
            else:
                logging.warning(f'Node "{node_filter}" not found')
                filtered_user_ids = set()

        # Find feature roles (roles with any feature enforcement enabled)
        feature_roles = set()
        for role_id, enforcements in role_enforcements.items():
            if any(enforcement.lower() in feature_enforcements for enforcement in enforcements.keys()):
                feature_roles.add(role_id)

        # Collect feature users
        feature_user_details = {}

        # Users directly assigned to feature roles
        for role_user in params.enterprise.get('role_users', []):
            role_id = role_user['role_id']
            user_id = role_user['enterprise_user_id']
            
            if role_id in feature_roles:
                if filtered_user_ids and user_id not in filtered_user_ids:
                    continue
                    
                if user_id not in feature_user_details:
                    user = users_by_id.get(user_id, {})
                    feature_user_details[user_id] = {
                        'user_id': user_id,
                        'username': user.get('username', ''),
                        'name': user.get('data', {}).get('displayname', ''),
                        'node_id': user.get('node_id', 0),
                        'status': user.get('status', ''),
                        'roles': [],
                        'teams': [],
                        'feature_enforcements': set()
                    }
                
                role = roles_by_id.get(role_id, {})
                role_name = role.get('data', {}).get('displayname', f'Role {role_id}')
                feature_user_details[user_id]['roles'].append(role_name)
                
                # Add enforcements from this role
                role_enf = role_enforcements.get(role_id, {})
                for enforcement in role_enf.keys():
                    if enforcement.lower() in feature_enforcements:
                        feature_user_details[user_id]['feature_enforcements'].add(enforcement.lower())

        # Users assigned to feature roles through teams
        if include_teams:
            teams_by_uid = {team['team_uid']: team for team in params.enterprise.get('teams', [])}
            
            # Get roles assigned to teams
            for role_team in params.enterprise.get('role_teams', []):
                role_id = role_team['role_id'] 
                team_uid = role_team['team_uid']
                
                if role_id in feature_roles:
                    # Get users in this team
                    for team_user in params.enterprise.get('team_users', []):
                        if team_user['team_uid'] == team_uid:
                            user_id = team_user['enterprise_user_id']
                            
                            if filtered_user_ids and user_id not in filtered_user_ids:
                                continue
                                
                            if user_id not in feature_user_details:
                                user = users_by_id.get(user_id, {})
                                feature_user_details[user_id] = {
                                    'user_id': user_id,
                                    'username': user.get('username', ''),
                                    'name': user.get('data', {}).get('displayname', ''),
                                    'node_id': user.get('node_id', 0),
                                    'status': user.get('status', ''),
                                    'roles': [],
                                    'teams': [],
                                    'feature_enforcements': set()
                                }
                            
                            team = teams_by_uid.get(team_uid, {})
                            team_name = team.get('name', f'Team {team_uid}')
                            role = roles_by_id.get(role_id, {})
                            role_name = role.get('data', {}).get('displayname', f'Role {role_id}')
                            
                            team_role_name = f'{team_name} -> {role_name}'
                            if team_role_name not in feature_user_details[user_id]['teams']:
                                feature_user_details[user_id]['teams'].append(team_role_name)
                            
                            # Add enforcements from this role
                            role_enf = role_enforcements.get(role_id, {})
                            for enforcement in role_enf.keys():
                                if enforcement.lower() in feature_enforcements:
                                    feature_user_details[user_id]['feature_enforcements'].add(enforcement.lower())

        return feature_user_details
