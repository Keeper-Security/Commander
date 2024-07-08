import argparse
import datetime
import logging

from . import enterprise_common, register
from ..sox.sox_types import RecordPermissions
from ..error import Error
from ..display import bcolors
from . import base


def register_commands(commands):
    commands['external-shares-report'] = ExternalSharesReportCommand()


def register_command_info(aliases, command_info):
    aliases['esr'] = 'external-shares-report'

    for p in [external_share_report_parser]:
        command_info[p.prog] = p.description


ext_shares_report_desc = 'Run an external shares report.'
external_share_report_parser = argparse.ArgumentParser(prog='external-shares-report', description=ext_shares_report_desc,
                                                       parents=[base.report_output_parser])
external_share_report_parser.add_argument('-a', '--action', action='store', choices=['remove', 'none'], default='none',
                                          help='action to perform on external shares, \'none\' if omitted')
external_share_report_parser.add_argument('-t', '--share-type', action='store', choices=['direct', 'shared-folder', 'all'],
                                          default='all', help='filter report by share type, \'all\' if omitted')
# external_share_report_parser.add_argument('-e', '--email', action='store', help='filter report by share-recipient email')
external_share_report_parser.add_argument('-f', '--force', action='store_true', help='apply action w/o confirmation')
external_share_report_parser.add_argument('-r', '--refresh-data', action='store_true', help='retrieve fresh data')


class ExternalSharesReportCommand(enterprise_common.EnterpriseCommand):
    def __init__(self):
        super(ExternalSharesReportCommand, self).__init__()
        self.sox_data = None

    def get_sox_data(self, params, refresh_data):
        if not self.sox_data or refresh_data:
            from keepercommander.sox import get_compliance_data
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
