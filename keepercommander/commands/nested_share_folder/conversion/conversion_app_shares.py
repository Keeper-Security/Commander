"""KSM application-share discovery and migration for folder conversion."""

from .... import nested_share_folder as _nsf
from .... import utils
from ....error import CommandError
from ....nested_share_folder.common import NSF_APP_INFO_BATCH_SIZE
from ..helpers import command_error_handler


class FolderApplicationShareMigration:
    """Read and recreate KSM application shares for converted content."""

    @staticmethod
    def _read_applications(params):
        """Read visible KSM app shares in batches for Classic folder/record migration."""
        from ...ksm import KSMCommand

        candidates = {}
        for uid, record in (getattr(params, 'record_cache', {}) or {}).items():
            app = KSMCommand._app_record_from_cache_entry(record)
            if app:
                app = dict(app)
                app.setdefault('record_uid', uid)
                candidates[uid] = app

        applications = {}
        for app_uid, app_record in candidates.items():
            applications[app_uid] = {
                'key': app_record.get('record_key_unencrypted'),
                'shares': [],
            }

        app_uids = list(applications)
        for start in range(0, len(app_uids), NSF_APP_INFO_BATCH_SIZE):
            batch = app_uids[start:start + NSF_APP_INFO_BATCH_SIZE]
            try:
                app_info_list = KSMCommand.get_app_info_batch(params, batch)
            except Exception as exc:
                batch_label = ', '.join(batch[:5])
                if len(batch) > 5:
                    batch_label += f', ... ({len(batch)} applications)'
                raise CommandError(
                    'nsf-convert-folder',
                    f'Could not inspect KSM application batch [{batch_label}]: {exc}')

            returned_app_uids = set()
            for app_info in app_info_list or []:
                app_uid = utils.base64_url_encode(app_info.appRecordUid)
                returned_app_uids.add(app_uid)
                app = applications.get(app_uid)
                if app is None:
                    continue
                for share in app_info.shares or []:
                    app['shares'].append({
                        'uid': utils.base64_url_encode(share.secretUid),
                        'type': int(share.shareType),
                        'editable': bool(share.editable),
                    })
            missing_app_uids = set(batch) - returned_app_uids
            if missing_app_uids:
                missing_apps = ', '.join(sorted(missing_app_uids)[:5])
                raise CommandError(
                    'nsf-convert-folder',
                    f'No application details were returned for KSM application(s): '
                    f'{missing_apps}')
        return applications

    @staticmethod
    def _collect_app_shares(applications, scopes, record_uids):
        """Select KSM shares that target the source folders or records."""
        from ....proto import APIRequest_pb2

        folder_type = APIRequest_pb2.ApplicationShareType.Value('SHARE_TYPE_FOLDER')
        record_type = APIRequest_pb2.ApplicationShareType.Value('SHARE_TYPE_RECORD')
        folder_shares = {}
        record_shares = {}
        scopes = {uid for uid in scopes if uid}
        record_uids = set(record_uids)
        for app_uid, app in applications.items():
            for share in app['shares']:
                if share['type'] == folder_type and share['uid'] in scopes:
                    folder_shares.setdefault(share['uid'], []).append({
                        'app_uid': app_uid, 'editable': share['editable'],
                    })
                elif share['type'] == record_type and share['uid'] in record_uids:
                    record_shares.setdefault(share['uid'], []).append({
                        'app_uid': app_uid, 'editable': share['editable'],
                    })
        return folder_shares, record_shares

    @staticmethod
    def _grant_folder_app_shares(params, folder_app_shares, scope_by_folder,
                                 target_uids, applications):
        """Recreate folder-level KSM application shares on NSF folders."""
        from ....proto import APIRequest_pb2

        folder_share_type = APIRequest_pb2.SHARE_TYPE_FOLDER
        for source_uid, scope_uid in scope_by_folder.items():
            if not scope_uid:
                continue
            for share in folder_app_shares.get(scope_uid) or []:
                app = applications[share['app_uid']]
                target_uid = target_uids[source_uid]
                if any(
                        existing.get('uid') == target_uid and
                        existing.get('type') == folder_share_type and
                        bool(existing.get('editable')) == bool(share['editable'])
                        for existing in app['shares']):
                    continue
                with command_error_handler('nsf-convert-folder'):
                    result = _nsf.grant_folder_access_to_application_v3(
                        params, target_uid, share['app_uid'],
                        app['key'], is_editable=share['editable'])
                    if not result.get('success'):
                        raise CommandError(
                            'nsf-convert-folder',
                            f"Could not preserve KSM application access on "
                            f"{target_uid}: {result.get('message')}")
                    app['shares'].append({
                        'uid': target_uid,
                        'type': folder_share_type,
                        'editable': bool(share['editable']),
                    })

    @staticmethod
    def _grant_record_app_shares(params, record_app_shares, converted_uids, applications):
        """Recreate KSM application shares for converted NSF records."""
        if not record_app_shares:
            return []

        from ...ksm import KSMCommand
        from ....proto import APIRequest_pb2

        targets = [
            (record_uid, share)
            for record_uid in converted_uids
            for share in record_app_shares.get(record_uid) or []
        ]
        app_uids = list(dict.fromkeys(share['app_uid'] for _, share in targets))
        record_share_type = APIRequest_pb2.SHARE_TYPE_RECORD
        share_state = {app_uid: set() for app_uid in app_uids}
        lookup_errors = {}
        for start in range(0, len(app_uids), NSF_APP_INFO_BATCH_SIZE):
            batch = app_uids[start:start + NSF_APP_INFO_BATCH_SIZE]
            try:
                app_info_list = KSMCommand.get_app_info_batch(params, batch)
            except Exception as exc:
                lookup_errors.update({app_uid: exc for app_uid in batch})
                continue
            returned_app_uids = set()
            for app_info in app_info_list or []:
                app_uid = utils.base64_url_encode(app_info.appRecordUid)
                if app_uid not in share_state:
                    continue
                returned_app_uids.add(app_uid)
                share_state[app_uid].update(
                    (utils.base64_url_encode(item.secretUid), bool(item.editable))
                    for item in (app_info.shares or [])
                    if item.shareType == record_share_type)
            for app_uid in set(batch) - returned_app_uids:
                lookup_errors[app_uid] = 'no application details were returned'

        failures = []
        for record_uid, share in targets:
            app_uid = share['app_uid']
            if app_uid in lookup_errors:
                failures.append(
                    f'{record_uid} / application {app_uid}: {lookup_errors[app_uid]}')
                continue
            app = applications.get(app_uid) or {}
            app_key = app.get('key')
            if not app_key:
                failures.append(
                    f'{record_uid} / application {app_uid}: application key is unavailable')
                continue

            existing = share_state[app_uid]
            desired_share = (record_uid, share['editable'])
            if desired_share in existing:
                continue

            try:
                if any(uid == record_uid for uid, _ in existing):
                    result = _nsf.update_record_share_to_application_v3(
                        params, record_uid, app_uid, app_key,
                        is_editable=share['editable'])
                else:
                    result = _nsf.share_record_to_application_v3(
                        params, record_uid, app_uid, app_key,
                        is_editable=share['editable'])
            except Exception as exc:
                failures.append(f'{record_uid} / application {app_uid}: {exc}')
                continue
            if result.get('success'):
                existing.difference_update({
                    current_share for current_share in existing
                    if current_share[0] == record_uid
                })
                existing.add(desired_share)
            else:
                failures.append(
                    f'{record_uid} / application {app_uid}: '
                    f'{result.get("message") or result.get("status") or "share failed"}')
        return failures

