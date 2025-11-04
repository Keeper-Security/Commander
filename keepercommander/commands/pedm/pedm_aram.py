import argparse
import datetime
import json
import re
from dataclasses import dataclass
from typing import Any, List, Dict, Optional, Callable, Union, Set

from prompt_toolkit import print_formatted_text, HTML

# from keepersdk.authentication import keeper_auth
# from keepersdk.enterprise import enterprise_types
from ... import utils, crypto, api
from ...proto import pedm_pb2, NotificationCenter_pb2
from .. import base
from . import pedm_admin
from ..helpers import report_utils
from ...params import KeeperParams
from ...pedm import admin_plugin, admin_storage


class PedmReportCommand(base.GroupCommandNew):
    def __init__(self):
        super().__init__('Display PEDM  reports')
        self.register_command_new(PedmPolicyUsageReportCommand(), 'policy-usage', 'pu')
        self.register_command_new(PedmColumnReportCommand(), 'column', 'c')
        self.register_command_new(PedmEventReportCommand(), 'event', 'e')
        self.register_command_new(PedmEventSummaryReportCommand(), 'summary', 's')


@dataclass
class FieldInfo:
    name: str
    type: str
    protection: str

in_pattern = re.compile(r"\s*in\s*\(\s*(.*)\s*\)", re.IGNORECASE)
between_pattern = re.compile(r"\s*between\s+(\S*)\s+and\s+(.*)", re.IGNORECASE)
predefined_date_filters = {'today', 'yesterday', 'last_7_days', 'last_30_days', 'month_to_date', 'last_month',
                           'year_to_date', 'last_year'}

display_fields = ('deployment_uid', 'admin_uid', 'agent_uid', 'agent_status', 'agent_version',
                  'session_uid', 'session_type', 'policy_uid', 'policy_version',
                  'request_uid', 'evaluation_status', 'request_status', 'plugin_uid', 'plugin_version', 'update_status',
                  'user_info', 'target_info', 'reason')

class AuditMixin:
    syslog_templates: Optional[Dict[str, str]] = None
    field_info: Optional[Dict[str, FieldInfo]] = None
    user_lookup: Optional[Dict[int, str]] = None

    @staticmethod
    def load_audit_metadata(params) -> None:
        if AuditMixin.syslog_templates is None:
            rq = {
                'fields': ['audit_event_type', 'report_field']
            }
            rs = api.execute_router_json(params, 'pedm/get_audit_event_dimensions', rq)
            assert rs is not None
            AuditMixin.syslog_templates = {}
            AuditMixin.field_info = {}
            name: Optional[str]
            for et in rs['audit_event_type']:
                name = et.get('name')
                syslog = et.get('syslog')
                if name and syslog:
                    AuditMixin.syslog_templates[name] = syslog

            for rf in rs['report_field']:
                name = rf.get('name') or ''
                field_type = rf.get('type') or ''
                protection = rf.get('protection') or ''
                AuditMixin.field_info[name] = FieldInfo(name=name, type=field_type, protection=protection)

        if AuditMixin.user_lookup is None:
            AuditMixin.user_lookup = {}
            for u in params.enterprise['users']:
                AuditMixin.user_lookup[u['enterprise_user_id']] = u['username']

    @staticmethod
    def convert_date_filter(value: Any) -> Union[int, str]:
        if isinstance(value, datetime.datetime):
            value = value.timestamp()
        elif isinstance(value, datetime.date):
            dt = datetime.datetime.combine(value, datetime.datetime.min.time())
            value = dt.timestamp()
        elif isinstance(value, (int, float)):
            value = float(value)
        elif isinstance(value, str):
            if value in {predefined_date_filters}:
                return value
            if len(value) <= 10:
                value = datetime.datetime.strptime(value, '%Y-%m-%d')
            else:
                value = datetime.datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ')
            value = value.timestamp()
        return int(value)

    @staticmethod
    def convert_str_or_int_filter(value: Any) -> Union[str, int]:
        if isinstance(value, str):
            if value.isdigit():
                return int(value)
            else:
                return value
        elif isinstance(value, int):
            return value
        return str(value)

    @staticmethod
    def get_filter(value: str, convert: Callable[[Any], Any]) -> Any:
        filter_value = value.strip()
        bet = between_pattern.match(filter_value)
        if bet is not None:
            dt1, dt2, *_ = bet.groups()
            dt1 = convert(dt1)
            dt2 = convert(dt2)
            return {'min': dt1, 'max': dt2}

        inp = in_pattern.match(filter_value)
        if inp is not None:
            arr = []
            for v in inp.groups()[0].split(','):
                arr.append(convert(v.strip()))
            return arr

        for prefix in ['>=', '<=', '>', '<', '=']:
            if filter_value.startswith(prefix):
                value = convert(filter_value[len(prefix):].strip())
                if prefix == '>=':
                    return {'min': value}
                if prefix == '<=':
                    return {'max': value}
                if prefix == '>':
                    return {'min': value, 'exclude_min': True}
                if prefix == '<':
                    return {'max': value, 'exclude_max': True}
                return value

        return convert(filter_value)

    @staticmethod
    def get_field_value(field: str, value: Any, *, report_type: str = 'raw') -> Any:
        if field in ('event_time', 'first_date', 'last_date'):
            if isinstance(value, str):
                return value
            if isinstance(value, (int, float)):
                value = int(value)
                dt = datetime.datetime.fromtimestamp(value, tz=datetime.timezone.utc)
                # dt = dt.replace(tzinfo=datetime.timezone.utc).astimezone(tz=None)
                if field == 'event_time':
                    if report_type in ('day', 'week'):
                        return dt.date()
                    if report_type == 'month':
                        return dt.strftime('%B, %Y')
                    if report_type == 'hour':
                        return dt.strftime('%Y-%m-%d @%H:00')
                return dt
        return value

    @staticmethod
    def get_enterprise_user_id(user_uid: str) -> Optional[int]:
        try:
            user_bytes = utils.base64_url_decode(user_uid)
            if len(user_bytes) == 16:
                return int.from_bytes(user_bytes[8:], byteorder='big')
        except:
            pass
        return None

    @staticmethod
    def get_enterprise_user_email(user_id: int) -> Optional[str]:
        if AuditMixin.user_lookup:
            return AuditMixin.user_lookup.get(user_id)
        return None


    @staticmethod
    def get_hash_fields() -> Optional[List[str]]:
        if not AuditMixin.field_info:
            return None
        return [key for key, value in AuditMixin.field_info.items() if value.protection == 'hash']

    """
    @staticmethod
    def replace_hash_fields() -> Optional[List[str]]:
        if not isinstance(events, list):
            return
        hash_fields = {key for key, value in AuditMixin.field_info.items() if value.protection == 'hash'}
        values: Set[bytes] = set()
        for event in events:
            if isinstance(event, dict):
                for field in hash_fields:
                    v = event.get(field)
                    if isinstance(v, str):
                        if v not in AuditMixin.hash_lookup:
                            try:
                                uid = utils.base64_url_decode(v)
                                if uid and len(uid) == 16:
                                    values.add(uid)
                            except:
                                pass
        if values:
            all_values = list(values)
            while len(all_values) > 0:
                chunk = all_values[:1000]
                all_values = all_values[1000:]
                rq = pedm_pb2.AuditCollectionRequest()
                rq.valueUid.extend(chunk)
                rs: Optional[pedm_pb2.AuditCollectionResponse] = (
                    api.execute_router(params, 'pedm/get_audit_collections', rq, rs_type=pedm_pb2.AuditCollectionResponse))
                if rs:
                    for cv in rs.values:
                        try:
                            v = utils.base64_url_encode(cv.valueUid)
                            decrypted_data = crypto.decrypt_ec(cv.encryptedData, ec_key)
                            AuditMixin.hash_lookup[v] = cv
                        except:
                            pass

        for event in events:
            if isinstance(event, dict):
                for field in hash_fields:
                    v = event.get(field)
                    if isinstance(v, str):
                        cv = AuditMixin.hash_lookup.get(v)
    """

audit_column_description = '''
<b>Audit Column Report Command</b>
Returns unique values for audit report fields.

To get a list of all report fields:
Commander> <ansigreen>pedm report column report_field</ansigreen>

To get a list of all report events:
Commander> <ansigreen>pedm report column audit_event_type</ansigreen>
'''

class PedmColumnReportCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='report column', description='Run column data audit reports',
                                         parents=[base.report_output_parser])
        parser.add_argument('--syntax-help', dest='syntax_help', action='store_true', help='display help')
        parser.add_argument('column', nargs='?', help='Audit report column')

        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        if kwargs.get("syntax_help") is True:
            print_formatted_text(HTML(audit_column_description))
            return None

        AuditMixin.load_audit_metadata(context)
        assert AuditMixin.field_info is not None

        enterprise = context.enterprise
        tree_key = enterprise['unencrypted_tree_key']
        encrypted_ec_private_key = utils.base64_url_decode(enterprise['keys']['ecc_encrypted_private_key'])
        ec_private_key = crypto.load_ec_private_key(crypto.decrypt_aes_v2(encrypted_ec_private_key, tree_key))

        column = kwargs.get('column')
        if not (isinstance(column, str) and len(column) > 0):
            raise base.CommandError('"column" must be a non-empty string')

        f_info: Optional[FieldInfo] = None
        if column != "report_field":
            f_info = AuditMixin.field_info.get(column)
            if not f_info:
                raise base.CommandError(f'column "{column}" is not a known audit report column')
            if f_info.type != 'group':
                raise base.CommandError(f'column "{column}" is not a known audit report grouping column')
        rq = {
            'fields': [column]
        }
        rs = api.execute_router_json(context, 'pedm/get_audit_event_dimensions', rq)
        assert rs is not None
        rows: List[List[Any]] = []
        headers: List[str]
        if column == 'report_field':
            headers = ['name', 'type', 'protection']
        elif column == 'audit_event_type':
            headers = ['name', 'id', 'is_client', 'syslog']
        else:
            headers = ['value']

        dimension = rs.get(column)
        if not isinstance(dimension, list):
            raise base.CommandError('Server response is not supported')
        for d in dimension:
            if isinstance(d, dict):
                row = []
                for header in headers:
                    row.append(d.pop(header, None))
                if len(d) > 0:
                    for k, v in d.items():
                        headers.append(k)
                        row.append(v)
                rows.append(row)
        if f_info is not None and f_info.protection == 'hash':
            headers.insert(0, 'uid')
            uids = [x[0] for x in rows]
            uids = uids[:500]
            coll_rq = pedm_pb2.AuditCollectionRequest()
            # coll_rq.collectionName.append(f_info.name)
            coll_rq.valueUid.extend([utils.base64_url_decode(x) for x in uids])
            coll_rs =  api.execute_router(context,
                'pedm/get_audit_collections', coll_rq, rs_type=pedm_pb2.AuditCollectionResponse)
            value_lookup: Dict[str, str] = {}
            assert coll_rs is not None

            for v in coll_rs.values:
                value_uid = utils.base64_url_encode(v.valueUid)
                try:
                    decrypted_data = crypto.decrypt_ec(v.encryptedData, ec_private_key)
                    value_lookup[value_uid] = decrypted_data.decode('utf-8', 'ignore')
                except:
                    pass
            for row in rows:
                value = value_lookup.get(row[0])
                if value:
                    row.append(value)

        if kwargs.get('format') != 'json':
            headers = [report_utils.field_to_title(x) for x in headers]

        return report_utils.dump_report_data(rows, headers, fmt=kwargs.get('format'), filename=kwargs.get('output'),
                                             row_number=True, sort_by=0, column_width=80)

audit_report_description = '''
<b>Audit Event Report Command</b>

To get a list of event fields run the following command:
Commander> <ansigreen>pedm report column report_field</ansigreen>

Any field that has type <u>group</u> or <u>filter</u> can be used as filter

Filter syntax: <b>[FIELD_NAME]=[CRITERIA]</b>
where criteria is
1. single value: Example: "agent_uid=NJvK0I5RpuF0UFMwRKY_Dw"
2. list of values: Example: "agent_uid=IN(NJvK0I5RpuF0UFMwRKY_Dw, VYLhwqhRvhIpma9e1HoDFw)"
3. range value: Example: "event_time=BETWEEN 2024-01-01 AND 2024-02-01"
Predefined date range values: today, yesterday, last_7_days, last_30_days, month_to_date, last_month, year_to_date, last_year
<ansigreen>event_time=last_month</ansigreen>
'''
class PedmEventReportCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='report event', description='Run audit event reports',
                                         parents=[base.report_output_parser])
        parser.add_argument('--syntax-help', dest='syntax_help', action='store_true', help='display help')
        parser.add_argument('--report-format', dest='report_format', action='store', default='message',
                            choices=['message', 'fields'], help='output format (raw reports only)')
        parser.add_argument('--timezone', dest='timezone', action='store', help='return results for specific timezone')
        parser.add_argument('--limit', dest='limit', type=int, action='store',
                            help='maximum number of returned rows (1000 max)')
        parser.add_argument('--order', dest='order', action='store', choices=['desc', 'asc'], help='sort order')
        parser.add_argument('filter', nargs='*', help='Report filters')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        if kwargs.get("syntax_help") is True:
            print_formatted_text(HTML(audit_report_description))
            return

        plugin = admin_plugin.get_pedm_plugin(context)

        tree_key = context.enterprise['unencrypted_tree_key']
        keys = context.enterprise['keys']
        ecc_private_key_data = utils.base64_url_decode(keys['ecc_encrypted_private_key'])
        ecc_private_key_data = crypto.decrypt_aes_v2(ecc_private_key_data, tree_key)
        ec_private_key = crypto.load_ec_private_key(ecc_private_key_data)

        AuditMixin.load_audit_metadata(context)
        hash_fields = AuditMixin.get_hash_fields()

        assert AuditMixin.field_info is not None
        assert AuditMixin.syslog_templates is not None

        filters = kwargs.get('filter')
        if filters and isinstance(filters, str):
            filters = [filters]
        report_filter: Dict[str, Any] = {}
        for filter_arg in filters:
            field, sep, criteria = filter_arg.partition('=')
            if not sep:
                raise base.CommandError(f'Filter syntax error: {filter_arg}')
            info = AuditMixin.field_info.get(field)
            if not info:
                raise base.CommandError(f'field "{field}" is not a known audit report column')
            if info.type not in ('group', 'filter'):
                raise base.CommandError(f'column "{field}" is not a known audit report filter column')
            convert: Callable[[Any], Any]
            if filter_arg == 'event_time':
                convert = AuditMixin.convert_date_filter
            else:
                convert = AuditMixin.convert_str_or_int_filter
            report_filter[field] = AuditMixin.get_filter(criteria, convert)
        rq: Dict[str, Any] = {
            'timezone': datetime.datetime.now().astimezone().tzname()
        }
        if len(report_filter) > 0:
            rq['filter'] = report_filter
        limit = kwargs.get('limit')
        if limit is not None:
            rq['limit'] = limit
        order = kwargs.get('order')
        if order:
            rq['order'] = order
        rs = api.execute_router_json(context, 'pedm/get_audit_events', rq)
        assert rs is not None
        events = rs.get('audit_event_overview_report_rows')
        assert isinstance(events, list)

        if hash_fields:
            field_values: Set[str] = set()
            for event in events:
                for field in hash_fields:
                    v = event.get(field)
                    if isinstance(v, str):
                        try:
                            uid = utils.base64_url_decode(v)
                            if uid and len(uid) == 16:
                                field_values.add(v)
                        except:
                            pass
            if len(field_values) > 0:
                all_values = [x.value_uid for x in plugin.storage.audit_event_values.get_all_entities()]
                field_values.difference_update(all_values)
            if len(field_values) > 0:
                uids = [utils.base64_url_decode(x) for x in field_values]
                while len(uids) > 0:
                    chunk = uids[:1000]
                    uids = uids[1000:]
                    v_rq = pedm_pb2.AuditCollectionRequest()
                    v_rq.valueUid.extend(chunk)
                    rs: Optional[pedm_pb2.AuditCollectionResponse] = (
                        api.execute_router(context, 'pedm/get_audit_collections', v_rq, rs_type=pedm_pb2.AuditCollectionResponse))
                    if rs:
                        to_add: List[admin_storage.PedmAuditEventValue] = []
                        for cv in rs.values:
                            try:
                                arv = admin_storage.PedmAuditEventValue(
                                    value_uid=utils.base64_url_encode(cv.valueUid), field_name=cv.collectionName,
                                    encrypted_data=cv.encryptedData, created=cv.created)
                                to_add.append(arv)
                            except:
                                pass
                        if to_add:
                            plugin.storage.audit_event_values.put_entities(to_add)

        value_lookup: Dict[str, str] = {}
        for event in events:
            if 'admin_uid' in event:
                user_id = AuditMixin.get_enterprise_user_id(event['admin_uid'])
                if isinstance(user_id, int):
                    username = AuditMixin.get_enterprise_user_email(user_id)
                    if isinstance(username, str):
                        event['admin_uid'] = username
            if 'request_status' in event:
                status = event['request_status']
                status_info = None
                if isinstance(status, int):
                    if status == NotificationCenter_pb2.NotificationApprovalStatus.NAS_APPROVED:
                        status_info = '"Approved"'
                    elif status == NotificationCenter_pb2.NotificationApprovalStatus.NAS_DENIED:
                        status_info = '"Denied"'
                if status_info:
                    event['request_status'] = status_info
            if 'evaluation_status' in event:
                status = event['evaluation_status']
                status_info = None
                if isinstance(status, int):
                    if status == 1:
                        status_info = '"Allowed"'
                    elif status == 2:
                        status_info = '"Denied"'
                    elif status == 3:
                        status_info = '"Denied - Failed MFA"'
                    elif status == 4:
                        status_info = '"Denied - Failed Justification"'
                if status_info:
                    event['evaluation_status'] = status_info
            if hash_fields:
                for hash_field in hash_fields:
                    if hash_field in event:
                        uid = event.get(hash_field)
                        if uid:
                            if uid not in value_lookup:
                                hash_value = ''
                                cv = plugin.storage.audit_event_values.get_entity(uid)
                                if cv:
                                    try:
                                        hash_value = crypto.decrypt_ec(cv.encrypted_data, ec_private_key).decode('utf-8')
                                    except:
                                        pass
                                value_lookup[uid] = hash_value
                            hash_value = value_lookup.get(uid)
                            if hash_value:
                                event[hash_field] = f'{uid} ({hash_value})'

            event_type = event.get('audit_event_type')
            if event_type == 'approval_request_status_changed':
                if 'admin_uid' not in event and 'admin_info' in event:
                    event['admin_uid'] = event['admin_info']

        if kwargs.get('format') == 'json':
            return json.dumps(events, indent=2)
        
        rows: List[List[Any]] = []
        headers: List[str] = []
        if kwargs.get('report_format') == 'message':
            headers.extend(('event_time', 'audit_event_type', 'message'))
            for event in events:
                event_type = event.get('audit_event_type')
                if not event_type:
                    rows.append([None, 'Event is missing "event_type" field'])
                    continue
                syslog = AuditMixin.syslog_templates.get(event_type)
                if not syslog:
                    rows.append([None, f'Syslog message is missing for event "{event_type}"'])
                    continue
                while True:
                    pattern = re.search(r'\${(\w+)}', syslog)
                    if pattern:
                        token = pattern[1]
                        value = event.get(token)
                        val = AuditMixin.get_field_value(token, value, report_type='raw')
                        if val is None:
                            val = '<missing>'
                        sp = pattern.span()
                        syslog = syslog[:sp[0]] + str(val) + syslog[sp[1]:]
                    else:
                        break
                event_time = event.get('event_time')
                e_time = AuditMixin.get_field_value('event_time', event_time, report_type='raw')
                rows.append([e_time, event_type, syslog])
        else:
            all_fields = set()
            if isinstance(events, list):
                for event in events:
                    all_fields.update(event.keys())
            headers = ['event_time', 'audit_event_type']
            headers.extend((x for x in display_fields if x in all_fields))
            for event in events:
                rows.append([AuditMixin.get_field_value(x, event.get(x)) for x in headers])

            headers = [report_utils.field_to_title(x) for x in headers]

        return report_utils.dump_report_data(rows, headers, fmt=kwargs.get('format'), filename=kwargs.get('output'),
                                             row_number=True)


audit_summary_report_description = '''
Audit Summary Report Command Syntax Description:

To get a list of event fields run the following command:
My Vault>  pedm report column report_field

Any field that has type "group" can be used as grouping column

Any field that has type "group" or "filter" can be used as filter

--group-by:             Defines break down report properties.

--aggregate:            Defines the aggregate value:
     occurrences        number of events. COUNT(*)
   first_created        starting date. MIN(event_time)
    last_created        ending date. MAX(event_time)

Filter syntax
<FIELD_NAME>=<CRITERIA>
where criteria is
1. single value: Example: "agent_uid=NJvK0I5RpuF0UFMwRKY_Dw"
2. list of values: Example: "agent_uid=IN(NJvK0I5RpuF0UFMwRKY_Dw, VYLhwqhRvhIpma9e1HoDFw)"
3. range value: Example: "event_time=BETWEEN 2024-01-01 AND 2024-02-01"
Predefined date range values: today, yesterday, last_7_days, last_30_days, month_to_date, last_month, year_to_date, last_year
"event_time=last_month"
'''

class PedmEventSummaryReportCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='report event', description='Run audit summary reports',
                                         parents=[base.report_output_parser])
        parser.add_argument('--syntax-help', dest='syntax_help', action='store_true', help='display help')
        parser.add_argument('--report-type', dest='report_type', action='store',
                            choices=['hour', 'day', 'month', 'span'], default='span', help='report type')
        parser.add_argument('--group-by', dest='group_by', action='append',
                            help='group by columns. (can be repeated).')
        parser.add_argument('--aggregate', dest='aggregate', action='append',
                            choices=['occurrences', 'first_date', 'last_date'],
                            help='aggregated value. (can be repeated).')
        parser.add_argument('--timezone', dest='timezone', action='store', help='return results for specific timezone')
        parser.add_argument('--limit', dest='limit', type=int, action='store',
                            help='maximum number of returned rows (2000 max)')
        parser.add_argument('--order', dest='order', action='store', choices=['desc', 'asc'], help='sort order')
        parser.add_argument('filter', nargs='*', help='Report filters')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        if kwargs.get("syntax_help") is True:
            return audit_summary_report_description

        AuditMixin.load_audit_metadata(context)
        assert AuditMixin.field_info is not None

        filters = kwargs.get('filter')
        if filters and isinstance(filters, str):
            filters = [filters]
        report_filter: Dict[str, Any] = {}
        for filter_arg in filters:
            field, sep, criteria = filter_arg.partition('=')
            if not sep:
                raise base.CommandError(f'Filter syntax error: {filter_arg}')
            info = AuditMixin.field_info.get(field)
            if not info:
                raise base.CommandError(f'field "{field}" is not a known audit report column')
            if info.type not in ('group', 'filter'):
                raise base.CommandError(f'column "{field}" is not a known audit report filter column')
            convert: Callable[[Any], Any]
            if filter_arg == 'event_time':
                convert = AuditMixin.convert_date_filter
            else:
                convert = AuditMixin.convert_str_or_int_filter
            report_filter[field] = AuditMixin.get_filter(criteria, convert)

        report_type: Optional[str] = kwargs.get('report_type')
        if not report_type:
            raise base.CommandError(f'"report-type" is a required argument')
        aggregate = kwargs.get('aggregate')
        if not aggregate:
            aggregate = ['occurrences']
        elif isinstance(aggregate, str):
            aggregate = [aggregate]

        rq: Dict[str, Any] = {
            'report_type': report_type,
            'aggregate': aggregate,
            'timezone': datetime.datetime.now().astimezone().tzname()
        }

        if len(report_filter) > 0:
            rq['filter'] = report_filter
        group_by = kwargs.get('group_by')
        if group_by:
            if isinstance(group_by, str):
                group_by = [group_by]
            rq['group_by'] = group_by

        limit = kwargs.get('limit') or 50
        rq['limit'] = limit
        order = kwargs.get('order') or 'desc'
        rq['order'] = order
        rs = api.execute_router_json(context, 'pedm/get_summary_audit_report', rq)
        assert rs is not None

        events = rs.get('audit_event_summary_report_rows')
        assert isinstance(events, list)

        if kwargs.get('format') == 'json':
            return json.dumps(events, indent=2)

        if not events:
            return

        headers = []
        if report_type != 'span':
            headers.append('event_time')
        headers.extend(aggregate)
        if group_by:
            headers.extend(group_by)
        rows: List[List[Any]] = []
        for event in events:
            rows.append([AuditMixin.get_field_value(x, event.get(x), report_type=report_type) for x in headers])

        headers = [report_utils.field_to_title(x) for x in headers]
        return report_utils.dump_report_data(
            rows, headers, fmt=kwargs.get('format'), filename=kwargs.get('output'), row_number=True)


class PedmPolicyUsageReportCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='report policy-usage', description='Run audit summary reports',
                                         parents=[base.report_output_parser])
        parser.add_argument('--summary', dest='summary', action='store_true', help='Agent count only')
        parser.add_argument('policy', nargs='+', help='Policy UID')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        plugin = admin_plugin.get_pedm_plugin(context)

        is_summary = kwargs.get('summary') is True
        rq = pedm_pb2.PolicyAgentRequest()
        rq.summaryOnly = is_summary
        policies = kwargs.get('policy')
        if not isinstance(policies, list):
            policies = [str(policies)]
        if '*' in policies:
            rq.policyUid.append(plugin.all_agents)
        else:
            policies = pedm_admin.PedmUtils.resolve_existing_policies(plugin, policies)
            if len(policies) == 0:
                raise base.CommandError(f'Cannot find any policy')
            rq.policyUid.extend([utils.base64_url_decode(x.policy_uid) for x in policies])

        rs = api.execute_router(context,'pedm/get_policy_agents', rq, rs_type=pedm_pb2.PolicyAgentResponse)
        assert rs is not None
        rows: List[List[Any]] = []
        headers: List[str]
        if is_summary:
            headers = ['policy_uid', 'agent_count']
            rows = [[[utils.base64_url_encode(x) for x in rq.policyUid], rs.agentCount]]
        else:
            headers = ['policy_uid', 'agent_uid']
            for i in range(max(len(rq.policyUid), len(rs.agentUid))):
                policy_uid = utils.base64_url_encode(rq.policyUid[i]) if i < len(rq.policyUid) else ''
                agent_uid = utils.base64_url_encode(rs.agentUid[i]) if i < len(rs.agentUid) else ''
                rows.append([policy_uid, agent_uid])

        return report_utils.dump_report_data(rows, headers, fmt=kwargs.get('format'), filename=kwargs.get('output'))