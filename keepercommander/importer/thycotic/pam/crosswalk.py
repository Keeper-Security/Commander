#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander — Delinea PAM import

import csv
from dataclasses import replace
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .client import DelineaPamClient
from .models import ChangerMapping, CrosswalkCheck, CrosswalkRow

# Field slugs shared with SecretMapper. Kept here so this module does not import it.
_HOST_SLUGS = frozenset(('machine', 'server', 'host', 'ip-address---host-name'))
_LOGIN_SLUGS = frozenset(('username',))
_PASSWORD_SLUGS = frozenset(('password',))
_PORT_SLUGS = frozenset(('port',))

_CSV_FORMULA_PREFIXES = ('=', '+', '-', '@')

# Record types SecretMapper can build from a crosswalk row.
RECORD_TYPES = frozenset(('pamMachine', 'pamDatabase', 'pamDirectory', 'login'))


def _row(name: str, record_type: str, rotation: Optional[str], protocol: Optional[str], port: str,
         **extra: str) -> ChangerMapping:
    return ChangerMapping(changer_name=name, record_type=record_type, rotation=rotation,
                          protocol=protocol, port=port, **extra)


def _ssh(name: str, rotation: Optional[str] = None, operating_system: str = '') -> ChangerMapping:
    return _row(name, 'pamMachine', rotation, 'ssh', '22', operating_system=operating_system)


def _telnet(name: str, operating_system: str = '') -> ChangerMapping:
    return _row(name, 'pamMachine', None, 'telnet', '23', operating_system=operating_system)


def _directory(name: str, directory_type: str) -> ChangerMapping:
    # 636 is LDAPS. A non-zero customPort on the password type replaces it.
    return _row(name, 'pamDirectory', 'general', None, '636', directory_type=directory_type)


def _database(name: str, protocol: str, port: str, database_type: str) -> ChangerMapping:
    return _row(name, 'pamDatabase', 'general', protocol, port, database_type=database_type)


def _login(name: str, port: str = '') -> ChangerMapping:
    return _row(name, 'login', None, None, port)


def _index(mappings: Iterable[ChangerMapping]) -> Dict[str, ChangerMapping]:
    indexed: Dict[str, ChangerMapping] = {}
    for mapping in mappings:
        key = mapping.changer_name.casefold()
        if key in indexed:
            raise ValueError(f'Duplicate password changer name: {mapping.changer_name}')
        indexed[key] = mapping
    return indexed


# Built-in Secret Server password changers (Admin > RPC > Configure RPC).
# protocol is a pam_settings.connection protocol. None means Keeper has no
# connection for that changer, so the secret is stored as a login when
# record_type is login, or as a resource without a connection block.
# rotation None means Keeper has no built-in rotation (UNSUPPORTED).
# SSH defaults to 22 and Telnet to 23; both are the changer setting and can
# be overridden by customPort. Windows is RDP 3389 — Delinea changes the
# password over Windows RPC, which is not the connection port.
_BUILTIN_CHANGERS: Tuple[ChangerMapping, ...] = (
    _row('Windows Account', 'pamMachine', 'general', 'rdp', '3389', operating_system='windows'),
    _directory('Microsoft AD Secret Template for RPC', 'active_directory'),
    _directory('Active Directory Account', 'active_directory'),
    _directory('Active Directory LDS', 'active_directory'),
    _directory('AD LDS', 'active_directory'),
    _directory('LDAP (Active Directory)', 'active_directory'),
    _directory('LDAP (OpenLDAP)', 'openldap'),
    _directory('OpenLDAP Account', 'openldap'),
    _directory('LDAP (DSEE)', 'openldap'),

    _ssh('Unix Account (SSH)', rotation='general', operating_system='linux'),
    _ssh('Unix Account Custom (SSH)', rotation='general', operating_system='linux'),
    _ssh('Unix Account SU Takeover (SSH)', rotation='general', operating_system='linux'),
    _ssh('Unix Account SUDO Takeover (SSH)', rotation='general', operating_system='linux'),
    _ssh('Unix Root Account Custom (SSH)', rotation='general', operating_system='linux'),
    _ssh('Unix Account (SSH Key Rotation)', rotation='general', operating_system='linux'),
    _ssh('SSH Key Rotation', rotation='general', operating_system='linux'),
    _ssh('SSH Key Rotation (No Password)', rotation='general', operating_system='linux'),
    _ssh('SSH Key Rotation Privileged Account', rotation='general', operating_system='linux'),
    _ssh('SSH Key Rotation Privileged Account (No Password)', rotation='general', operating_system='linux'),
    _ssh('Nutanix CVM Account', rotation='general', operating_system='linux'),
    _telnet('Unix Account (Telnet)', operating_system='linux'),
    _telnet('Unix Account Custom (Telnet)', operating_system='linux'),

    _ssh('Cisco Account Custom (SSH)'),
    _ssh('Cisco Account (SSH)'),
    _ssh('Cisco Enable Secret Custom (SSH)'),
    _ssh('New Cisco PW Changer'),
    _telnet('Cisco Account Custom (Telnet)'),
    _telnet('Cisco Enable Secret Custom (Telnet)'),
    _ssh('Blue Coat Account Custom (SSH)'),
    _ssh('Blue Coat Enable Password Custom (SSH)'),
    _ssh('F5 BIG-IP Root Account (SSH)'),
    _ssh('HP iLO Account Custom (SSH)'),
    _ssh('Juniper Account Custom (SSH)'),
    _ssh('WatchGuard Custom (SSH)'),
    _ssh('Check Point'),
    _ssh('Enterasys'),
    _ssh('Dell DRAC'),
    _telnet('AS/400 IBM iSystem'),
    _telnet('IBM iSeries Mainframe'),

    _database('SQL Server Account', 'sql-server', '1433', 'mssql'),
    _database('Generic ODBC (SQL DataSource)', 'sql-server', '1433', 'mssql'),
    _database('MySQL Account', 'mysql', '3306', 'mysql'),
    _database('PostgreSQL Account', 'postgresql', '5432', 'postgresql'),
    _database('PostgreSQL Account (x64)', 'postgresql', '5432', 'postgresql'),
    _database('Generic ODBC (PostgreSQL DataSource)', 'postgresql', '5432', 'postgresql'),
    _database('Oracle Account', 'oracle', '1521', 'oracle'),
    _database('Oracle Account (AS SYS)', 'oracle', '1521', 'oracle'),
    _database('Oracle Account (DataSource)', 'oracle', '1521', 'oracle'),
    _database('Oracle Account (Template Ver 2)', 'oracle', '1521', 'oracle'),
    _database('Oracle Account (TCPS)', 'oracle', '2484', 'oracle'),

    # No Keeper connection protocol. Port is recorded so the CSV lists it.
    _login('AliCloud RAM Access Key', '443'),
    _login('AliCloud RAM Console Password Privileged Account', '443'),
    _login('Amazon IAM Console Password Privileged Account', '443'),
    _login('Amazon IAM Key', '443'),
    _login('Azure AD', '443'),
    _login('Entra ID', '443'),
    _login('Azure Application Registrations (Account Client Secret Rotation)', '443'),
    _login('Azure Application Registrations (Privileged Account Client Secret Rotation)', '443'),
    _login('GCP Console User', '443'),
    _login('Google IAM Service Account Key', '443'),
    _login('Web User Account', '443'),
    _login('Web Password', '443'),
    _login('Okta Secret Template for RPC', '443'),
    _login('ServiceNow Template for RPC', '443'),
    _login('Workday', '443'),
    _login('SailPoint IIQ Secret Template for RPC', '443'),
    _login('Snowflake Secret Template for RPC', '443'),
    _login('Snowflake Key Pair Auth Secret Template for RPC', '443'),
    _login('Jamf Account', '443'),
    _login('Jamf Privileged Account', '443'),
    _login('Jamf Pro Secret Template for RPC', '443'),
    _login('SonicWall NSA Web Admin Account', '443'),
    _login('SonicWall NSA Web Local User Account', '443'),
    _login('ESX/ESXi (API)', '443'),
    _login('Nutanix Prism Central Template for RPC', '9440'),
    _login('Nutanix Service Account API Key', '9440'),
    _login('Splunk Enterprise Secret Template for RPC', '8089'),
    _login('Sybase Account', '5000'),
    _login('Teradata', '1025'),
    _login('Generic ODBC (DataSource)'),
    _login('z/OS Mainframe', '23'),
    _login('z/OS Mainframe (Priv Account)', '23'),
    _login('SAP Account'),
    _login('Websphere Account'),
    _login('Powershell Secret Template for RPC'),
    _login('PowerShell Script'),
    _login('Dummy PowerShell Changer'),
    _login('Generic Discovery-Only Credentials'),
    _login('New PW Changer'),
)

# Single source of truth for built-in changers, keyed by casefolded Delinea password type name.
DEFAULT_CROSSWALK: Dict[str, ChangerMapping] = _index(_BUILTIN_CHANGERS)

FALLBACK_MAPPING = ChangerMapping(
    changer_name='', record_type='login', rotation=None, protocol=None)

TEMPLATE_COLUMNS = (
    'changer_id', 'changer_name', 'templates', 'secret_count',
    'record_type', 'rotation', 'protocol', 'port',
    'database_type', 'directory_type', 'operating_system',
)


def _csv_cell(value) -> str:
    text = '' if value is None else str(value)
    if text[:1] in _CSV_FORMULA_PREFIXES:
        return "'" + text
    return text


def _uncsv_cell(value: str) -> str:
    text = (value or '').strip()
    if len(text) > 1 and text[0] == "'" and text[1] in _CSV_FORMULA_PREFIXES:
        return text[1:]
    return text


def _custom_port(password_type: Optional[dict]) -> str:
    """Non-zero ``customPort`` from a password type detail, or ''."""
    if not isinstance(password_type, dict):
        return ''
    raw = password_type.get('customPort')
    if raw in (None, '', 0, '0'):
        return ''
    text = str(raw).strip()
    if not text or text == '0':
        return ''
    return text


def _password_type_ids(template: dict) -> List[int]:
    """Password changer ids attached to a secret template."""
    found: List[int] = []

    def add(value) -> None:
        if isinstance(value, bool):
            return
        if isinstance(value, int):
            found.append(value)
            return
        if isinstance(value, str) and value.strip().isdigit():
            found.append(int(value.strip()))

    add(template.get('passwordTypeId'))
    for key in ('passwordTypeIds', 'secretTemplatePasswordTypes', 'passwordTypes'):
        value = template.get(key)
        if not isinstance(value, list):
            continue
        for item in value:
            if isinstance(item, dict):
                add(item.get('passwordTypeId', item.get('id')))
            else:
                add(item)
    unique: List[int] = []
    seen = set()
    for type_id in found:
        if type_id not in seen:
            seen.add(type_id)
            unique.append(type_id)
    return unique


def _changer_name(password_type: dict) -> str:
    return str(password_type.get('name') or password_type.get('passwordTypeName') or '').strip()


def _has_slug(secret: dict, slugs: frozenset) -> bool:
    for item in secret.get('items') or []:
        if not isinstance(item, dict):
            continue
        if item.get('slug') in slugs and str(item.get('itemValue') or '').strip():
            return True
    return False


def _secret_port(secret: dict, mapping: Optional[ChangerMapping]) -> str:
    for item in secret.get('items') or []:
        if not isinstance(item, dict) or item.get('slug') not in _PORT_SLUGS:
            continue
        text = str(item.get('itemValue') or '').strip()
        if text:
            return text
    if mapping and mapping.port:
        return str(mapping.port)
    return ''


class Crosswalk:
    """Delinea password changer to Keeper PAM type map.

    ``DEFAULT_CROSSWALK`` overlaid with rows loaded from an admin-edited CSV
    (``TEMPLATE_COLUMNS``; ``changer_id``, ``templates`` and ``secret_count``
    are informational and ignored on load).
    """

    def __init__(self, overrides: Optional[Dict[str, ChangerMapping]] = None):
        self.mappings: Dict[str, ChangerMapping] = {
            **DEFAULT_CROSSWALK, **(overrides or {})}

    @classmethod
    def load(cls, path: str) -> 'Crosswalk':
        """Read a CSV produced by ``write_template``; rows with empty ``record_type`` are skipped."""
        overrides: Dict[str, ChangerMapping] = {}
        try:
            handle = open(path, newline='', encoding='utf-8-sig')
        except OSError as e:
            raise OSError(f'Crosswalk file not found: {path}') from e
        with handle:
            reader = csv.DictReader(handle)
            missing = [col for col in ('changer_name', 'record_type') if col not in (reader.fieldnames or [])]
            if missing:
                raise ValueError(
                    f'Crosswalk file is missing columns: {", ".join(missing)}')
            for rec in reader:
                record_type = _uncsv_cell(rec.get('record_type') or '')
                name = _uncsv_cell(rec.get('changer_name') or '')
                if not record_type or not name:
                    continue
                if record_type not in RECORD_TYPES:
                    raise ValueError(
                        f'Crosswalk line {reader.line_num}: record_type "{record_type}" must be one of '
                        f'{", ".join(sorted(RECORD_TYPES))}')
                rotation = _uncsv_cell(rec.get('rotation') or '') or None
                protocol = _uncsv_cell(rec.get('protocol') or '') or None
                overrides[name.casefold()] = ChangerMapping(
                    changer_name=name,
                    record_type=record_type,
                    rotation=rotation,
                    protocol=protocol,
                    port=_uncsv_cell(rec.get('port') or ''),
                    database_type=_uncsv_cell(rec.get('database_type') or ''),
                    directory_type=_uncsv_cell(rec.get('directory_type') or ''),
                    operating_system=_uncsv_cell(rec.get('operating_system') or ''),
                )
        return cls(overrides)

    def resolve(self, changer_name: str, password_type: Optional[dict] = None) -> Optional[ChangerMapping]:
        """Mapping for a changer, or ``None`` when unmapped.

        A non-zero ``customPort`` on the password type detail overrides the default port.
        """
        mapping = self.mappings.get((changer_name or '').casefold())
        custom_port = _custom_port(password_type)
        if mapping and custom_port:
            mapping = replace(mapping, port=custom_port)
        return mapping

    def discover(self, client: DelineaPamClient) -> List[CrosswalkRow]:
        """List every password changer on the tenant with protocol, port and usage.

        Changers come from ``client.password_types()``; templates and secret
        counts from ``client.secret_templates()`` joined on each template's
        ``passwordTypeId`` (``client.secret_template``). ``mapping`` is
        ``self.resolve(name, client.password_type(id))``.
        """
        usage: Dict[int, dict] = {}
        for summary in client.secret_templates() or []:
            if not isinstance(summary, dict):
                continue
            template_id = summary.get('id')
            detail = client.secret_template(template_id) if isinstance(template_id, int) else None
            source = detail if isinstance(detail, dict) else summary
            try:
                secret_count = int(summary.get('secretCount') or source.get('secretCount') or 0)
            except (TypeError, ValueError):
                secret_count = 0
            template_name = str(source.get('name') or summary.get('name') or '').strip()
            for type_id in _password_type_ids(source):
                bucket = usage.setdefault(type_id, {'templates': [], 'count': 0})
                if template_name and template_name not in bucket['templates']:
                    bucket['templates'].append(template_name)
                bucket['count'] += secret_count

        rows: List[CrosswalkRow] = []
        for type_id, summary in (client.password_types() or {}).items():
            if not isinstance(summary, dict):
                continue
            detail = client.password_type(type_id)
            source = detail if isinstance(detail, dict) else summary
            name = _changer_name(source) or _changer_name(summary)
            info = usage.get(type_id, {'templates': [], 'count': 0})
            rows.append(CrosswalkRow(
                changer_id=int(type_id),
                changer_name=name,
                templates=list(info['templates']),
                secret_count=info['count'],
                mapping=self.resolve(name, source),
            ))
        rows.sort(key=lambda row: (row.changer_name.casefold(), row.changer_id))
        return rows

    @staticmethod
    def write_template(rows: Sequence[CrosswalkRow], path: str) -> None:
        """Write *rows* as CSV with ``TEMPLATE_COLUMNS``; unmapped rows leave mapping columns empty.

        Cells beginning with ``= + - @`` are prefixed with ``'`` (CSV injection).
        """
        with open(path, 'w', newline='', encoding='utf-8') as handle:
            writer = csv.DictWriter(handle, fieldnames=TEMPLATE_COLUMNS, lineterminator='\n')
            writer.writeheader()
            for row in rows:
                mapping = row.mapping
                writer.writerow({
                    'changer_id': row.changer_id,
                    'changer_name': _csv_cell(row.changer_name),
                    'templates': _csv_cell('; '.join(row.templates)),
                    'secret_count': row.secret_count,
                    'record_type': _csv_cell(mapping.record_type if mapping else ''),
                    'rotation': _csv_cell(mapping.rotation if mapping and mapping.rotation else ''),
                    'protocol': _csv_cell(mapping.protocol if mapping and mapping.protocol else ''),
                    'port': _csv_cell(mapping.port if mapping else ''),
                    'database_type': _csv_cell(mapping.database_type if mapping else ''),
                    'directory_type': _csv_cell(mapping.directory_type if mapping else ''),
                    'operating_system': _csv_cell(mapping.operating_system if mapping else ''),
                })

    def check(self, client: DelineaPamClient, rows: Sequence[CrosswalkRow],
              sample_size: int) -> List[CrosswalkCheck]:
        """Validate the map against up to *sample_size* real secrets per changer.

        Problems reported per sample: changer unmapped; no host field for a
        non-``login`` type; no username / password; non-numeric port;
        ``database_type`` / ``directory_type`` missing for pamDatabase / pamDirectory.
        Secret values are read only to test presence and never logged.
        """
        if sample_size <= 0:
            return []
        templates_by_name: Dict[str, List[dict]] = {}
        for summary in client.secret_templates() or []:
            if isinstance(summary, dict):
                templates_by_name.setdefault(str(summary.get('name') or ''), []).append(summary)

        checks: List[CrosswalkCheck] = []
        for row in rows:
            for summary in self._sample_secrets(client, row, templates_by_name, sample_size):
                secret_id = summary.get('id')
                secret_id = secret_id if isinstance(secret_id, int) else 0
                secret_name = str(summary.get('name') or summary.get('secretName') or secret_id)
                secret = summary if isinstance(summary.get('items'), list) else None
                if secret is None and secret_id:
                    secret = client.secret(secret_id)
                problems: List[str] = []
                if not isinstance(secret, dict):
                    problems.append('secret could not be read')
                else:
                    problems.extend(self._problems(row.mapping, secret))
                checks.append(CrosswalkCheck(
                    changer_name=row.changer_name,
                    secret_id=secret_id,
                    secret_name=secret_name,
                    problems=tuple(problems),
                ))
        return checks

    @staticmethod
    def _sample_secrets(client: DelineaPamClient, row: CrosswalkRow,
                        templates_by_name: Dict[str, List[dict]], sample_size: int) -> List[dict]:
        found: List[dict] = []
        for template_name in row.templates:
            for template in templates_by_name.get(template_name, []):
                template_id = template.get('id')
                if not isinstance(template_id, int):
                    continue
                remaining = sample_size - len(found)
                if remaining <= 0:
                    return found
                found.extend(client.secrets_for_template(template_id, remaining) or [])
                if len(found) >= sample_size:
                    return found[:sample_size]
        return found[:sample_size]

    @staticmethod
    def _problems(mapping: Optional[ChangerMapping], secret: dict) -> List[str]:
        problems: List[str] = []
        if mapping is None:
            problems.append('changer is not mapped')
        else:
            if mapping.record_type != 'login' and not _has_slug(secret, _HOST_SLUGS):
                problems.append('no host')
            if mapping.record_type != 'login':
                port = _secret_port(secret, mapping)
                if not port.isdigit():
                    problems.append('port is not numeric')
            if mapping.record_type == 'pamDatabase' and not mapping.database_type:
                problems.append('database_type is missing')
            if mapping.record_type == 'pamDirectory' and not mapping.directory_type:
                problems.append('directory_type is missing')
        if not _has_slug(secret, _LOGIN_SLUGS):
            problems.append('no username')
        if not _has_slug(secret, _PASSWORD_SLUGS):
            problems.append('no password')
        return problems