import csv
import os
import tempfile
import unittest
from io import StringIO
from unittest import mock

from keepercommander.commands.pam_import.delinea_import import (
    DelineaImportOptions, DelineaImportOrchestrator,
)
from keepercommander.importer.thycotic.pam.crosswalk import (
    DEFAULT_CROSSWALK, Crosswalk,
)
from keepercommander.importer.thycotic.pam.models import ChangerMapping, CrosswalkRow

# pam_settings.connection protocols accepted by pam project import.
_PROTOCOLS = {
    'rdp', 'vnc', 'telnet', 'ssh', 'kubernetes', 'http',
    'sql-server', 'postgresql', 'mysql', 'mariadb', 'oracle', 'mongodb',
    'redis', 'elasticsearch', 'clickhouse', 'dynamodb',
}

# Built-in names from Delinea's password changer list. Aliases the product
# also uses (template names, older labels) are covered separately.
_DOCUMENTED_CHANGERS = (
    'Microsoft AD Secret Template for RPC',
    'Active Directory LDS',
    'AD LDS',
    'AliCloud RAM Access Key',
    'AliCloud RAM Console Password Privileged Account',
    'Amazon IAM Console Password Privileged Account',
    'Amazon IAM Key',
    'AS/400 IBM iSystem',
    'Azure AD',
    'Azure Application Registrations (Account Client Secret Rotation)',
    'Azure Application Registrations (Privileged Account Client Secret Rotation)',
    'Blue Coat Account Custom (SSH)',
    'Blue Coat Enable Password Custom (SSH)',
    'Cisco Account Custom (SSH)',
    'Cisco Account Custom (Telnet)',
    'Cisco Enable Secret Custom (SSH)',
    'Cisco Enable Secret Custom (Telnet)',
    'Dummy PowerShell Changer',
    'Entra ID',
    'ESX/ESXi (API)',
    'F5 BIG-IP Root Account (SSH)',
    'Generic Discovery-Only Credentials',
    'Generic ODBC (DataSource)',
    'Generic ODBC (PostgreSQL DataSource)',
    'Generic ODBC (SQL DataSource)',
    'GCP Console User',
    'Google IAM Service Account Key',
    'HP iLO Account Custom (SSH)',
    'IBM iSeries Mainframe',
    'Jamf Account',
    'Jamf Privileged Account',
    'Jamf Pro Secret Template for RPC',
    'Juniper Account Custom (SSH)',
    'LDAP (Active Directory)',
    'LDAP (DSEE)',
    'LDAP (OpenLDAP)',
    'MySQL Account',
    'New Cisco PW Changer',
    'New PW Changer',
    'Nutanix CVM Account',
    'Nutanix Prism Central Template for RPC',
    'Nutanix Service Account API Key',
    'Okta Secret Template for RPC',
    'Oracle Account',
    'Oracle Account (AS SYS)',
    'Oracle Account (DataSource)',
    'Oracle Account (TCPS)',
    'Oracle Account (Template Ver 2)',
    'PostgreSQL Account (x64)',
    'Powershell Secret Template for RPC',
    'PowerShell Script',
    'SailPoint IIQ Secret Template for RPC',
    'SAP Account',
    'ServiceNow Template for RPC',
    'Snowflake Key Pair Auth Secret Template for RPC',
    'Snowflake Secret Template for RPC',
    'SonicWall NSA Web Admin Account',
    'SonicWall NSA Web Local User Account',
    'Splunk Enterprise Secret Template for RPC',
    'SQL Server Account',
    'SSH Key Rotation',
    'SSH Key Rotation (No Password)',
    'SSH Key Rotation Privileged Account',
    'SSH Key Rotation Privileged Account (No Password)',
    'Sybase Account',
    'Teradata',
    'Unix Account (SSH)',
    'Unix Account (Telnet)',
    'Unix Account Custom (SSH)',
    'Unix Account Custom (Telnet)',
    'Unix Account SU Takeover (SSH)',
    'Unix Account SUDO Takeover (SSH)',
    'Unix Root Account Custom (SSH)',
    'WatchGuard Custom (SSH)',
    'Websphere Account',
    'Web User Account',
    'Windows Account',
    'Workday',
    'z/OS Mainframe',
    'z/OS Mainframe (Priv Account)',
)


class FakeClient:
    def __init__(self):
        self.types = {}
        self.type_details = {}
        self.templates = []
        self.template_details = {}
        self.by_template = {}
        self.secrets = {}
        self.fetched = []

    def password_types(self):
        return self.types

    def password_type(self, type_id):
        return self.type_details.get(type_id)

    def secret_templates(self):
        return self.templates

    def secret_template(self, template_id):
        return self.template_details.get(template_id)

    def secrets_for_template(self, template_id, take):
        return list(self.by_template.get(template_id, []))[:take]

    def secret(self, secret_id):
        self.fetched.append(secret_id)
        return self.secrets.get(secret_id)


class DelineaCrosswalkTest(unittest.TestCase):
    def test_every_documented_changer_is_mapped(self):
        missing = [name for name in _DOCUMENTED_CHANGERS if name.casefold() not in DEFAULT_CROSSWALK]
        self.assertEqual(missing, [])

    def test_protocols_and_ports(self):
        expected = {
            'Windows Account': ('pamMachine', 'rdp', '3389', 'general'),
            'Unix Account (SSH)': ('pamMachine', 'ssh', '22', 'general'),
            'Unix Account (Telnet)': ('pamMachine', 'telnet', '23', None),
            'Cisco Account Custom (SSH)': ('pamMachine', 'ssh', '22', None),
            'SQL Server Account': ('pamDatabase', 'sql-server', '1433', 'general'),
            'MySQL Account': ('pamDatabase', 'mysql', '3306', 'general'),
            'PostgreSQL Account (x64)': ('pamDatabase', 'postgresql', '5432', 'general'),
            'Oracle Account': ('pamDatabase', 'oracle', '1521', 'general'),
            'Oracle Account (TCPS)': ('pamDatabase', 'oracle', '2484', 'general'),
            'LDAP (OpenLDAP)': ('pamDirectory', None, '636', 'general'),
            'Web User Account': ('login', None, '443', None),
            'Sybase Account': ('login', None, '5000', None),
            'PowerShell Script': ('login', None, '', None),
        }
        for name, (record_type, protocol, port, rotation) in expected.items():
            mapping = DEFAULT_CROSSWALK[name.casefold()]
            self.assertEqual(mapping.record_type, record_type, name)
            self.assertEqual(mapping.protocol, protocol, name)
            self.assertEqual(mapping.port, port, name)
            self.assertEqual(mapping.rotation, rotation, name)
            if protocol is not None:
                self.assertIn(protocol, _PROTOCOLS, name)
            if record_type != 'login':
                self.assertTrue(port.isdigit(), name)

    def test_custom_port_overrides_default(self):
        crosswalk = Crosswalk()
        mapping = crosswalk.resolve('Unix Account (SSH)', {'customPort': 2222})
        self.assertEqual(mapping.port, '2222')
        self.assertEqual(mapping.protocol, 'ssh')
        untouched = crosswalk.resolve('Unix Account (SSH)', {'customPort': 0})
        self.assertEqual(untouched.port, '22')
        self.assertIsNone(crosswalk.resolve('Totally Custom Changer'))

    def test_csv_round_trip_and_formula_guard(self):
        rows = [
            CrosswalkRow(1, '=cmd|evil', templates=['Unix'], secret_count=2,
                         mapping=DEFAULT_CROSSWALK['unix account (ssh)']),
            CrosswalkRow(9, 'Custom Appliance', templates=[], secret_count=0, mapping=None),
        ]
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, 'crosswalk.csv')
            Crosswalk.write_template(rows, path)
            with open(path, encoding='utf-8', newline='') as handle:
                raw = handle.read()
            self.assertIn("'=cmd|evil", raw)
            loaded = Crosswalk.load(path)
            mapping = loaded.resolve('=cmd|evil')
            self.assertEqual(mapping.protocol, 'ssh')
            self.assertEqual(mapping.port, '22')
            self.assertIsNone(loaded.resolve('Custom Appliance'))

            edited = os.path.join(folder, 'edited.csv')
            with open(path, encoding='utf-8', newline='') as handle:
                reader = csv.DictReader(handle)
                out_rows = list(reader)
            out_rows.append({
                'changer_id': '9',
                'changer_name': 'Custom Appliance',
                'templates': '',
                'secret_count': '0',
                'record_type': 'pamMachine',
                'rotation': '',
                'protocol': 'ssh',
                'port': '22',
                'database_type': '',
                'directory_type': '',
                'operating_system': 'linux',
            })
            with open(edited, 'w', encoding='utf-8', newline='') as handle:
                writer = csv.DictWriter(handle, fieldnames=reader.fieldnames, lineterminator='\n')
                writer.writeheader()
                writer.writerows(out_rows)
            overridden = Crosswalk.load(edited).resolve('Custom Appliance')
            self.assertEqual(overridden.record_type, 'pamMachine')
            self.assertIsNone(overridden.rotation)

    def test_load_rejects_a_bad_file(self):
        with self.assertRaises(OSError):
            Crosswalk.load('no-such-crosswalk.csv')
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, 'bad.csv')
            with open(path, 'w', encoding='utf-8') as handle:
                handle.write('foo,bar\n1,2\n')
            with self.assertRaises(ValueError):
                Crosswalk.load(path)

    def test_discover_joins_templates_and_custom_port(self):
        client = FakeClient()
        client.types = {
            3: {'passwordTypeId': 3, 'name': 'Unix Account (SSH)'},
            8: {'passwordTypeId': 8, 'name': 'Lab Widget'},
        }
        client.type_details = {
            3: {'passwordTypeId': 3, 'name': 'Unix Account (SSH)', 'customPort': 2200},
            8: {'passwordTypeId': 8, 'name': 'Lab Widget', 'customPort': 0},
        }
        client.templates = [
            {'id': 60, 'name': 'Unix Account (SSH)', 'secretCount': 4},
            {'id': 61, 'name': 'Empty', 'secretCount': 0},
        ]
        client.template_details = {
            60: {'id': 60, 'name': 'Unix Account (SSH)', 'passwordTypeId': 3},
            61: {'id': 61, 'name': 'Empty'},
        }
        rows = Crosswalk().discover(client)
        by_name = {row.changer_name: row for row in rows}
        unix = by_name['Unix Account (SSH)']
        self.assertEqual(unix.templates, ['Unix Account (SSH)'])
        self.assertEqual(unix.secret_count, 4)
        self.assertEqual(unix.mapping.port, '2200')
        self.assertEqual(unix.mapping.protocol, 'ssh')
        self.assertIsNone(by_name['Lab Widget'].mapping)
        self.assertEqual(by_name['Lab Widget'].secret_count, 0)

    def test_check_reports_problems_without_secret_values(self):
        client = FakeClient()
        client.templates = [{'id': 60, 'name': 'Unix Account (SSH)'}]
        client.by_template = {60: [{'id': 100, 'name': 'prod-host'}]}
        client.secrets = {100: {'id': 100, 'name': 'prod-host', 'items': [
            {'slug': 'username', 'itemValue': 'root'},
            {'slug': 'password', 'itemValue': 's3cret-value'},
        ]}}
        mapped = CrosswalkRow(
            3, 'Unix Account (SSH)', templates=['Unix Account (SSH)'], secret_count=1,
            mapping=DEFAULT_CROSSWALK['unix account (ssh)'])
        unmapped = CrosswalkRow(8, 'Lab Widget', templates=['Unix Account (SSH)'], secret_count=1)
        checks = Crosswalk().check(client, [mapped, unmapped], 1)
        self.assertEqual(len(checks), 2)
        unix, lab = checks
        self.assertEqual(unix.problems, ('no host',))
        self.assertIn('changer is not mapped', lab.problems)
        rendered = repr(checks)
        self.assertNotIn('s3cret-value', rendered)
        self.assertNotIn('root', rendered)

    def test_check_accepts_a_complete_secret(self):
        client = FakeClient()
        client.templates = [{'id': 70, 'name': 'SQL Server Account'}]
        client.by_template = {70: [{'id': 5, 'name': 'payroll'}]}
        client.secrets = {5: {'id': 5, 'name': 'payroll', 'items': [
            {'slug': 'server', 'itemValue': 'sql.example'},
            {'slug': 'username', 'itemValue': 'sa'},
            {'slug': 'password', 'itemValue': 'hidden'},
            {'slug': 'port', 'itemValue': '1433'},
        ]}}
        row = CrosswalkRow(
            1, 'SQL Server Account', templates=['SQL Server Account'], secret_count=1,
            mapping=DEFAULT_CROSSWALK['sql server account'])
        checks = Crosswalk().check(client, [row], 2)
        self.assertTrue(checks[0].ok)
        blank = ChangerMapping('SQL Server Account', 'pamDatabase', 'general', 'sql-server', '1433')
        broken = CrosswalkRow(1, 'SQL Server Account', templates=['SQL Server Account'],
                              mapping=blank)
        problems = Crosswalk().check(client, [broken], 1)[0].problems
        self.assertIn('database_type is missing', problems)

    def test_run_crosswalk_writes_csv_and_prints_check(self):
        client = FakeClient()
        client.types = {3: {'passwordTypeId': 3, 'name': 'Unix Account (SSH)'}}
        client.type_details = {3: {'name': 'Unix Account (SSH)', 'customPort': 0}}
        client.templates = [{'id': 60, 'name': 'Unix Account (SSH)', 'secretCount': 1}]
        client.template_details = {60: {'id': 60, 'name': 'Unix Account (SSH)', 'passwordTypeIds': [3]}}
        client.by_template = {60: [{'id': 100, 'name': 'box'}]}
        client.secrets = {100: {'id': 100, 'name': 'box', 'items': []}}
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, 'out.csv')
            options = DelineaImportOptions(
                server='ss.example.com', crosswalk_out=path, crosswalk_check=1)
            orchestrator = DelineaImportOrchestrator(None, client, options)
            with mock.patch('keepercommander.commands.pam_import.delinea_import.utils.set_file_permissions'):
                with mock.patch('sys.stdout', new_callable=StringIO) as stdout:
                    orchestrator.run_crosswalk(Crosswalk())
            text = stdout.getvalue()
            self.assertIn('1 mapped, 0 unmapped', text)
            self.assertIn('1 with problems', text)
            self.assertIn('no host', text)
            self.assertNotIn('s3cret', text)
            with open(path, encoding='utf-8', newline='') as handle:
                written = list(csv.DictReader(handle))
            self.assertEqual(written[0]['protocol'], 'ssh')
            self.assertEqual(written[0]['port'], '22')
            self.assertEqual(written[0]['templates'], 'Unix Account (SSH)')


if __name__ == '__main__':
    unittest.main()
