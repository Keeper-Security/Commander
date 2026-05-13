import json
import os
import tempfile
import unittest

from keepercommander.commands.keeper_tenant_migrate.audit import append_audit_event
from keepercommander.commands.keeper_tenant_migrate.audit_export import (
    SUPPORTED_FORMATS,
    export,
    read_audit_events,
    to_cef,
    to_jsonlines,
    to_syslog,
)


def _seed(log_path, count=3):
    for i in range(count):
        append_audit_event(log_path, {
            'subcommand': 'users' if i % 2 == 0 else 'verify',
            'summary': {'total': i, 'ok': True},
            'inputs': {'inventory.json': 'abcd'},
        })


class ReadEventsTests(unittest.TestCase):
    def test_yields_parsed_events(self):
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, 'audit.log')
            _seed(log, 2)
            events = list(read_audit_events(log))
            self.assertEqual(len(events), 2)
            self.assertIn('signature', events[0])

    def test_missing_file_yields_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(list(read_audit_events(
                os.path.join(d, 'no-such.log'))), [])

    def test_malformed_json_raises(self):
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, 'audit.log')
            with open(log, 'w') as f:
                f.write('not-json\n')
            with self.assertRaises(ValueError):
                list(read_audit_events(log))


class JsonLinesFormatTests(unittest.TestCase):
    def test_strips_prev_hash_but_keeps_signature(self):
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, 'audit.log')
            _seed(log, 1)
            events = list(read_audit_events(log))
            lines = list(to_jsonlines(iter(events)))
            self.assertEqual(len(lines), 1)
            out = json.loads(lines[0])
            self.assertNotIn('prev_hash', out)
            self.assertIn('signature', out)


class SyslogFormatTests(unittest.TestCase):
    def test_each_line_has_rfc5424_structure(self):
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, 'audit.log')
            _seed(log, 2)
            lines = list(to_syslog(read_audit_events(log), hostname='host1'))
            self.assertEqual(len(lines), 2)
            for line in lines:
                # <pri>1 TIMESTAMP HOST APP - MSGID [SD] MSG
                self.assertTrue(line.startswith('<'))
                self.assertIn('keeper-tenant-migrate', line)
                self.assertIn('host1', line)
                self.assertIn('[ktm@32473', line)

    def test_destructive_subcommands_get_warning_severity(self):
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, 'audit.log')
            append_audit_event(log, {'subcommand': 'cleanup',
                                      'summary': {}})
            lines = list(to_syslog(read_audit_events(log)))
            # PRI = 1*8 + 4 (warning) = 12
            self.assertTrue(lines[0].startswith('<12>'))

    def test_read_only_subcommands_get_informational(self):
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, 'audit.log')
            append_audit_event(log, {'subcommand': 'verify',
                                      'summary': {}})
            lines = list(to_syslog(read_audit_events(log)))
            # PRI = 1*8 + 6 = 14
            self.assertTrue(lines[0].startswith('<14>'))


class CefFormatTests(unittest.TestCase):
    def test_cef_header_format(self):
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, 'audit.log')
            _seed(log, 1)
            lines = list(to_cef(read_audit_events(log)))
            self.assertEqual(len(lines), 1)
            self.assertTrue(lines[0].startswith(
                'CEF:0|Keeper|TenantMigrate|'))
            self.assertIn('signatureId=', lines[0])

    def test_cef_escapes_pipes_and_equals_in_values(self):
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, 'audit.log')
            append_audit_event(log, {
                'subcommand': 'structure',
                'summary': {'weird': 'a=b|c'},
            })
            lines = list(to_cef(read_audit_events(log)))
            self.assertIn('cs_weird=a\\=b\\|c', lines[0])


class ExportDriverTests(unittest.TestCase):
    def test_writes_file_0600(self):
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, 'audit.log')
            out = os.path.join(d, 'out.log')
            _seed(log, 3)
            result = export(log, out, 'json-lines')
            self.assertEqual(result['written'], 3)
            self.assertEqual(oct(os.stat(out).st_mode & 0o777), '0o600')
            with open(out) as f:
                content = f.read()
            self.assertEqual(content.strip().count('\n'), 2)  # 3 lines

    def test_rejects_unsupported_format(self):
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, 'audit.log')
            _seed(log, 1)
            out = os.path.join(d, 'o')
            with self.assertRaises(ValueError):
                export(log, out, 'xml')

    def test_each_supported_format_produces_output(self):
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, 'audit.log')
            _seed(log, 2)
            for fmt in SUPPORTED_FORMATS:
                out = os.path.join(d, f'out.{fmt}.log')
                result = export(log, out, fmt)
                self.assertEqual(result['written'], 2)
                self.assertTrue(os.path.exists(out))


if __name__ == '__main__':
    unittest.main()
