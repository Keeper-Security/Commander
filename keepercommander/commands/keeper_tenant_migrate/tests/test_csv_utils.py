"""Regression for B#8 — BOM CSVs silently yielding zero rows.

Also covers wrong-header detection and header-whitespace tolerance.
"""

import os
import tempfile
import unittest

from keepercommander.commands.keeper_tenant_migrate.csv_utils import CSVHeaderError, read_csv_dictreader


def _write(path, content, encoding='utf-8'):
    with open(path, 'w', encoding=encoding, newline='') as f:
        f.write(content)


class BOMStrippingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, 'roster.csv')

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp)

    def test_bom_csv_still_parses(self):
        # Excel-saved UTF-8-BOM file — `\ufeff` prefix on the first byte
        _write(self.path, '\ufeffemail,name\nalice@x,Alice\n')
        header, rows = read_csv_dictreader(self.path,
                                            required_columns=('email',))
        self.assertEqual(rows[0]['email'], 'alice@x')

    def test_no_bom_still_parses(self):
        _write(self.path, 'email,name\nalice@x,Alice\n')
        _, rows = read_csv_dictreader(self.path, required_columns=('email',))
        self.assertEqual(rows[0]['email'], 'alice@x')

    def test_wrong_header_raises(self):
        _write(self.path, 'user_email,name\nalice@x,Alice\n')
        with self.assertRaises(CSVHeaderError) as cm:
            read_csv_dictreader(self.path, required_columns=('email',))
        self.assertIn('user_email', str(cm.exception))

    def test_whitespace_in_header_tolerated(self):
        _write(self.path, 'email , name\nalice@x,Alice\n')
        _, rows = read_csv_dictreader(self.path, required_columns=('email',))
        self.assertEqual(rows[0]['email'], 'alice@x')

    def test_no_required_columns_disables_check(self):
        _write(self.path, 'arbitrary,whatever\nx,y\n')
        header, rows = read_csv_dictreader(self.path)
        self.assertEqual(len(rows), 1)


class LoadersUseCsvUtilsTests(unittest.TestCase):
    """Each high-impact loader should now reject BOM + wrong-header CSVs."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp)

    def test_decommission_rejects_wrong_header(self):
        from keepercommander.commands.keeper_tenant_migrate.decommission import load_user_emails
        path = os.path.join(self.tmp, 'roster.csv')
        _write(path, 'user_email,name\na@x,Alice\n')
        with self.assertRaises(CSVHeaderError):
            list(load_user_emails(path))

    def test_decommission_handles_bom(self):
        from keepercommander.commands.keeper_tenant_migrate.decommission import load_user_emails
        path = os.path.join(self.tmp, 'roster.csv')
        _write(path, '\ufeffemail\na@x\nb@x\n')
        self.assertEqual(list(load_user_emails(path)), ['a@x', 'b@x'])

    def test_manifest_rejects_wrong_header(self):
        from keepercommander.commands.keeper_tenant_migrate.attachments import load_manifest
        path = os.path.join(self.tmp, 'manifest.csv')
        _write(path, 'src,tgt\nuid1,uid2\n')
        with self.assertRaises(CSVHeaderError):
            load_manifest(path)

    def test_manifest_handles_bom(self):
        from keepercommander.commands.keeper_tenant_migrate.attachments import load_manifest
        path = os.path.join(self.tmp, 'manifest.csv')
        _write(path, '\ufeffsource_uid,target_uid\nsrc1,tgt1\n')
        pairs = load_manifest(path)
        self.assertEqual(pairs[0]['source_uid'], 'src1')


if __name__ == '__main__':
    unittest.main()
