import csv
import json
import os
import tempfile
from types import SimpleNamespace
from unittest import TestCase, mock, skipUnless

from data_vault import get_synced_params
from keepercommander.importer import importer, imp_exp
from keepercommander.importer.bitwarden.bitwarden import BitwardenImporter
from keepercommander.importer.csv.csv import KeeperCsvExporter, KeeperCsvImporter, EMPTY_FOLDER_MARKER
from keepercommander.importer.json.json import KeeperJsonExporter, KeeperJsonImporter
from keepercommander.importer.nordpass.nordpass import NordpassCsvImporter
from keepercommander.subfolder import BaseFolderNode

try:
    from keepercommander.importer.keepass.keepass import KeepassExporter, KeepassImporter
    from pykeepass import PyKeePass
except ImportError:
    KeepassExporter = None
    KeepassImporter = None
    PyKeePass = None


def empty_folder(path=None, domain=None):
    ef = importer.EmptyFolder()
    f = importer.Folder()
    f.path = path
    f.domain = domain
    ef.folders.append(f)
    return ef


def record(title, path=None, domain=None):
    r = importer.Record()
    r.title = title
    f = importer.Folder()
    f.path = path
    f.domain = domain
    r.folders = [f]
    return r


def describe(items):
    return [(type(x).__name__, x.folders[0].domain or None, x.folders[0].path or None) for x in items]


class TempFileMixin:
    def tmp(self, suffix):
        fd, path = tempfile.mkstemp(suffix=suffix)
        os.close(fd)
        self.addCleanup(os.remove, path)
        return path


class TestJsonEmptyFolders(TempFileMixin, TestCase):
    def test_round_trip(self):
        path = self.tmp('.json')
        KeeperJsonExporter().do_export(path, [
            empty_folder(path='A\\B'), empty_folder(path='sub', domain='SF'), record('r', path='X')])
        imported = list(KeeperJsonImporter().do_import(path))
        self.assertEqual(describe(imported), [
            ('EmptyFolder', None, 'A\\B'), ('EmptyFolder', 'SF', 'sub'), ('Record', None, 'X')])

    def test_file_without_empty_folders_section(self):
        path = self.tmp('.json')
        with open(path, 'w') as f:
            json.dump({'records': [{'title': 'r'}]}, f)
        self.assertEqual([type(x).__name__ for x in KeeperJsonImporter().do_import(path)], ['Record'])


class TestCsvEmptyFolders(TempFileMixin, TestCase):
    def test_round_trip(self):
        path = self.tmp('.csv')
        KeeperCsvExporter().do_export(path, [
            empty_folder(path='A\\B'), empty_folder(path='sub', domain='SF'), record('r', path='X')])
        imported = list(KeeperCsvImporter().do_import(path))
        self.assertEqual(describe(imported), [
            ('EmptyFolder', None, 'A\\B'), ('EmptyFolder', 'SF', 'sub'), ('Record', None, 'X')])

    def test_export_warns_about_older_importers(self):
        path = self.tmp('.csv')
        with self.assertLogs(level='WARNING') as logs:
            KeeperCsvExporter().do_export(path, [empty_folder(path='A')])
        self.assertIn('older Commander versions', logs.output[0])

    def test_export_without_empty_folders_does_not_warn(self):
        path = self.tmp('.csv')
        with mock.patch('logging.warning') as warn:
            KeeperCsvExporter().do_export(path, [record('r', path='A')])
        warn.assert_not_called()

    def import_rows(self, *rows):
        path = self.tmp('.csv')
        with open(path, 'w', newline='') as f:
            csv.writer(f).writerows(rows)
        return list(KeeperCsvImporter().do_import(path))

    def test_record_with_marker_field_is_not_dropped(self):
        rs = self.import_rows(['Personal', 'Bank login', 'alice', 'S3cret!', 'https://bank.example', '', '',
                               EMPTY_FOLDER_MARKER, 'true'])
        self.assertEqual([type(x).__name__ for x in rs], ['Record'])
        self.assertEqual(rs[0].title, 'Bank login')

    def test_marker_with_notes_only_is_a_record(self):
        rs = self.import_rows(['Personal', '', '', '', '', 'a note', '', EMPTY_FOLDER_MARKER, 'true'])
        self.assertEqual([type(x).__name__ for x in rs], ['Record'])

    def test_marker_value_must_be_true(self):
        rs = self.import_rows(['Personal', '', '', '', '', '', '', EMPTY_FOLDER_MARKER, 'false'])
        self.assertEqual([type(x).__name__ for x in rs], ['Record'])

    def test_marker_row_is_an_empty_folder(self):
        rs = self.import_rows(['Personal', '', '', '', '', '', '', EMPTY_FOLDER_MARKER, 'true'])
        self.assertEqual(describe(rs), [('EmptyFolder', None, 'Personal')])


def folder_node(uid, name, parent_uid=None, type=BaseFolderNode.UserFolderType):
    node = BaseFolderNode(type)
    node.uid = uid
    node.name = name
    node.parent_uid = parent_uid
    return node


def vault_params(*nodes):
    return SimpleNamespace(folder_cache={n.uid: n for n in nodes})


class TestFindEmptyFolders(TestCase):
    def test_empty_leaf_is_found(self):
        params = vault_params(folder_node('a', 'A'), folder_node('b', 'B', 'a'))
        self.assertEqual(imp_exp.find_empty_folders(params, set()), ['b'])

    def test_parent_of_exported_folder_is_not_found(self):
        params = vault_params(folder_node('a', 'A'), folder_node('b', 'B', 'a'))
        self.assertEqual(imp_exp.find_empty_folders(params, {'b'}), [])

    def test_folder_with_exported_records_is_not_found(self):
        params = vault_params(folder_node('a', 'A'), folder_node('b', 'B', 'a'))
        self.assertEqual(imp_exp.find_empty_folders(params, {'a'}), ['b'])

    def test_folder_whose_records_were_not_exported_is_found(self):
        # e.g. --owned-only filtered out its shared records, so it is absent from exported_folder_uids
        params = vault_params(folder_node('a', 'A'))
        self.assertEqual(imp_exp.find_empty_folders(params, set()), ['a'])

    def test_chain_of_empty_folders_exports_only_the_leaf(self):
        params = vault_params(folder_node('a', 'A'), folder_node('b', 'B', 'a'), folder_node('c', 'C', 'b'))
        self.assertEqual(imp_exp.find_empty_folders(params, set()), ['c'])

    def test_folder_filter(self):
        params = vault_params(folder_node('a', 'A'), folder_node('b', 'B'))
        self.assertEqual(imp_exp.find_empty_folders(params, set(), {'b'}), ['b'])

    def test_shared_folder_only_when_requested(self):
        params = vault_params(folder_node('s', 'SF', type=BaseFolderNode.SharedFolderType))
        self.assertEqual(imp_exp.find_empty_folders(params, set()), [])
        self.assertEqual(imp_exp.find_empty_folders(params, set(), include_shared=True), ['s'])

    def test_shared_folder_subfolder(self):
        params = vault_params(folder_node('s', 'SF', type=BaseFolderNode.SharedFolderType),
                              folder_node('t', 'T', 's', BaseFolderNode.SharedFolderFolderType))
        self.assertEqual(imp_exp.find_empty_folders(params, set()), ['t'])
        self.assertEqual(imp_exp.find_empty_folders(params, set(), include_shared=True), ['t'])

    def test_nested_share_folder(self):
        params = vault_params(folder_node('n', 'N', type=BaseFolderNode.NestedShareFolderType))
        self.assertEqual(imp_exp.find_empty_folders(params, set()), ['n'])


class TestSourceImporters(TempFileMixin, TestCase):
    def test_bitwarden(self):
        path = self.tmp('.json')
        with open(path, 'w') as f:
            json.dump({
                'encrypted': False,
                'folders': [{'id': '1', 'name': 'Empty/Sub'}, {'id': '2', 'name': 'Used'}],
                'collections': [{'id': 'c', 'name': 'Col/in'}, {'id': 'd', 'name': 'TopOnly'}],
                'items': [{'type': 1, 'name': 'x', 'folderId': '2'}],
            }, f)
        items = list(BitwardenImporter().do_import(path))
        empties = [x for x in items if isinstance(x, importer.EmptyFolder)]
        self.assertEqual(describe(empties), [('EmptyFolder', None, 'Empty\\Sub'), ('EmptyFolder', 'Col', 'in')])
        # an empty top-level collection comes through as a shared folder
        self.assertEqual(sorted(x.path for x in items if isinstance(x, importer.SharedFolder)), ['Col', 'TopOnly'])

    def test_nordpass_folder_rows(self):
        path = self.tmp('.csv')
        with open(path, 'w', newline='') as f:
            w = csv.writer(f)
            w.writerow(['name', 'url', 'username', 'password', 'note', 'cardholdername', 'cardnumber', 'cvc',
                        'expirydate', 'zipcode', 'folder', 'full_name', 'phone_number', 'email', 'address1',
                        'address2', 'city', 'country', 'state', 'type'])
            w.writerow(['Work', '', '', '', '', '', '', '', '', '', 'Work', '', '', '', '', '', '', '', '', 'folder'])
            w.writerow(['site', 'https://a.example', 'u', 'p', '', '', '', '', '', '', '', '', '', '', '', '', '', '',
                        '', 'password'])
        items = list(NordpassCsvImporter().do_import(path))
        self.assertEqual([type(x).__name__ for x in items], ['EmptyFolder', 'Record'])
        self.assertEqual(items[0].folders[0].path, 'Work')


@skipUnless(PyKeePass, 'pykeepass is not installed')
class TestKeepassEmptyFolders(TempFileMixin, TestCase):
    def test_round_trip(self):
        path = self.tmp('.kdbx')
        with mock.patch('getpass.getpass', return_value='pw'), mock.patch('builtins.input', return_value=''):
            KeepassExporter().do_export(path, [
                empty_folder(path='A\\B'), empty_folder(path='sub', domain='SF'), record('r', path='X')],
                file_password='pw')
            imported = list(KeepassImporter().do_import(path))
        paths = sorted(x.folders[0].path for x in imported if isinstance(x, importer.EmptyFolder))
        self.assertEqual(paths, ['A\\B', 'SF\\sub'])

    def test_recycle_bin_group_is_detected(self):
        from pykeepass.group import Group
        bin_group = mock.Mock(spec=Group)
        bin_group.uuid = 'bin'
        bin_group.group = None
        child = mock.Mock(spec=Group)
        child.uuid = 'child'
        child.group = bin_group
        other = mock.Mock(spec=Group)
        other.uuid = 'other'
        other.group = None
        kdb = SimpleNamespace(recyclebin_group=bin_group)
        self.assertTrue(KeepassImporter.in_recycle_bin(kdb, bin_group))
        self.assertTrue(KeepassImporter.in_recycle_bin(kdb, child))
        self.assertFalse(KeepassImporter.in_recycle_bin(kdb, other))
        self.assertFalse(KeepassImporter.in_recycle_bin(SimpleNamespace(recyclebin_group=None), other))


class TestImportFlag(TempFileMixin, TestCase):
    def run_import(self, **kwargs):
        path = self.tmp('.json')
        with open(path, 'w') as f:
            json.dump({'empty_folders': [{'folder': 'A\\B'}], 'records': [{'title': 'r', 'folders': [{'folder': 'X'}]}]}, f)
        params = get_synced_params()
        with mock.patch.object(imp_exp, 'prepare_folder_add', return_value=[]) as prepare, \
                mock.patch.object(imp_exp.sync_down, 'sync_down'):
            imp_exp._import(params, 'json', path, dry_run=True, **kwargs)
        return prepare.call_args[0][2]  # records and empty folders handed to prepare_folder_add

    def test_empty_folders_ignored_without_flag(self):
        items = self.run_import()
        self.assertEqual([type(x).__name__ for x in items], ['Record'])

    def test_empty_folders_created_with_flag(self):
        items = self.run_import(include_empty_folders=True)
        self.assertEqual([type(x).__name__ for x in items], ['Record', 'EmptyFolder'])
