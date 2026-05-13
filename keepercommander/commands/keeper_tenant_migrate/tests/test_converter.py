import json
import os
import subprocess
import sys
import tempfile
import unittest

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), 'fixtures')
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
LEGACY_SCRIPT = os.path.join(REPO_ROOT, 'migration_scripts', 'convert_v3_to_import.py')

sys.path.insert(0, REPO_ROOT)

from keepercommander.commands.keeper_tenant_migrate.converter import (  # noqa: E402
    RecordConverter,
    convert_v3_record,
    extract_field_value,
    extract_record_dependencies,
    topological_sort_records,
)



# Module-level guard: tests below depend on the rehearsal harness or
# legacy reference script under `migration_scripts/`, which ships
# separately from the Commander tree. When absent, the dependent
# classes are skipped.
import os as _os
_HARNESS_DIR = _os.path.abspath(_os.path.join(
    _os.path.dirname(__file__), '..', '..', '..', '..', 'migration_scripts'))
_HAS_HARNESS = _os.path.isdir(_HARNESS_DIR)

class ExtractFieldValueTests(unittest.TestCase):
    def test_returns_scalar_for_single_value(self):
        fields = [{'type': 'login', 'value': ['alice@example.com']}]
        self.assertEqual(extract_field_value(fields, 'login'), 'alice@example.com')

    def test_returns_list_for_multi_value(self):
        fields = [{'type': 'url', 'value': ['a', 'b']}]
        self.assertEqual(extract_field_value(fields, 'url'), ['a', 'b'])

    def test_returns_empty_for_missing_type(self):
        self.assertEqual(extract_field_value([{'type': 'login', 'value': ['x']}], 'password'), '')

    def test_returns_empty_for_non_list_input(self):
        self.assertEqual(extract_field_value(None, 'login'), '')


class ConvertRecordTests(unittest.TestCase):
    def test_preserves_type_defaulting_to_login(self):
        # Bug 34 — Commander's KeeperJsonImporter reads `$type`, not
        # `type`. Verify the converted record uses the correct key.
        self.assertEqual(
            convert_v3_record({'title': 't', 'type': 'encryptedNotes'})['$type'],
            'encryptedNotes')
        self.assertEqual(convert_v3_record({'title': 't'})['$type'], 'login')

    def test_totp_goes_to_custom_fields_dict(self):
        # Bug 39 — TOTP fields land under `$oneTimeCode` (no redundant
        # `:oneTimeCode` label). Commander parses `$type` as a typed
        # field with empty label — matches source records' shape.
        rec = {
            'title': 'T',
            'type': 'login',
            'fields': [{'type': 'oneTimeCode', 'value': ['otpauth://totp/x?secret=ABC']}],
        }
        result = convert_v3_record(rec)
        self.assertIn('custom_fields', result)
        self.assertEqual(result['custom_fields']['$oneTimeCode'],
                         'otpauth://totp/x?secret=ABC')

    def test_fileref_is_excluded(self):
        rec = {
            'title': 'T',
            'fields': [{'type': 'fileRef', 'value': ['fileuid-1', 'fileuid-2']}],
        }
        result = convert_v3_record(rec)
        self.assertNotIn('custom_fields', result)

    def test_custom_text_field_uses_label_as_key(self):
        rec = {
            'title': 'T',
            'custom': [{'type': 'text', 'label': 'Environment', 'value': ['Production']}],
        }
        result = convert_v3_record(rec)
        self.assertEqual(result['custom_fields']['$text:Environment'], 'Production')

    def test_empty_custom_value_is_dropped(self):
        rec = {
            'title': 'T',
            'custom': [{'type': 'text', 'label': 'Empty', 'value': ['']}],
        }
        self.assertNotIn('custom_fields', convert_v3_record(rec))

    def test_duplicate_custom_label_gets_numeric_suffix(self):
        rec = {
            'title': 'T',
            'custom': [
                {'type': 'text', 'label': 'Env', 'value': ['dev']},
                {'type': 'text', 'label': 'Env', 'value': ['prod']},
            ],
        }
        result = convert_v3_record(rec)
        self.assertEqual(result['custom_fields']['$text:Env'], 'dev')
        self.assertEqual(result['custom_fields']['$text:Env:2'], 'prod')

    def test_client_modified_time_epoch_seconds_becomes_millis(self):
        self.assertEqual(convert_v3_record({'title': 't', 'client_modified_time': 1700000000})['last_modified'],
                         1700000000000)

    def test_client_modified_time_iso_becomes_epoch_millis(self):
        out = convert_v3_record({'title': 't', 'client_modified_time': '2026-04-18T10:00:00Z'})
        self.assertIn('last_modified', out)
        self.assertIsInstance(out['last_modified'], int)


@unittest.skipUnless(_HAS_HARNESS, "requires migration_scripts/ harness (not shipped with Commander)")
class LegacyScriptEquivalenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def _legacy_output(self):
        legacy_out = os.path.join(self.tmp, 'legacy.json')
        subprocess.run(
            [sys.executable, LEGACY_SCRIPT, '--input-dir', FIXTURE_DIR, '--output', legacy_out],
            check=True, capture_output=True,
        )
        with open(legacy_out) as f:
            return json.load(f)

    def _converter_output(self):
        new_out = os.path.join(self.tmp, 'new.json')
        converter = RecordConverter()
        converter.run(FIXTURE_DIR, new_out)
        with open(new_out) as f:
            return json.load(f)

    def test_record_count_matches(self):
        self.assertEqual(len(self._legacy_output()['records']),
                         len(self._converter_output()['records']))

    def test_record_bodies_match_by_title(self):
        legacy = {r['title']: r for r in self._legacy_output()['records']}
        new = {r['title']: r for r in self._converter_output()['records']}
        self.assertEqual(set(legacy.keys()), set(new.keys()))
        for title, lrec in legacy.items():
            # Bug 34 — the legacy bash script emitted `type`, which
            # Commander's importer silently ignored (every record
            # imported as `login`). New converter emits `$type` per
            # Commander's KeeperJsonImporter contract. Normalize both
            # sides to compare structural equivalence; the new key is
            # itself covered by ConvertRecordTests.test_preserves_type_*.
            l_norm = {k: v for k, v in lrec.items() if k != 'type'}
            l_type = lrec.get('type')
            n_norm = {k: v for k, v in new[title].items() if k != '$type'}
            n_type = new[title].get('$type')
            self.assertEqual(l_type, n_type,
                             f'Type drift on record: {title}')
            self.assertEqual(l_norm, n_norm,
                             f'Mismatch on record: {title}')


class SplitByTypeFilenameSanitizationTests(unittest.TestCase):
    """Bug 30 — record types whose names came from imported file MIME
    types (`image/png`, `application/json`, …) or operator-named
    enterprise templates with spaces would crash _write_split with
    FileNotFoundError because the `/` was treated as a path separator.
    """

    def test_sanitize_basic_alnum_passthrough(self):
        self.assertEqual(
            RecordConverter._sanitize_for_filename('login'), 'login')
        self.assertEqual(
            RecordConverter._sanitize_for_filename('pamUser'), 'pamUser')

    def test_sanitize_replaces_path_separators(self):
        self.assertEqual(
            RecordConverter._sanitize_for_filename('image/png'), 'image_png')
        self.assertEqual(
            RecordConverter._sanitize_for_filename('application/x-sh'),
            'application_x-sh')
        # Hyphens are kept, underscores replace path-unsafe chars.

    def test_sanitize_replaces_spaces(self):
        self.assertEqual(
            RecordConverter._sanitize_for_filename('Multiple creds for docker'),
            'Multiple_creds_for_docker')

    def test_sanitize_handles_backslash_and_colon(self):
        # Both colon and backslash become underscores; consecutive
        # unsafe chars produce consecutive underscores (no collapsing).
        self.assertEqual(
            RecordConverter._sanitize_for_filename('C:\\foo'), 'C__foo')

    def test_sanitize_empty_input_returns_default(self):
        self.assertEqual(RecordConverter._sanitize_for_filename(''), 'untyped')
        self.assertEqual(
            RecordConverter._sanitize_for_filename('___'), 'untyped')

    def test_split_writes_unique_files_for_each_type(self):
        """Live regression: two record types whose names sanitize to the
        same slug must not overwrite each other (numeric suffix)."""
        with tempfile.TemporaryDirectory() as td:
            output_path = os.path.join(td, 'out.json')
            conv = RecordConverter(split_by_type=True)
            # Records here are already in import-bundle shape ($type
            # per Bug 34), since _write_split runs post-convert.
            recs = [
                {'title': 'A', '$type': 'image/png', 'login': 'a'},
                {'title': 'B', '$type': 'image_png', 'login': 'b'},
                {'title': 'C', '$type': 'login', 'login': 'c'},
            ]
            written = conv._write_split(recs, [], output_path)
            # 3 type files + 1 batch file
            self.assertEqual(len(written), 4)
            slugs = sorted(os.path.basename(w) for w in written
                           if w.endswith('.json'))
            # image/png → out_image_png.json
            # image_png → out_image_png_2.json (collision suffix)
            # login → out_login.json
            self.assertIn('out_image_png.json', slugs)
            self.assertIn('out_image_png_2.json', slugs)
            self.assertIn('out_login.json', slugs)

    def test_split_handles_mime_type_records_end_to_end(self):
        """The exact failure mode from 2026-04-28 EU full-vault convert:
        record type `application/json` produced
        `out_application/json.json` with split-by-type, FileNotFoundError.
        """
        with tempfile.TemporaryDirectory() as td:
            output_path = os.path.join(td, 'out.json')
            conv = RecordConverter(split_by_type=True)
            recs = [{'title': 'cfg', '$type': 'application/json',
                     'login': 'x'}]
            written = conv._write_split(recs, [], output_path)
            # Pre-fix: FileNotFoundError on
            # /tmp/.../out_application/json.json
            self.assertEqual(len(written), 2)  # 1 type file + 1 batch
            type_file = [w for w in written if w.endswith('.json')][0]
            self.assertTrue(os.path.isfile(type_file),
                            f'expected file at {type_file}')

    def test_split_batch_file_uses_original_record_type_arg(self):
        """The sanitized slug is filesystem-only; Commander's
        `--record-type` argument inside the batch file must be the
        original record type string so import lands on the right type
        on the target."""
        with tempfile.TemporaryDirectory() as td:
            output_path = os.path.join(td, 'out.json')
            conv = RecordConverter(split_by_type=True)
            recs = [{'title': 'A', '$type': 'image/png'}]
            written = conv._write_split(recs, [], output_path)
            batch_file = [w for w in written
                          if w.endswith('.batch')][0]
            with open(batch_file) as f:
                batch_text = f.read()
            self.assertIn('--record-type "image/png"', batch_text)


class Bug87ExtractRecordDependenciesTests(unittest.TestCase):
    """Bug 87 — pre-import topological-sort dependency extraction."""

    def test_no_refs_returns_empty_set(self):
        rec = {
            'record_uid': 'A',
            'fields': [{'type': 'login', 'value': ['x']}],
        }
        self.assertEqual(extract_record_dependencies(rec), set())

    def test_top_level_fileref_field_extracts_uids(self):
        rec = {
            'record_uid': 'A',
            'fields': [{'type': 'fileRef', 'value': ['B', 'C']}],
        }
        self.assertEqual(extract_record_dependencies(rec), {'B', 'C'})

    def test_nested_script_fileref_extracts_uid(self):
        # Real shape from PAM USER postgresrotation in rehearsal-15.
        rec = {
            'record_uid': 'PAMUSER',
            'fields': [{
                'type': 'script',
                'label': 'rotationScripts',
                'value': [{
                    'command': '',
                    'fileRef': 'SCRIPT_REC',
                    'recordRef': [],
                }],
            }],
        }
        self.assertEqual(extract_record_dependencies(rec), {'SCRIPT_REC'})

    def test_pam_settings_http_credentials_extracted(self):
        rec = {
            'record_uid': 'PAM',
            'fields': [{
                'type': 'pamSettings',
                'value': [{
                    'connection': {'httpCredentialsUid': 'CREDS'},
                }],
            }],
        }
        self.assertEqual(extract_record_dependencies(rec), {'CREDS'})

    def test_record_ref_field_extracts_list_of_uids(self):
        rec = {
            'record_uid': 'A',
            'fields': [{'type': 'recordRef', 'value': ['X', 'Y', 'Z']}],
        }
        self.assertEqual(extract_record_dependencies(rec), {'X', 'Y', 'Z'})

    def test_self_reference_filtered_out(self):
        rec = {
            'record_uid': 'A',
            'fields': [{'type': 'fileRef', 'value': ['A', 'B']}],
        }
        # A → A is dropped; we never wait on ourselves.
        self.assertEqual(extract_record_dependencies(rec), {'B'})

    def test_custom_fields_walked(self):
        rec = {
            'record_uid': 'A',
            'fields': [],
            'custom': [{'type': 'fileRef', 'label': 'extra', 'value': ['X']}],
        }
        self.assertEqual(extract_record_dependencies(rec), {'X'})


class Bug87TopologicalSortTests(unittest.TestCase):
    """Bug 87 — referenced records sort before referencing ones."""

    def test_simple_dependency_reorders(self):
        a = {'record_uid': 'A', 'title': 'A',
             'fields': [{'type': 'fileRef', 'value': ['B']}]}
        b = {'record_uid': 'B', 'title': 'B', 'fields': []}
        # Incoming order: [A, B] (referencer first). After sort: [B, A].
        ordered = topological_sort_records([a, b])
        self.assertEqual([r['record_uid'] for r in ordered], ['B', 'A'])

    def test_no_deps_preserves_incoming_order(self):
        recs = [
            {'record_uid': 'X', 'title': 'X', 'fields': []},
            {'record_uid': 'Y', 'title': 'Y', 'fields': []},
            {'record_uid': 'Z', 'title': 'Z', 'fields': []},
        ]
        ordered = topological_sort_records(recs)
        self.assertEqual([r['record_uid'] for r in ordered], ['X', 'Y', 'Z'])

    def test_external_uid_dep_treated_as_no_edge(self):
        # A references EXTERNAL (not in source set). No reorder pressure.
        a = {'record_uid': 'A', 'title': 'A',
             'fields': [{'type': 'fileRef', 'value': ['EXTERNAL']}]}
        b = {'record_uid': 'B', 'title': 'B', 'fields': []}
        ordered = topological_sort_records([a, b])
        self.assertEqual([r['record_uid'] for r in ordered], ['A', 'B'])

    def test_chain_dependency_resolves_in_order(self):
        # A → B → C. Incoming [A, B, C]. Output [C, B, A].
        a = {'record_uid': 'A', 'title': 'A',
             'fields': [{'type': 'fileRef', 'value': ['B']}]}
        b = {'record_uid': 'B', 'title': 'B',
             'fields': [{'type': 'fileRef', 'value': ['C']}]}
        c = {'record_uid': 'C', 'title': 'C', 'fields': []}
        ordered = topological_sort_records([a, b, c])
        self.assertEqual([r['record_uid'] for r in ordered], ['C', 'B', 'A'])

    def test_cycle_falls_back_to_incoming_order(self):
        # A → B and B → A — cyclic. Should not infinite-loop.
        a = {'record_uid': 'A', 'title': 'A',
             'fields': [{'type': 'fileRef', 'value': ['B']}]}
        b = {'record_uid': 'B', 'title': 'B',
             'fields': [{'type': 'fileRef', 'value': ['A']}]}
        ordered = topological_sort_records([a, b])
        self.assertEqual(set(r['record_uid'] for r in ordered), {'A', 'B'})
        self.assertEqual(len(ordered), 2)

    def test_real_pam_user_script_fileref_pattern(self):
        # Reproduces rehearsal-15 PAM USER postgresrotation shape.
        date_script = {
            'record_uid': 'ZDIfcH_dNqeYqdyidZo9lw',
            'title': 'Date script.sh',
            'type': 'file',
            'fields': [],
        }
        pam_user = {
            'record_uid': 'YNIlPjSoChzOme_gcjcjzQ',
            'title': 'PAM USER postgresrotation',
            'type': 'pamUser',
            'fields': [{
                'type': 'script',
                'label': 'rotationScripts',
                'value': [{
                    'command': '',
                    'fileRef': 'ZDIfcH_dNqeYqdyidZo9lw',
                    'recordRef': [],
                }],
            }],
        }
        # Incoming order: PAM USER first (referencer), Date script after.
        ordered = topological_sort_records([pam_user, date_script])
        self.assertEqual(
            [r['record_uid'] for r in ordered],
            ['ZDIfcH_dNqeYqdyidZo9lw', 'YNIlPjSoChzOme_gcjcjzQ'],
        )


class Bug87ConverterIntegrationTests(unittest.TestCase):
    """Bug 87 — RecordConverter.convert applies topological sort."""

    def test_convert_reorders_dependent_records(self):
        a = {'record_uid': 'A', 'title': 'A', 'type': 'login',
             'fields': [{'type': 'fileRef', 'value': ['B']}]}
        b = {'record_uid': 'B', 'title': 'B', 'type': 'login', 'fields': []}
        conv = RecordConverter()
        import_records, _ = conv.convert([a, b], record_to_sf={})
        self.assertEqual(
            [r['title'] for r in import_records],
            ['B', 'A'],
        )


if __name__ == '__main__':
    unittest.main()
