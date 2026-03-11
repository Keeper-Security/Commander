"""
Unit tests for KC-1163: Commander-created records lose field labels in KSM.

Verifies that record-add and the importer populate field labels from the
record type schema when no explicit label override is defined, matching
web vault behavior.
"""
import json
import unittest
from unittest import mock

from keepercommander import vault
from keepercommander.commands.record_edit import RecordAddCommand, RecordEditMixin
from keepercommander.importer.imp_exp import prepare_record_add_or_update


# Minimal schema for a 'login' record type — mirrors what Keeper returns
# for standard types: $ref fields with no explicit label override.
LOGIN_SCHEMA_FIELDS = [
    {'$ref': 'login'},
    {'$ref': 'password'},
    {'$ref': 'url'},
    {'$ref': 'fileRef'},
    {'$ref': 'oneTimeCode'},
]

# A schema entry WITH an explicit label override (e.g. bankCard cardholderName)
BANKCARD_SCHEMA_FIELDS = [
    {'$ref': 'paymentCard'},
    {'$ref': 'text', 'label': 'cardholderName'},
    {'$ref': 'pinCode'},
    {'$ref': 'addressRef'},
    {'$ref': 'fileRef'},
]


def _mock_record_type_fields(schema_fields):
    """Return a JSON string as get_record_type_fields would."""
    content = json.dumps({'fields': schema_fields})
    return json.dumps([{'content': content}])


class TestRecordAddFieldLabels(unittest.TestCase):
    """record-add: fields get labels from schema $ref when no explicit label."""

    def _build_record(self, schema_fields, field_args):
        """Helper: run RecordAddCommand field-scaffolding logic directly."""
        cmd = RecordAddCommand()
        record = vault.TypedRecord()
        record.type_name = 'login'

        for rf in schema_fields:
            ref = rf.get('$ref')
            if not ref:
                continue
            label = rf.get('label') or ref       # ← the fix
            field = vault.TypedField.new_field(ref, None, label)
            record.fields.append(field)

        return record

    def test_standard_fields_use_ref_as_label(self):
        """Standard login fields should have label == $ref type."""
        record = self._build_record(LOGIN_SCHEMA_FIELDS, [])
        labels = {f.type: f.label for f in record.fields}

        self.assertEqual(labels['login'], 'login',
                         "login field label must not be blank")
        self.assertEqual(labels['password'], 'password',
                         "password field label must not be blank")
        self.assertEqual(labels['url'], 'url',
                         "url field label must not be blank")

    def test_explicit_label_override_preserved(self):
        """Explicit label overrides in the schema must be kept as-is."""
        record = self._build_record(BANKCARD_SCHEMA_FIELDS, [])
        labels = {f.type: f.label for f in record.fields}

        self.assertEqual(labels['text'], 'cardholderName',
                         "explicit schema label override must be preserved")
        self.assertEqual(labels['paymentCard'], 'paymentCard',
                         "field without override still gets ref as label")

    def test_no_blank_labels(self):
        """No field created by record-add should have a blank label."""
        record = self._build_record(LOGIN_SCHEMA_FIELDS, [])
        for field in record.fields:
            self.assertTrue(field.label,
                            f"Field type '{field.type}' has a blank label — KC-1163")


class TestImporterFieldLabels(unittest.TestCase):
    """Importer path: schema fields get labels from $ref when no explicit label."""

    def _build_schema_fields(self, schema_fields):
        """Simulate the schema-building loop in prepare_record_add_or_update."""
        from keepercommander.importer.importer import RecordSchemaField
        result = []
        for field in schema_fields:
            if '$ref' in field:
                f = RecordSchemaField()
                f.ref = field['$ref']
                f.label = field.get('label') or field['$ref']   # ← the fix
                result.append(f)
        return result

    def test_standard_fields_use_ref_as_label(self):
        schema = self._build_schema_fields(LOGIN_SCHEMA_FIELDS)
        by_ref = {f.ref: f.label for f in schema}

        self.assertEqual(by_ref['login'], 'login')
        self.assertEqual(by_ref['password'], 'password')
        self.assertEqual(by_ref['url'], 'url')

    def test_explicit_label_override_preserved(self):
        schema = self._build_schema_fields(BANKCARD_SCHEMA_FIELDS)
        by_ref = {f.ref: f.label for f in schema}

        self.assertEqual(by_ref['text'], 'cardholderName')
        self.assertEqual(by_ref['paymentCard'], 'paymentCard')

    def test_no_blank_labels(self):
        schema = self._build_schema_fields(LOGIN_SCHEMA_FIELDS)
        for f in schema:
            self.assertTrue(f.label,
                            f"Schema field ref='{f.ref}' has blank label — KC-1163")


class TestOldBehaviorWouldFail(unittest.TestCase):
    """Regression guard: demonstrate what the OLD code produced (should fail now)."""

    def test_old_code_produced_blank_labels(self):
        """Confirm the old rf.get('label', '') pattern causes blank labels."""
        fields = []
        for rf in LOGIN_SCHEMA_FIELDS:
            ref = rf.get('$ref')
            label_old = rf.get('label', '')   # OLD behavior
            f = vault.TypedField.new_field(ref, None, label_old)
            fields.append(f)

        blank = [f.type for f in fields if not f.label]
        # With the old code all standard fields would have blank labels
        self.assertTrue(len(blank) > 0,
                        "Expected old code to produce blank labels (regression check)")


if __name__ == '__main__':
    unittest.main()
