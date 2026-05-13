import unittest

from keepercommander.commands.keeper_tenant_migrate.email_remap import (
    infer_domains_from_spec,
    remap_email,
    remap_many,
    remap_rows,
    summarize_remap,
    validate_domain,
)


class RemapEmailTests(unittest.TestCase):
    def test_happy_path(self):
        self.assertEqual(
            remap_email('alice@acme.com', 'acme.com', 'acme.io'),
            'alice@acme.io',
        )

    def test_pass_through_when_old_domain_empty(self):
        self.assertEqual(
            remap_email('alice@acme.com', '', 'acme.io'),
            'alice@acme.com',
        )

    def test_pass_through_when_new_domain_empty(self):
        self.assertEqual(
            remap_email('alice@acme.com', 'acme.com', ''),
            'alice@acme.com',
        )

    def test_pass_through_when_domain_mismatches(self):
        self.assertEqual(
            remap_email('alice@other.com', 'acme.com', 'acme.io'),
            'alice@other.com',
        )

    def test_case_insensitive_domain_match(self):
        self.assertEqual(
            remap_email('Alice@Acme.COM', 'acme.com', 'acme.io'),
            'Alice@acme.io',   # local-part case preserved
        )

    def test_empty_input_returns_empty(self):
        self.assertEqual(remap_email('', 'a.com', 'b.com'), '')

    def test_none_input_passes_through(self):
        # remap_email is permissive — a None email with no @ passes the
        # helper's "no local-part, no remap" guard unchanged.
        self.assertIsNone(remap_email(None, 'a.com', 'b.com'))

    def test_bare_word_no_at_returns_unchanged(self):
        self.assertEqual(remap_email('bogus', 'a.com', 'b.com'), 'bogus')


class RemapManyTests(unittest.TestCase):
    def test_preserves_order_and_nonmatches(self):
        got = remap_many(
            ['a@x.com', 'b@y.com', 'c@x.com'],
            'x.com', 'z.com',
        )
        self.assertEqual(got, ['a@z.com', 'b@y.com', 'c@z.com'])


class RemapRowsTests(unittest.TestCase):
    def test_annotates_original_field(self):
        rows = [{'email': 'a@x.com', 'name': 'Alice'}]
        out = remap_rows(rows, 'email', 'x.com', 'y.com')
        self.assertEqual(out[0]['email'], 'a@y.com')
        self.assertEqual(out[0]['_email_original'], 'a@x.com')
        self.assertEqual(out[0]['name'], 'Alice')

    def test_unmatched_row_has_no_annotation(self):
        rows = [{'email': 'a@other.com'}]
        out = remap_rows(rows, 'email', 'x.com', 'y.com')
        self.assertNotIn('_email_original', out[0])

    def test_missing_field_is_left_alone(self):
        rows = [{'name': 'Alice'}]
        out = remap_rows(rows, 'email', 'x.com', 'y.com')
        self.assertEqual(out, [{'name': 'Alice'}])


class ValidateDomainTests(unittest.TestCase):
    def test_empty_is_ok(self):
        self.assertEqual(validate_domain(''), '')

    def test_rejects_at_sign(self):
        self.assertIn('@', validate_domain('a@b.com'))

    def test_rejects_no_dot(self):
        self.assertIn('dot', validate_domain('localhost'))

    def test_accepts_normal_domain(self):
        self.assertEqual(validate_domain('acme.io'), '')


class SummarizeRemapTests(unittest.TestCase):
    def test_counts_and_examples(self):
        summary = summarize_remap(
            'acme.com', 'acme.io',
            ['alice@acme.com', 'bob@acme.com', 'eve@other.com'],
        )
        self.assertEqual(summary['matched'], 2)
        self.assertEqual(summary['unchanged'], 1)
        self.assertEqual(len(summary['examples']), 2)


class InferDomainsTests(unittest.TestCase):
    def test_explicit_email_remap_key_wins(self):
        spec = {'email_remap': {'old_domain': 'a.com', 'new_domain': 'b.com'}}
        self.assertEqual(infer_domains_from_spec(spec), ('a.com', 'b.com'))

    def test_falls_back_to_source_target_email_domain(self):
        spec = {'source': {'email_domain': 'a.com'},
                'target': {'email_domain': 'b.com'}}
        self.assertEqual(infer_domains_from_spec(spec), ('a.com', 'b.com'))

    def test_returns_empty_when_same_domain(self):
        spec = {'source': {'email_domain': 'a.com'},
                'target': {'email_domain': 'a.com'}}
        self.assertEqual(infer_domains_from_spec(spec), ('', ''))

    def test_empty_spec_returns_empty(self):
        self.assertEqual(infer_domains_from_spec({}), ('', ''))
        self.assertEqual(infer_domains_from_spec(None), ('', ''))


if __name__ == '__main__':
    unittest.main()
