import unittest

from keepercommander.importer import commands
from keepercommander.importer.thycotic.thycotic import (
    DELINEA_RESTRICTED_SECRET_PERMISSION,
    ThycoticImporter,
    build_secrets_lookup_query,
    lookup_secret_ids,
    with_secret_access_params,
)

VISIBLE_ID = 7
RESTRICTED_ID = 4242


def _search(query):
    rows = [{'id': VISIBLE_ID, 'name': 'visible'}]
    if 'filter.includeRestricted=true' in query:
        rows.append({'id': RESTRICTED_ID, 'name': 'restricted'})
    return rows


class TestRestrictedLookup(unittest.TestCase):
    def test_parameter_is_on_every_lookup(self):
        tenant = build_secrets_lookup_query()
        folder = build_secrets_lookup_query(15)
        self.assertEqual(tenant, '/v1/secrets/lookup?filter.includeRestricted=true')
        self.assertEqual(
            folder,
            '/v1/secrets/lookup?filter.folderId=15&filter.includeSubFolders=true&filter.includeRestricted=true',
        )

    def test_restricted_ids_appear_only_when_enabled(self):
        self.assertEqual(lookup_secret_ids(_search), [VISIBLE_ID, RESTRICTED_ID])
        self.assertEqual(lookup_secret_ids(_search, include_restricted=False), [VISIBLE_ID])

        folder_default = lookup_secret_ids(_search, folder_ids=[15])
        folder_without = lookup_secret_ids(_search, folder_ids=[15], include_restricted=False)
        self.assertEqual(build_secrets_lookup_query(15),
                         '/v1/secrets/lookup?filter.folderId=15&filter.includeSubFolders=true&filter.includeRestricted=true')
        self.assertIn(RESTRICTED_ID, folder_default)
        self.assertNotIn(RESTRICTED_ID, folder_without)

    def test_include_restricted_flag_is_not_on_the_command(self):
        self.assertEqual(DELINEA_RESTRICTED_SECRET_PERMISSION, 'View Restricted Secret')
        flags = [
            option
            for action in commands.import_parser._actions
            for option in action.option_strings
        ]
        self.assertNotIn('--include-restricted', flags)
        self.assertNotIn('--report', flags)
        self.assertIn('View Restricted Secret', build_secrets_lookup_query.__doc__)

    def test_secret_read_sends_checkout_params(self):
        endpoint = with_secret_access_params('/v1/secrets/42')
        self.assertTrue(endpoint.startswith('/v1/secrets/42?'))
        self.assertIn('autoCheckout=true', endpoint)
        self.assertIn('autoCheckIn=true', endpoint)
        self.assertIn('autoComment=Checking+out', endpoint)
        field_endpoint = with_secret_access_params('/v1/secrets/42/fields/private-key')
        self.assertIn('autoCheckout=true', field_endpoint)


class TestThycoticTerminalSummary(unittest.TestCase):
    def test_uses_cyberark_finish_summary(self):
        self.assertTrue(ThycoticImporter.verbose_import_summary)


if __name__ == '__main__':
    unittest.main()
