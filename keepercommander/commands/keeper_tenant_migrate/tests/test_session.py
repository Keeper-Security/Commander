import unittest

from keepercommander.commands.keeper_tenant_migrate.session import (
    detect_session,
    detect_session_role,
    format_session_banner,
)


class _FakeParams:
    def __init__(self, user='', server='', enterprise=None,
                  session_token='fake'):
        self.user = user
        self.server = server
        self.enterprise = enterprise or {}
        self.session_token = session_token


class DetectSessionTests(unittest.TestCase):
    def test_all_fields_populated(self):
        p = _FakeParams(user='a@x', server='keepersecurity.eu',
                        enterprise={'enterprise_name': 'Acme',
                                    'managed_companies': [{'id': 1}]})
        ctx = detect_session(p)
        self.assertEqual(ctx['user'], 'a@x')
        self.assertEqual(ctx['region'], 'EU')
        self.assertEqual(ctx['enterprise_name'], 'Acme')
        self.assertTrue(ctx['is_msp'])
        self.assertEqual(ctx['mc_count'], 1)

    def test_empty_session(self):
        ctx = detect_session(_FakeParams(session_token=''))
        self.assertFalse(ctx['session_token_present'])

    def test_region_detection_for_each_server(self):
        mapping = {
            'keepersecurity.com': 'US',
            'keepersecurity.eu': 'EU',
            'keepersecurity.com.au': 'AU',
            'keepersecurity.ca': 'CA',
            'keepersecurity.jp': 'JP',
            'govcloud.keepersecurity.us': 'GOV',
        }
        for server, expected in mapping.items():
            ctx = detect_session(_FakeParams(server=server))
            self.assertEqual(ctx['region'], expected,
                             f'{server!r} should map to {expected!r}')


class DetectSessionRoleTests(unittest.TestCase):
    def test_matches_source_by_enterprise_name(self):
        p = _FakeParams(enterprise={'enterprise_name': 'Acme Corp'})
        spec = {'source': {'enterprise_name': 'acme corp'}}
        self.assertEqual(detect_session_role(p, spec), 'source')

    def test_matches_target_by_user(self):
        p = _FakeParams(user='admin@target.io')
        spec = {'target': {'user': 'ADMIN@TARGET.IO'}}
        self.assertEqual(detect_session_role(p, spec), 'target')

    def test_matches_source_by_region_plus_tenant_type(self):
        p = _FakeParams(server='keepersecurity.eu')
        spec = {'source': {'region': 'EU', 'tenant_type': 'enterprise'}}
        self.assertEqual(detect_session_role(p, spec), 'source')

    def test_no_match_returns_unknown(self):
        p = _FakeParams(user='a@x')
        spec = {'source': {'user': 'b@y'},
                'target': {'user': 'c@z'}}
        self.assertEqual(detect_session_role(p, spec), 'unknown')

    def test_empty_context_returns_unknown(self):
        p = _FakeParams()
        self.assertEqual(detect_session_role(p, {'source': {'user': 'x'}}),
                         'unknown')


class FormatBannerTests(unittest.TestCase):
    def test_banner_contains_user_and_region(self):
        p = _FakeParams(user='a@x', server='keepersecurity.eu',
                        enterprise={'enterprise_name': 'Acme'})
        text = format_session_banner(detect_session(p))
        self.assertIn('a@x', text)
        self.assertIn('EU', text)
        self.assertIn('Acme', text)

    def test_no_session_banner(self):
        ctx = detect_session(_FakeParams(session_token=''))
        self.assertIn('No active session', format_session_banner(ctx))


if __name__ == '__main__':
    unittest.main()
