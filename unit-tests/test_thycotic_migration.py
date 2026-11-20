import contextlib
import io
import unittest
from unittest import mock

import requests

from keepercommander.importer import commands
from keepercommander.importer.thycotic.thycotic import (
    ThycoticAttachment,
    ThycoticAuth,
    ThycoticImporter,
    build_secrets_lookup_query,
    get_secret_access_param_names,
    get_secret_access_params,
    lookup_secret_ids,
    with_secret_access_params,
)

VISIBLE_ID = 7
RESTRICTED_ID = 4242
SHARED_ID = 99
CHECKOUT_QUERY = 'autoCheckout=true&autoCheckIn=true&autoComment=Checking%20out'
PLAIN_QUERY = 'autoCheckout=false&autoComment=Checking%20out&noAutoCheckout=true'
REQUESTS_GET = 'keepercommander.importer.thycotic.thycotic.requests.get'
SLEEP = 'keepercommander.importer.thycotic.thycotic.time.sleep'


def _search(query):
    rows = [{'id': VISIBLE_ID, 'name': 'visible'}]
    if 'filter.includeRestricted=true' in query:
        rows.append({'id': RESTRICTED_ID, 'name': 'restricted'})
    return rows


def _response(status_code, text='', json_value=None, reason=''):
    rs = mock.Mock(spec=requests.Response)
    rs.status_code = status_code
    rs.text = text
    rs.reason = reason
    if json_value is None:
        rs.json.side_effect = ValueError('Expecting value')
    else:
        rs.json.return_value = json_value
    return rs


def _checkout_required():
    return _response(400, '{"message": "API_SecretRequiresCheckout"}', {'message': 'API_SecretRequiresCheckout'})


def _auth():
    auth = ThycoticAuth('https://ss.example.com/SecretServer')
    auth.access_token = 'token'
    auth.expires_in = 3600
    auth.last_login = 2 ** 40
    return auth


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
        self.assertIn(RESTRICTED_ID, lookup_secret_ids(_search, folder_ids=[15]))
        self.assertNotIn(RESTRICTED_ID, lookup_secret_ids(_search, folder_ids=[15], include_restricted=False))

    def test_include_restricted_flag_is_not_on_the_command(self):
        flags = [
            option
            for action in commands.import_parser._actions
            for option in action.option_strings
        ]
        self.assertNotIn('--include-restricted', flags)
        self.assertNotIn('--report', flags)


class TestLookupDeduplication(unittest.TestCase):
    def test_secret_in_overlapping_folders_is_returned_once(self):
        # Folder 20 is a subfolder of 10; both match the folder filter, and
        # includeSubFolders=true makes folder 10 return folder 20's secrets too.
        by_folder = {
            '10': [{'id': VISIBLE_ID}, {'id': SHARED_ID}],
            '20': [{'id': SHARED_ID}, {'id': RESTRICTED_ID}],
        }

        def search(query):
            folder_id = query.split('filter.folderId=')[1].split('&')[0]
            return by_folder[folder_id]

        ids = lookup_secret_ids(search, folder_ids=[10, 20])
        self.assertEqual(ids, [VISIBLE_ID, SHARED_ID, RESTRICTED_ID])

    def test_same_folder_listed_twice_is_returned_once(self):
        ids = lookup_secret_ids(_search, folder_ids=[15, 15])
        self.assertEqual(ids, [VISIBLE_ID, RESTRICTED_ID])


class TestSecretAccessParams(unittest.TestCase):
    def test_default_is_plain_read_params(self):
        self.assertEqual(with_secret_access_params('/v1/secrets/42'), f'/v1/secrets/42?{PLAIN_QUERY}')
        self.assertEqual(
            with_secret_access_params('/v1/secrets/42', enabled=False),
            f'/v1/secrets/42?{PLAIN_QUERY}',
        )

    def test_enabled_sends_checkout_params(self):
        self.assertEqual(
            with_secret_access_params('/v1/secrets/42', enabled=True),
            f'/v1/secrets/42?{CHECKOUT_QUERY}',
        )
        self.assertEqual(
            with_secret_access_params('/v1/secrets/42/fields/private-key', enabled=True),
            f'/v1/secrets/42/fields/private-key?{CHECKOUT_QUERY}',
        )

    def test_enabled_does_not_send_no_auto_checkout(self):
        self.assertNotIn('noAutoCheckout', with_secret_access_params('/v1/secrets/42', enabled=True))

    def test_plain_read_does_not_check_in(self):
        self.assertNotIn('autoCheckIn', with_secret_access_params('/v1/secrets/42', enabled=False))

    def test_param_helpers(self):
        self.assertEqual(
            tuple(get_secret_access_params(True)),
            (('autoCheckout', 'true'), ('autoCheckIn', 'true'), ('autoComment', 'Checking out')),
        )
        self.assertEqual(
            tuple(get_secret_access_params(False)),
            (('autoCheckout', 'false'), ('autoComment', 'Checking out'), ('noAutoCheckout', 'true')),
        )
        self.assertEqual(set(get_secret_access_param_names(True)), {'autoCheckout', 'autoCheckIn', 'autoComment'})
        self.assertEqual(set(get_secret_access_param_names(False)), {'autoCheckout', 'autoComment', 'noAutoCheckout'})

    def test_space_is_percent_encoded(self):
        for enabled in (False, True):
            endpoint = with_secret_access_params('/v1/secrets/42', enabled=enabled)
            self.assertIn('autoComment=Checking%20out', endpoint)
            self.assertNotIn('+', endpoint)

    def test_existing_query_params_are_kept(self):
        endpoint = with_secret_access_params('/v1/secrets/42?includeInactive=true', enabled=True)
        self.assertEqual(endpoint, f'/v1/secrets/42?includeInactive=true&{CHECKOUT_QUERY}')
        endpoint = with_secret_access_params('/v1/secrets/42?includeInactive=true')
        self.assertEqual(endpoint, f'/v1/secrets/42?includeInactive=true&{PLAIN_QUERY}')

    def test_existing_checkout_params_are_replaced_not_duplicated(self):
        endpoint = with_secret_access_params('/v1/secrets/42?autoCheckout=false&autoComment=old', enabled=True)
        self.assertEqual(endpoint.count('autoCheckout='), 1)
        self.assertEqual(endpoint.count('autoComment='), 1)
        self.assertIn('autoCheckout=true', endpoint)
        self.assertNotIn('autoComment=old', endpoint)

    def test_round_trip_is_stable(self):
        for enabled in (False, True):
            once = with_secret_access_params('/v1/secrets/42', enabled=enabled)
            self.assertEqual(with_secret_access_params(once, enabled=enabled), once)


class TestFetchThycoticSecret(unittest.TestCase):
    def setUp(self):
        sleep = mock.patch(SLEEP)
        sleep.start()
        self.addCleanup(sleep.stop)

    def test_plain_read_success_does_not_check_out(self):
        with mock.patch(REQUESTS_GET, return_value=_response(200, '{"id": 42}', {'id': 42})) as get:
            secret, status, message = _auth().fetch_thycotic_secret(42)
        self.assertEqual(secret, {'id': 42})
        self.assertIsNone(status)
        self.assertIsNone(message)
        self.assertEqual(get.call_count, 1)
        self.assertTrue(get.call_args[0][0].endswith(f'/api/v1/secrets/42?{PLAIN_QUERY}'))

    def test_retries_with_checkout_when_checkout_required(self):
        ok = _response(200, '{"id": 42}', {'id': 42})
        with mock.patch(REQUESTS_GET, side_effect=[_checkout_required(), ok]) as get:
            secret, status, message = _auth().fetch_thycotic_secret(42)
        self.assertEqual(secret, {'id': 42})
        self.assertIsNone(status)
        self.assertIsNone(message)
        self.assertEqual(get.call_count, 2)
        self.assertTrue(get.call_args_list[0][0][0].endswith(f'/api/v1/secrets/42?{PLAIN_QUERY}'))
        self.assertTrue(get.call_args_list[1][0][0].endswith(f'/api/v1/secrets/42?{CHECKOUT_QUERY}'))

    def test_returns_error_when_checkout_retry_fails(self):
        denied = _response(403, '{"message": "Access denied"}', {'message': 'Access denied'})
        with mock.patch(REQUESTS_GET, side_effect=[_checkout_required(), denied]):
            secret, status, message = _auth().fetch_thycotic_secret(42)
        self.assertIsNone(secret)
        self.assertEqual(status, 403)
        self.assertEqual(message, 'Access denied')

    def test_other_400_error_is_not_retried(self):
        bad = _response(400, '{"message": "Bad request"}', {'message': 'Bad request'})
        with mock.patch(REQUESTS_GET, return_value=bad) as get:
            secret, status, message = _auth().fetch_thycotic_secret(42)
        self.assertIsNone(secret)
        self.assertEqual(status, 400)
        self.assertEqual(message, 'Bad request')
        self.assertEqual(get.call_count, 1)

    def test_returns_error_when_plain_read_fails(self):
        denied = _response(403, '{"message": "Access denied"}', {'message': 'Access denied'})
        with mock.patch(REQUESTS_GET, return_value=denied) as get:
            secret, status, message = _auth().fetch_thycotic_secret(42)
        self.assertIsNone(secret)
        self.assertEqual(status, 403)
        self.assertEqual(message, 'Access denied')
        self.assertEqual(get.call_count, 1)

    def test_error_uses_body_when_response_is_not_json(self):
        html = _response(502, '<html>Bad Gateway</html>', reason='Bad Gateway')
        with mock.patch(REQUESTS_GET, return_value=html):
            secret, status, message = _auth().fetch_thycotic_secret(42)
        self.assertIsNone(secret)
        self.assertEqual(status, 502)
        self.assertEqual(message, '<html>Bad Gateway</html>')

    def test_error_reports_network_failure(self):
        with mock.patch(REQUESTS_GET, side_effect=requests.exceptions.ConnectionError('refused')) as get:
            secret, status, message = _auth().fetch_thycotic_secret(42)
        self.assertIsNone(secret)
        self.assertEqual(status, 'N/A')
        self.assertEqual(message, 'refused')
        # _read_entity retries once on a network error; no checkout retry follows.
        self.assertEqual(get.call_count, 2)
        for call in get.call_args_list:
            self.assertIn('autoCheckout=false', call[0][0])

    def test_error_reports_exception_from_token_refresh(self):
        auth = _auth()
        with mock.patch.object(auth, 'ensure_auth_token', side_effect=Exception('refresh failed')), \
                mock.patch(REQUESTS_GET) as get:
            secret, status, message = auth.fetch_thycotic_secret(42)
        self.assertIsNone(secret)
        self.assertEqual(status, 'N/A')
        self.assertEqual(message, 'refresh failed')
        get.assert_not_called()


class TestThycoticSecretGet(unittest.TestCase):
    def test_plain_field_read_succeeds_without_checkout(self):
        ok = _response(200, 'key')
        with mock.patch(REQUESTS_GET, return_value=ok) as get:
            rs = _auth().thycotic_secret_get('/v1/secrets/42/fields/private-key')
        self.assertIs(rs, ok)
        self.assertEqual(get.call_count, 1)
        self.assertTrue(get.call_args[0][0].endswith(f'/api/v1/secrets/42/fields/private-key?{PLAIN_QUERY}'))

    def test_field_read_retries_with_checkout_when_checkout_required(self):
        denied = _checkout_required()
        ok = _response(200, 'key')
        with mock.patch(REQUESTS_GET, side_effect=[denied, ok]) as get:
            rs = _auth().thycotic_secret_get('/v1/secrets/42/fields/private-key')
        self.assertIs(rs, ok)
        self.assertEqual(get.call_count, 2)
        retry_url = get.call_args_list[1][0][0]
        self.assertTrue(retry_url.endswith(f'/api/v1/secrets/42/fields/private-key?{CHECKOUT_QUERY}'))

    def test_field_read_other_error_is_returned_without_retry(self):
        denied = _response(403, '{"message": "Access denied"}', {'message': 'Access denied'})
        with mock.patch(REQUESTS_GET, return_value=denied) as get:
            rs = _auth().thycotic_secret_get('/v1/secrets/42/fields/private-key')
        self.assertIs(rs, denied)
        self.assertEqual(get.call_count, 1)

    def test_field_read_recovers_after_connection_error(self):
        ok = _response(200, 'key')
        with mock.patch(SLEEP), mock.patch(REQUESTS_GET, side_effect=[
                requests.exceptions.ConnectionError('reset'), ok]) as get:
            rs = _auth().thycotic_secret_get('/v1/secrets/42/fields/private-key')
        self.assertIs(rs, ok)
        self.assertEqual(get.call_count, 2)


class TestCheckoutCommentArgument(unittest.TestCase):
    def test_default_checkout_comment(self):
        opts = commands.import_parser.parse_args(['--format', 'thycotic', 'https://ss.example.com'])
        self.assertEqual(opts.checkout_comment, 'Checking out for Keeper Import')

    def test_custom_checkout_comment(self):
        opts = commands.import_parser.parse_args(
            ['--format', 'thycotic', '--checkout-comment', 'Migration', 'https://ss.example.com'])
        self.assertEqual(opts.checkout_comment, 'Migration')


class TestThycoticEntity(unittest.TestCase):
    def setUp(self):
        sleep = mock.patch(SLEEP)
        sleep.start()
        self.addCleanup(sleep.stop)

    def test_entity_never_adds_checkout_params(self):
        denied = _response(400, '{"message": "Bad request"}', {'message': 'Bad request'})
        with mock.patch(REQUESTS_GET, return_value=denied) as get:
            self.assertIsNone(_auth().thycotic_entity('/v1/secret-templates/5/export'))
        self.assertEqual(get.call_count, 1)

    def test_network_error_returns_none(self):
        error = requests.exceptions.ConnectionError('connection refused')
        with mock.patch(REQUESTS_GET, side_effect=error) as get:
            secret = _auth().thycotic_entity('/v1/secrets/42')
        self.assertIsNone(secret)
        self.assertEqual(get.call_count, 2)

    def test_network_error_recovers_on_retry(self):
        error = requests.exceptions.ConnectionError('connection reset')
        ok = _response(200, '{"id": 42}', {'id': 42})
        with mock.patch(REQUESTS_GET, side_effect=[error, ok]):
            secret = _auth().thycotic_entity('/v1/secrets/42')
        self.assertEqual(secret, {'id': 42})

    def test_non_json_error_response_does_not_crash(self):
        html = _response(502, '<html>Bad Gateway</html>', reason='Bad Gateway')
        with mock.patch(REQUESTS_GET, return_value=html):
            self.assertIsNone(_auth().thycotic_entity('/v1/secrets/42'))

    def test_non_json_success_response_does_not_crash(self):
        with mock.patch(REQUESTS_GET, return_value=_response(200, '<html>login</html>')):
            self.assertIsNone(_auth().thycotic_entity('/v1/secrets/42'))

    def test_json_error_that_is_not_an_object_does_not_crash(self):
        with mock.patch(REQUESTS_GET, return_value=_response(500, '["boom"]', ['boom'])):
            self.assertIsNone(_auth().thycotic_entity('/v1/secrets/42'))


class TestThycoticAttachment(unittest.TestCase):
    def test_successful_download_sets_content(self):
        ok = _response(200, 'data')
        ok.headers = {'Content-Length': '4'}
        ok.content = b'data'
        ok.__enter__ = mock.Mock(return_value=ok)
        ok.__exit__ = mock.Mock(return_value=False)
        auth = _auth()
        with mock.patch.object(auth, 'thycotic_secret_get', return_value=ok):
            attachment = ThycoticAttachment(auth, '/v1/secrets/42/fields/cert', 'cert.pem')
            attachment.prepare()
        self.assertEqual(attachment.size, 4)

    def test_failed_download_warns_and_leaves_size_unset(self):
        denied = _response(403, '{"message": "Access denied"}', {'message': 'Access denied'})
        denied.__enter__ = mock.Mock(return_value=denied)
        denied.__exit__ = mock.Mock(return_value=False)
        auth = _auth()
        with mock.patch.object(auth, 'thycotic_secret_get', return_value=denied), \
                self.assertLogs(level='WARNING') as logs:
            attachment = ThycoticAttachment(auth, '/v1/secrets/42/fields/cert', 'cert.pem')
            attachment.prepare()
        self.assertIsNone(attachment.size)
        self.assertIn('cert.pem', logs.output[0])
        self.assertIn('403', logs.output[0])
        self.assertIn('Access denied', logs.output[0])

    def test_network_error_warns_instead_of_raising(self):
        auth = _auth()
        with mock.patch.object(auth, 'thycotic_secret_get',
                               side_effect=requests.exceptions.ConnectionError('reset')), \
                self.assertLogs(level='WARNING') as logs:
            ThycoticAttachment(auth, '/v1/secrets/42/fields/cert', 'cert.pem').prepare()
        self.assertIn('reset', logs.output[0])


class TestPrintSkipped(unittest.TestCase):
    def _output(self, secrets, fields):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            ThycoticImporter.print_skipped(secrets, fields)
        return out.getvalue()

    def test_nothing_printed_when_nothing_skipped(self):
        self.assertEqual(self._output([], []), '')

    def test_skipped_secrets_table(self):
        output = self._output([
            {'ID': 42, 'Status': 403, 'Message': 'Access denied'},
            {'ID': 108, 'Status': 'N/A', 'Message': 'Read timed out'},
        ], [])
        self.assertIn('Skipped 2 Secrets:', output)
        for text in ('ID', 'Status', 'Message', '42', '403', 'Access denied', '108', 'Read timed out'):
            self.assertIn(text, output)
        self.assertNotIn('Fields', output)

    def test_skipped_fields_table(self):
        output = self._output([], [
            {'ID': 77, 'Secret': 'DB Server', 'Field': 'private-key', 'Status': 400, 'Message': 'Checkout required'},
        ])
        self.assertIn('Skipped 1 Fields:', output)
        for text in ('Secret', 'Field', 'DB Server', 'private-key', 'Checkout required'):
            self.assertIn(text, output)
        self.assertNotIn('Secrets:', output)


class TestErrorResponses(unittest.TestCase):
    def test_log_response_handles_none(self):
        with self.assertLogs(level='INFO') as logs:
            _auth()._log_thycotic_response('/v1/secrets/42', None, 'boom')
        self.assertIn('no response', logs.output[0])

    def test_search_non_json_error_raises_readable_message(self):
        html = _response(503, '<html>Service Unavailable</html>', reason='Service Unavailable')
        with mock.patch(REQUESTS_GET, return_value=html):
            with self.assertRaises(Exception) as ctx:
                _auth().thycotic_search('/v1/secrets/lookup')
        self.assertIn('HTTP 503', str(ctx.exception))
        self.assertNotIsInstance(ctx.exception, ValueError)

    def test_search_json_error_uses_message(self):
        denied = _response(403, '{"message": "Access denied"}', {'message': 'Access denied'})
        with mock.patch(REQUESTS_GET, return_value=denied):
            with self.assertRaises(Exception) as ctx:
                _auth().thycotic_search('/v1/secrets/lookup')
        self.assertEqual(str(ctx.exception), 'Access denied')

    def test_refresh_non_json_error_raises_readable_message(self):
        auth = _auth()
        auth.refresh_token = 'refresh'
        html = _response(500, '<html>Server Error</html>', reason='Internal Server Error')
        with mock.patch('keepercommander.importer.thycotic.thycotic.requests.post', return_value=html):
            with self.assertRaises(Exception) as ctx:
                auth.refresh_auth_token()
        self.assertIn('HTTP 500', str(ctx.exception))


class TestThycoticTerminalSummary(unittest.TestCase):
    def test_uses_cyberark_finish_summary(self):
        self.assertTrue(ThycoticImporter.verbose_import_summary)


if __name__ == '__main__':
    unittest.main()
