import contextlib
import io
import unittest
from unittest import mock

import requests
from keepercommander.importer.thycotic.thycotic import _SECRET_ACCESS_COMMENT
from keepercommander.importer import commands
from keepercommander.importer.thycotic.thycotic import (
    ThycoticAttachment,
    ThycoticAuth,
    ThycoticImporter,
    build_secrets_lookup_query,
    lookup_secret_ids,
    secret_access_params,
    with_secret_access_params,
)

CHECKOUT_ERROR = 'API_SecretRequiresCheckout'

VISIBLE_ID = 7
RESTRICTED_ID = 4242
SHARED_ID = 99
PLAIN_QUERY = ('autoCheckout=false&autoComment=Checking%20out%20for%20Keeper%20Import'
               '&noAutoCheckout=true')
CHECKOUT_QUERY = ('autoCheckout=true&autoCheckIn=true'
                  '&autoComment=Checking%20out%20for%20Keeper%20Import')
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
    body = {'message': CHECKOUT_ERROR}
    return _response(400, '{"message": "API_SecretRequiresCheckout"}', body)


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
    def test_plain_read_does_not_check_out(self):
        self.assertEqual(secret_access_params(False), [
            ('autoCheckout', 'false'),
            ('autoComment', _SECRET_ACCESS_COMMENT),
            ('noAutoCheckout', 'true'),
        ])

    def test_checkout_read_checks_back_in(self):
        params = secret_access_params(True)
        self.assertEqual(params, [
            ('autoCheckout', 'true'),
            ('autoCheckIn', 'true'),
            ('autoComment', _SECRET_ACCESS_COMMENT),
        ])
        self.assertNotIn('forceCheckIn', dict(params))
        self.assertNotIn('noAutoCheckout', dict(params))


class TestAccessParams(unittest.TestCase):
    def test_other_query_params_are_kept(self):
        endpoint = with_secret_access_params('/v1/secrets/42?includeInactive=true', enabled=False)
        self.assertEqual(endpoint, f'/v1/secrets/42?includeInactive=true&{PLAIN_QUERY}')

    def test_space_is_percent_encoded(self):
        endpoint = with_secret_access_params('/v1/secrets/42', enabled=False)
        self.assertIn('autoComment=Checking%20out%20for%20Keeper%20Import', endpoint)
        self.assertNotIn('+', endpoint)

    def test_plain_read_strips_a_checkout_left_on_the_url(self):
        endpoint = with_secret_access_params(
            '/v1/secrets/42?autoCheckout=true&autoCheckIn=true',
            enabled=False,
        )
        self.assertEqual(endpoint, f'/v1/secrets/42?{PLAIN_QUERY}')


class TestFetchThycoticSecret(unittest.TestCase):
    def setUp(self):
        sleep = mock.patch(SLEEP)
        sleep.start()
        self.addCleanup(sleep.stop)

    def test_plain_read_does_not_check_out(self):
        secret_body = _response(200, '{"id": 42}', {'id': 42})
        with mock.patch(REQUESTS_GET, return_value=secret_body) as get:
            secret, status, message = _auth().fetch_thycotic_secret(42)
        self.assertEqual(secret, {'id': 42})
        self.assertIsNone(status)
        self.assertIsNone(message)
        self.assertEqual(get.call_count, 1)
        self.assertTrue(get.call_args[0][0].endswith(f'/api/v1/secrets/42?{PLAIN_QUERY}'))

    def test_checkout_required_retries_with_checkout(self):
        secret_body = _response(200, '{"id": 42}', {'id': 42})
        with mock.patch(REQUESTS_GET, side_effect=[_checkout_required(), secret_body]) as get:
            secret, status, message = _auth().fetch_thycotic_secret(42)
        self.assertEqual(secret, {'id': 42})
        self.assertIsNone(status)
        self.assertIsNone(message)
        self.assertEqual(get.call_count, 2)
        self.assertTrue(get.call_args_list[0][0][0].endswith(f'/api/v1/secrets/42?{PLAIN_QUERY}'))
        self.assertTrue(get.call_args_list[1][0][0].endswith(f'/api/v1/secrets/42?{CHECKOUT_QUERY}'))

    def test_any_400_is_retried_with_checkout(self):
        body = {'message': 'Comment is required.', 'errorCode': 'API_CommentRequired'}
        denied = _response(400, '{"message": "Comment is required."}', body)
        with mock.patch(REQUESTS_GET, return_value=denied) as get:
            secret, status, message = _auth().fetch_thycotic_secret(42)
        self.assertIsNone(secret)
        self.assertEqual((status, message), (400, 'Comment is required.'))
        self.assertEqual(get.call_count, 2)
        self.assertTrue(get.call_args_list[1][0][0].endswith(f'/api/v1/secrets/42?{CHECKOUT_QUERY}'))

    def test_failed_checkout_read_returns_the_retry_error(self):
        failed = _response(500, '{"message": "boom"}', {'message': 'boom'})
        with mock.patch(REQUESTS_GET, side_effect=[_checkout_required(), failed]) as get:
            secret, status, message = _auth().fetch_thycotic_secret(42)
        self.assertIsNone(secret)
        self.assertEqual((status, message), (500, 'boom'))
        self.assertEqual(get.call_count, 2)
        self.assertTrue(get.call_args_list[1][0][0].endswith(f'/api/v1/secrets/42?{CHECKOUT_QUERY}'))

    def test_other_error_is_not_retried_as_checkout(self):
        denied = _response(403, '{"message": "Access denied"}', {'message': 'Access denied'})
        with mock.patch(REQUESTS_GET, return_value=denied) as get:
            secret, status, message = _auth().fetch_thycotic_secret(42)
        self.assertIsNone(secret)
        self.assertEqual((status, message), (403, 'Access denied'))
        self.assertEqual(get.call_count, 1)
        self.assertNotIn('autoCheckout=true', get.call_args[0][0])

    def test_non_json_secret_error_is_returned(self):
        html = _response(502, '<html>Bad Gateway</html>', reason='Bad Gateway')
        with mock.patch(REQUESTS_GET, return_value=html):
            secret, status, message = _auth().fetch_thycotic_secret(42)
        self.assertIsNone(secret)
        self.assertEqual(status, 502)
        self.assertEqual(message, '<html>Bad Gateway</html>')

    def test_network_failure_returns_the_error(self):
        with mock.patch(REQUESTS_GET, side_effect=requests.exceptions.ConnectionError('refused')) as get:
            secret, status, message = _auth().fetch_thycotic_secret(42)
        self.assertIsNone(secret)
        self.assertEqual(status, 'N/A')
        self.assertEqual(message, 'refused')
        self.assertEqual(get.call_count, 2)

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
    def test_plain_field_read_does_not_check_out(self):
        ok = _response(200, 'key')
        with mock.patch(REQUESTS_GET, return_value=ok) as get:
            rs = _auth().fetch_thycotic_secret_field(42, 'private-key')
        self.assertIs(rs, ok)
        self.assertEqual(get.call_count, 1)
        self.assertTrue(get.call_args[0][0].endswith(
            f'/api/v1/secrets/42/fields/private-key?{PLAIN_QUERY}'))

    def test_field_read_retries_when_checkout_is_required(self):
        ok = _response(200, 'key')
        denied = _checkout_required()
        with mock.patch(REQUESTS_GET, side_effect=[denied, ok]) as get:
            rs = _auth().fetch_thycotic_secret_field(42, 'private-key')
        self.assertIs(rs, ok)
        self.assertEqual(get.call_count, 2)
        self.assertTrue(get.call_args_list[0][0][0].endswith(
            f'/api/v1/secrets/42/fields/private-key?{PLAIN_QUERY}'))
        self.assertTrue(get.call_args_list[1][0][0].endswith(
            f'/api/v1/secrets/42/fields/private-key?{CHECKOUT_QUERY}'))
        denied.close.assert_called_once()

    def test_field_read_retries_when_error_code_requires_checkout(self):
        body = {
            'message': 'The requested secret requires checkout.',
            'errorCode': CHECKOUT_ERROR,
        }
        denied = _response(400, '{"errorCode": "API_SecretRequiresCheckout"}', body)
        ok = _response(200, 'key')
        with mock.patch(REQUESTS_GET, side_effect=[denied, ok]) as get:
            rs = _auth().fetch_thycotic_secret_field(42, 'private-key')
        self.assertIs(rs, ok)
        self.assertEqual(get.call_count, 2)
        self.assertIn('autoCheckout=true', get.call_args_list[1][0][0])

    def test_field_error_is_returned_without_a_checkout_retry(self):
        denied = _response(403, '{"message": "Access denied"}', {'message': 'Access denied'})
        with mock.patch(REQUESTS_GET, return_value=denied) as get:
            rs = _auth().fetch_thycotic_secret_field(42, 'private-key')
        self.assertIs(rs, denied)
        self.assertEqual(get.call_count, 1)
        self.assertNotIn('autoCheckout=true', get.call_args[0][0])

    def test_field_read_recovers_after_connection_error(self):
        ok = _response(200, 'key')
        with mock.patch(SLEEP), mock.patch(REQUESTS_GET, side_effect=[
                requests.exceptions.ConnectionError('reset'), ok]) as get:
            rs = _auth().fetch_thycotic_secret_field(42, 'private-key')
        self.assertIs(rs, ok)
        self.assertEqual(get.call_count, 2)
        self.assertIn(PLAIN_QUERY, get.call_args_list[1][0][0])
        self.assertNotIn('autoCheckout=true', get.call_args_list[1][0][0])

    def test_field_checkout_retry_failure_raises(self):
        denied = _checkout_required()
        calls = []

        def get(url, **kwargs):
            calls.append(url)
            if len(calls) == 1:
                return denied
            raise requests.exceptions.ConnectionError('reset')

        with mock.patch(REQUESTS_GET, side_effect=get), mock.patch(SLEEP), \
                self.assertRaises(requests.exceptions.ConnectionError):
            _auth().fetch_thycotic_secret_field(42, 'private-key')
        self.assertGreaterEqual(len(calls), 2)
        self.assertIn(PLAIN_QUERY, calls[0])
        self.assertIn('autoCheckout=true', calls[1])


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
        with mock.patch.object(auth, 'fetch_thycotic_secret_field', return_value=ok) as get_field:
            attachment = ThycoticAttachment(auth, 42, 'cert', 'cert.pem')
            attachment.prepare()
        get_field.assert_called_once_with(42, 'cert')
        self.assertEqual(attachment.size, 4)

    def test_failed_download_warns_and_leaves_size_unset(self):
        denied = _response(403, '{"message": "Access denied"}', {'message': 'Access denied'})
        denied.__enter__ = mock.Mock(return_value=denied)
        denied.__exit__ = mock.Mock(return_value=False)
        auth = _auth()
        with mock.patch.object(auth, 'fetch_thycotic_secret_field', return_value=denied), \
                self.assertLogs(level='WARNING') as logs:
            attachment = ThycoticAttachment(auth, 42, 'cert', 'cert.pem')
            attachment.prepare()
        self.assertIsNone(attachment.size)
        self.assertIn('cert.pem', logs.output[0])
        self.assertIn('403', logs.output[0])
        self.assertIn('Access denied', logs.output[0])

    def test_network_error_warns_instead_of_raising(self):
        auth = _auth()
        with mock.patch.object(auth, 'fetch_thycotic_secret_field',
                               side_effect=requests.exceptions.ConnectionError('reset')), \
                self.assertLogs(level='WARNING') as logs:
            ThycoticAttachment(auth, 42, 'cert', 'cert.pem').prepare()
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

    def test_search_pages_until_has_next_is_false(self):
        pages = [
            _response(200, json_value={
                'records': [{'id': 1}, {'id': 2}], 'hasNext': True, 'nextSkip': 2,
            }),
            _response(200, json_value={
                'records': [{'id': 3}], 'hasNext': False,
            }),
        ]
        with mock.patch(REQUESTS_GET, side_effect=pages) as get:
            result = _auth().thycotic_search('/v1/secrets?filter.includeRestricted=true')
        self.assertEqual([row['id'] for row in result], [1, 2, 3])
        first, second = (call[0][0] for call in get.call_args_list)
        self.assertIn('/api/v1/secrets?', first)
        self.assertIn('filter.includeRestricted=true', first)
        self.assertIn('take=1000', first)
        self.assertNotIn('skip=', first)
        self.assertIn('skip=2', second)
        self.assertIn('take=1000', second)

    def test_search_stops_when_has_next_is_false(self):
        full = [{'id': i} for i in range(1000)]
        page = _response(200, json_value={'records': full, 'hasNext': False})
        with mock.patch(REQUESTS_GET, return_value=page) as get:
            result = _auth().thycotic_search('/v1/users')
        self.assertEqual(len(result), 1000)
        get.assert_called_once()
        url = get.call_args[0][0]
        self.assertIn('take=1000', url)
        self.assertNotIn('skip=', url)

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
