import base64
import hashlib
import json
import threading
import urllib.parse
import urllib.request
from unittest import TestCase, mock

from keepercommander.commands.pam_cloud import entra_sign_in
from keepercommander.error import CommandError


def _jwt(**claims):
    body = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=')
    return f'h.{body}.s'


def _token_response(status=200, **payload):
    response = mock.Mock()
    response.status_code = status
    response.json.return_value = payload
    return response


class FakeBrowser:
    """Follows the authorize URL by calling the loopback redirect, like a signed-in browser."""

    def __init__(self, **redirect_params):
        self.redirect_params = redirect_params
        self.authorize_url = None

    def __call__(self, url):
        self.authorize_url = urllib.parse.urlparse(url)
        query = {k: v[0] for k, v in urllib.parse.parse_qs(self.authorize_url.query).items()}
        params = {'state': query['state'], **self.redirect_params}
        redirect = f'{query["redirect_uri"]}/?{urllib.parse.urlencode(params)}'
        # The listener is single-threaded and not yet serving, so hit it from another thread.
        threading.Thread(target=lambda: urllib.request.urlopen(redirect, timeout=10).read(), daemon=True).start()


class PkceTest(TestCase):

    def test_challenge_is_s256_of_verifier(self):
        verifier, challenge = entra_sign_in.pkce_pair()
        expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
        self.assertEqual(expected, challenge)
        self.assertGreaterEqual(len(verifier), 43)

    def test_authorize_url_carries_pkce_state_and_hint(self):
        url = entra_sign_in.build_authorize_url(
            'https://login.microsoftonline.com', 'tenant-1', 'client-1', 'http://localhost:1234',
            'https://management.azure.com/.default openid', 'st', 'chal', 'alice@contoso.com')
        parsed = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(parsed.query)
        self.assertEqual('/tenant-1/oauth2/v2.0/authorize', parsed.path)
        self.assertEqual(['S256'], query['code_challenge_method'])
        self.assertEqual(['chal'], query['code_challenge'])
        self.assertEqual(['st'], query['state'])
        self.assertEqual(['alice@contoso.com'], query['login_hint'])


class SignInTest(TestCase):

    def _sign_in(self, browser, token_response, login='alice@contoso.com'):
        with mock.patch.object(entra_sign_in.requests, 'post', return_value=token_response) as post, \
                mock.patch('builtins.print'):
            token = entra_sign_in.sign_in('tenant-1', 'client-1', 'https://management.azure.com/.default',
                                          login_hint=login, timeout=10, open_browser=browser)
        return token, post

    def test_success_redeems_code_with_verifier_and_no_secret(self):
        browser = FakeBrowser(code='auth-code')
        ok = _token_response(access_token='at', expires_in=3599,
                             id_token=_jwt(preferred_username='alice@contoso.com'))

        token, post = self._sign_in(browser, ok)

        self.assertEqual('at', token['access_token'])
        body = post.call_args.kwargs['data']
        self.assertEqual('authorization_code', body['grant_type'])
        self.assertEqual('auth-code', body['code'])
        self.assertIn('code_verifier', body)
        self.assertNotIn('client_secret', body)
        self.assertTrue(post.call_args.args[0].endswith('/tenant-1/oauth2/v2.0/token'))
        challenge = urllib.parse.parse_qs(browser.authorize_url.query)['code_challenge'][0]
        expected = base64.urlsafe_b64encode(hashlib.sha256(body['code_verifier'].encode()).digest()).rstrip(b'=').decode()
        self.assertEqual(expected, challenge)

    def test_other_user_is_refused(self):
        ok = _token_response(access_token='at', id_token=_jwt(preferred_username='mallory@contoso.com'))
        with self.assertRaises(CommandError) as ctx:
            self._sign_in(FakeBrowser(code='c'), ok)
        self.assertIn('different user', str(ctx.exception))

    def test_token_without_identity_claims_is_refused(self):
        with self.assertRaises(CommandError):
            self._sign_in(FakeBrowser(code='c'), _token_response(access_token='opaque'))

    def test_user_cancelling_raises(self):
        with self.assertRaises(CommandError) as ctx:
            self._sign_in(FakeBrowser(error='access_denied', error_description='cancelled'), mock.Mock())
        self.assertIn('cancelled', str(ctx.exception))

    def test_state_mismatch_is_refused(self):
        browser = FakeBrowser(code='c', state='forged')
        with self.assertRaises(CommandError) as ctx:
            self._sign_in(browser, mock.Mock())
        self.assertIn('did not match', str(ctx.exception))

    def test_timeout_raises(self):
        with mock.patch('builtins.print'):
            with self.assertRaises(CommandError) as ctx:
                entra_sign_in.sign_in('t', 'c', 's', 'a@b.com', timeout=0, open_browser=lambda url: None)
        self.assertIn('not completed in time', str(ctx.exception))

    def test_rejected_token_request_raises_first_line_only(self):
        rejected = _token_response(400, error='invalid_client',
                                   error_description='AADSTS7000218: public client\r\nTrace ID: x')
        with self.assertRaises(CommandError) as ctx:
            self._sign_in(FakeBrowser(code='c'), rejected)
        self.assertIn('AADSTS7000218', str(ctx.exception))
        self.assertNotIn('Trace ID', str(ctx.exception))
