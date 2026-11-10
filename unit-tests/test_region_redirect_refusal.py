import unittest
from unittest import mock

from keepercommander import error, loginv3

REFUSAL = ("Your organization's Keeper server asked this app to use another server. "
           'The app does not follow it. Contact your administrator.')
REDIRECT = {'error': 'region_redirect', 'message': 'redirect', 'region_host': 'evil.example'}
FUNCTIONS = ('startLoginMessage', 'resume_login')


def _call(name, server):
    params = mock.Mock()
    params.server = server
    params.user = 'u@example.com'
    api = loginv3.LoginV3API
    if name == 'startLoginMessage':
        return params, lambda: api.startLoginMessage(params, b'tok')
    return params, lambda: api.resume_login(params, b'lt', b'tok')


class RegionRedirectTest(unittest.TestCase):
    def test_custom_host_refuses_redirect(self):
        for name in FUNCTIONS:
            if True:
                params, run = _call(name, 'keeper.corp.example')
                with mock.patch.object(loginv3.rest_api, 'execute_rest', return_value=REDIRECT), \
                        mock.patch.object(loginv3.LoginV3API, 'register_device_in_region') as reg:
                    with self.assertRaises(error.KeeperApiError) as ctx:
                        run()
                self.assertEqual(ctx.exception.result_code, 'server_redirect_refused')
                self.assertEqual(ctx.exception.message, REFUSAL)
                self.assertEqual(params.server, 'keeper.corp.example')
                reg.assert_not_called()

    def test_cloud_host_still_follows_redirect(self):
        params, run = _call('startLoginMessage', 'keepersecurity.com')
        with mock.patch.object(loginv3.rest_api, 'execute_rest', side_effect=[REDIRECT, b'']), \
                mock.patch.object(loginv3.LoginV3API, 'register_device_in_region') as reg:
            try:
                run()
            except Exception:
                pass
        self.assertEqual(params.server, 'evil.example')
        reg.assert_called_once()

    def test_protobuf_redirect_on_custom_host_is_refused(self):
        from keepercommander.proto import APIRequest_pb2
        params = mock.Mock()
        params.server = 'keeper.corp.example'
        params.user = 'u@example.com'
        params.biometric = False
        params.clone_code = None
        params.config = {}
        resp = mock.Mock(loginState=APIRequest_pb2.REGION_REDIRECT, stateSpecificValue='evil.example')
        api = loginv3.LoginV3API
        with mock.patch.object(api, 'get_device_id', return_value=b'tok'), \
                mock.patch.object(api, 'startLoginMessage', side_effect=[resp, RuntimeError('followed the redirect')]), \
                mock.patch.object(api, 'register_device_in_region') as reg:
            with self.assertRaises(error.KeeperApiError) as ctx:
                loginv3.LoginV3Flow().login(params)
        self.assertEqual(ctx.exception.result_code, 'server_redirect_refused')
        self.assertEqual(params.server, 'keeper.corp.example')
        reg.assert_not_called()


if __name__ == '__main__':
    unittest.main()
