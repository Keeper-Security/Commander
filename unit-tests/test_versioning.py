from unittest import TestCase, mock

from keepercommander import versioning


class TestUpdateCheckAirGap(TestCase):
    def test_self_hosted_server_makes_no_request(self):
        params = mock.Mock(server='keeper.corp.example')
        with mock.patch('keepercommander.versioning.requests.get') as get:
            result = versioning.is_up_to_date_version(params)
        get.assert_not_called()
        self.assertTrue(result['is_up_to_date'])

    def test_cloud_server_requests_release_info(self):
        params = mock.Mock(server='keepersecurity.com')
        with mock.patch('keepercommander.versioning.requests.get') as get:
            get.return_value.text = '{"tag_name": "v99.0.0"}'
            versioning.is_up_to_date_version(params)
        get.assert_called_once()
