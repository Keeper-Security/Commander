from unittest import TestCase

import pytest
from keepercommander.commands import scim

@pytest.mark.skip
class TestScimCommands(TestCase):
    @staticmethod
    def add_scim_team():
        scim_url = 'SCIM URL'
        token = 'SCIM TOKEN'
        payload = {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "externalId":"e9e306a331660a",
            "displayName": "Queued Team",
        }
        scim.ScimPushCommand.post_scim_resource(f'{scim_url}/Groups', token, payload)
