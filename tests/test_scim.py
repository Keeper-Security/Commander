from unittest import TestCase

import pytest
from keepercommander.commands import scim
from keepercommander.scim.data_sources import AdCrmDataSource


def test_ad_group_selector_keeps_direct_membership_by_default():
    group, expand_subgroups = AdCrmDataSource._parse_group_selector('Engineering')

    assert group == 'Engineering'
    assert expand_subgroups is False


def test_ad_group_selector_expands_direct_subgroups_when_prefixed_with_plus():
    group, expand_subgroups = AdCrmDataSource._parse_group_selector('+CN=Engineering,DC=example,DC=com')

    assert group == 'CN=Engineering,DC=example,DC=com'
    assert expand_subgroups is True
    assert AdCrmDataSource._direct_subgroups_filter(group) == (
        '(&(objectClass=group)(memberOf=CN=Engineering,DC=example,DC=com))')

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
