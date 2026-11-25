"""`pam project import` loads a top-level pamUser with the rotation parameters, like `extend` and `update`.

`rotation_settings` may be the NAME of a `rotation_profiles` entry; without the parameters the name was not expanded and
the user got no rotation at all. An iam_user / scripts_only / saas profile also takes the PAM configuration as resource.
"""
import unittest
from unittest.mock import MagicMock, patch

from keepercommander.commands.pam_import import edit
from keepercommander.commands.pam_import.edit import PAMProjectImportCommand


class _StopAfterLoading(Exception):
    pass


def _load_users(users, rotation_profiles):
    """Run process_data up to the point where the loaded objects get their uids, and return those objects."""
    project = {
        'data': {'pam_data': {'resources': [], 'users': users, 'rotation_profiles': rotation_profiles}},
        'pam_config': {'pam_config_uid': 'CFG'},
        'folders': {'resources_folder_uid': 'sfr-test', 'users_folder_uid': 'sfu-test'},
    }
    seen = []

    def stop(objects, **_kwargs):
        seen.extend(objects)
        raise _StopAfterLoading()

    params = MagicMock()
    params.record_cache, params.shared_folder_cache, params.folder_cache = {}, {}, {}
    with patch.object(edit, 'assign_uids', side_effect=stop):
        with patch('builtins.print'):
            with unittest.TestCase().assertRaises(_StopAfterLoading):
                PAMProjectImportCommand().process_data(params, project)
    return seen


class TestTopLevelUserRotationProfile(unittest.TestCase):
    PROFILES = {'p1': {'rotation': 'scripts_only', 'enabled': 'on', 'schedule': {'type': 'on-demand'}}}

    def test_a_profile_name_is_expanded_and_takes_the_configuration(self):
        users = [{'type': 'pamUser', 'title': 'U', 'login': 'u', 'password': 'x', 'rotation_settings': 'p1'}]
        loaded, = _load_users(users, self.PROFILES)
        rotation = loaded.rotation_settings
        self.assertEqual((rotation.rotation, rotation.resource, rotation.enabled), ('scripts_only', 'CFG', 'on'))

    def test_an_inline_rotation_takes_the_configuration_too(self):
        users = [{'type': 'pamUser', 'title': 'U', 'login': 'u', 'password': 'x',
                  'rotation_settings': {'rotation': 'iam_user', 'enabled': 'on'}}]
        loaded, = _load_users(users, {})
        self.assertEqual((loaded.rotation_settings.rotation, loaded.rotation_settings.resource), ('iam_user', 'CFG'))


if __name__ == '__main__':
    unittest.main()
