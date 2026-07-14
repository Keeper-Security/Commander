from unittest import TestCase
import json
from keepercommander.service.util.parse_keeper_response import KeeperResponseParser, ensure_record_add_json_format

class TestKeeperResponseParser(TestCase):
    def test_ensure_record_add_json_format(self):
        self.assertEqual(
            ensure_record_add_json_format('record-add -t test -rt login'),
            'record-add -t test -rt login --format=json',
        )
        self.assertEqual(
            ensure_record_add_json_format('record-add -t test --format=json'),
            'record-add -t test --format=json',
        )
        self.assertEqual(
            ensure_record_add_json_format('ls'),
            'ls',
        )

    def test_parse_ls_command(self):
        """Test parsing of 'ls' command output"""
        sample_output = """# Folder UID                           Title                                                   Flags
  1   b4pBzT1WowoUXHk_US0SCg   Root                                                    RS
# Record UID                           Type           Title                                      Description   
  1   dGJ3xbH8CXhNF00FBX0wMA            login          My Login                                   Important"""
          
        result = KeeperResponseParser._parse_ls_command(sample_output)
          
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['command'], 'ls')
        self.assertEqual(len(result['data']['folders']), 1)
        self.assertEqual(len(result['data']['records']), 1)
          
        folder = result['data']['folders'][0]
        self.assertEqual(folder['number'], 1)
        self.assertEqual(folder['name'], 'Root')
          
        record = result['data']['records'][0]
        self.assertEqual(record['number'], 1)
        self.assertEqual(record['title'], 'My Login')
        self.assertEqual(record['description'], 'Important')

    def test_parse_tree_command(self):
        """Test parsing of 'tree' command output"""
        sample_output = """Root
Folder1
  SubFolder1
Folder2"""
          
        result = KeeperResponseParser._parse_tree_command(sample_output)
          
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['command'], 'tree')
        self.assertEqual(len(result['data']['tree']), 4)  # Updated: now returns dict with 'tree' key
          
        self.assertEqual(result['data']['tree'][0]['level'], 0)
        self.assertEqual(result['data']['tree'][0]['name'], 'Root')
        self.assertEqual(result['data']['tree'][0]['path'], 'Root')
          
        self.assertEqual(result['data']['tree'][1]['level'], 0)
        self.assertEqual(result['data']['tree'][1]['name'], 'Folder1')
        self.assertEqual(result['data']['tree'][1]['path'], 'Folder1')

    def test_parse_tree_command_share_permissions_structured(self):
        """tree -s -v: share_permissions splits default/user vs per-user list"""
        sample_output = """Share Permissions Key:
======================
RO = Read-Only
MU = Can Manage Users
======================
My Vault
 └── Shared Folder (abc123) [SHARED] (default:CE; user:CE; users:[a@x.com:RO],[b@y.com:MU,MR])
"""
        result = KeeperResponseParser._parse_tree_command(sample_output)
        self.assertEqual(result['data']['share_permissions_key'][:2], ['RO = Read-Only', 'MU = Can Manage Users'])
        entry = result['data']['tree'][0]
        self.assertTrue(entry['shared'])
        sp = entry['share_permissions']
        self.assertEqual(sp['default'], 'CE')
        self.assertEqual(sp['user'], 'CE')
        self.assertEqual(len(sp['users']), 2)
        self.assertEqual(sp['users'][0]['username'], 'a@x.com')
        self.assertEqual(sp['users'][0]['permissions'], 'RO')
        self.assertEqual(sp['users'][1]['username'], 'b@y.com')
        self.assertEqual(sp['users'][1]['permissions'], 'MU,MR')

    def test_parse_mkdir_command(self):
        """Test parsing of 'mkdir' command output"""

        result = KeeperResponseParser._parse_mkdir_command('b4pBzT1WowoUXHk_US0SCg')
        self.assertEqual(result['data']['folder_uid'], 'b4pBzT1WowoUXHk_US0SCg')
          
        result = KeeperResponseParser._parse_mkdir_command('Created folder with folder_uid=b4pBzT1WowoUXHk_US0SCg')
        self.assertEqual(result['data']['folder_uid'], 'b4pBzT1WowoUXHk_US0SCg')

    def test_parse_record_add_command_two_line_output(self):
        """record-add --self-destruct returns record_uid on line 1 and share_url on line 2"""
        record_uid = 'riK9X5/XcxGPWRYM2Be1Ow=='
        share_url = 'https://keepersecurity.com/vault/share#abc123'
        response = f'{record_uid}\n{share_url}'

        result = KeeperResponseParser._parse_record_add_command(response)
        self.assertEqual(result['data']['record_uid'], record_uid)
        self.assertEqual(result['data']['share_url'], share_url)

    def test_parse_record_add_command_json_format(self):
        """record-add --format=json is parsed as structured JSON"""
        record_uid = 'riK9X5/XcxGPWRYM2Be1Ow=='
        share_url = 'https://keepersecurity.com/vault/share#abc123'
        response = json.dumps({'record_uid': record_uid, 'share_url': share_url})

        result = KeeperResponseParser.parse_response(
            'record-add --self-destruct 2mi --format=json',
            response,
        )
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['data']['record_uid'], record_uid)
        self.assertEqual(result['data']['share_url'], share_url)

    def test_parse_record_add_command_uid_only(self):
        """Normal record-add returns bare record_uid"""
        record_uid = 'riK9X5/XcxGPWRYM2Be1Ow=='
        result = KeeperResponseParser._parse_record_add_command(record_uid)
        self.assertEqual(result['data']['record_uid'], record_uid)

    def test_parse_get_command(self):
        """Test parsing of 'get' command output"""
        sample_output = """Title: Test Record
Username: testuser
Password: testpass
URL: https://example.com"""
          
        result = KeeperResponseParser._parse_get_command(sample_output)
          
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['command'], 'get')
        self.assertEqual(result['data']['title'], 'Test Record')
        self.assertEqual(result['data']['username'], 'testuser')
        self.assertEqual(result['data']['password'], 'testpass')
        self.assertEqual(result['data']['url'], 'https://example.com')