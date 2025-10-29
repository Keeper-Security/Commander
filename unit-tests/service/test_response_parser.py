import sys
if sys.version_info >= (3, 8):
  import pytest
  from unittest import TestCase
  from keepercommander.service.util.parse_keeper_response import KeeperResponseParser

  class TestKeeperResponseParser(TestCase):
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

      def test_parse_mkdir_command(self):
          """Test parsing of 'mkdir' command output"""

          result = KeeperResponseParser._parse_mkdir_command('b4pBzT1WowoUXHk_US0SCg')
          self.assertEqual(result['data']['folder_uid'], 'b4pBzT1WowoUXHk_US0SCg')
          
          result = KeeperResponseParser._parse_mkdir_command('Created folder with folder_uid=b4pBzT1WowoUXHk_US0SCg')
          self.assertEqual(result['data']['folder_uid'], 'b4pBzT1WowoUXHk_US0SCg')

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