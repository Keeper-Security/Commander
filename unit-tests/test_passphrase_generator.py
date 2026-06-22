from unittest import TestCase, mock

from keepercommander import generator


class TestKeeperPassphraseGenerator(TestCase):

  def test_default_generates_five_hyphen_separated_words(self):
    gen = generator.KeeperPassphraseGenerator()
    with mock.patch('secrets.choice', side_effect=['alpha', 'bravo', 'charlie', 'delta', 'echo']):
      with mock.patch('secrets.randbelow', return_value=3):
        result = gen.generate()
    self.assertEqual(result, 'Alpha3-Bravo-Charlie-Delta-Echo')

  def test_does_not_shuffle_words_like_diceware(self):
    gen = generator.KeeperPassphraseGenerator(
      word_count=3, separator=' ', capitalize=False, append_number=False)
    with mock.patch('secrets.choice', side_effect=['one', 'two', 'three']):
      result = gen.generate()
    self.assertEqual(result, 'one two three')

  def test_capitalize_and_number_apply_to_first_word_only(self):
    gen = generator.KeeperPassphraseGenerator(
      word_count=2, separator='-', capitalize=True, append_number=True)
    with mock.patch('secrets.choice', side_effect=['alpha', 'bravo']):
      with mock.patch('secrets.randbelow', return_value=7):
        result = gen.generate()
    self.assertEqual(result, 'Alpha7-Bravo')

  def test_create_from_policy_honors_passphrase_fields(self):
    gen = generator.KeeperPassphraseGenerator.create_from_policy({
      'passphrase-length': 3,
      'passphrase-separator': '-',
      'passphrase-capitalize': True,
      'passphrase-number': True,
    })
    with mock.patch('secrets.choice', side_effect=['alpha', 'bravo', 'charlie']):
      with mock.patch('secrets.randbelow', return_value=4):
        result = gen.generate()
    self.assertEqual(result, 'Alpha4-Bravo-Charlie')

  def test_parse_passphrase_gen_parameters(self):
    opts = generator.parse_passphrase_gen_parameters(['passphrase', '7', '_', 'true', 'false'])
    self.assertEqual(opts.word_count, 7)
    self.assertEqual(opts.separator, '_')
    self.assertTrue(opts.capitalize)
    self.assertFalse(opts.append_number)

  def test_create_with_options_overrides_policy(self):
    policy = {
      'passphrase-length': 5,
      'passphrase-separator': '-',
      'passphrase-capitalize': False,
      'passphrase-number': False,
    }
    gen = generator.KeeperPassphraseGenerator.create_with_options(
      policy, word_count=3, separator='_', capitalize=True, append_number=True)
    self.assertEqual(gen.word_count, 3)
    self.assertEqual(gen.separator, '_')
    self.assertTrue(gen.capitalize)
    self.assertTrue(gen.append_number)

  def test_commander_defaults_override_policy_capitalize_and_number(self):
    gen = generator.KeeperPassphraseGenerator.create_with_options({
      'passphrase-capitalize': False,
      'passphrase-number': False,
    })
    self.assertTrue(gen.capitalize)
    self.assertTrue(gen.append_number)

  def test_policy_separator_uses_vault_order_not_raw_first_char(self):
    gen = generator.KeeperPassphraseGenerator.create_with_options({
      'passphrase-separator': '!._?-',
    })
    self.assertEqual(gen.separator, '-')

  def test_invalid_separator_override_falls_back_to_default(self):
    gen = generator.KeeperPassphraseGenerator.create_with_options(
      None, separator='~', word_count=3)
    self.assertEqual(gen.separator, '-')

  def test_loads_bundled_eff_wordlist(self):
    words = generator._load_wordlist()
    self.assertEqual(len(words), 7776)
    self.assertEqual(words[0], 'abacus')


class TestGeneratePasswordPassphrase(TestCase):

  def test_record_edit_generate_password_passphrase(self):
    from keepercommander.commands.record_edit import RecordEditMixin
    with mock.patch('secrets.choice', side_effect=['alpha', 'bravo', 'charlie', 'delta', 'echo']):
      with mock.patch('secrets.randbelow', return_value=5):
        result = RecordEditMixin.generate_password(['passphrase'])
    self.assertEqual(result, 'Alpha5-Bravo-Charlie-Delta-Echo')

  def test_record_edit_passphrase_uses_policy_when_allowed(self):
    from keepercommander.commands.record_edit import RecordEditMixin
    policy = {
      'passphrase-allow': True,
      'passphrase-length': 2,
      'passphrase-separator': '_',
      'passphrase-capitalize': True,
      'passphrase-number': False,
    }
    with mock.patch('secrets.choice', side_effect=['alpha', 'bravo']):
      with mock.patch('secrets.randbelow', return_value=4):
        result = RecordEditMixin.generate_password(['passphrase'], policy=policy)
    self.assertEqual(result, 'Alpha4_Bravo')

  def test_record_edit_passphrase_cli_overrides_policy(self):
    from keepercommander.commands.record_edit import RecordEditMixin
    policy = {
      'passphrase-allow': True,
      'passphrase-length': 2,
      'passphrase-separator': '-',
      'passphrase-capitalize': False,
      'passphrase-number': False,
    }
    with mock.patch('secrets.choice', side_effect=['alpha', 'bravo', 'charlie']):
      with mock.patch('secrets.randbelow', return_value=9):
        result = RecordEditMixin.generate_password(
          ['passphrase', '3', '_', 'true', 'true'], policy=policy)
    self.assertEqual(result, 'Alpha9_Bravo_Charlie')
