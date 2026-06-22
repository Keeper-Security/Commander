#  _  __  
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|            
#
# Keeper Commander 
# Contact: ops@keepersecurity.com
#

import abc
import hashlib
import logging
import os
import secrets
import string
from secrets import choice
from typing import Optional, List, Iterator, Sequence
from collections import namedtuple

from . import crypto

from Cryptodome.Random.random import shuffle

DEFAULT_PASSWORD_LENGTH = 20
PW_SPECIAL_CHARACTERS = '!@#$%()+;<>=?[]{}^.,'
PP_SEPARATOR_CHARACTERS = '-._?! '
DEFAULT_PASSPHRASE_SEPARATOR = '-'
DEFAULT_PASSPHRASE_WORD_COUNT = 5
DEFAULT_PASSPHRASE_CAPITALIZE = True
DEFAULT_PASSPHRASE_NUMBER = True
DEFAULT_DICEWARE_WORDLIST = 'diceware.wordlist.asc.txt'
PASSPHRASE_SEPARATOR_HELP = '- . _ ? ! space'


def format_passphrase_separators_for_display(separators=None):
    # type: (Optional[str]) -> str
    """Human-readable list of allowed passphrase separator characters."""
    if not separators:
        separators = PP_SEPARATOR_CHARACTERS
    parts = []   # type: List[str]
    for ch in separators:
        parts.append('space' if ch == ' ' else ch)
    return ', '.join(parts)

PasswordStrength = namedtuple('PasswordStrength', 'length caps lower digits symbols')
PassphraseGenOptions = namedtuple(
    'PassphraseGenOptions', ('word_count', 'separator', 'capitalize', 'append_number'))


def get_password_strength(password):  # type: (str) -> PasswordStrength
    length = len(password)
    caps = 0
    lower = 0
    digits = 0
    symbols = 0

    for ch in password:
        if ch.isalpha():
            if ch.isupper():
                caps += 1
            else:
                lower += 1
        elif ch.isdigit():
            digits += 1
        elif ch in PW_SPECIAL_CHARACTERS:
            symbols += 1
    return PasswordStrength(length=length, caps=caps, lower=lower, digits=digits, symbols=symbols)


def generate(length=64):
    generator = KeeperPasswordGenerator(length=length)
    return generator.generate()


class PasswordGenerator(abc.ABC):
    @abc.abstractmethod
    def generate(self):   # type: () -> str
        pass


class KeeperPasswordGenerator(PasswordGenerator):
    def __init__(self, length: int = DEFAULT_PASSWORD_LENGTH,
                 symbols: Optional[int] = None,
                 digits: Optional[int] = None,
                 caps: Optional[int] = None,
                 lower: Optional[int] = None,
                 special_characters: str = PW_SPECIAL_CHARACTERS):

        sum_categories = sum((abs(i) if isinstance(i, int) else 0) for i in (symbols, digits, caps, lower))
        extra_count = length - sum_categories if length > sum_categories else 0
        extra_chars = ''
        if symbols is None or isinstance(symbols, int) and symbols > 0:
            extra_chars += special_characters
        if digits is None or isinstance(digits, int) and digits > 0:
            extra_chars += string.digits
        if caps is None or isinstance(caps, int) and caps > 0:
            extra_chars += string.ascii_uppercase
        if lower is None or isinstance(lower, int) and lower > 0:
            extra_chars += string.ascii_lowercase
        if extra_count > 0 and not extra_chars:
            if isinstance(symbols, int) and symbols < 0:
                extra_chars += special_characters
            if isinstance(digits, int) and digits < 0:
                extra_chars += string.digits
            if isinstance(caps, int) and caps < 0:
                extra_chars += string.ascii_uppercase
            if isinstance(lower, int) and lower < 0:
                extra_chars += string.ascii_lowercase

            if extra_count > 0 and not extra_chars:
                raise Exception('Password character set is empty')
        self.category_map = [
            (abs(symbols) if isinstance(symbols, int) else 0, special_characters),
            (abs(digits) if isinstance(digits, int) else 0, string.digits),
            (abs(caps) if isinstance(caps, int) else 0, string.ascii_uppercase),
            (abs(lower) if isinstance(lower, int) else 0, string.ascii_lowercase),
            (extra_count, extra_chars)
        ]

    def generate(self) -> str:
        password_list = []
        for count, chars in self.category_map:
            password_list.extend(choice(chars) for i in range(count))
        shuffle(password_list)
        return ''.join(password_list)

    @classmethod
    def create_from_rules(cls, rule_string: str, length: Optional[int] = None,
                          special_characters: str = PW_SPECIAL_CHARACTERS):
        """Create instance of class from rules string

        rule_string: comma separated integer character counts of [length,] uppercase, lowercase, numbers, symbols
        length: length of password
        special_characters: set of characters used to generate password symbols
        """
        try:
            rule_list = [int(s.strip()) for s in rule_string.split(',')]
            if len(rule_list) == 5:
                l = rule_list.pop(0)
                if not length:
                    length = l
            if len(rule_list) != 4:
                raise Exception('Invalid rules')
        except:
            logging.warning('Invalid rules to generate password. Format is "[length,] upper, lower, digits, symbols"')
            return None

        if length is None:
            length = DEFAULT_PASSWORD_LENGTH
        upper, lower, digits, symbols = rule_list
        length = sum(rule_list) if length is None else length
        return cls(length=length, caps=upper, lower=lower, digits=digits, symbols=symbols, special_characters=special_characters)

    @classmethod
    def create_from_policy(cls, policy, length_override=None):
        # type: (dict, Optional[int]) -> KeeperPasswordGenerator
        """Create a generator that satisfies the given password complexity enforcement policy."""
        pw_length = length_override or policy.get('length') or DEFAULT_PASSWORD_LENGTH
        lower_min = policy.get('lower-min', 0) if policy.get('lower-use') else None
        upper_min = policy.get('upper-min', 0) if policy.get('upper-use') else None
        digit_min = policy.get('digit-min', 0) if policy.get('digit-use') else None
        special_min = policy.get('special-min', 0) if policy.get('special-use') else None
        special_chars = policy.get('special', PW_SPECIAL_CHARACTERS) or PW_SPECIAL_CHARACTERS

        return cls(
            length=pw_length,
            lower=lower_min,
            caps=upper_min,
            digits=digit_min,
            symbols=special_min,
            special_characters=special_chars
        )


def _normalize_passphrase_separator(separator):
    # type: (Optional[str]) -> str
    if not separator:
        return DEFAULT_PASSPHRASE_SEPARATOR
    if separator == '\u2423':  # OPEN BOX (Vault UI glyph for space)
        return ' '
    return separator[0]


def _passphrase_separators_from_policy(policy_sep):
    # type: (str) -> str
    """Return allowed separators in Vault order (see getPasswordRules.ts)."""
    normalized = policy_sep.replace('\u2423', ' ')
    allowed = ''
    for ch in PP_SEPARATOR_CHARACTERS:
        if ch in normalized:
            allowed += ch
    return allowed


def _default_passphrase_separator_from_policy(policy_sep):
    # type: (Optional[str]) -> str
    """Pick the default generation separator matching Vault / PowerCommander."""
    if not policy_sep or not isinstance(policy_sep, str) or not policy_sep.strip():
        return DEFAULT_PASSPHRASE_SEPARATOR
    allowed = _passphrase_separators_from_policy(policy_sep.strip())
    return allowed[0] if allowed else DEFAULT_PASSPHRASE_SEPARATOR


def _parse_gen_bool(value):
    # type: (str) -> Optional[bool]
    normalized = value.strip().lower()
    if normalized in ('true', '1', 'yes', 'on'):
        return True
    if normalized in ('false', '0', 'no', 'off'):
        return False
    return None


def parse_passphrase_gen_parameters(parameters):
    # type: (Optional[Sequence[str]]) -> PassphraseGenOptions
    """Parse $GEN:passphrase optional parameters.

    Format: $GEN:passphrase[,word_count][,separator][,capitalize][,number]
    Examples:
        $GEN:passphrase,7
        $GEN:passphrase,7,_
        $GEN:passphrase,7,_,true,true
        $GEN:passphrase,7,space,false,true
    """
    if not parameters:
        return PassphraseGenOptions(None, None, None, None)

    extras = [p.strip() for p in parameters if p.strip() and p.strip() != 'passphrase']
    word_count = None
    separator = None
    capitalize = None
    append_number = None
    idx = 0

    if idx < len(extras) and extras[idx].isdigit():
        word_count = int(extras[idx])
        idx += 1

    if idx < len(extras):
        candidate = extras[idx]
        if _parse_gen_bool(candidate) is None:
            if candidate.lower() in ('space', 'sp'):
                separator = ' '
            else:
                separator = _normalize_passphrase_separator(candidate)
            idx += 1

    if idx < len(extras):
        parsed = _parse_gen_bool(extras[idx])
        if parsed is not None:
            capitalize = parsed
            idx += 1

    if idx < len(extras):
        parsed = _parse_gen_bool(extras[idx])
        if parsed is not None:
            append_number = parsed

    return PassphraseGenOptions(word_count, separator, capitalize, append_number)


def _resolve_wordlist_path(word_list_file=None):
    # type: (Optional[str]) -> str
    if word_list_file:
        dice_path = os.path.join(os.path.dirname(__file__), 'resources', word_list_file)
        if not os.path.isfile(dice_path):
            dice_path = os.path.expanduser(word_list_file)
    else:
        dice_path = os.path.join(os.path.dirname(__file__), 'resources', DEFAULT_DICEWARE_WORDLIST)
    return dice_path


def _load_wordlist(word_list_file=None):
    # type: (Optional[str]) -> List[str]
    dice_path = _resolve_wordlist_path(word_list_file)
    if not os.path.isfile(dice_path):
        raise Exception(f'Word list file \"{dice_path}\" not found.')

    vocabulary = []   # type: List[str]
    unique_words = set()
    with open(dice_path, 'r', encoding='utf-8') as dw:
        for line in dw:
            line = line.strip()
            if not line or line.startswith('--'):
                continue
            if line.lower().startswith('source url:') or line.lower().startswith('title:'):
                continue
            parts = line.split()
            word = parts[1] if len(parts) >= 2 else parts[0]
            vocabulary.append(word)
            unique_words.add(word.lower())
    if len(vocabulary) != len(unique_words):
        raise Exception(f'Word list file \"{dice_path}\" contains non-unique words.')
    return vocabulary


class DicewarePasswordGenerator(PasswordGenerator):
    def __init__(self, number_of_rolls, word_list_file=None, delimiter=' '):   # type: (int, Optional[str], str) -> None
        self._number_of_rolls = number_of_rolls if number_of_rolls > 0 else 5
        self.delimiter = delimiter
        self._vocabulary = _load_wordlist(word_list_file)

    def generate(self):
        if not self._vocabulary:
            raise Exception(f'Diceware word list was not loaded')

        words = [secrets.choice(self._vocabulary) for _ in range(self._number_of_rolls)]
        shuffle(words)
        return self.delimiter.join(words)


class KeeperPassphraseGenerator(PasswordGenerator):
    """Vault-style passphrase generator using the bundled EFF large word list."""

    def __init__(self, word_count=DEFAULT_PASSPHRASE_WORD_COUNT, separator=DEFAULT_PASSPHRASE_SEPARATOR,
                 capitalize=DEFAULT_PASSPHRASE_CAPITALIZE, append_number=DEFAULT_PASSPHRASE_NUMBER,
                 word_list_file=None):
        # type: (int, str, bool, bool, Optional[str]) -> None
        if isinstance(word_count, int):
            if word_count < 1:
                word_count = 1
            elif word_count > 40:
                word_count = 40
        else:
            word_count = DEFAULT_PASSPHRASE_WORD_COUNT
        self.word_count = word_count
        self.separator = _normalize_passphrase_separator(separator)
        self.capitalize = capitalize
        self.append_number = append_number
        self._vocabulary = _load_wordlist(word_list_file)

    def generate(self):
        if not self._vocabulary:
            raise Exception('Passphrase word list was not loaded')

        passphrase = ''
        first_word = True
        for _ in range(self.word_count):
            word = secrets.choice(self._vocabulary)
            if self.capitalize and word:
                word = word[0].upper() + word[1:]
            if self.append_number and first_word:
                word += str(secrets.randbelow(10))
            if not first_word:
                passphrase += self.separator
            passphrase += word
            first_word = False
        return passphrase

    @classmethod
    def create_with_options(cls, policy=None, word_count=None, separator=None,
                            capitalize=None, append_number=None):
        # type: (Optional[dict], Optional[int], Optional[str], Optional[bool], Optional[bool]) -> KeeperPassphraseGenerator
        """Build a generator from CLI/$GEN overrides with optional policy defaults."""
        wc = word_count
        if wc is None:
            if policy:
                wc = policy.get('passphrase-length', DEFAULT_PASSPHRASE_WORD_COUNT)
            else:
                wc = DEFAULT_PASSPHRASE_WORD_COUNT

        sep = separator
        if sep is not None and sep not in PP_SEPARATOR_CHARACTERS:
            logging.warning(
                'Ignoring invalid passphrase separator %r. Allowed: %s.',
                sep, format_passphrase_separators_for_display())
            sep = None
        if sep is None:
            if policy:
                policy_sep = policy.get('passphrase-separator')
                sep = _default_passphrase_separator_from_policy(
                    policy_sep if isinstance(policy_sep, str) else None)
            else:
                sep = DEFAULT_PASSPHRASE_SEPARATOR

        cap = capitalize
        if cap is None:
            cap = DEFAULT_PASSPHRASE_CAPITALIZE

        num = append_number
        if num is None:
            num = DEFAULT_PASSPHRASE_NUMBER

        return cls(word_count=wc, separator=sep, capitalize=cap, append_number=num)

    @classmethod
    def create_from_policy(cls, policy, length_override=None, separator_override=None):
        # type: (dict, Optional[int], Optional[str]) -> KeeperPassphraseGenerator
        return cls.create_with_options(
            policy,
            word_count=length_override,
            separator=separator_override,
        )


class CryptoPassphraseGenerator(PasswordGenerator):
    def __init__(self):
        self._vocabulary = None    # type: Optional[List[str]]
        dice_path = os.path.join(os.path.dirname(__file__), 'resources', 'bip-39.english.txt')
        if os.path.isfile(dice_path):
            with open(dice_path, 'r', encoding='utf-8') as dw:
                self._vocabulary = []
                for line in dw.readlines():
                    if not line:
                        continue
                    if line.startswith('--'):
                        continue
                    words = [x.strip() for x in line.split()]
                    word = words[1] if len(words) >= 2 else words[0]
                    self._vocabulary.append(word)

                unique_words = set((x.lower() for x in self._vocabulary))
                if len(self._vocabulary) != len(unique_words):
                    raise Exception(f'Word list file \"{dice_path}\" contains non-unique words.')
                if len(unique_words) != 2 ** 11:
                    raise Exception(f'Word list file \"{dice_path}\" is incorrect crypto dictionary.')
        else:
            raise Exception(f'Word list file \"{dice_path}\" not found.')

    def get_vocabulary(self):    # type: () -> Iterator[str]
        return (x for x in self._vocabulary)

    def generate(self):
        key = crypto.get_random_bytes(32)
        hasher = hashlib.sha256()
        hasher.update(key)
        digest = hasher.digest()
        secret = int.from_bytes(key + digest[:1], byteorder='big')

        words = []
        for i in range(24):
            words.append(secret & 0x07ff)
            secret >>= 11

        words.reverse()
        return ' '.join((self._vocabulary[x] for x in words))
