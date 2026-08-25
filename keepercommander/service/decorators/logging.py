#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2024 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

from functools import wraps
from typing import Callable, Any
import logging
import sys, os, yaml
import re
import shlex
from enum import Enum
from ... import utils

# Values that must never reach the logs when set via record-add/record-update/
# nsf-record-* CLI args.
SENSITIVE_FIELD_TYPES = frozenset({
    'password', 'login', 'secret', 'onetimecode', 'pincode', 'keypair',
    'privatekey', 'passphrase', 'paymentcard', 'bankaccount',
    'securityquestion', 'passkey',
})

class LogLevel(Enum):
    ERROR = logging.ERROR
    WARNING = logging.WARNING
    DEBUG = logging.DEBUG
    INFO = logging.INFO

class GlobalLogger:
    _instance = None
    _initialized = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(GlobalLogger, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        if not GlobalLogger._initialized:
            self._creat_logging_config()
            self._config = self._load_config()
            self._logger = logging.getLogger('keeper_service')
            self._setup_logger()
            GlobalLogger._initialized = True

    def _creat_logging_config(self):
        config_path = utils.get_default_path() / "logging_config.yaml"
    
        default_config = {
            "logging": {
                "enabled": True,
                "level": "INFO"  # Options: DEBUG, INFO, WARNING, ERROR
            }
        }
        if not os.path.exists(config_path):
        # Create the directory if it doesn't exist
            config_path.parent.mkdir(parents=True, exist_ok=True)
            # Write the default config
            with open(config_path, "w") as f:
                yaml.dump(default_config, f, sort_keys=False)
            utils.set_file_permissions(str(config_path))
        return default_config["logging"]
    
    def _load_config(self):
        config_path = utils.get_default_path() / "logging_config.yaml";
        
        # config_path = os.getenv("LOGGING_CONFIG_PATH", "logging_config.yaml")
        if os.path.exists(config_path):
            utils.ensure_config_permissions(str(config_path))
            with open(config_path, "r") as f:
                return yaml.safe_load(f).get("logging", {})
        return {"enabled": True, "level": "INFO"}
    
    def _setup_logger(self):
        if not self._config.get("enabled", True):
            # Disable logging if it's not enabled in the config
            logging.disable(logging.CRITICAL)
            return
        
        if not self._logger.handlers:
            handler = logging.StreamHandler(sys.stderr)
            formatter = logging.Formatter(
                '%(asctime)s [%(levelname)s] %(name)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            handler.setFormatter(formatter)
            self._logger.addHandler(handler)
            # Prevent log propagation to parent loggers to avoid duplicate entries
            self._logger.propagate = False
            # self._logger.setLevel(logging.INFO) # Change for debug
            log_level_str = self._config.get("level", "INFO").upper()
            log_level = getattr(logging, log_level_str, logging.INFO)
            self._logger.setLevel(log_level)

    def set_level(self, level: LogLevel):
        self._logger.setLevel(level.value)

    def info(self, message: str):
        self._logger.info(message)

    def debug(self, message: str):
        self._logger.debug(message)

    def warning(self, message: str):
        self._logger.warning(message)

    def error(self, message: str):
        self._logger.error(message)

    def exception(self, message: str):
        self._logger.exception(message)

def debug_decorator(fn: Callable) -> Callable:
    """Debug decorator - only active when logging level is DEBUG"""
    @wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        if logger._logger.isEnabledFor(logging.DEBUG):
            args_repr = [sanitize_debug_data(repr(a)) for a in args]
            kwargs_repr = [f"{k}={sanitize_debug_data(repr(v))}" for k, v in kwargs.items()]
            signature = ", ".join(args_repr + kwargs_repr)
            logger.debug(f"Call: {fn.__name__}({signature})")

        value = fn(*args, **kwargs)

        if logger._logger.isEnabledFor(logging.INFO):
            logger.debug(f"Return: {fn.__name__} → {sanitize_debug_data(repr(value))}")
        
        return value
    return wrapper

def catch_all(fn: Callable) -> Callable:
    """Global exception handler"""
    @wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return fn(*args, **kwargs)
        except Exception as e:
            logger.exception(f"Unhandled error in {fn.__name__}")
            raise
    return wrapper


def sanitize_debug_data(data: str) -> str:
    """Sanitize sensitive data from debug output."""
    if not data:
        return data
    
    sanitized = data
    
    # Sanitize common password patterns
    patterns = [
        (r'"password"\s*:\s*"[^"]*"', '"password": "***"'),
        (r'"login"\s*:\s*"[^"]*"', '"login": "***"'),  
        (r'"secret"\s*:\s*"[^"]*"', '"secret": "***"'),
        (r'"token"\s*:\s*"[^"]*"', '"token": "***"'),
        (r'"key"\s*:\s*"[^"]*"', '"key": "***"'),
        (r'\bpassword=[^\s]*', 'password=***'),
        (r'\blogin=[^\s]*', 'login=***'),
        # oneTimeCode=otpauth://totp/...?secret=... — mask the whole value, TOTP seed included
        (r'\boneTimeCode=[^\s]*', 'oneTimeCode=***'),
        (r'\bsecret=[^\s]*', 'secret=***'),
        # Other sensitive record field types (see SENSITIVE_FIELD_TYPES) that can
        # appear as bare CLI args on record-add/record-update/nsf-* commands.
        (r'\bpinCode=[^\s]*', 'pinCode=***'),
        (r'\bkeyPair=[^\s]*', 'keyPair=***'),
        (r'\bprivateKey=[^\s]*', 'privateKey=***'),
        (r'\bpassphrase=[^\s]*', 'passphrase=***'),
        (r'\bpaymentCard=[^\s]*', 'paymentCard=***'),
        (r'\bbankAccount=[^\s]*', 'bankAccount=***'),
        (r'\bsecurityQuestion=[^\s]*', 'securityQuestion=***'),
        (r'\bpasskey=[^\s]*', 'passkey=***'),
        # Sanitize email addresses in logs to protect PII
        (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '***@***.***'),
    ]
    
    for pattern, replacement in patterns:
        sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)

    return sanitized


def _record_field_type(token_key: str) -> str:
    """Extract the FIELD_TYPE from a record-add/record-update field token key.

    Field tokens follow [f.|c.]<FIELD_TYPE>[.<FIELD_LABEL>]=<VALUE> (see the
    `record-add`/`record-update` --syntax-help). Custom fields carrying a
    sensitive type (e.g. c.secret.APIKey=...) must be masked the same as bare
    fields (secret=...).
    """
    key = token_key[2:] if token_key[:2] in ('f.', 'c.') else token_key
    return key.split('.', 1)[0]


def sanitize_command_fields(command: str) -> str:
    """Mask sensitive record field values (password, secret, keyPair, private
    key passphrases, payment/bank data, security answers, ...) in a
    record-add/record-update/nsf-record-* command string.

    Unlike the plain keyword patterns in `sanitize_debug_data`, this masks
    labeled and custom fields too (password.Label=..., c.secret.APIKey=...),
    which a literal `password=` substring match cannot catch.
    """
    if not command:
        return command

    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        # Unbalanced quotes: fall back to whitespace split so we still mask
        # what we can instead of logging the raw string.
        tokens = command.split()

    masked_tokens = []
    for token in tokens:
        key, sep, value = token.partition('=')
        if sep and value and _record_field_type(key).lower() in SENSITIVE_FIELD_TYPES:
            masked_tokens.append(f'{key}=***')
        else:
            masked_tokens.append(token)

    return sanitize_debug_data(' '.join(masked_tokens))


logger = GlobalLogger()