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
from enum import Enum
from ... import utils

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
            args_repr = [repr(a) for a in args]
            kwargs_repr = [f"{k}={v!r}" for k, v in kwargs.items()]
            signature = ", ".join(args_repr + kwargs_repr)
            logger.debug(f"Call: {fn.__name__}({signature})")
        
        value = fn(*args, **kwargs)
        
        if logger._logger.isEnabledFor(logging.INFO):
            logger.debug(f"Return: {fn.__name__} → {value!r}")
        
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
        (r'password=[^\s]*', 'password=***'),
        (r'login=[^\s]*', 'login=***'),
        # Sanitize email addresses in logs to protect PII
        (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '***@***.***'),
    ]
    
    for pattern, replacement in patterns:
        sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)
    
    return sanitized


logger = GlobalLogger()