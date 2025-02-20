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
import sys
from enum import Enum

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
            self._logger = logging.getLogger('keeper_service')
            self._setup_logger()
            GlobalLogger._initialized = True

    def _setup_logger(self):
        if not self._logger.handlers:
            handler = logging.StreamHandler(sys.stderr)
            formatter = logging.Formatter(
                '%(asctime)s [%(levelname)s] %(name)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            handler.setFormatter(formatter)
            self._logger.addHandler(handler)
            self._logger.setLevel(logging.INFO) # Change for debug

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
        
        if logger._logger.isEnabledFor(logging.DEBUG):
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

logger = GlobalLogger()