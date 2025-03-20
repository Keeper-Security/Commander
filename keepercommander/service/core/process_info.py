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

import os
from dataclasses import dataclass
from typing import Optional
from dotenv import load_dotenv, set_key
from ..decorators.logging import logger
from .terminal_handler import TerminalHandler
from keepercommander import utils

@dataclass
class ProcessInfo:
    pid: Optional[int]
    terminal: Optional[str]
    is_running: bool
    
    _env_file = utils.get_default_path() / ".service.env"
    
    @classmethod
    def _str_to_bool(cls, value: str) -> bool:
        return value.lower() in ('true', '1', 'yes', 'on')
    
    @classmethod
    def save(cls, is_running: bool) -> None:
        """Save current process information to .env file."""
        
        env_path = str(cls._env_file)
        
        # Create the file if it doesn't exist
        if not cls._env_file.exists():
            cls._env_file.touch()
        
        process_info = {
            'KEEPER_SERVICE_PID': str(os.getpid()),
            'KEEPER_SERVICE_TERMINAL': TerminalHandler.get_terminal_info() or '',
            'KEEPER_SERVICE_IS_RUNNING': str(is_running).lower()
        }
        
        try:
            for key, value in process_info.items():
                set_key(env_path, key, value, quote_mode='never')
            logger.debug("Process information saved successfully to .env")
        except Exception as e:
            logger.error(f"Failed to save process information: {e}")
            pass

    @classmethod
    def load(cls) -> 'ProcessInfo':
        """Load process information from .env file."""
        try:
            if cls._env_file.exists():
                load_dotenv(cls._env_file)
                
                pid_str = os.getenv('KEEPER_SERVICE_PID')
                pid = int(pid_str) if pid_str else None
                
                terminal = os.getenv('KEEPER_SERVICE_TERMINAL') or None
                
                is_running_str = os.getenv('KEEPER_SERVICE_IS_RUNNING', 'false')
                is_running = cls._str_to_bool(is_running_str)
                
                logger.debug("Process information loaded successfully from .env")
                return cls(
                    pid=pid,
                    terminal=terminal,
                    is_running=is_running
                )
        except Exception as e:
            logger.error(f"Failed to load process information: {e}")
            pass
        
        return cls(pid=None, terminal=None, is_running=False)
    
    @classmethod
    def clear(cls) -> None:
        """Remove the process information file."""
        try:
            cls._env_file.unlink(missing_ok=True)
            logger.debug("Process information file removed")
        except Exception as e:
            logger.error(f"Failed to remove process information file: {e}")
            pass