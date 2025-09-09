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
from dotenv import load_dotenv, set_key, dotenv_values
from ..decorators.logging import logger
from .terminal_handler import TerminalHandler
from ... import utils

@dataclass
class ProcessInfo:
    pid: Optional[int]
    terminal: Optional[str]
    is_running: bool
    ngrok_pid: Optional[int] = None
    cloudflare_pid: Optional[int] = None
    
    _env_file = utils.get_default_path() / ".service.env"
    
    @classmethod
    def _str_to_bool(cls, value: str) -> bool:
        return value.lower() in ('true', '1', 'yes', 'on')
    
    @classmethod
    def save(cls, pid, is_running: bool, ngrok_pid: Optional[int] = None, cloudflare_pid: Optional[int] = None) -> None:
        """Save current process information to .env file."""
        
        env_path = str(cls._env_file)
        
        # Create the file if it doesn't exist
        if not cls._env_file.exists():
            cls._env_file.touch()
        
        process_info = {
            'KEEPER_SERVICE_PID': str(pid),
            'KEEPER_SERVICE_TERMINAL': TerminalHandler.get_terminal_info() or '',
            'KEEPER_SERVICE_IS_RUNNING': str(is_running).lower()
        }
        
        if ngrok_pid is not None:
            process_info['KEEPER_SERVICE_NGROK_PID'] = str(ngrok_pid)
        
        if cloudflare_pid is not None:
            process_info['KEEPER_SERVICE_CLOUDFLARE_PID'] = str(cloudflare_pid)
        
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
            for key in dotenv_values(cls._env_file).keys():
                os.environ.pop(key, None)  # Remove old values
            
            if ProcessInfo._env_file.exists():
                load_dotenv(ProcessInfo._env_file, override=True)
                
                pid_str = os.getenv('KEEPER_SERVICE_PID')
                pid = int(pid_str) if pid_str else None
                
                terminal = os.getenv('KEEPER_SERVICE_TERMINAL') or None
                
                is_running_str = os.getenv('KEEPER_SERVICE_IS_RUNNING', 'false')
                is_running = ProcessInfo._str_to_bool(is_running_str)
                
                ngrok_pid_str = os.getenv('KEEPER_SERVICE_NGROK_PID')
                ngrok_pid = int(ngrok_pid_str) if ngrok_pid_str else None
                
                cloudflare_pid_str = os.getenv('KEEPER_SERVICE_CLOUDFLARE_PID')
                cloudflare_pid = int(cloudflare_pid_str) if cloudflare_pid_str else None
                
                logger.debug("Process information loaded successfully from .env")
                return ProcessInfo(
                    pid=pid,
                    terminal=terminal,
                    is_running=is_running,
                    ngrok_pid=ngrok_pid,
                    cloudflare_pid=cloudflare_pid
                )
        except Exception as e:
            logger.error(f"Failed to load process information: {e}")
            pass
        
        return ProcessInfo(pid=None, terminal=None, is_running=False, ngrok_pid=None, cloudflare_pid=None)
    
    @classmethod
    def clear(cls) -> None:
        """Remove the process information file."""
        try:
            cls._env_file.unlink(missing_ok=True)
            logger.debug("Process information file removed")
        except Exception as e:
            logger.error(f"Failed to remove process information file: {e}")
            pass