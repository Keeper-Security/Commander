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

import io, html
from pathlib import Path
import sys
import json
import logging
import time
import threading
from typing import Any, Tuple, Optional
from .config_reader import ConfigReader
from .exceptions import CommandExecutionError
from .parse_keeper_response import parse_keeper_response
from ..core.globals import get_current_params
from ..decorators.logging import logger, debug_decorator, sanitize_debug_data
from ... import cli, utils
from ...__main__ import get_params_from_config
from ...service.config.service_config import ServiceConfig
from ...crypto import encrypt_aes_v2

# Commands that fetch shared data/records - need sync before execution if cache expired
FETCH_SHARED_DATA_COMMANDS = {
    # Core record & folder fetch commands
    'get', 'search', 'search-record', 'search-folder',
    'tree', 'ls', 'list', 'find',
    'list-sf', 'list-team',
    'record-history', 'totp',
    'find-password', 'find-duplicate', 'find-ownerless',
    'download-attachment',

    # Reporting commands
    'audit-report', 'audit-log', 'report', 'export',
    'user-report', 'security-audit-report', 'share-report',
    'shared-records-report', 'aging-report', 'action-report',
    'compliance-report', 'compliance',
    'external-shares-report', 'risk-management',
    'file-report', 'password-report',

    # Sharing & permission-related commands
    'share-record', 'share-folder', 'record-permission',
    'one-time-share',

    # Folder and structure commands that rely on shared data
    'cd', 'mkdir', 'mv', 'rmdir', 'shortcut',
    'transform-folder', 'arrange-folders',

    # Record type & import/export helpers
    'record-type', 'record-type-info',
    'import', 'export',

    # Attachment and data access helpers
    'upload-attachment', 'delete-attachment',
    'clipboard-copy',

    # Account and ownership helpers
    'create-account',

    # Integrity / verification
    'verify-records', 'verify-shared-folders',
}

# Sync cache to track last sync time and revision for optimization
# This is module-level to be shared across requests in the same service instance.
# Protected by a lock to avoid race conditions between concurrent service requests.
_sync_cache_lock = threading.Lock()
_sync_cache = {
    'last_sync_time': 0,      # Timestamp of last sync
    'last_revision': 0,       # Revision at last sync
    'cache_ttl': 5            # Cache TTL in seconds (default: 5 seconds)
}

class CommandExecutor:
    @staticmethod
    @debug_decorator
    def validate_command(command: str) -> Optional[Tuple[dict, int]]:
        if not command:
            return {"error": "No command provided."}, 400
        return None

    @staticmethod
    @debug_decorator
    def validate_session() -> Optional[Tuple[dict, int]]:
        params = get_current_params()
        if not params:
            return {"error": "No active session. Please log in through the CLI first."}, 401
        return None

    @staticmethod
    @debug_decorator
    def capture_output_and_logs(params: Any, command: str) -> Tuple[Any, str, str]:
        """Capture both stdout/stderr and logging output from command execution."""
        captured_stdout = io.StringIO()
        captured_stderr = io.StringIO()
        captured_logs = io.StringIO()
        
        # Create a temporary log handler to capture command logs
        temp_handler = logging.StreamHandler(captured_logs)
        temp_handler.setFormatter(logging.Formatter('%(message)s'))
        
        # Get the root logger to capture all logging output
        root_logger = logging.getLogger()
        original_level = root_logger.level
        original_handlers = root_logger.handlers[:]
        
        original_stdout = sys.stdout
        original_stderr = sys.stderr
        
        sys.stdout = captured_stdout
        sys.stderr = captured_stderr
        
        try:
            # Add our temporary handler and set appropriate level
            root_logger.addHandler(temp_handler)
            root_logger.setLevel(logging.INFO)
            
            return_value = cli.do_command(params, command)
            
            stdout_content = captured_stdout.getvalue()
            stderr_content = captured_stderr.getvalue()
            log_content = captured_logs.getvalue()
            
            # Combine stdout and stderr
            stdout_clean = stdout_content.strip()
            stderr_clean = stderr_content.strip()
            log_clean = log_content.strip()
            
            if stderr_clean and stdout_clean:
                combined_output = stderr_clean + '\n' + stdout_clean
            else:
                combined_output = stderr_clean or stdout_clean
            
            return return_value, combined_output, log_clean
        except Exception as e:
            # If there's an exception, capture any error output
            stderr_content = captured_stderr.getvalue()
            log_content = captured_logs.getvalue()
            error_output = stderr_content.strip()
            
            if error_output:
                raise CommandExecutionError(f"Command failed: {error_output}")
            raise
        finally:
            sys.stdout = original_stdout
            sys.stderr = original_stderr
            # Restore original logging configuration
            root_logger.removeHandler(temp_handler)
            root_logger.setLevel(original_level)
            temp_handler.close()


    @staticmethod
    @debug_decorator
    def should_sync_before_fetch(params, command_base: str) -> bool:
        """
        Determine if sync-down is needed before fetching shared data.
        
        Uses revision-aware TTL strategy:
        1. Only sync for commands that fetch shared data
        2. If local revision > last synced revision: Already synced after modify, skip
        3. If cache expired (TTL): Need to sync to check server revision
        4. Otherwise: Cache valid, skip sync
        
        Args:
            params: KeeperParams object
            command_base: Base command name (e.g., 'get', 'tree', 'search')
            
        Returns:
            True if sync needed, False if skip sync
        """
        global _sync_cache

        with _sync_cache_lock:
            # Step 1: Only sync for commands that fetch shared data
            if command_base not in FETCH_SHARED_DATA_COMMANDS:
                logger.debug(f"Command '{command_base}' does not fetch shared data - skipping sync")
                return False
            
            # Step 2: Check if this is the first sync (cache not initialized)
            # On service startup, last_sync_time will be 0, so we need to sync first
            if _sync_cache['last_sync_time'] == 0:
                logger.debug(f"First sync needed: cache not initialized")
                return True
            
            # Step 3: Check if local revision changed (optimization)
            # This means we modified something and already synced
            if params.revision > _sync_cache['last_revision']:
                # Update cache (revision already synced after modify command)
                old_revision = _sync_cache['last_revision']
                _sync_cache['last_revision'] = params.revision
                _sync_cache['last_sync_time'] = time.time()
                logger.debug(f"Local revision ({params.revision}) > last synced ({old_revision}), already synced, skipping")
                return False
            
            # Step 3: Check if cache expired (TTL fallback)
            # This catches external changes (other users, other instances)
            current_time = time.time()
            cache_age = current_time - _sync_cache['last_sync_time']
            cache_ttl = _sync_cache['cache_ttl']
            
            # First sync or cache expired - need to sync to check server revision
            if _sync_cache['last_sync_time'] == 0 or cache_age > cache_ttl:
                logger.debug(f"Sync needed for '{command_base}': cache expired (age: {cache_age:.1f}s, TTL: {cache_ttl}s)")
                return True
            
            # Step 4: Cache valid, skip sync
            logger.debug(f"Skipping sync for '{command_base}': cache valid (age: {cache_age:.1f}s < TTL: {cache_ttl}s)")
            return False

    @staticmethod
    @debug_decorator
    def sync_if_needed(params, command_base: str):
        """
        Sync-down if needed before fetching shared data.
        Updates cache after sync.
        """
        if CommandExecutor.should_sync_before_fetch(params, command_base):
            logger.debug(f"Executing sync-down before '{command_base}'")
            cli.do_command(params, 'sync-down')
            # Update cache after sync
            global _sync_cache
            with _sync_cache_lock:
                _sync_cache['last_sync_time'] = time.time()
                _sync_cache['last_revision'] = params.revision
            logger.debug(f"Sync completed, cache updated: revision={params.revision}")

    @staticmethod
    @debug_decorator
    def update_sync_cache_after_modify(params):
        """
        Update sync cache after modify command completes.
        Modify commands sync internally, so we update cache to reflect new revision.
        """
        global _sync_cache
        with _sync_cache_lock:
            _sync_cache['last_sync_time'] = time.time()
            _sync_cache['last_revision'] = params.revision
        logger.debug(f"Modify command completed, cache updated: revision={params.revision}")

    @staticmethod
    @debug_decorator
    def reset_sync_cache():
        """
        Reset sync cache to initial state.
        Should be called on login/logout to prevent cache from persisting across user sessions.
        """
        global _sync_cache
        with _sync_cache_lock:
            _sync_cache = {
                'last_sync_time': 0,
                'last_revision': 0,
                'cache_ttl': 5
            }
        logger.debug("Sync cache reset to initial state")

    @staticmethod
    @debug_decorator
    def encrypt_response(response: Any) -> bytes:
        encryption_key = ConfigReader.read_config('encryption_private_key')
        if encryption_key:
            try:
                encryption_key_bytes = encryption_key.encode('utf-8')
                response_bytes = json.dumps(response).encode('utf-8')
                return encrypt_aes_v2(response_bytes, encryption_key_bytes)
            except Exception as e:
                raise
        return response

    @classmethod
    def execute(cls, command: str) -> Tuple[Any, int]:
        logger.debug(f"Executing command: {command}")
        
        validation_error = cls.validate_command(command)
        if validation_error:
            return validation_error
        
        from ..core.globals import ensure_params_loaded
        try:
            params = ensure_params_loaded()
            # Set service mode flag to bypass master password enforcement
            if params:
                params.service_mode = True

            command = html.unescape(command)
            command_base = command.split()[0] if command.split() else command
            
            # Special case: login/logout commands - reset cache to prevent cross-user contamination
            if command_base in ('login', 'logout'):
                logger.debug(f"{command_base} command detected, resetting sync cache")
                cls.reset_sync_cache()
            
            # Special case: sync-down command itself - execute as-is, no additional sync needed
            if command_base == 'sync-down':
                logger.debug("sync-down command detected, executing without additional sync logic")
                return_value, printed_output, log_output = CommandExecutor.capture_output_and_logs(params, command)
                response = return_value if return_value else printed_output
                
                # Update cache after sync-down completes
                global _sync_cache
                with _sync_cache_lock:
                    _sync_cache['last_sync_time'] = time.time()
                    _sync_cache['last_revision'] = params.revision
                logger.debug(f"sync-down completed, cache updated: revision={params.revision}")
            else:
                # For fetch commands: sync before execution if cache expired (revision-aware TTL)
                cls.sync_if_needed(params, command_base)
                
                # Capture revision before command execution to detect if it changed
                revision_before = params.revision
                
                # Execute the command
                return_value, printed_output, log_output = CommandExecutor.capture_output_and_logs(params, command)
                response = return_value if return_value else printed_output
                
                # Check if command modified data (revision changed or sync_data flag set)
                # Modify commands sync internally, so we update cache to reflect new revision
                revision_after = params.revision
                if revision_after > revision_before or params.sync_data:
                    # Command modified data and synced internally
                    cls.update_sync_cache_after_modify(params)
                    # Note: Don't reset params.sync_data here, let cli.do_command handle it

            # Debug logging with sanitization
            sanitized_output = sanitize_debug_data(printed_output)
            sanitized_logs = sanitize_debug_data(log_output)
            logger.debug(f"After capture_output - return_value: '{return_value}', printed_output: '{sanitized_output}', log_output: '{sanitized_logs}'")
            sanitized_response = sanitize_debug_data(str(response))
            logger.debug(f"Final response: '{sanitized_response}', response type: {type(response)}")
            
            # Always let the parser handle the response (including empty responses and logs)
            response = parse_keeper_response(command, response, log_output)
            
            if isinstance(response, dict):
                # Extract status_code and remove it from response body
                if 'status_code' in response:
                    status_code = response.pop('status_code')
                elif response.get("status") == "error":
                    status_code = 400
                elif response.get("status") == "warning":
                    status_code = 400
                else:
                    status_code = 200
            else:
                status_code = 200
            
            response = CommandExecutor.encrypt_response(response)
            logger.debug(f"Command executed successfully")
            return response, status_code
        except CommandExecutionError as e:
            # Return the actual command error instead of generic "server busy"
            logger.error(f"Command execution error: {e}")
            error_response = {
                "status": "error",
                "error": str(e)
            }
            return error_response, 400
        except Exception as e:
            # Log unexpected errors and return a proper error response
            logger.error(f"Unexpected error during command execution: {e}")
            error_response = {
                "status": "error",
                "error": f"Unexpected error: {str(e)}"
            }
            return error_response, 500