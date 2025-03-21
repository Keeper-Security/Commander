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
import logging
import psutil
from ..config.service_config import ServiceConfig
from ..decorators.logging import logger, debug_decorator
from .process_info import ProcessInfo
from .terminal_handler import TerminalHandler
from .signal_handler import SignalHandler

class ServiceManager:
    """Manages the lifecycle of the service including start, stop, and status operations."""
    
    _flask_app = None
    _is_running = False
    
    @classmethod
    @debug_decorator
    def _handle_shutdown(cls) -> None:
        """Handle service shutdown."""
        logger.debug("Handling service shutdown")
        cls._is_running = False
        cls._flask_app = None
        ProcessInfo.clear()

    @classmethod
    def start_service(cls) -> None:
        """Start the service if not already running."""
        process_info = ProcessInfo.load()
        
        if process_info.is_running:
            try:
                process = psutil.Process(process_info.pid)
                if process.is_running():
                    print(f"Error: Commander Service is already running (PID: {process_info.pid})")
                    return
            except psutil.NoSuchProcess:
                pass
            
        SignalHandler.setup_signal_handlers(cls._handle_shutdown)
            
        try:
            service_config = ServiceConfig()
            config_data = service_config.load_config()
            
            if not (port := config_data.get("port")):
                print("Error: Service configuration is incomplete. Please configure the service port in service_config")
                return
            
            from ..app import create_app
            from ..config.ngrok_config import NgrokConfigurator
            
            cls._flask_app = create_app()
            cls._is_running = True
            ProcessInfo.save(cls._is_running)
            
            print(f"Commander Service starting on http://localhost:{port}")
            print(f"Process ID: {os.getpid()}")
            
            NgrokConfigurator.configure_ngrok(config_data, service_config)
            
            logging.getLogger('werkzeug').setLevel(logging.WARNING)
            
            cls._flask_app.run(host='0.0.0.0', port=port)
            
        except FileNotFoundError:
            print("Error: Service configuration file not found. Please use 'service-create' command to create a service_config file.")
            return
        except Exception as e:
            logger.error(f"Error: Failed to start Commander Service")
            logger.error(f"Reason: {e}")
            cls._handle_shutdown()

    @classmethod
    def stop_service(cls) -> None:
        """Stop the service if running."""
        process_info = ProcessInfo.load()
        
        if not process_info.pid:
            print("Error: No running service found to stop")
            return

        try:
            process = psutil.Process(process_info.pid)
            process.terminate()
            logger.debug(f"Commander Service stopped (PID: {process_info.pid})")
            print("Service stopped successfully")

            if process_info.terminal and process_info.terminal != TerminalHandler.get_terminal_info():
                TerminalHandler.notify_other_terminal(process_info.terminal)

        except (psutil.NoSuchProcess, ProcessLookupError):
            print("Error: No running service found to stop")
        except Exception as e:
            logger.error(f"Error stopping service: {str(e)}")

        cls._handle_shutdown()

    @staticmethod
    def get_status() -> str:
        """Get current service status."""
        process_info = ProcessInfo.load()
        
        if process_info.pid and process_info.is_running:
            try:
                process = psutil.Process(process_info.pid)
                if process.is_running():
                    terminal = process_info.terminal or "unknown terminal"
                    status = f"Commander Service is Running (PID: {process_info.pid}, Terminal: {terminal})"
                    logger.debug(f"Service status check: {status}")
                    return status
            except psutil.NoSuchProcess:
                pass
        status = "Commander Service is Stopped"
        logger.debug(f"Service status check: {status}")
        return status