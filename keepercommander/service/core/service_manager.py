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
import signal
import psutil

from keepercommander.params import KeeperParams
from keepercommander.service.config.service_config import ServiceConfig
from ..decorators.logging import logger, debug_decorator
from .process_info import ProcessInfo
from .terminal_handler import TerminalHandler
from .signal_handler import SignalHandler
import json, io, sys, os, subprocess, atexit

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
        
        try:
            if process_info.is_running:
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
            
            from ..config.ngrok_config import NgrokConfigurator
            
            
            is_running = True
            print(f"Commander Service starting on http://localhost:{port}")
            
            NgrokConfigurator.configure_ngrok(config_data, service_config)
            
            logging.getLogger('werkzeug').setLevel(logging.WARNING)


            base_dir = os.path.dirname(os.path.abspath(__file__))
            service_path = os.path.join(base_dir, "service_app.py")
            print(f"Starting Flask process at: {service_path}")  # Debugging line
            

            # # log_file = os.path.join(base_dir, "service.log")

            if sys.platform == "win32":
                DETACHED_PROCESS = 0x00000008
                flask_process = subprocess.Popen(
                    ["python", service_path],
                    creationflags=DETACHED_PROCESS,
                    stdout=log, stderr=log  # Redirect output to log file
                )
            else:
                cls = subprocess.Popen(
                    ["python3", service_path],
                    preexec_fn=os.setsid
                )

            print(f"Commander Service started with PID: {cls.pid}")

            # Save the process ID for future reference
            ProcessInfo.save(cls.pid, is_running)
            
            # cls._flask_app.run(host='localhost', port=port)
            
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
            if ServiceManager.kill_process_by_pid(process_info.pid):
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
                terminal = process_info.terminal or "unknown terminal"
                status = f"Commander Service is Running (PID: {process_info.pid}, Terminal: {terminal})"
                logger.debug(f"Service status check: {status}")
                return status
            except psutil.NoSuchProcess:
                pass
        status = "Commander Service is Stopped"
        logger.debug(f"Service status check: {status}")
        return status
    
    @staticmethod
    def kill_process_by_pid(pid: int):
        """Terminates a process by PID without using psutil."""
        try:
            if sys.platform.startswith("win"):  #  Windows
                subprocess.run(["taskkill", "/PID", str(pid), "/F"], check=True)
                return True
            else:  #  Linux & macOS
                os.kill(pid, signal.SIGTERM)  # Try graceful termination first
                print(f" Process {pid} terminated successfully.")
                return True
        except ProcessLookupError:
            print(f"⚠️ No process found with PID {pid}. It may have already exited.")
        except Exception as e:
            print(f" Error terminating process {pid}: {str(e)}")
        return False