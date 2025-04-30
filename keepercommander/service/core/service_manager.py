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
from pathlib import Path
import signal
import psutil

from keepercommander import utils
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

    @staticmethod
    def get_ssl_context(config_data):
        """
        Get SSL context from configuration data if certificates are available.
        Returns None if no valid certificates are found.
        """
        ssl_context = None
        if config_data.get("certfile") and config_data.get("certpassword"):
            certfile = utils.get_default_path() / os.path.basename(config_data.get("certfile"))
            certpassword = utils.get_default_path() / os.path.basename(config_data.get("certpassword"))
            
            if os.path.exists(certfile) and os.path.exists(certpassword):
                logger.debug('Using SSL certificates')
                ssl_context = (certfile, certpassword)
        
        return ssl_context

    
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
            print(f"Commander Service starting on https://localhost:{port}")
            
            NgrokConfigurator.configure_ngrok(config_data, service_config)
            
            logging.getLogger('werkzeug').setLevel(logging.WARNING)

            if config_data.get("run_mode") == "background":

                base_dir = os.path.dirname(os.path.abspath(__file__))
                service_path = os.path.join(base_dir, "service_app.py")

                if sys.platform == "win32":
                    subprocess.DETACHED_PROCESS = 0x00000008
                    cls = subprocess.Popen(
                        ["py", service_path],
                        creationflags= subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL  # Redirect output to log file
                    )
                else:
                    cls = subprocess.Popen(
                        ["python3", service_path],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        preexec_fn=os.setpgrp
                    )

                print(f"Commander Service started with PID: {cls.pid}")

            else:
                from keepercommander.service.app import create_app
                cls._flask_app = create_app()
                cls._is_running = True

                ssl_context = ServiceManager.get_ssl_context(config_data)
                
                cls._flask_app.run(
                    host='0.0.0.0',
                    port=port,
                    ssl_context=ssl_context
                )
                
            # Save the process ID for future reference
            ProcessInfo.save(cls.pid, is_running)
            
        except FileNotFoundError:
            logging.info("Error: Service configuration file not found. Please use 'service-create' command to create a service_config file.")
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
                process = psutil.Process(process_info.pid)
                process.terminate()

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
                psutil.Process(process_info.pid)
                terminal = process_info.terminal or "unknown terminal"
                status = f"Commander Service is Running (PID: {process_info.pid}, Terminal: {terminal})"
                logger.debug(f"Service status check: {status}")
                return status
            except psutil.NoSuchProcess:
                ProcessInfo.clear()
                pass
        else:
            status = "No Commander Service is running currently"
            return status
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
                env_file = Path(__file__).parent / ".service.env"
                if os.path.exists(env_file):
                    os.remove(env_file)
                    print("⚠️ Deleted old .env file")
                return True
        except ProcessLookupError:
            print(f"⚠️ No process found with PID {pid}. It may have already exited.")
        except Exception as e:
            print(f" Error terminating process {pid}: {str(e)}")
        return False
