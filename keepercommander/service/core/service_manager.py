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

from ... import utils
from ...service.config.service_config import ServiceConfig
from ..decorators.logging import logger, debug_decorator
from .process_info import ProcessInfo
from .terminal_handler import TerminalHandler
from .signal_handler import SignalHandler
import sys, subprocess

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
        
        if process_info.pid and process_info.is_running:
            print(f"Error: Commander Service is already running (PID: {process_info.pid})")
            return
            
        SignalHandler.setup_signal_handlers(cls._handle_shutdown)
            
        try:
            service_config = ServiceConfig()
            config_data = service_config.load_config()
            
            if not (port := config_data.get("port")):
                print("Error: Service configuration is incomplete. Please configure the service port in service_config")
                return
            
            from ..config.ngrok_config import NgrokConfigurator
            from ..config.cloudflare_config import CloudflareConfigurator
            
            is_running = True
            queue_enabled = config_data.get("queue_enabled", "y")
            api_version = "v2" if queue_enabled == "y" else "v1"
            
            # Check if SSL is configured to determine the correct protocol
            ssl_context = cls.get_ssl_context(config_data)
            protocol = "https" if ssl_context else "http"
            
            print(f"Commander Service starting on {protocol}://localhost:{port}/api/{api_version}/")
            
            ngrok_pid = NgrokConfigurator.configure_ngrok(config_data, service_config)
            cloudflare_pid = None

            try:
                cloudflare_pid = CloudflareConfigurator.configure_cloudflare(config_data, service_config)
            except Exception as e:
                if ngrok_pid and psutil:
                    try:
                        process = psutil.Process(ngrok_pid)
                        process.terminate()
                        logger.debug(f"Terminated ngrok process {ngrok_pid}")
                    except (psutil.NoSuchProcess, psutil.AccessDenied, OSError) as ngrok_error:
                        logger.debug(f"Error terminating ngrok process: {type(ngrok_error).__name__}")
                elif ngrok_pid:
                    logger.warning("Cannot terminate ngrok process: psutil not available")

                ProcessInfo.clear()

                logger.info(f"\n{str(e)}")
                return

            # Custom logging filter to replace SSL handshake errors with user-friendly message
            class SSLHandshakeFilter(logging.Filter):
                def filter(self, record):
                    # Replace "Bad request version" errors with a clearer message
                    if hasattr(record, 'getMessage'):
                        message = record.getMessage()
                        if "Bad request version" in message and any(ord(c) > 127 for c in message):
                            # Replace the ugly SSL handshake error with a user-friendly message
                            record.msg = "HTTPS request received but HTTPS protocol is not enabled on this service"
                            record.args = ()
                    return True
            
            werkzeug_logger = logging.getLogger('werkzeug')
            werkzeug_logger.setLevel(logging.WARNING)
            werkzeug_logger.addFilter(SSLHandshakeFilter())

            if config_data.get("run_mode") == "background":

                base_dir = os.path.dirname(os.path.abspath(__file__))
                service_module = "keepercommander.service.core.service_app"  # Use module path instead of file path
                python_executable = sys.executable

                # Create logs directory for subprocess output
                log_dir = os.path.join(base_dir, "logs")
                os.makedirs(log_dir, exist_ok=True)
                log_file = os.path.join(log_dir, "service_subprocess.log")

                try:
                    if sys.platform == "win32":
                        subprocess.DETACHED_PROCESS = 0x00000008
                        with open(log_file, 'w') as log_f:
                            cls = subprocess.Popen(
                                [python_executable, '-m', service_module],
                                creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP,
                                stdout=log_f,
                                stderr=subprocess.STDOUT,  # Combine stderr with stdout
                                cwd=os.getcwd(),  # Use current working directory to access config files
                                env=os.environ.copy()  # Inherit environment variables
                            )
                    else:
                        # For macOS and Linux - improved subprocess handling
                        with open(log_file, 'w') as log_f:
                            cls = subprocess.Popen(
                                [python_executable, '-m', service_module],
                                stdout=log_f,
                                stderr=subprocess.STDOUT,  # Combine stderr with stdout
                                preexec_fn=os.setpgrp,
                                cwd=os.getcwd(),  # Use current working directory to access config files
                                env=os.environ.copy()  # Inherit environment variables
                            )
                    
                    logger.debug(f"Service subprocess logs available at: {log_file}")
                    print(f"Commander Service started with PID: {cls.pid}")
                    ProcessInfo.save(cls.pid, is_running, ngrok_pid)

                except Exception as e:
                    logger.error(f"Failed to start service subprocess: {e}")
                    raise

            else:
                cleanup_done = False

                def cleanup_cloudflare_on_foreground_exit():
                    """Clean up Cloudflare tunnel when foreground service exits."""
                    nonlocal cleanup_done
                    if cleanup_done:
                        return
                    cleanup_done = True

                    try:
                        # Try to load PID from ProcessInfo first (more reliable)
                        try:
                            process_info = ProcessInfo.load()
                            saved_cloudflare_pid = process_info.cloudflare_pid
                        except (KeyboardInterrupt, SystemExit):
                            raise
                        except Exception as e:
                            logger.debug(f"Could not load process info: {e}")
                            saved_cloudflare_pid = None

                        # Kill Cloudflare tunnel if running
                        cf_pid = saved_cloudflare_pid or cloudflare_pid
                        if cf_pid:
                            print(f"Stopping Cloudflare tunnel (PID: {cf_pid})...")
                            try:
                                if ServiceManager.kill_process_by_pid(cf_pid):
                                    print("Cloudflare tunnel stopped")
                                else:
                                    try:
                                        if ServiceManager.kill_cloudflare_processes():
                                            print("Cloudflare tunnel stopped")
                                    except (KeyboardInterrupt, SystemExit):
                                        raise
                                    except Exception as e:
                                        logger.debug(f"Fallback cloudflare cleanup failed: {e}")
                            except (KeyboardInterrupt, SystemExit):
                                raise
                            except Exception as e:
                                logger.debug(f"Primary cloudflare cleanup failed: {e}")
                                try:
                                    if ServiceManager.kill_cloudflare_processes():
                                        print("Cloudflare tunnel stopped")
                                except (KeyboardInterrupt, SystemExit):
                                    raise
                                except Exception as e:
                                    logger.debug(f"Fallback cloudflare cleanup also failed: {e}")
                        else:
                            try:
                                if ServiceManager.kill_cloudflare_processes():
                                    print("Cloudflare tunnel stopped")
                            except (KeyboardInterrupt, SystemExit):
                                raise
                            except Exception as e:
                                logger.debug(f"Fallback cloudflare cleanup failed: {e}")

                        # Clear process info
                        try:
                            ProcessInfo.clear()
                        except (KeyboardInterrupt, SystemExit):
                            raise
                        except Exception as e:
                            logger.debug(f"Could not clear process info: {e}")

                    except (KeyboardInterrupt, SystemExit):
                        logger.info("Cloudflare cleanup interrupted by user or system")
                        raise
                    except Exception as e:
                        print(f"Unexpected error during Cloudflare cleanup: {e}")
                        logger.error(f"Unexpected error during Cloudflare cleanup: {e}")

                def foreground_signal_handler(signum, frame):
                    """Handle interrupt signals in foreground mode."""
                    cleanup_cloudflare_on_foreground_exit()
                    sys.exit(0)

                # Set up signal handlers for foreground mode
                import signal
                signal.signal(signal.SIGINT, foreground_signal_handler)   # Ctrl+C
                signal.signal(signal.SIGTERM, foreground_signal_handler)  # Termination

                from ...service.app import create_app
                cls._flask_app = create_app()
                cls._is_running = True

                ProcessInfo.save(os.getpid(), is_running, ngrok_pid)
                ssl_context = ServiceManager.get_ssl_context(config_data)
                
                try:
                    cls._flask_app.run(
                        host='0.0.0.0',
                        port=port,
                        ssl_context=ssl_context
                    )
                finally:
                    cleanup_cloudflare_on_foreground_exit()

            # Save the process ID for future reference
            ProcessInfo.save(cls.pid, is_running, ngrok_pid, cloudflare_pid)
            
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
        
        logger.debug(f"Loaded process info - Service PID: {process_info.pid}, Ngrok PID: {process_info.ngrok_pid}, Cloudflare PID: {process_info.cloudflare_pid}")
        
        if not process_info.pid:
            print("Error: No running service found to stop")
            return

        try:
            # Stop ngrok process first if it exists
            ngrok_stopped = False
            if process_info.ngrok_pid:
                try:
                    logger.debug(f"Attempting to stop ngrok process (PID: {process_info.ngrok_pid})")
                    
                    # Check if ngrok process is actually running first
                    try:
                        ngrok_process = psutil.Process(process_info.ngrok_pid)
                        logger.debug(f"Ngrok process {process_info.ngrok_pid} is running: {ngrok_process.name()}")
                    except psutil.NoSuchProcess:
                        logger.debug(f"Ngrok process {process_info.ngrok_pid} is not running")
                        
                    logger.debug(f"Calling kill_process_by_pid for ngrok PID {process_info.ngrok_pid}")
                    if ServiceManager.kill_process_by_pid(process_info.ngrok_pid):
                        # Verify that we actually killed an ngrok process, not just any process
                        logger.debug(f"Verifying that PID {process_info.ngrok_pid} was actually ngrok...")
                        try:
                            # Check if there are still any ngrok processes running
                            ngrok_still_running = False
                            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                                try:
                                    if proc.info['name'] and 'ngrok' in proc.info['name'].lower():
                                        ngrok_still_running = True
                                        logger.debug(f"Found remaining ngrok process: PID {proc.info['pid']}")
                                        break
                                    elif proc.info['cmdline']:
                                        cmdline_str = ' '.join(proc.info['cmdline'])
                                        if 'ngrok' in cmdline_str.lower() and 'http' in cmdline_str.lower():
                                            ngrok_still_running = True
                                            logger.debug(f"Found remaining ngrok process: PID {proc.info['pid']}")
                                            break
                                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                                    continue
                            
                            if not ngrok_still_running:
                                logger.debug(f"Ngrok process stopped (PID: {process_info.ngrok_pid})")
                                print("Ngrok tunnel stopped")
                                ngrok_stopped = True
                            else:
                                logger.warning(f"Wrong PID was stored for ngrok process: {process_info.ngrok_pid}")
                                print("Warning: Stored ngrok PID was incorrect, will use fallback cleanup")
                        except Exception as e:
                            logger.debug(f"Error verifying ngrok termination: {e}")
                    else:
                        logger.warning(f"Failed to stop ngrok process (PID: {process_info.ngrok_pid})")
                except Exception as e:
                    logger.warning(f"Error stopping ngrok process: {str(e)}")
            else:
                logger.debug("No ngrok PID found in process info")
            
            # Fallback: Try to kill any remaining ngrok processes
            if not ngrok_stopped:
                logger.debug("Attempting fallback ngrok cleanup...")
                if ServiceManager.kill_ngrok_processes():
                    print("Ngrok tunnel stopped (via cleanup)")
                    ngrok_stopped = True
            
            if not ngrok_stopped:
                logger.debug("No ngrok processes found to stop")

            # Stop Cloudflare tunnel process if it exists
            cloudflare_stopped = False
            if process_info.cloudflare_pid:
                try:
                    logger.debug(f"Attempting to stop Cloudflare tunnel process (PID: {process_info.cloudflare_pid})")

                    # Check if Cloudflare process is actually running first
                    try:
                        cloudflare_process = psutil.Process(process_info.cloudflare_pid)
                        logger.debug(f"Cloudflare tunnel process {process_info.cloudflare_pid} is running: {cloudflare_process.name()}")
                    except psutil.NoSuchProcess:
                        logger.debug(f"Cloudflare tunnel process {process_info.cloudflare_pid} is not running")

                    logger.debug(f"Calling kill_process_by_pid for Cloudflare PID {process_info.cloudflare_pid}")
                    if ServiceManager.kill_process_by_pid(process_info.cloudflare_pid):
                        logger.debug(f"Cloudflare tunnel process stopped (PID: {process_info.cloudflare_pid})")
                        print("Cloudflare tunnel stopped")
                        cloudflare_stopped = True
                    else:
                        logger.warning(f"Failed to stop Cloudflare tunnel process (PID: {process_info.cloudflare_pid})")
                except Exception as e:
                    logger.warning(f"Error stopping Cloudflare tunnel process: {str(e)}")
            else:
                logger.debug("No Cloudflare tunnel PID found in process info")

            # Fallback: Try to kill any remaining cloudflared processes
            if not cloudflare_stopped:
                logger.debug("Attempting fallback Cloudflare tunnel cleanup...")
                if ServiceManager.kill_cloudflare_processes():
                    print("Cloudflare tunnel stopped (via cleanup)")
                    cloudflare_stopped = True

            if not cloudflare_stopped:
                logger.debug("No Cloudflare tunnel processes found to stop")

            # Stop the main service process
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
                
                # Check ngrok status if available
                if process_info.ngrok_pid:
                    try:
                        psutil.Process(process_info.ngrok_pid)
                        # Try to get the current ngrok URL dynamically
                        try:
                            from ..util.tunneling import get_ngrok_url_from_api
                            current_url = get_ngrok_url_from_api(max_retries=1, retry_delay=0.5)
                            if current_url:
                                status += f"\nNgrok tunnel is Running (PID: {process_info.ngrok_pid}, URL: {current_url})"
                            else:
                                status += f"\nNgrok tunnel is Running (PID: {process_info.ngrok_pid})"
                        except Exception:
                            status += f"\nNgrok tunnel is Running (PID: {process_info.ngrok_pid})"
                    except psutil.NoSuchProcess:
                        status += f"\nNgrok tunnel is Stopped (was PID: {process_info.ngrok_pid})"
                
                # Check Cloudflare tunnel status if available
                if process_info.cloudflare_pid:
                    try:
                        psutil.Process(process_info.cloudflare_pid)
                        status += f"\nCloudflare tunnel is Running (PID: {process_info.cloudflare_pid})"
                    except psutil.NoSuchProcess:
                        status += f"\nCloudflare tunnel is Stopped (was PID: {process_info.cloudflare_pid})"

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
        logger.debug(f"Attempting to kill process {pid}")
        try:
            if sys.platform.startswith("win"):  #  Windows
                logger.debug(f"Using Windows taskkill for PID {pid}")
                subprocess.run(["taskkill", "/PID", str(pid), "/F"], check=True)
                return True
            else:  #  Linux & macOS
                try:
                    logger.debug(f"Sending SIGTERM to PID {pid}")
                    os.kill(pid, signal.SIGTERM)
                    # Wait a moment for graceful termination
                    import time
                    time.sleep(0.5)
                    # Check if process is still running
                    try:
                        logger.debug(f"Checking if PID {pid} is still running")
                        os.kill(pid, 0)  # This doesn't kill, just checks if process exists
                        # If we get here, process is still running, force kill it
                        logger.debug(f"Process {pid} still running, sending SIGKILL")
                        os.kill(pid, signal.SIGKILL)
                        logger.debug(f"Sent SIGKILL to PID {pid}")
                    except ProcessLookupError:
                        # Process has terminated gracefully
                        logger.debug(f"Process {pid} terminated gracefully after SIGTERM")
                        pass
                    return True
                except ProcessLookupError:
                    # Process doesn't exist
                    logger.debug(f"Process {pid} doesn't exist")
                    return True
        except ProcessLookupError:
            logger.warning(f"No process found with PID {pid}. It may have already exited.")
            return True
        except Exception as e:
            logger.error(f"Error terminating process {pid}: {str(e)}")
        return False

    @staticmethod
    def kill_ngrok_processes():
        """Kill all ngrok processes as a fallback method."""
        killed_count = 0
        try:
            logger.debug("Looking for ngrok processes to kill...")
            
            # Find all ngrok processes
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    if proc.info['name'] and 'ngrok' in proc.info['name'].lower():
                        pid = proc.info['pid']
                        logger.debug(f"Found ngrok process by name: PID {pid}")
                        if ServiceManager.kill_process_by_pid(pid):
                            killed_count += 1
                    elif proc.info['cmdline']:
                        # Check if ngrok is in the command line
                        cmdline_str = ' '.join(proc.info['cmdline'])
                        if 'ngrok' in cmdline_str.lower() and 'http' in cmdline_str.lower():
                            pid = proc.info['pid']
                            logger.debug(f"Found ngrok process by cmdline: PID {pid}")
                            if ServiceManager.kill_process_by_pid(pid):
                                killed_count += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            
            if killed_count > 0:
                logger.info(f"Killed {killed_count} ngrok processes")
                return True
            else:
                logger.debug("No ngrok processes found to kill")
                return False
                
        except Exception as e:
            logger.error(f"Exception while killing ngrok processes: {str(e)}")
            return False

    @staticmethod
    def kill_cloudflare_processes():
        """Kill all cloudflared processes as a fallback method."""
        killed_count = 0
        try:
            logger.debug("Looking for cloudflared processes to kill...")

            # Find all cloudflared processes
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    if proc.info['name'] and 'cloudflared' in proc.info['name'].lower():
                        pid = proc.info['pid']
                        logger.debug(f"Found cloudflared process by name: PID {pid}")
                        if ServiceManager.kill_process_by_pid(pid):
                            killed_count += 1
                    elif proc.info['cmdline']:
                        # Check if cloudflared is in the command line
                        cmdline_str = ' '.join(proc.info['cmdline'])
                        if 'cloudflared' in cmdline_str.lower() and ('tunnel' in cmdline_str.lower() or 'http' in cmdline_str.lower()):
                            pid = proc.info['pid']
                            logger.debug(f"Found cloudflared process by cmdline: PID {pid}")
                            if ServiceManager.kill_process_by_pid(pid):
                                killed_count += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

            if killed_count > 0:
                logger.info(f"Killed {killed_count} cloudflared processes")
                return True
            else:
                logger.debug("No cloudflared processes found to kill")
                return False

        except Exception as e:
            logger.error(f"Exception while killing cloudflared processes: {str(e)}")
            return False
