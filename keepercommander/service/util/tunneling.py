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

from pyngrok import ngrok, conf
import os
import logging
import subprocess
import sys
import time
import requests
import re
import json
import tempfile

from ... import utils
from .process_util import spawn_detached_process, CREATE_NO_WINDOW

# Same user-writable log directory service_manager.py uses for the service subprocess log
TUNNEL_LOG_DIR = os.path.join(utils.get_default_path(), "service_logs")


def get_tunnel_log_file(name):
    os.makedirs(TUNNEL_LOG_DIR, exist_ok=True)
    return os.path.join(TUNNEL_LOG_DIR, name)


def start_ngrok(port, auth_token=None, subdomain=None):
    """
    Start ngrok as a fully detached subprocess and return the PID.
    """
    ngrok_config = conf.get_default()
    ngrok.install_ngrok(ngrok_config)
    ngrok_cmd = [ngrok_config.ngrok_path, "http", str(port), "--log=stdout", "--log-level=info"]
    
    if subdomain:
        ngrok_cmd += ["--subdomain", subdomain]
    if auth_token:
        ngrok_cmd += ["--authtoken", auth_token]


    service_core_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "core")
    log_file = get_tunnel_log_file("ngrok_subprocess.log")
    process = spawn_detached_process(ngrok_cmd, log_file, cwd=service_core_dir, env=os.environ.copy())

    time.sleep(0.5)  # Give ngrok a moment to start
    if process.poll() is not None:
        raise RuntimeError(
            f"ngrok exited immediately (exit code {process.returncode}); see {log_file} for details"
        )

    actual_ngrok_pid = process.pid
    try:
        import psutil

        # Look for the actual ngrok binary process
        for proc in psutil.process_iter(['pid', 'ppid', 'name', 'cmdline']):
            try:
                if (proc.info['ppid'] == process.pid and 
                    proc.info['name'] and 'ngrok' in proc.info['name'].lower()):
                    actual_ngrok_pid = proc.info['pid']
                    logging.debug(f"Found actual ngrok process: PID {actual_ngrok_pid} (child of {process.pid})")
                    break
                elif (proc.info['cmdline'] and 
                      any('ngrok' in str(arg).lower() for arg in proc.info['cmdline']) and
                      'http' in ' '.join(proc.info['cmdline'])):
                    # Check if this looks like the real ngrok process
                    if proc.info['pid'] != process.pid:  # Not the wrapper
                        actual_ngrok_pid = proc.info['pid']
                        logging.debug(f"Found actual ngrok process by cmdline: PID {actual_ngrok_pid}")
                        break
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
    except Exception as e:
        logging.debug(f"Could not find actual ngrok PID, using wrapper PID: {e}")
    
    return actual_ngrok_pid

def get_ngrok_url_from_api(max_retries=10, retry_delay=1):
    """
    Retrieve the ngrok tunnel URL from the local ngrok API.
    Returns the public URL if found, None otherwise.
    """
    for attempt in range(max_retries):
        try:
            # ngrok exposes a local API on port 4040 by default
            response = requests.get('http://127.0.0.1:4040/api/tunnels', timeout=5)
            if response.status_code == 200:
                tunnels_data = response.json()
                tunnels = tunnels_data.get('tunnels', [])
                
                # Find the first HTTPS tunnel
                for tunnel in tunnels:
                    if tunnel.get('proto') == 'https':
                        return tunnel.get('public_url')
                
                # If no HTTPS tunnel found, look for HTTP and convert to HTTPS
                for tunnel in tunnels:
                    if tunnel.get('proto') == 'http':
                        http_url = tunnel.get('public_url')
                        if http_url:
                            return http_url.replace('http://', 'https://')
                        
        except requests.exceptions.RequestException:
            # ngrok might not be ready yet, wait and retry
            if attempt < max_retries - 1:
                time.sleep(retry_delay)
                continue
            
        except Exception as e:
            logging.debug(f"Error retrieving ngrok URL from API: {e}")
            
    return None

def get_ngrok_url_from_log(log_file, max_retries=10, retry_delay=1):
    """
    Parse the ngrok log file to extract the public URL.
    Returns the public URL if found, None otherwise.
    """
    url_pattern = r'url=https://[a-zA-Z0-9\-\.]+\.ngrok\.io'
    
    for attempt in range(max_retries):
        try:
            if os.path.exists(log_file):
                with open(log_file, 'r') as f:
                    content = f.read()
                    
                # Look for URL pattern in the log
                match = re.search(url_pattern, content)
                if match:
                    url = match.group().replace('url=', '')
                    return url
                    
        except Exception as e:
            logging.debug(f"Error reading ngrok log file: {e}")
        
        # Wait and retry if URL not found yet
        if attempt < max_retries - 1:
            time.sleep(retry_delay)
            
    return None

def start_ngrok_with_url(port, auth_token=None, subdomain=None):
    """
    Start ngrok subprocess and return both PID and the actual public URL.
    Returns a tuple (pid, public_url).
    """
    pid = start_ngrok(port, auth_token, subdomain)
    
    time.sleep(2)
    
    # Try to get URL from API first (more reliable)
    public_url = get_ngrok_url_from_api()

    # If API method fails, try parsing the log file
    if not public_url:
        public_url = get_ngrok_url_from_log(get_tunnel_log_file("ngrok_subprocess.log"))
    
    # If we still don't have a URL and subdomain was provided, construct it
    if not public_url and subdomain:
        public_url = f"https://{subdomain}.ngrok.io"
        logging.warning("Could not retrieve dynamic ngrok URL, using constructed URL")
    
    return pid, public_url

def generate_ngrok_url(port, auth_token, ngrok_custom_domain, run_mode):
    """
    Start an ngrok tunnel with complete log suppression.
    Returns a tuple of (public_url, ngrok_pid) for background mode, or (public_url, None) for foreground mode.
    """
    if not port or not auth_token:
        raise ValueError("Both 'port' and 'ngrok_auth_token' must be provided.")

    # Strip .ngrok.io suffix if user provided full domain (e.g., "mycompany.ngrok.io" -> "mycompany")
    if ngrok_custom_domain:
        for suffix in ['.ngrok.io', '.ngrok.app', '.ngrok-free.app']:
            if ngrok_custom_domain.lower().endswith(suffix):
                ngrok_custom_domain = ngrok_custom_domain[:-len(suffix)]
                break

    logging.getLogger("ngrok").setLevel(logging.CRITICAL)
    logging.getLogger("pyngrok").setLevel(logging.CRITICAL)
    
    ngrok_config = conf.PyngrokConfig(
        auth_token=auth_token,
        log_event_callback=None,
    )
    
    if run_mode == "background":
        # Own subprocess with its own log file - skip the console-unsafe fd redirection below.
        if ngrok_custom_domain:
            ngrok_pid, public_url = start_ngrok_with_url(port=port, auth_token=auth_token, subdomain=ngrok_custom_domain)
        else:
            ngrok_pid, public_url = start_ngrok_with_url(port=port, auth_token=auth_token)
        return public_url, ngrok_pid

    old_stdout_fd = None
    old_stderr_fd = None
    try:
        old_stdout_fd = os.dup(1)
        old_stderr_fd = os.dup(2)
        devnull_fd = os.open(os.devnull, os.O_WRONLY)
        try:
            os.dup2(devnull_fd, 1)
            os.dup2(devnull_fd, 2)
        finally:
            os.close(devnull_fd)
    except OSError:
        # Redirection didn't fully succeed - close whatever we already opened and
        # continue without suppressing ngrok's console output.
        for fd in (old_stdout_fd, old_stderr_fd):
            if fd is not None:
                os.close(fd)
        old_stdout_fd = None
        old_stderr_fd = None

    try:
        if ngrok_custom_domain:
            tunnel = ngrok.connect(port, subdomain=ngrok_custom_domain, pyngrok_config=ngrok_config)
        else:
            tunnel = ngrok.connect(port, pyngrok_config=ngrok_config)
        return tunnel.public_url, None

    finally:
        if old_stdout_fd is not None:
            os.dup2(old_stdout_fd, 1)
            os.close(old_stdout_fd)
        if old_stderr_fd is not None:
            os.dup2(old_stderr_fd, 2)
            os.close(old_stderr_fd)


# Cloudflare Tunnel Functions

def _download_cloudflared():
    """
    Download cloudflared binary if not available.
    Returns path to cloudflared binary.
    """
    try:
        # First try to find existing cloudflared
        if sys.platform == "win32":
            result = subprocess.run(
                ['where', 'cloudflared'],
                capture_output=True,
                text=True,
                creationflags=CREATE_NO_WINDOW
            )
        else:
            result = subprocess.run(['which', 'cloudflared'], capture_output=True, text=True)
        if result.returncode == 0:
            # 'where' can print multiple matches, one per line; take the first
            return result.stdout.strip().split('\n')[0]
    except Exception as e:
        logging.debug(f"Could not find existing cloudflared on PATH: {e}")

    # Download cloudflared binary
    import platform
    import urllib.request
    
    system = platform.system().lower()
    machine = platform.machine().lower()
    
    # Determine the correct binary URL
    if system == "linux":
        if "arm" in machine or "aarch64" in machine:
            url = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64"
        else:
            url = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64"
    elif system == "darwin":  # macOS
        if "arm64" in machine or "aarch64" in machine:
            url = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-darwin-arm64.tgz"
        else:
            url = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-darwin-amd64.tgz"
    elif system == "windows":
        url = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe"
    else:
        raise Exception(f"Unsupported platform: {system}")
    
    # Create temp directory for cloudflared
    service_core_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "core")
    bin_dir = os.path.join(service_core_dir, "bin")
    os.makedirs(bin_dir, exist_ok=True)
    
    binary_name = "cloudflared.exe" if system == "windows" else "cloudflared"
    binary_path = os.path.join(bin_dir, binary_name)
    
    if os.path.exists(binary_path):
        return binary_path
    
    logging.info("Downloading cloudflared binary...")
    
    if url.endswith('.tgz'):
        # Handle compressed download for macOS
        import tarfile
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            urllib.request.urlretrieve(url, tmp_file.name)
            with tarfile.open(tmp_file.name, 'r:gz') as tar:
                tar.extractall(bin_dir)
        os.unlink(tmp_file.name)
    else:
        urllib.request.urlretrieve(url, binary_path)
    
    # Make executable on Unix systems
    if system != "windows":
        os.chmod(binary_path, 0o755)
    
    return binary_path


def start_cloudflare_tunnel(port, tunnel_token, custom_domain=None):
    """
    Start Cloudflare tunnel as a detached subprocess and return the PID.
    """
    # Use direct cloudflared binary approach
    return _start_cloudflare_with_binary(port, tunnel_token, custom_domain)


def _start_cloudflare_with_binary(port, tunnel_token, custom_domain=None):
    """
    Start Cloudflare tunnel using cloudflared binary.
    """
    cloudflared_path = _download_cloudflared()
    
    if tunnel_token and tunnel_token.strip():
        # Named tunnel with token - need to specify local service URL
        cloudflared_cmd = [cloudflared_path, "tunnel", "run", "--token", tunnel_token, "--url", f"http://localhost:{port}"]
        if custom_domain:
            # For named tunnels, domain is configured in Cloudflare dashboard
            logging.info(f"Using custom domain: {custom_domain} (configured in Cloudflare dashboard)")
    else:
        raise Exception(
            "Tunnel token is required for secure tunnel operation. "
            "Quick tunnels are not supported for production use. "
            "Please provide a valid Cloudflare tunnel token."
        )
    
    service_core_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "core")
    log_file = get_tunnel_log_file("cloudflare_tunnel_subprocess.log")
    process = spawn_detached_process(cloudflared_cmd, log_file, cwd=service_core_dir, env=os.environ.copy())

    tunnel_url = get_cloudflare_url_from_log(log_file, custom_domain)
    
    return process.pid, tunnel_url


def get_cloudflare_url_from_log(log_file, custom_domain=None, max_retries=10, retry_delay=1):
    """
    Parse the Cloudflare tunnel log file to extract the public URL.
    Returns the public URL if found, None otherwise.
    """
    # Patterns to match different Cloudflare tunnel URL formats
    url_patterns = [
        r'https://[a-zA-Z0-9\-]+\.trycloudflare\.com',
        r'https://[a-zA-Z0-9\-\.]+\.cfargotunnel\.com',
        r'https://[a-zA-Z0-9\-\.]+',  # Generic HTTPS URLs
    ]
    
    for attempt in range(max_retries):
        try:
            if os.path.exists(log_file):
                with open(log_file, 'r') as f:
                    content = f.read()
                    
                # Look for URL patterns in the log
                for pattern in url_patterns:
                    matches = re.findall(pattern, content)
                    for match in matches:
                        # Filter out localhost and other non-public URLs
                        if ('localhost' not in match and 
                            '127.0.0.1' not in match and
                            'trycloudflare.com' in match or 'cfargotunnel.com' in match or custom_domain in match if custom_domain else True):
                            return match
                            
        except Exception as e:
            logging.debug(f"Error reading Cloudflare tunnel log file: {e}")
        
        # Wait and retry if URL not found yet
        if attempt < max_retries - 1:
            time.sleep(retry_delay)
            
    # If custom domain provided and no URL found, construct it
    if custom_domain:
        return f"https://{custom_domain}"
        
    return None


def start_cloudflare_tunnel_with_url(port, tunnel_token, custom_domain=None):
    """
    Start Cloudflare tunnel subprocess and return both PID and the actual public URL.
    Returns a tuple (pid, public_url).
    """
    pid, public_url = start_cloudflare_tunnel(port, tunnel_token, custom_domain)
    return pid, public_url


def generate_cloudflare_url(port, tunnel_token, custom_domain, run_mode):
    """
    Start a Cloudflare tunnel as a detached subprocess and return its public URL.
    Returns a tuple of (public_url, tunnel_pid).
    """
    if not port:
        raise ValueError("Port must be provided for Cloudflare tunnel.")

    if not tunnel_token or not tunnel_token.strip():
        raise ValueError(
            "Tunnel token is required for secure Cloudflare tunnel operation. "
            "Temporary tunnels are not supported for production use."
        )

    # Always runs as a detached subprocess with its own log file - nothing to suppress here.
    tunnel_pid, public_url = start_cloudflare_tunnel_with_url(
        port=port,
        tunnel_token=tunnel_token,
        custom_domain=custom_domain
    )
    return public_url, tunnel_pid
