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


def start_ngrok(port, auth_token=None, subdomain=None):
    """
    Start ngrok as a fully detached subprocess and return the PID.
    """
    ngrok_cmd = ["ngrok", "http", str(port), "--log=stdout", "--log-level=info"]
    
    if subdomain:
        ngrok_cmd += ["--subdomain", subdomain]
    if auth_token:
        ngrok_cmd += ["--authtoken", auth_token]


    service_core_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "core")
    log_dir = os.path.join(service_core_dir, "logs")
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, "ngrok_subprocess.log")

    if sys.platform == "win32":
        subprocess.DETACHED_PROCESS = 0x00000008
        with open(log_file, 'w') as log_f:
            process = subprocess.Popen(
                ngrok_cmd,
                creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP,
                stdout=log_f,
                stderr=subprocess.STDOUT,  # Combine stderr with stdout
                cwd=service_core_dir,  # Set working directory
                env=os.environ.copy()  # Inherit environment variables
            )
    else:
        with open(log_file, 'w') as log_f:
            process = subprocess.Popen(
                ngrok_cmd,
                stdout=log_f,
                stderr=subprocess.STDOUT,  # Combine stderr with stdout
                preexec_fn=os.setpgrp,
                cwd=service_core_dir,  # Set working directory
                env=os.environ.copy()  # Inherit environment variables
            )

    actual_ngrok_pid = process.pid
    try:
        import psutil
        time.sleep(0.5)  # Give ngrok a moment to start
        
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
        service_core_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "core")
        log_file = os.path.join(service_core_dir, "logs", "ngrok_subprocess.log")
        public_url = get_ngrok_url_from_log(log_file)
    
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
    
    with open(os.devnull, 'w') as devnull:
        old_stdout_fd = os.dup(1)
        old_stderr_fd = os.dup(2)
        os.dup2(devnull.fileno(), 1)
        os.dup2(devnull.fileno(), 2)
        
        try:
            if run_mode == "background":
                # Background mode: use subprocess for both custom and non-custom domains
                if ngrok_custom_domain:
                    ngrok_pid, public_url = start_ngrok_with_url(port=port, auth_token=auth_token, subdomain=ngrok_custom_domain)
                else:
                    ngrok_pid, public_url = start_ngrok_with_url(port=port, auth_token=auth_token)
                return public_url, ngrok_pid
            else:
                # Foreground mode: use pyngrok library
                if ngrok_custom_domain:
                    tunnel = ngrok.connect(port, subdomain=ngrok_custom_domain, pyngrok_config=ngrok_config)
                else:
                    tunnel = ngrok.connect(port, pyngrok_config=ngrok_config)
                return tunnel.public_url, None
            
        finally:
            os.dup2(old_stdout_fd, 1)
            os.dup2(old_stderr_fd, 2) 
            os.close(old_stdout_fd)
            os.close(old_stderr_fd)


# Cloudflare Tunnel Functions

def _download_cloudflared():
    """
    Download cloudflared binary if not available.
    Returns path to cloudflared binary.
    """
    try:
        # First try to find existing cloudflared
        result = subprocess.run(['which', 'cloudflared'], capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout.strip()
    except:
        pass
        
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
    log_dir = os.path.join(service_core_dir, "logs")
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, "cloudflare_tunnel_subprocess.log")
    
    if sys.platform == "win32":
        subprocess.DETACHED_PROCESS = 0x00000008
        with open(log_file, 'w') as log_f:
            process = subprocess.Popen(
                cloudflared_cmd,
                creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP,
                stdout=log_f,
                stderr=subprocess.STDOUT,
                cwd=service_core_dir,
                env=os.environ.copy()
            )
    else:
        with open(log_file, 'w') as log_f:
            process = subprocess.Popen(
                cloudflared_cmd,
                stdout=log_f,
                stderr=subprocess.STDOUT,
                preexec_fn=os.setpgrp,
                cwd=service_core_dir,
                env=os.environ.copy()
            )
    
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
    Start a Cloudflare tunnel with complete log suppression.
    Returns a tuple of (public_url, tunnel_pid) for background mode, or (public_url, None) for foreground mode.
    """
    if not port:
        raise ValueError("Port must be provided for Cloudflare tunnel.")
    
    if not tunnel_token or not tunnel_token.strip():
        raise ValueError(
            "Tunnel token is required for secure Cloudflare tunnel operation. "
            "Temporary tunnels are not supported for production use."
        )
    
    # Cloudflare tunnel configuration
    
    with open(os.devnull, 'w') as devnull:
        old_stdout_fd = os.dup(1)
        old_stderr_fd = os.dup(2)
        os.dup2(devnull.fileno(), 1)
        os.dup2(devnull.fileno(), 2)
        
        try:
            tunnel_pid, public_url = start_cloudflare_tunnel_with_url(
                port=port,
                tunnel_token=tunnel_token,
                custom_domain=custom_domain
            )
            return public_url, tunnel_pid

        finally:
            os.dup2(old_stdout_fd, 1)
            os.dup2(old_stderr_fd, 2)
            os.close(old_stdout_fd)
            os.close(old_stderr_fd)


# Tailscale Funnel Functions

TAILSCALE_INSTALL_URL = "https://tailscale.com/download"


def is_tailscale_installed():
    """
    Check whether the Tailscale CLI is available on PATH.
    Returns True if found, False otherwise.
    """
    import shutil
    return shutil.which('tailscale') is not None


def get_tailscale_install_guidance():
    """
    Return a user-facing guidance message when the Tailscale CLI is missing,
    for manual installation or as a fallback when automatic installation
    (see install_tailscale()) isn't available or doesn't succeed.
    """
    return (
        "Tailscale CLI was not found on this system. Commander Service Mode "
        "requires Tailscale to be installed before enabling Tailscale Funnel. "
        f"Please install Tailscale from {TAILSCALE_INSTALL_URL} and retry."
    )


TAILSCALE_INSTALL_SCRIPT_URL = "https://tailscale.com/install.sh"
TAILSCALE_MSI_INSTALLER_URL = "https://pkgs.tailscale.com/stable/tailscale-setup-latest-amd64.msi"
TAILSCALE_INSTALL_TIMEOUT = 180


def _install_tailscale_macos():
    """
    Attempt to install Tailscale via Homebrew on macOS.
    Returns True on apparent success, False otherwise. Does not attempt a
    GUI/App-Store install -- if Homebrew isn't available, returns False so
    the caller falls back to manual guidance.
    """
    import shutil
    if not shutil.which('brew'):
        logging.info("Homebrew not available for automatic Tailscale install on macOS")
        return False

    cmd = ['brew', 'install', 'tailscale']
    print(f"Running: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, timeout=TAILSCALE_INSTALL_TIMEOUT, env=os.environ.copy())
        if result.returncode != 0:
            logging.error(f"Tailscale installation command failed with exit code {result.returncode}")
            return False
        return True
    except subprocess.TimeoutExpired:
        logging.error(f"Tailscale installation timed out after {TAILSCALE_INSTALL_TIMEOUT}s")
        return False
    except Exception as e:
        logging.error(f"Error installing Tailscale via Homebrew: {type(e).__name__}")
        return False


def _install_tailscale_linux():
    """
    Attempt to install Tailscale via the official install script on Linux.
    Downloads the script (no shell pipe) and runs it with `sh`. The script
    may prompt for sudo interactively -- expected, since this always runs
    in a real foreground terminal (see configure_tailscale's caller).
    Returns True on apparent success, False otherwise.
    """
    import urllib.request
    import tempfile

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix='.sh') as tmp_file:
            tmp_path = tmp_file.name
        urllib.request.urlretrieve(TAILSCALE_INSTALL_SCRIPT_URL, tmp_path)

        cmd = ['sh', tmp_path]
        print(f"Running: sh {tmp_path} (Tailscale official install script, downloaded from {TAILSCALE_INSTALL_SCRIPT_URL})")

        result = subprocess.run(cmd, timeout=TAILSCALE_INSTALL_TIMEOUT, env=os.environ.copy())
        if result.returncode != 0:
            logging.error(f"Tailscale installation command failed with exit code {result.returncode}")
            return False
        return True
    except subprocess.TimeoutExpired:
        logging.error(f"Tailscale installation timed out after {TAILSCALE_INSTALL_TIMEOUT}s")
        return False
    except Exception as e:
        logging.error(f"Error installing Tailscale via install script: {type(e).__name__}")
        return False
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def _install_tailscale_windows():
    """
    Attempt to install Tailscale on Windows via the official MSI installer,
    run silently with msiexec.

    There is no verified/documented winget package for Tailscale (the
    plausible-looking ID "tailscale.tailscale" does not resolve to a real
    package), so this downloads the official MSI directly -- mirroring the
    urllib-based download approach already used for the Linux install
    script -- rather than depending on an unconfirmed package manager.
    TS_NOLAUNCH=1 prevents the GUI app from auto-launching after install.
    msiexec may require an elevated/admin shell; if not elevated, Windows
    may prompt via UAC or the command may fail, analogous to sudo on
    macOS/Linux.
    Returns True on apparent success, False otherwise.
    """
    import urllib.request
    import tempfile

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix='.msi') as tmp_file:
            tmp_path = tmp_file.name
        urllib.request.urlretrieve(TAILSCALE_MSI_INSTALLER_URL, tmp_path)

        cmd = ['msiexec', '/i', tmp_path, '/quiet', 'TS_NOLAUNCH=1']
        print(f"Running: {' '.join(cmd)} (downloaded from {TAILSCALE_MSI_INSTALLER_URL})")

        result = subprocess.run(cmd, timeout=TAILSCALE_INSTALL_TIMEOUT, env=os.environ.copy())
        if result.returncode != 0:
            logging.error(f"Tailscale installation command failed with exit code {result.returncode}")
            return False
        return True
    except subprocess.TimeoutExpired:
        logging.error(f"Tailscale installation timed out after {TAILSCALE_INSTALL_TIMEOUT}s")
        return False
    except Exception as e:
        logging.error(f"Error installing Tailscale via MSI: {type(e).__name__}")
        return False
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def install_tailscale():
    """
    Attempt to automatically install the Tailscale CLI for the current OS.
    Returns True if the install command completed successfully, False
    otherwise. Callers should re-check is_tailscale_installed() afterward
    rather than trusting this return value alone.
    """
    import platform
    system = platform.system()

    if system == "Darwin":
        return _install_tailscale_macos()
    elif system == "Linux":
        return _install_tailscale_linux()
    elif system == "Windows":
        return _install_tailscale_windows()
    else:
        logging.error(f"Automatic Tailscale installation is not supported on platform: {system}")
        return False


TAILSCALE_DAEMON_START_TIMEOUT = 60


_TAILSCALE_DAEMON_UNREACHABLE_HINT = "failed to connect to local tailscale service"


def is_tailscale_daemon_running():
    """
    Check whether the tailscaled daemon is reachable (distinct from the CLI
    binary being present on PATH -- `tailscale up`/`funnel` require a live
    daemon connection, not just the binary).

    `tailscale status` returns a non-zero exit code both when the daemon is
    genuinely unreachable AND when it's reachable but the node is simply
    logged out ("Logged out.", also exit code 1) -- so exit code alone
    can't distinguish the two. Only the specific "failed to connect to
    local Tailscale service" message indicates the daemon itself is down;
    any other outcome (including "Logged out.") means the daemon is up.

    Returns True if the daemon is reachable, False otherwise.
    """
    try:
        result = subprocess.run(['tailscale', 'status'], capture_output=True, text=True, timeout=10)
        combined_output = f"{result.stdout or ''}{result.stderr or ''}".lower()
        return _TAILSCALE_DAEMON_UNREACHABLE_HINT not in combined_output
    except Exception as e:
        logging.debug(f"Error checking Tailscale daemon status: {type(e).__name__}")
        return False


def get_tailscale_daemon_start_guidance():
    """
    Return a user-facing guidance message when the Tailscale CLI is present
    but the tailscaled daemon isn't running/reachable.
    """
    return (
        "Tailscale CLI is installed, but the Tailscale daemon is not running. "
        "On macOS: run 'sudo brew services start tailscale' (or open the Tailscale app). "
        "On Linux: run 'sudo systemctl start tailscaled'. "
        "On Windows: ensure the Tailscale service is running (reinstall or restart it from Services). "
        "Then retry."
    )


def _start_tailscale_daemon_macos():
    """
    Attempt to start the Tailscale daemon on macOS via the Homebrew service.
    Requires sudo (the daemon needs elevated privileges for network setup) --
    inherits stdio so any real sudo password prompt is visible/interactive.
    Returns True on apparent success, False otherwise.
    """
    cmd = ['sudo', 'brew', 'services', 'start', 'tailscale']
    print(f"Running: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, timeout=TAILSCALE_DAEMON_START_TIMEOUT, env=os.environ.copy())
        if result.returncode != 0:
            logging.error(f"Tailscale daemon start command failed with exit code {result.returncode}")
            return False
        return True
    except subprocess.TimeoutExpired:
        logging.error(f"Tailscale daemon start timed out after {TAILSCALE_DAEMON_START_TIMEOUT}s")
        return False
    except Exception as e:
        logging.error(f"Error starting Tailscale daemon via Homebrew services: {type(e).__name__}")
        return False


def _start_tailscale_daemon_linux():
    """
    Attempt to start the tailscaled daemon on Linux via systemd.
    Requires sudo -- inherits stdio for an interactive password prompt.
    Returns True on apparent success, False otherwise.
    """
    cmd = ['sudo', 'systemctl', 'start', 'tailscaled']
    print(f"Running: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, timeout=TAILSCALE_DAEMON_START_TIMEOUT, env=os.environ.copy())
        if result.returncode != 0:
            logging.error(f"Tailscale daemon start command failed with exit code {result.returncode}")
            return False
        return True
    except subprocess.TimeoutExpired:
        logging.error(f"Tailscale daemon start timed out after {TAILSCALE_DAEMON_START_TIMEOUT}s")
        return False
    except Exception as e:
        logging.error(f"Error starting Tailscale daemon via systemctl: {type(e).__name__}")
        return False


def _start_tailscale_daemon_windows():
    """
    Attempt to start the Tailscale Windows service.
    Returns True on apparent success, False otherwise.
    """
    cmd = ['net', 'start', 'Tailscale']
    print(f"Running: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, timeout=TAILSCALE_DAEMON_START_TIMEOUT, env=os.environ.copy())
        if result.returncode != 0:
            logging.error(f"Tailscale daemon start command failed with exit code {result.returncode}")
            return False
        return True
    except subprocess.TimeoutExpired:
        logging.error(f"Tailscale daemon start timed out after {TAILSCALE_DAEMON_START_TIMEOUT}s")
        return False
    except Exception as e:
        logging.error(f"Error starting Tailscale Windows service: {type(e).__name__}")
        return False


def start_tailscale_daemon():
    """
    Attempt to start the tailscaled daemon for the current OS.
    Returns True if the start command completed successfully, False
    otherwise. Callers should re-check is_tailscale_daemon_running()
    afterward rather than trusting this return value alone.
    """
    import platform
    system = platform.system()

    if system == "Darwin":
        return _start_tailscale_daemon_macos()
    elif system == "Linux":
        return _start_tailscale_daemon_linux()
    elif system == "Windows":
        return _start_tailscale_daemon_windows()
    else:
        logging.error(f"Automatic Tailscale daemon start is not supported on platform: {system}")
        return False


def _get_tailscale_log_path():
    """
    Get the path to the Tailscale subprocess log file, creating the
    containing directory if needed.
    """
    service_core_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "core")
    log_dir = os.path.join(service_core_dir, "logs")
    os.makedirs(log_dir, exist_ok=True)
    return os.path.join(log_dir, "tailscale_subprocess.log")


def tailscale_up(auth_key):
    """
    Authenticate this node to the tailnet using the configured auth key.
    Runs `tailscale up --authkey=<auth_key>`. The auth key is passed as a
    single argv element (never via a shell string) and is never logged.

    Note: like ngrok/cloudflare tokens passed as CLI args today, the auth
    key is visible in this process's argv to other local users via ps/psutil
    for the short lifetime of the subprocess -- a pre-existing OS-level
    exposure class, not a regression introduced here.
    """
    if not auth_key:
        raise ValueError("Tailscale auth key must be provided for 'tailscale up'.")

    cmd = ["tailscale", "up", f"--authkey={auth_key}"]
    log_file = _get_tailscale_log_path()

    try:
        with open(log_file, 'a') as log_f:
            result = subprocess.run(
                cmd,
                stdout=log_f,
                stderr=subprocess.STDOUT,
                env=os.environ.copy(),
                timeout=60,
            )
        if result.returncode != 0:
            raise Exception(
                "Tailscale authentication failed ('tailscale up' returned "
                f"exit code {result.returncode}). See {log_file} for details."
            )
        logging.info("Tailscale authentication successful")
    except subprocess.TimeoutExpired:
        logging.error("Tailscale authentication timed out")
        raise Exception("Tailscale authentication timed out after 60 seconds.")


# Tailscale Funnel only accepts one of these as the external-facing port;
# the local target port (the Commander service port) is unrestricted and
# separate. 443 is the default so the public URL needs no port suffix.
TAILSCALE_FUNNEL_ALLOWED_PORTS = (443, 8443, 10000)
TAILSCALE_FUNNEL_DEFAULT_PORT = 443


def start_tailscale_funnel(local_port, funnel_port=TAILSCALE_FUNNEL_DEFAULT_PORT):
    """
    Enable Tailscale Funnel, forwarding the external funnel_port (must be
    443, 8443, or 10000) to the local Commander service on localhost:local_port.
    Runs `tailscale funnel --bg --https=<funnel_port> localhost:<local_port>`.
    `--bg` is required -- without it, the command runs in the foreground and
    blocks until interrupted (per Tailscale's documented behavior), which
    would hang here indefinitely.
    """
    if not local_port:
        raise ValueError("Port must be provided to start Tailscale Funnel.")

    cmd = [
        "tailscale", "funnel", "--bg",
        f"--https={funnel_port}", f"localhost:{local_port}",
    ]
    log_file = _get_tailscale_log_path()

    try:
        with open(log_file, 'a') as log_f:
            result = subprocess.run(
                cmd,
                stdout=log_f,
                stderr=subprocess.STDOUT,
                env=os.environ.copy(),
                timeout=30,
            )
        if result.returncode != 0:
            raise Exception(
                f"Failed to start Tailscale Funnel (local port {local_port}, "
                f"funnel port {funnel_port}, exit code {result.returncode}). "
                f"See {log_file} for details. Note: the first time Funnel is "
                "enabled on a tailnet, it may require one-time approval in the "
                "Tailscale admin console."
            )
        logging.info(f"Tailscale Funnel enabled: localhost:{local_port} -> :{funnel_port}")
    except subprocess.TimeoutExpired:
        logging.error("Starting Tailscale Funnel timed out")
        raise Exception("Starting Tailscale Funnel timed out after 30 seconds.")


def get_tailscale_funnel_url(local_port, funnel_port=TAILSCALE_FUNNEL_DEFAULT_PORT, max_retries=10, retry_delay=1):
    """
    Retrieve the public HTTPS Funnel URL, combining this node's MagicDNS
    hostname (from `tailscale status --json`) with funnel_port. No port
    suffix is added for the default port 443.
    Returns the public URL if found, None otherwise.
    """
    for attempt in range(max_retries):
        try:
            result = subprocess.run(
                ["tailscale", "status", "--json"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0 and result.stdout:
                status = json.loads(result.stdout)
                self_node = status.get("Self", {})
                dns_name = (self_node.get("DNSName") or "").rstrip('.')
                if dns_name:
                    if funnel_port == TAILSCALE_FUNNEL_DEFAULT_PORT:
                        return f"https://{dns_name}"
                    return f"https://{dns_name}:{funnel_port}"
        except subprocess.TimeoutExpired:
            logging.debug("Timed out retrieving Tailscale status")
        except Exception as e:
            logging.debug(f"Error retrieving Tailscale funnel URL: {type(e).__name__}")

        if attempt < max_retries - 1:
            time.sleep(retry_delay)

    return None


def stop_tailscale_funnel(local_port, funnel_port=TAILSCALE_FUNNEL_DEFAULT_PORT):
    """
    Disable Tailscale Funnel (does not tear down the tailnet connection
    itself, only the funnel exposure).

    The installed CLI's `tailscale funnel --help` shows only `status` and
    `reset` as subcommands -- there is no documented per-target `off`
    argument in this version. `tailscale funnel reset` clears ALL funnel
    config on this node (not scoped to local_port), which is acceptable
    here since Commander only ever manages its own single Funnel target,
    consistent with how the existing ngrok/cloudflare cleanup already scans
    and kills broadly rather than surgically. `local_port`/`funnel_port` are
    accepted for call-site symmetry with start_tailscale_funnel but unused.
    Returns True on success, False otherwise.
    """
    cmd = ["tailscale", "funnel", "reset"]
    log_file = _get_tailscale_log_path()

    try:
        with open(log_file, 'a') as log_f:
            result = subprocess.run(
                cmd,
                stdout=log_f,
                stderr=subprocess.STDOUT,
                env=os.environ.copy(),
                timeout=30,
            )
        if result.returncode == 0:
            logging.info(f"Tailscale Funnel disabled for localhost:{local_port}")
            return True
        logging.warning(f"Failed to stop Tailscale Funnel for localhost:{local_port} (exit code {result.returncode})")
        return False
    except Exception as e:
        logging.error(f"Error stopping Tailscale Funnel: {type(e).__name__}")
        return False


def get_tailscale_funnel_status(local_port):
    """
    Query live Funnel status via `tailscale funnel status --json` for the
    given local port. Returns True if Funnel is currently on for that
    local target, False otherwise.
    """
    try:
        result = subprocess.run(
            ["tailscale", "funnel", "status", "--json"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0 and result.stdout:
            data = json.loads(result.stdout)
            return f"localhost:{local_port}" in json.dumps(data)
    except Exception as e:
        logging.debug(f"Error checking Tailscale funnel status: {type(e).__name__}")
    return False