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
    """Check whether the Tailscale CLI is on PATH."""
    import shutil
    return shutil.which('tailscale') is not None


def get_tailscale_install_guidance():
    """Manual install guidance; used when auto-install is unavailable or fails."""
    return (
        "Tailscale CLI was not found on this system. Commander Service Mode "
        "requires Tailscale to be installed before enabling Tailscale Funnel. "
        f"Please install Tailscale from {TAILSCALE_INSTALL_URL} and retry."
    )


TAILSCALE_INSTALL_SCRIPT_URL = "https://tailscale.com/install.sh"
TAILSCALE_MSI_INSTALLER_URL = "https://pkgs.tailscale.com/stable/tailscale-setup-latest-amd64.msi"
TAILSCALE_INSTALL_TIMEOUT = 180


def _run_privileged_tailscale_command(cmd, timeout, action_label):
    """
    Run a Tailscale management command (install/daemon-start, may need sudo)
    with standard timeout/error handling. Returns True on success, False otherwise.
    """
    print(f"Running: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, timeout=timeout, env=os.environ.copy())
        if result.returncode != 0:
            logging.error(f"{action_label} failed, exit code {result.returncode}")
            return False
        return True
    except subprocess.TimeoutExpired:
        logging.error(f"{action_label} timed out after {timeout}s")
        return False
    except Exception as e:
        logging.error(f"Error during {action_label.lower()}: {type(e).__name__}")
        return False


def _install_tailscale_macos():
    """Install via Homebrew. Returns False if Homebrew isn't available (no GUI/App Store fallback)."""
    import shutil
    if not shutil.which('brew'):
        logging.info("Homebrew not available for automatic Tailscale install")
        return False
    return _run_privileged_tailscale_command(['brew', 'install', 'tailscale'], TAILSCALE_INSTALL_TIMEOUT, "Tailscale install")


def _install_tailscale_linux():
    """Download and run the official install script. May prompt for sudo interactively."""
    import urllib.request
    import tempfile

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix='.sh') as tmp_file:
            tmp_path = tmp_file.name
        urllib.request.urlretrieve(TAILSCALE_INSTALL_SCRIPT_URL, tmp_path)
        return _run_privileged_tailscale_command(['sh', tmp_path], TAILSCALE_INSTALL_TIMEOUT, "Tailscale install")
    except Exception as e:
        logging.error(f"Error downloading Tailscale install script: {type(e).__name__}")
        return False
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def _is_windows_process_elevated():
    """Check whether this process has Administrator privileges."""
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception as e:
        logging.debug(f"Could not determine Windows elevation state: {type(e).__name__}")
        return False


def _run_msiexec_elevated_windows(msi_path, timeout):
    """Run msiexec via a UAC prompt (Start-Process -Verb RunAs). Returns exit code, or None if declined/failed."""
    msi_args = f'/i "{msi_path}" /quiet TS_NOLAUNCH=1'
    ps_command = (
        "try { "
        f"$p = Start-Process -FilePath msiexec.exe -ArgumentList '{msi_args}' -Verb RunAs -Wait -PassThru; "
        "Write-Output $p.ExitCode "
        "} catch { Write-Output 'ELEVATION_FAILED' }"
    )
    cmd = ["powershell", "-NoProfile", "-Command", ps_command]
    print("Requesting Administrator approval (UAC prompt) to install Tailscale...")

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    output = (result.stdout or '').strip()
    if 'ELEVATION_FAILED' in output:
        logging.error("Elevation request failed or was declined")
        return None
    try:
        return int(output.splitlines()[-1].strip())
    except (ValueError, IndexError):
        logging.error(f"Could not parse msiexec exit code: {output!r}")
        return None


def _install_tailscale_windows():
    """Download the official MSI and install silently (no verified winget package exists). Elevates via UAC if needed."""
    import urllib.request
    import tempfile

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix='.msi') as tmp_file:
            tmp_path = tmp_file.name
        urllib.request.urlretrieve(TAILSCALE_MSI_INSTALLER_URL, tmp_path)

        if _is_windows_process_elevated():
            cmd = ['msiexec', '/i', tmp_path, '/quiet', 'TS_NOLAUNCH=1']
            print(f"Running: {' '.join(cmd)}")
            result = subprocess.run(cmd, timeout=TAILSCALE_INSTALL_TIMEOUT, env=os.environ.copy())
            returncode = result.returncode
        else:
            returncode = _run_msiexec_elevated_windows(tmp_path, TAILSCALE_INSTALL_TIMEOUT)

        if returncode is None or returncode != 0:
            logging.error(f"Tailscale install failed, exit code {returncode}")
            return False

        _add_windows_tailscale_to_process_path()
        return True
    except subprocess.TimeoutExpired:
        logging.error(f"Tailscale install timed out after {TAILSCALE_INSTALL_TIMEOUT}s")
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


def _add_windows_tailscale_to_process_path():
    """Extend this process's PATH so is_tailscale_installed() sees a fresh install without a shell restart."""
    default_install_dir = r"C:\Program Files\Tailscale"
    current_path = os.environ.get("PATH", "")
    if default_install_dir not in current_path.split(os.pathsep):
        os.environ["PATH"] = current_path + os.pathsep + default_install_dir
        logging.debug(f"Added {default_install_dir} to process PATH")


def install_tailscale():
    """Install Tailscale for the current OS. Caller should re-check is_tailscale_installed() after."""
    import platform
    system = platform.system()

    if system == "Darwin":
        return _install_tailscale_macos()
    elif system == "Linux":
        return _install_tailscale_linux()
    elif system == "Windows":
        return _install_tailscale_windows()
    else:
        logging.error(f"Automatic Tailscale install not supported on platform: {system}")
        return False


TAILSCALE_DAEMON_START_TIMEOUT = 60


_TAILSCALE_DAEMON_UNREACHABLE_HINT = "failed to connect to local tailscale service"


def is_tailscale_daemon_running():
    """
    Check whether tailscaled is reachable. `tailscale status` exits non-zero
    both when unreachable and when merely logged out, so check for the
    specific unreachable-connection message rather than the exit code.
    """
    try:
        result = subprocess.run(['tailscale', 'status'], capture_output=True, text=True, timeout=10)
        combined_output = f"{result.stdout or ''}{result.stderr or ''}".lower()
        return _TAILSCALE_DAEMON_UNREACHABLE_HINT not in combined_output
    except Exception as e:
        logging.debug(f"Error checking Tailscale daemon status: {type(e).__name__}")
        return False


def get_tailscale_daemon_start_guidance():
    """Manual daemon-start guidance; used when auto-start fails."""
    return (
        "Tailscale CLI is installed, but the Tailscale daemon is not running. "
        "On macOS: run 'sudo brew services start tailscale' (or open the Tailscale app). "
        "On Linux: run 'sudo systemctl start tailscaled'. "
        "On Windows: ensure the Tailscale service is running (reinstall or restart it from Services). "
        "Then retry."
    )


def _start_tailscale_daemon_macos():
    """Start tailscaled via Homebrew services. Requires sudo."""
    return _run_privileged_tailscale_command(['sudo', 'brew', 'services', 'start', 'tailscale'], TAILSCALE_DAEMON_START_TIMEOUT, "Daemon start")


def _start_tailscale_daemon_linux():
    """Start tailscaled via systemd. Requires sudo."""
    return _run_privileged_tailscale_command(['sudo', 'systemctl', 'start', 'tailscaled'], TAILSCALE_DAEMON_START_TIMEOUT, "Daemon start")


def _start_tailscale_daemon_windows():
    """Start the Tailscale Windows service."""
    return _run_privileged_tailscale_command(['net', 'start', 'Tailscale'], TAILSCALE_DAEMON_START_TIMEOUT, "Daemon start")


def start_tailscale_daemon():
    """Start the daemon for the current OS. Caller should re-check is_tailscale_daemon_running() after."""
    import platform
    system = platform.system()

    if system == "Darwin":
        return _start_tailscale_daemon_macos()
    elif system == "Linux":
        return _start_tailscale_daemon_linux()
    elif system == "Windows":
        return _start_tailscale_daemon_windows()
    else:
        logging.error(f"Automatic daemon start not supported on platform: {system}")
        return False


def _get_tailscale_log_path():
    """Path to the Tailscale subprocess log file."""
    service_core_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "core")
    log_dir = os.path.join(service_core_dir, "logs")
    os.makedirs(log_dir, exist_ok=True)
    return os.path.join(log_dir, "tailscale_subprocess.log")


def reset_tailscale_log():
    """
    Truncate the Tailscale subprocess log at the start of a service lifecycle,
    matching Ngrok/Cloudflare's per-session log convention. Without this, the
    log grows unbounded across every start/stop cycle -- unlike the other
    tunnel providers' 'w'-mode logs, Tailscale's is always opened in append
    mode since multiple one-shot commands (up/funnel) share it within a
    single lifecycle.
    """
    try:
        open(_get_tailscale_log_path(), 'w').close()
    except OSError as e:
        logging.debug(f"Could not reset Tailscale log: {type(e).__name__}")


def tailscale_up(auth_key, advertise_tags=None):
    """
    Authenticate via `tailscale up --auth-key=... --advertise-tags=... --force-reauth`.
    advertise_tags is required for OAuth-client-issued auth keys. --advertise-tags
    is always passed explicitly (empty if unused) -- `tailscale up` requires every
    non-default setting to be re-specified on each call, or it errors out; omitting
    the flag entirely fails if a previous run (e.g. a prior OAuth key) left tags set.

    --force-reauth is required too: without it, `tailscale up` returns exit code 0
    for an invalid auth key as long as the node is already authenticated under any
    identity -- there's nothing to re-authenticate, so the key is silently ignored
    rather than validated. --force-reauth makes Tailscale genuinely re-validate the
    key every time, so the exit code can be trusted. Per Tailscale's own docs, this
    may briefly disrupt an active connection if this same Tailscale link is being
    used for something else (e.g. an SSH session) at the moment of the call.

    The auth key is written to a short-lived, owner-only-readable temp file
    and passed as `--auth-key=file:<path>` rather than a raw argv value --
    Tailscale supports this directly, avoiding exposing the key via `ps`/
    `/proc` to other local users for the life of the subprocess. Never logged.
    """
    if not auth_key:
        raise ValueError("Tailscale auth key must be provided for 'tailscale up'.")

    import tempfile
    log_file = _get_tailscale_log_path()
    key_file_path = None

    try:
        fd, key_file_path = tempfile.mkstemp(suffix='.tskey')
        os.chmod(key_file_path, 0o600)
        with os.fdopen(fd, 'w') as key_f:
            key_f.write(auth_key)

        cmd = ["tailscale", "up", f"--auth-key=file:{key_file_path}",
               f"--advertise-tags={advertise_tags or ''}", "--force-reauth"]

        with open(log_file, 'a') as log_f:
            result = subprocess.run(
                cmd,
                stdout=log_f,
                stderr=subprocess.STDOUT,
                env=os.environ.copy(),
                timeout=60,
            )
        if result.returncode != 0:
            hint = ""
            try:
                with open(log_file, 'r') as f:
                    if "requires --advertise-tags" in f.read() and not advertise_tags:
                        hint = " This auth key requires --advertise-tags (OAuth-issued key)."
            except OSError:
                pass
            logging.error(f"Tailscale authentication failed, exit code {result.returncode}")
            raise Exception(
                f"Tailscale authentication failed (exit code {result.returncode}).{hint} "
                f"See {log_file} for details."
            )
        logging.info("Tailscale authentication successful")
    except subprocess.TimeoutExpired:
        logging.error("Tailscale authentication timed out")
        raise Exception("Tailscale authentication timed out after 60 seconds.")
    finally:
        if key_file_path:
            try:
                os.unlink(key_file_path)
            except OSError:
                pass


# Tailscale Funnel only accepts one of these as the external-facing port;
# the local target port (the Commander service port) is unrestricted and
# separate. 443 is the default so the public URL needs no port suffix.
TAILSCALE_FUNNEL_ALLOWED_PORTS = (443, 8443, 10000)
TAILSCALE_FUNNEL_DEFAULT_PORT = 443


def start_tailscale_funnel(local_port, funnel_port=TAILSCALE_FUNNEL_DEFAULT_PORT):
    """
    Enable Funnel: forward funnel_port -> localhost:local_port.
    --bg is required, otherwise the command blocks in the foreground indefinitely.
    """
    if not local_port:
        raise ValueError("Port must be provided to start Tailscale Funnel.")

    cmd = ["tailscale", "funnel", "--bg", f"--https={funnel_port}", f"localhost:{local_port}"]
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
            logging.error(f"Tailscale Funnel start failed, exit code {result.returncode}")
            raise Exception(
                f"Failed to start Tailscale Funnel (exit code {result.returncode}). "
                f"See {log_file} for details. First-time Funnel use on a tailnet may "
                "require one-time approval in the Tailscale admin console."
            )
        logging.info(f"Tailscale Funnel enabled: localhost:{local_port} -> :{funnel_port}")
    except subprocess.TimeoutExpired:
        logging.error("Starting Tailscale Funnel timed out")
        raise Exception("Starting Tailscale Funnel timed out after 30 seconds.")


def get_tailscale_funnel_url(local_port, funnel_port=TAILSCALE_FUNNEL_DEFAULT_PORT, max_retries=10, retry_delay=1):
    """Build the public Funnel URL from this node's MagicDNS hostname + funnel_port."""
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
                dns_name = (status.get("Self", {}).get("DNSName") or "").rstrip('.')
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

    logging.warning(f"Could not retrieve Tailscale Funnel URL after {max_retries} attempts")
    return None


def stop_tailscale_funnel(local_port, funnel_port=TAILSCALE_FUNNEL_DEFAULT_PORT):
    """
    Disable Funnel via `tailscale funnel reset` (no per-target `off` exists
    in this CLI version). Resets all funnel config on this node; acceptable
    since Commander manages a single target. local_port/funnel_port kept
    for signature symmetry with start_tailscale_funnel.
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
        logging.warning(f"Failed to stop Tailscale Funnel, exit code {result.returncode}")
        return False
    except Exception as e:
        logging.error(f"Error stopping Tailscale Funnel: {type(e).__name__}")
        return False


def get_tailscale_funnel_status(local_port):
    """
    Check live Funnel status via `tailscale funnel status --json`. Verified
    schema: active targets appear as data["Web"]["<host>:<port>"]["Handlers"]
    ["<path>"]["Proxy"] == "http://localhost:<local_port>".
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
            target = f"http://localhost:{local_port}"
            for web_config in (data.get("Web") or {}).values():
                for handler in (web_config.get("Handlers") or {}).values():
                    if handler.get("Proxy") == target:
                        return True
    except Exception as e:
        logging.debug(f"Error checking Tailscale funnel status: {type(e).__name__}")
    return False