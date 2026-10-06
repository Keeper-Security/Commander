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
import contextlib
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
from .process_util import spawn_detached_process

def get_tunnel_log_file(name):
    # Resolved per call, not cached at import time, so a later --data-dir override is respected.
    log_dir = os.path.join(utils.get_default_path(), "service_logs")
    os.makedirs(log_dir, exist_ok=True)
    return os.path.join(log_dir, name)


# DOA check only catches immediate crashes; a slower failure (bad auth) is caught later below.
NGROK_STARTUP_CHECK_DELAY_SECONDS = 0.5


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
    utils.set_file_permissions(log_file)

    time.sleep(NGROK_STARTUP_CHECK_DELAY_SECONDS)
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

    # No URL and the process is gone (e.g. bad auth token) is a real failure, not just slow.
    if not public_url:
        try:
            import psutil
            if not psutil.pid_exists(pid):
                raise RuntimeError(f"ngrok process {pid} is no longer running; see logs for details")
        except ImportError:
            pass

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
        # Restore anything already redirected (else fd 1 could stay pointed at devnull forever).
        for fd, target in ((old_stdout_fd, 1), (old_stderr_fd, 2)):
            if fd is not None:
                try:
                    os.dup2(fd, target)
                finally:
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
    # Windows `where`/shutil.which both search cwd before PATH (planted-binary risk) - only search on POSIX.
    if sys.platform != "win32":
        try:
            result = subprocess.run(['which', 'cloudflared'], capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip().splitlines()[0]
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
    utils.set_file_permissions(log_file)

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
                        if ('localhost' not in match and '127.0.0.1' not in match and
                                ('trycloudflare.com' in match or 'cfargotunnel.com' in match
                                 or (custom_domain and custom_domain in match))):
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
    """Run an install/daemon-start command with standard timeout/error handling."""
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


@contextlib.contextmanager
def _downloaded_to_tempfile(url, suffix):
    """Download url to a temp file, yield its path, and always delete it after."""
    import urllib.request

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp_file:
            tmp_path = tmp_file.name
        urllib.request.urlretrieve(url, tmp_path)
        yield tmp_path
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def _install_tailscale_linux():
    """Download and run the official install script. May prompt for sudo interactively."""
    try:
        with _downloaded_to_tempfile(TAILSCALE_INSTALL_SCRIPT_URL, '.sh') as tmp_path:
            return _run_privileged_tailscale_command(['sh', tmp_path], TAILSCALE_INSTALL_TIMEOUT, "Tailscale install")
    except Exception as e:
        logging.error(f"Error downloading Tailscale install script: {type(e).__name__}")
        return False


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
    # Escape embedded quotes - msi_path sits in a single-quoted PS literal (e.g. O'Brien via %TEMP%).
    escaped_msi_path = msi_path.replace("'", "''")
    msi_args = f'/i "{escaped_msi_path}" /quiet TS_NOLAUNCH=1'
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


def _verify_windows_msi_signer(msi_path, timeout):
    """Verify the MSI is Tailscale-signed before elevating - UAC shows msiexec.exe as the
    elevating process, not the payload's publisher, so this check has to stand in for the user."""
    # Same single-quoted-PS-literal escaping as _run_msiexec_elevated_windows above.
    escaped_msi_path = msi_path.replace("'", "''")
    # Match the O= component specifically, not a bare substring of the whole subject --
    # any validly-chained cert merely containing "Tailscale" would otherwise pass here.
    ps_command = (
        f"$sig = Get-AuthenticodeSignature -FilePath '{escaped_msi_path}'; "
        "if ($sig.Status -eq 'Valid' -and $sig.SignerCertificate.Subject -match 'O=Tailscale Inc') "
        "{ Write-Output 'VALID' } else { Write-Output 'INVALID' }"
    )
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_command],
            capture_output=True, text=True, timeout=timeout,
        )
        return (result.stdout or '').strip() == 'VALID'
    except Exception as e:
        logging.error(f"Could not verify MSI signature: {type(e).__name__}")
        return False


def _install_tailscale_windows():
    """Download the official MSI and install silently (no verified winget package exists). Elevates via UAC if needed."""
    try:
        with _downloaded_to_tempfile(TAILSCALE_MSI_INSTALLER_URL, '.msi') as tmp_path:
            if not _verify_windows_msi_signer(tmp_path, TAILSCALE_INSTALL_TIMEOUT):
                logging.error("Downloaded Tailscale MSI is not validly signed by Tailscale Inc. -- aborting install")
                return False

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
    """Truncate the log at lifecycle start - it's opened in append mode elsewhere
    (several one-shot commands share it), so this is what keeps it from growing unbounded."""
    try:
        open(_get_tailscale_log_path(), 'w').close()
    except OSError as e:
        logging.debug(f"Could not reset Tailscale log: {type(e).__name__}")


class TailscaleAccessDeniedError(Exception):
    """Raised when `tailscale up`/`funnel` is denied for not being the tailscaled operator (fresh Linux installs)."""


_TAILSCALE_ACCESS_DENIED_HINT = "checkprefs access denied"


def set_tailscale_operator():
    """One-time Linux fix: grants operator rights via `sudo tailscale set --operator=$USER`."""
    # SUDO_USER first - under `sudo keeper ...`, $USER/$LOGNAME resolve to root instead.
    user = os.environ.get("SUDO_USER") or os.environ.get("USER") or os.environ.get("LOGNAME") or ""
    if not user:
        logging.error("Could not determine current username for Tailscale operator setup")
        return False
    return _run_privileged_tailscale_command(
        ["sudo", "tailscale", "set", f"--operator={user}"], TAILSCALE_DAEMON_START_TIMEOUT, "Operator setup"
    )


def tailscale_up(auth_key, advertise_tags=None):
    """
    Authenticate via `tailscale up --auth-key=... --advertise-tags=... --force-reauth`.

    --advertise-tags is always explicit, even empty: omitting it doesn't clear tags
    a prior run left set, and OAuth-issued keys require it outright.
    --force-reauth is required so a bad key can't be silently ignored by an already-
    authenticated node (exit 0, nothing re-validated) - may briefly disrupt another
    active use of this Tailscale link (e.g. SSH), per Tailscale's own docs.
    The key goes through a short-lived, owner-only temp file (`--auth-key=file:<path>`)
    instead of argv, so it isn't visible via `ps`/`/proc`. Never logged.
    --unattended is Windows-only: see the comment at the call site below.
    """
    if not auth_key:
        raise ValueError("Tailscale auth key must be provided for 'tailscale up'.")

    import platform
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
        # Windows keeps the node up only while the GUI client runs, and the MSI is
        # installed with TS_NOLAUNCH=1 (no GUI). Without this the backend sits at
        # NoState after a successful login and Funnel has nothing to bind to.
        if platform.system() == "Windows":
            cmd.append("--unattended")

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
            access_denied = False
            try:
                with open(log_file, 'r') as f:
                    content = f.read()
                    if "requires --advertise-tags" in content and not advertise_tags:
                        hint = " This auth key requires --advertise-tags (OAuth-issued key)."
                    if _TAILSCALE_ACCESS_DENIED_HINT in content.lower():
                        access_denied = True
            except OSError:
                pass

            logging.error(f"Tailscale authentication failed, exit code {result.returncode}")

            if access_denied:
                raise TailscaleAccessDeniedError(
                    "Tailscale denied the request because this user isn't the tailscaled "
                    "operator on this machine (common on a fresh Linux install). Run "
                    "'sudo tailscale set --operator=$USER' once, then retry."
                )
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


# Funnel only accepts one of these as the external-facing port (local target port is unrestricted).
TAILSCALE_FUNNEL_ALLOWED_PORTS = (443, 8443, 10000)
TAILSCALE_FUNNEL_DEFAULT_PORT = 443


def start_tailscale_funnel(local_port, funnel_port=TAILSCALE_FUNNEL_DEFAULT_PORT):
    """
    Enable Funnel: forward funnel_port -> localhost:local_port.
    --bg is required, otherwise the command blocks in the foreground indefinitely.
    """
    if not local_port:
        raise ValueError("Port must be provided to start Tailscale Funnel.")
    if funnel_port not in TAILSCALE_FUNNEL_ALLOWED_PORTS:
        raise ValueError(
            f"Invalid Tailscale Funnel port {funnel_port}; must be one of {TAILSCALE_FUNNEL_ALLOWED_PORTS}."
        )

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


def _run_tailscale_funnel_teardown(cmd, log_file, local_port):
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
    return False


def stop_tailscale_funnel(local_port, funnel_port=TAILSCALE_FUNNEL_DEFAULT_PORT):
    """
    Disable Funnel for just this target via `tailscale funnel --https=<port> off`
    (undocumented in --help, but confirmed working - it's what Tailscale's own CLI
    suggests after `funnel --bg`). Falls back to the broader `funnel reset` only if
    the target is genuinely still up afterwards, since reset wipes any other
    Serve/Funnel config on the node too.
    """
    log_file = _get_tailscale_log_path()

    try:
        scoped_cmd = ["tailscale", "funnel", f"--https={funnel_port}", "off"]
        if _run_tailscale_funnel_teardown(scoped_cmd, log_file, local_port):
            return True

        # Scoped teardown also exits non-zero when the target is already gone (routine on
        # double teardown), so treat that as success - escalating to `reset` would wipe
        # unrelated Serve/Funnel config for nothing.
        if not get_tailscale_funnel_status(local_port):
            logging.debug(f"Tailscale Funnel for localhost:{local_port} was already inactive")
            return True

        logging.warning("Scoped Tailscale Funnel teardown failed, falling back to 'funnel reset'")
        reset_cmd = ["tailscale", "funnel", "reset"]
        if _run_tailscale_funnel_teardown(reset_cmd, log_file, local_port):
            return True

        logging.warning("Failed to stop Tailscale Funnel")
        return False
    except Exception as e:
        logging.error(f"Error stopping Tailscale Funnel: {type(e).__name__}")
        return False


def get_tailscale_funnel_status(local_port):
    """
    Check live Funnel status via `tailscale funnel status --json`: a target is active
    when Web[host:port].Handlers[path].Proxy matches AND AllowFunnel[host:port] is
    true - the same Web entry is also used for a tailnet-only `serve`, so Proxy alone
    can't distinguish Funnel (public) from Serve (private).
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
            allow_funnel = data.get("AllowFunnel") or {}
            for host_port, web_config in (data.get("Web") or {}).items():
                if not allow_funnel.get(host_port):
                    continue
                for handler in (web_config.get("Handlers") or {}).values():
                    if handler.get("Proxy") == target:
                        return True
    except Exception as e:
        logging.debug(f"Error checking Tailscale funnel status: {type(e).__name__}")
    return False
