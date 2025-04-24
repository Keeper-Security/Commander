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


def start_ngrok(port, auth_token=None, subdomain=None):
    """
    Start ngrok as a fully detached subprocess and return the public URL.
    """
    ngrok_cmd = ["ngrok", "http", str(port)]
    
    if subdomain:
        ngrok_cmd += ["--subdomain", subdomain]
    if auth_token:
        ngrok_cmd += ["--authtoken", auth_token]

    # Fully detach the process
    if sys.platform == "win32":
        DETACHED_PROCESS = 0x00000008
        subprocess.Popen(
            ngrok_cmd,
            creationflags=DETACHED_PROCESS,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
    else:
        subprocess.Popen(
            ngrok_cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=os.setpgrp  # fully detached from shell and parent
        )

def generate_ngrok_url(port, auth_token, ngrok_custom_domain, run_mode):
    """
    Start an ngrok tunnel with complete log suppression.
    Returns only the public URL.
    """
    if not port or not auth_token:
        raise ValueError("Both 'port' and 'ngrok_auth_token' must be provided.")

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
            if ngrok_custom_domain:
                if run_mode == "background":
                    url = start_ngrok(port=port, auth_token=auth_token, subdomain=ngrok_custom_domain)
                    return url
                else:
                    tunnel = ngrok.connect(port, subdomain=ngrok_custom_domain, pyngrok_config=ngrok_config)
                    return tunnel.public_url
            else:
                # url = start_ngrok(port=port, auth_token=auth_token)
               tunnel = ngrok.connect(port, pyngrok_config=ngrok_config)
               return tunnel.public_url
            
        finally:
            os.dup2(old_stdout_fd, 1)
            os.dup2(old_stderr_fd, 2) 
            os.close(old_stdout_fd)
            os.close(old_stderr_fd)