#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
# Contact: commander@keepersecurity.com
#

"""
Output formatting utilities for Docker setup commands.
"""

from ...display import bcolors
from .models import SetupResult


class DockerSetupPrinter:
    """Utility class for consistent formatting across docker setup commands"""
    
    @staticmethod
    def print_header(title: str) -> None:
        """Print a formatted header"""
        separator = "═" * 59
        print(f"\n{bcolors.BOLD}{separator}{bcolors.ENDC}")
        print(f"{bcolors.BOLD}    {title}{bcolors.ENDC}")
        print(f"{bcolors.BOLD}{separator}{bcolors.ENDC}")
    
    @staticmethod
    def print_step(step_num: int, total_steps: int, message: str) -> None:
        """Print a step indicator"""
        print(f"\n{bcolors.OKBLUE}[{step_num}/{total_steps}]{bcolors.ENDC} {message}")
    
    @staticmethod
    def print_success(message: str, indent: bool = True) -> None:
        """Print a success message"""
        prefix = "  " if indent else ""
        print(f"{prefix}{bcolors.OKGREEN}✓{bcolors.ENDC}  {message}")
    
    @staticmethod
    def print_warning(message: str, indent: bool = True) -> None:
        """Print a warning message"""
        prefix = "  " if indent else ""
        print(f"{prefix}{bcolors.WARNING}⚠{bcolors.ENDC}  {message}")
    
    @staticmethod
    def print_completion(message: str) -> None:
        """Print a completion message"""
        print(f"\n{bcolors.OKGREEN}{bcolors.BOLD}✓ {message}{bcolors.ENDC}")
    
    @staticmethod
    def print_phase1_resources(setup_result: SetupResult, indent: str = "  ") -> None:
        """Print Phase 1 resources created (folder, app, record, config)"""
        print(f"{indent}• Shared Folder: {bcolors.OKBLUE}{setup_result.folder_name}{bcolors.ENDC}")
        print(f"{indent}• KSM App: {bcolors.OKBLUE}{setup_result.app_name}{bcolors.ENDC} (with edit permissions)")
        print(f"{indent}• Config Record: {bcolors.OKBLUE}{setup_result.record_uid}{bcolors.ENDC}")
        print(f"{indent}• KSM Base64 Config: {bcolors.OKGREEN}✓ Generated{bcolors.ENDC}")
    
    @staticmethod
    def print_common_deployment_steps(port: str, config_path: str = None) -> None:
        """Print common deployment steps (header + steps 1-5)"""
        DockerSetupPrinter.print_header("Next Steps to Deploy")
        
        print(f"\n{bcolors.BOLD}Step 1: Quit from this session{bcolors.ENDC}")
        print(f"  {bcolors.OKGREEN}quit{bcolors.ENDC}")
        
        config_file = config_path if config_path else '~/.keeper/config.json'
        print(f"\n{bcolors.BOLD}Step 2: Delete the local config.json file{bcolors.ENDC}")
        print(f"  {bcolors.OKGREEN}rm {config_file}{bcolors.ENDC}")
        print(f"  Why? Prevents device token conflicts - Docker will download its own config.")
        
        print(f"\n{bcolors.BOLD}Step 3: Review docker-compose.yml{bcolors.ENDC}")
        print(f"  {bcolors.OKGREEN}cat docker-compose.yml{bcolors.ENDC}")
        
        print(f"\n{bcolors.BOLD}Step 4: Start the services{bcolors.ENDC}")
        print(f"  {bcolors.OKGREEN}docker compose up -d{bcolors.ENDC}")
        
        print(f"\n{bcolors.BOLD}Step 5: Check services health{bcolors.ENDC}")
        print(f"  {bcolors.OKGREEN}docker ps{bcolors.ENDC} - View container status")
        print(f"  {bcolors.OKGREEN}docker logs keeper-service{bcolors.ENDC} - View Commander logs")
        print(f"  {bcolors.OKGREEN}curl http://localhost:{port}/health{bcolors.ENDC} - Test health endpoint")

