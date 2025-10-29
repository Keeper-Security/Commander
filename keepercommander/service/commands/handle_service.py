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

import argparse
from ...params import KeeperParams
from ...commands.base import report_output_parser, Command
from ..core.service_manager import ServiceManager
from ..core.globals import init_globals
from ..decorators.logging import debug_decorator

class StartService(Command):
    """Command to start the service."""
    @debug_decorator
    def get_parser(self):
        parser = argparse.ArgumentParser(prog='service-start', parents=[report_output_parser], description='Starts the Commander API service with existing configuration')
        return parser

    def execute(self, params: KeeperParams, **kwargs) -> None:
        init_globals(params)
        ServiceManager.start_service()

class StopService(Command):
    """Command to stop the service."""
    @debug_decorator
    def get_parser(self):
        parser = argparse.ArgumentParser(prog='service-stop', parents=[report_output_parser], description='Stops the Commander API service currently running')
        return parser
    
    def execute(self, params: KeeperParams, **kwargs) -> None:
        ServiceManager.stop_service()

class ServiceStatus(Command):
    """Command to get service status."""
    @debug_decorator
    def get_parser(self):
        parser = argparse.ArgumentParser(prog='service-status', parents=[report_output_parser], description='Displays if the Commander API service is running or stopped')
        return parser
    
    def execute(self, params: KeeperParams, **kwargs) -> str:
        status = ServiceManager.get_status()
        print(f"Current status: {status}")