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
from ..config.service_config import ServiceConfig
from ..core.globals import init_globals
from ..decorators.logging import logger, debug_decorator
from ...commands.base import report_output_parser, Command
from ...params import KeeperParams

class AddConfigService(Command):
    """Command to add a new configuration to an existing service."""   
    @debug_decorator
    def get_parser(self):
        parser = argparse.ArgumentParser(prog='service-config-add', parents=[report_output_parser], description='Adds new record to the Commander API service configuration')
        return parser
        
    def execute(self, params: KeeperParams, **kwargs) -> str:
        init_globals(params)
        try:
            logger.debug("Loading existing configuration")
            service_config = ServiceConfig()
            config = service_config.load_config()
            
            new_record = service_config.create_record(
                config["is_advanced_security_enabled"],
                params
            )
            
            config["records"].append(new_record)
            
            service_config.save_config(config)
            service_config.update_or_add_record(params)
            
            logger.info("Config Record with API key created successfully.")
            return ''
            
        except Exception as e:
            print("Error: Service configuration file not found. Please use 'service-create' command to create a service_config file.")
            return ''