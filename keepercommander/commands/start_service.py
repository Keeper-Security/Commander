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

from ..service.commands.create_service import CreateService
from ..service.commands.config_operation import AddConfigService
from ..service.commands.handle_service import StartService, StopService, ServiceStatus

def register_commands(commands):
    commands['service-create'] = CreateService()
    commands['service-config-add'] = AddConfigService()
    commands['service-start'] = StartService()
    commands['service-stop'] = StopService()
    commands['service-status'] = ServiceStatus()

def register_command_info(aliases, command_info):
    service_classes = [
        CreateService,
        AddConfigService,
        StartService,
        StopService,
        ServiceStatus
    ]
    
    for service_class in service_classes:
        parser = service_class()
        p = parser.get_parser()
        command_info[p.prog] = p.description