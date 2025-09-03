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

from ...service.app import create_app
from ...service.config.service_config import ServiceConfig
from ...service.core.service_manager import ServiceManager

flask_app = create_app()


if __name__ == '__main__':
    service_config = ServiceConfig()
    config_data = service_config.load_config()
    ssl_context = None
    
    if not (port := config_data.get("port")):
        print("Error: Service configuration is incomplete. Please configure the service port in service_config")

    ssl_context = ServiceManager.get_ssl_context(config_data)
    
    flask_app.run(
        host='0.0.0.0',
        port=port,
        ssl_context=ssl_context
    )

