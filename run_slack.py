#!/usr/bin/env python3
"""
Keeper Commander Slack App - Startup Script
"""

import sys
from keepercommander.service.slack import KeeperSlackApp

if __name__ == "__main__":
    config_path = sys.argv[1] if len(sys.argv) > 1 else "slack_config.yaml"
    
    print(f"Starting Keeper Slack App with config: {config_path}")
    
    app = KeeperSlackApp(config_path=config_path)
    app.start()

