#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander - Slack Integration
# Copyright 2025 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

"""
Keeper Commander Slack Integration

A Slack app that enables secure password management 
and approval workflows through Slack, powered by Keeper Commander 
Service Mode.
"""

from .app import KeeperSlackApp

__version__ = "1.0.0"
__all__ = ["KeeperSlackApp"]

