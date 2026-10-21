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

def split_to_list(s: str, sep: str):
    """ Split a string to a list using the supplied delimiter/separator """
    return [e.strip() for e in s.split(sep) if e.strip()]


def get_api_path_suffix(queue_enabled: str) -> str:
    return "/api/v2" if queue_enabled == "y" else "/api/v1"
