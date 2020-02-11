# -*- coding: utf-8 -*-
#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2019 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import locale # for strxfrm sort

__version__ = '4.19'
__logging_format__ = "%(levelname)s: %(message)s by %(module)s.%(funcName)s in %(fileName)s:%(lineno) at %(asctime)s"

locale.setlocale(locale.LC_ALL, '' if locale.getdefaultlocale() else 'ja_JP.UTF-8')

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

pager = None
