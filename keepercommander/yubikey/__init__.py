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
import logging
from ..display import bcolors

warned_on_fido_package = False
install_fido_package_warning = 'You can use Security Key with Commander:\n' + \
                               'Install fido2 package ' + bcolors.OKGREEN + \
                               '\'pip install fido2\'\n' + bcolors.ENDC


def display_fido2_warning():
    global warned_on_fido_package

    if not warned_on_fido_package:
        logging.warning(install_fido_package_warning)
    warned_on_fido_package = True
