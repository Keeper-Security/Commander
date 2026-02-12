#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2025 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

from .edit import PAMProjectImportCommand
from .extend import PAMProjectExtendCommand
from ..base import GroupCommand

class PAMProjectCommand(GroupCommand):
    def __init__(self):
        super(PAMProjectCommand, self).__init__()
        self.register_command("import", PAMProjectImportCommand(), "Import PAM Project", "i")
        self.register_command("extend", PAMProjectExtendCommand(), "Extend PAM Project by importing additional data", "e")
