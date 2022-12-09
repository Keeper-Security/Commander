#  _  __  
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|            
#
# Keeper Commander 
# Contact: ops@keepersecurity.com
#

class Error(Exception):
    """Base class for exceptions in this module."""
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return self.message


class KeeperApiError(Error):
    """Exception raised with failed Keeper API request
    """

    def __init__(self, result_code, message):
        super().__init__(message)
        self.result_code = result_code

    def __str__(self):
        return f'{self.result_code or ""}: {self.message or ""}'


class CommandError(Error):
    def __init__(self, command, message):
        super().__init__(message)
        self.command = command

    def __str__(self):
        if self.command:
            return f'{self.command}: {self.message}'
        else:
            return super().__str__()
        