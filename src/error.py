#  _  __  
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|            
#
# Keeper Commander 
# Copyright 2015 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

class Error(Exception):
    """Base class for exceptions in this module."""
    pass

class InputError(Error):
    """Exception raised for errors in the input.

    Attributes:
        expression -- input expression in which the error occurred
        message -- explanation of the error
    """

    def __init__(self, expression, message):
        self.expression = expression
        self.message = message

class AuthenticationError(Error):
    """Exception raised with user fails authentication

    Attributes:
        message -- explanation of authentication error
    """

    def __init__(self, message):
        self.message = message

class CommunicationError(Error):
    """Exception raised with network issues

    Attributes:
        message -- explanation of communication error
    """

    def __init__(self, message):
        self.message = message


class CryptoError(Error):
    """Exception raised with cryptography issues

    Attributes:
        message -- explanation of crypto error
    """

    def __init__(self, message):
        self.message = message
