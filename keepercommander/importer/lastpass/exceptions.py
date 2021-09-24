# coding: utf-8


class Error(Exception):
    """Base class for all errors, should not be raised"""
    pass


#
# Generic errors
#

class NetworkError(Error):
    """Something went wrong with the network"""
    pass


class InvalidResponseError(Error):
    """Server responded with something we don't understand"""
    pass


class UnknownResponseSchemaError(Error):
    """Server responded with XML we don't understand"""
    pass


#
# LastPass returned errors
#

class LastPassUnknownUsernameError(Error):
    """LastPass error: unknown username"""
    pass


class LastPassInvalidPasswordError(Error):
    """LastPass error: invalid password"""
    pass


class LastPassIncorrectGoogleAuthenticatorCodeError(Error):
    """LastPass error: missing or incorrect Google Authenticator code"""
    pass


class LastPassIncorrectYubikeyPasswordError(Error):
    """LastPass error: missing or incorrect Yubikey password"""
    pass


class LastPassUnknownError(Error):
    """LastPass error we don't know about"""
    pass
